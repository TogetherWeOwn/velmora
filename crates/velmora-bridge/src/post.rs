//! Post stage: plan an extent's articles, persist the plan, then POST.
//!
//! Durability rules:
//! - Message-ids and rendered headers are stored before the first POST and
//!   the stored plan is the only thing ever posted. A retry or a crashed
//!   job's successor re-sends the same message-id, so a repeat is answered
//!   as a duplicate and can never create a second copy under a new id.
//! - A duplicate reply the server cannot confirm (`435`/`441`, then `430`
//!   on `STAT`) fails the job as `dup-unconfirmed`; it is retried later
//!   with the same message-id.
//! - Every catalogue write carries the fenced [`Lease`]. A stale lease
//!   stops the job at once.

use sha2::{Digest, Sha256};
use velmora::article::{
    assemble_article, obfuscate_article, render_obfuscated_headers, OBFUSCATED_YENC_NAME_LEN,
};
use velmora::nntp::{is_retryable_post_error, NntpClient, PostOutcome, MAX_POST_ATTEMPTS};
use velmora::rng::{uniform_below, SystemRng};
use velmora::transport::Transport;
use velmora::yenc::{encode_segment, SegmentParams};

use crate::articles::article_spans;
use crate::fetch::ProviderSession;
use crate::ports::{
    BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, PermitClass, MAX_QUEUE_DELAY_SECS,
};
use crate::types::{
    ArticleRow, ArticleState, BridgeError, ExtentRow, FailClass, Job, JobExtent, JobOutcome,
    OutboxStage, Result, JOB_VERSION,
};

impl<T: Transport> NntpSession for NntpClient<T> {
    async fn post(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        Ok(self.post_article(message_id, article).await?)
    }

    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        match NntpClient::stat(self, message_id).await {
            Ok(_) => Ok(true),
            Err(velmora::Error::ArticleNotFound(_)) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        match self.body_to(message_id, out).await {
            Ok(()) => Ok(BodyOutcome::Found),
            // A single-line reply: the session stays at a command boundary.
            Err(velmora::Error::ArticleNotFound(_)) => Ok(BodyOutcome::Missing),
            Err(e) => Err(e.into()),
        }
    }

    async fn quit(self) {
        NntpClient::quit(self).await;
    }
}

/// First retry delay of a failed job; doubles per attempt.
const RETRY_BASE_SECS: u32 = 60;
/// Longest retry delay of a failed job.
const RETRY_MAX_SECS: u32 = 3600;
/// Retry delay when the catalogue itself failed and nothing was recorded.
const CATALOG_RETRY_SECS: u32 = 60;
/// A job without a provider slot comes back after 15–60 s.
const NO_PERMIT_MIN_SECS: u32 = 15;
const NO_PERMIT_SPREAD_SECS: u32 = 46;

/// Why a stage stopped before finishing.
#[derive(Debug)]
pub(crate) enum Stop {
    /// The lease token no longer matches: write nothing more and ack.
    Fenced,
    /// No provider slot: free the lease without spending an attempt.
    NoPermit,
    /// Free the lease with a failure class; `None` = the default backoff.
    Fail(FailClass, Option<u32>),
    /// The catalogue failed, so nothing can be recorded; the lease expires.
    Catalog,
    /// A session error the caller has not classified yet (it may reconnect).
    Session(BridgeError),
}

impl Stop {
    pub(crate) fn fail(class: FailClass) -> Stop {
        Stop::Fail(class, None)
    }
}

impl From<BridgeError> for Stop {
    fn from(e: BridgeError) -> Stop {
        match e {
            // `440`, or a `502` in answer to a command: the provider
            // refuses this account. Only a `502` to the connection itself
            // means "no slot" (see `ProviderSession::session`).
            BridgeError::Nntp(
                velmora::Error::PostProhibited(_) | velmora::Error::NoPermission(_),
            ) => Stop::fail(FailClass::PostRefused),
            BridgeError::Nntp(_) => Stop::fail(FailClass::NntpError),
            BridgeError::Blob(_) => Stop::fail(FailClass::BlobError),
            BridgeError::Crypto(_) => Stop::fail(FailClass::CryptoError),
            BridgeError::Queue(_) => Stop::fail(FailClass::QueueError),
            BridgeError::Sql(_) | BridgeError::GuardFailed => Stop::Catalog,
            _ => Stop::fail(FailClass::Internal),
        }
    }
}

/// `60 s · 2^(attempts-1)`, capped at one hour.
pub(crate) fn backoff_secs(attempts: u32) -> u32 {
    let shift = attempts.saturating_sub(1).min(6);
    (RETRY_BASE_SECS << shift).min(RETRY_MAX_SECS)
}

/// Turns an early stop into the catalogue write and the queue outcome.
pub(crate) async fn settle<C: Catalog, T: Clock>(
    catalog: &C,
    clock: &T,
    lease: &Lease,
    stop: Stop,
) -> JobOutcome {
    let now = clock.now();
    let stop = match stop {
        Stop::Session(e) => e.into(),
        stop => stop,
    };
    match stop {
        Stop::Fenced | Stop::Session(_) => JobOutcome::Ack,
        Stop::Catalog => JobOutcome::Retry {
            delay_secs: CATALOG_RETRY_SECS,
        },
        Stop::NoPermit => {
            let jitter = uniform_below(&mut SystemRng, u64::from(NO_PERMIT_SPREAD_SECS))
                .ok()
                .and_then(|j| u32::try_from(j).ok())
                .unwrap_or(0);
            let delay_secs = NO_PERMIT_MIN_SECS + jitter;
            match catalog.defer(lease, now.plus_secs(delay_secs), now).await {
                Ok(false) => JobOutcome::Ack,
                _ => JobOutcome::Retry { delay_secs },
            }
        }
        Stop::Fail(class, delay) => {
            let delay_secs = delay.unwrap_or_else(|| backoff_secs(lease.attempts));
            match catalog
                .fail(lease, class, now.plus_secs(delay_secs), now)
                .await
            {
                Ok(false) => JobOutcome::Ack,
                _ => JobOutcome::Retry {
                    delay_secs: delay_secs.min(MAX_QUEUE_DELAY_SECS),
                },
            }
        }
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The slice of `cipher` an article row describes, if it is in bounds.
fn payload_of<'a>(cipher: &'a [u8], row: &ArticleRow) -> Option<&'a [u8]> {
    let start = usize::try_from(row.cipher_offset).ok()?;
    let len = usize::try_from(row.cipher_len).ok()?;
    cipher.get(start..start.checked_add(len)?)
}

/// Renders the complete article for a stored row. Everything on the wire
/// is a function of the stored row and the ciphertext (the yEnc name is
/// the head of the message-id), so a repost is byte-identical.
fn render_article(row: &ArticleRow, total: u32, file_size: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let name: String = row
        .message_id
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .take(OBFUSCATED_YENC_NAME_LEN)
        .collect();
    let params = SegmentParams {
        name,
        part: row.idx + 1,
        total,
        begin: row.cipher_offset + 1,
        end: row.cipher_offset + row.cipher_len,
        file_size,
    };
    let mut body = Vec::with_capacity(payload.len() + payload.len() / 16 + 512);
    encode_segment(&mut body, &params, payload)?;
    Ok(assemble_article(&row.headers, &body)?)
}

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Runs the post stage for a claimed extent: plan, POST every planned
    /// article, then hand over to the verify stage.
    pub async fn post_stage(&self, lease: &Lease, job: &JobExtent) -> JobOutcome {
        match self.post_extent(lease, &job.extent).await {
            Ok(()) => JobOutcome::Ack,
            Err(stop) => settle(&self.catalog, &self.clock, lease, stop).await,
        }
    }

    async fn post_extent(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
    ) -> core::result::Result<(), Stop> {
        let cipher = self
            .safety
            .get(&extent.id.safety_key(), None)
            .await?
            .ok_or(Stop::fail(FailClass::BlobError))?;
        // Only the exact sealed ciphertext is ever posted.
        if cipher.len() as u64 != extent.cipher_size || sha256(&cipher) != extent.cipher_sha256 {
            return Err(Stop::fail(FailClass::Corrupt));
        }
        let plan = self.stored_plan(lease, extent, &cipher).await?;

        if plan.iter().any(|a| a.state == ArticleState::Planned) {
            let provider = self
                .cfg
                .providers
                .iter()
                .find(|p| p.post)
                .ok_or(Stop::fail(FailClass::Internal))?;
            let holder = format!("post:{}", extent.id);
            let mut session = ProviderSession::open(
                &self.catalog,
                &self.nntp,
                &self.clock,
                provider,
                PermitClass::Background,
                &holder,
            )
            .await?
            .ok_or(Stop::NoPermit)?;
            let posted = self
                .post_planned(lease, extent, &plan, &cipher, &mut session)
                .await;
            session.close().await;
            posted?;
        }

        let now = self.clock.now();
        let delay = self.cfg.verify_delay_secs;
        if !self
            .catalog
            .advance(lease, OutboxStage::Verify, now.plus_secs(delay), now)
            .await?
        {
            return Err(Stop::Fenced);
        }
        let next = Job::Extent {
            v: JOB_VERSION,
            extent: lease.extent.clone(),
            generation: lease.generation.clone(),
            stage: OutboxStage::Verify,
        };
        // The outbox row is the obligation: the dispatcher re-sends a
        // notification that is lost here.
        let _ = self.jobs.send(&next, delay.min(MAX_QUEUE_DELAY_SECS)).await;
        Ok(())
    }

    /// The authoritative stored plan, created first when the extent has
    /// none. Whatever this job planned in memory is discarded: a planner
    /// that lost the insert race posts the winner's message-ids.
    async fn stored_plan(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        cipher: &[u8],
    ) -> core::result::Result<Vec<ArticleRow>, Stop> {
        let spans = article_spans(extent.cipher_size);
        let mut plan = self.catalog.articles(&extent.id).await?;
        if plan.is_empty() {
            let groups: Vec<&str> = self.cfg.newsgroups.iter().map(String::as_str).collect();
            let now_secs = self.clock.now().secs().0;
            let mut rows = Vec::with_capacity(spans.len());
            for (idx, span) in (0u32..).zip(&spans) {
                let meta = obfuscate_article(&mut SystemRng, now_secs, &groups)
                    .map_err(|_| Stop::fail(FailClass::Internal))?;
                let headers = render_obfuscated_headers(&meta)
                    .map_err(|_| Stop::fail(FailClass::Internal))?;
                let mut row = ArticleRow {
                    extent_id: extent.id.clone(),
                    idx,
                    message_id: meta.message_id,
                    newsgroup: meta.newsgroup,
                    headers,
                    cipher_offset: span.start,
                    cipher_len: span.len,
                    payload_sha256: [0; 32],
                    state: ArticleState::Planned,
                    provider_id: None,
                    posted_at: None,
                };
                let payload = payload_of(cipher, &row).ok_or(Stop::fail(FailClass::Internal))?;
                row.payload_sha256 = sha256(payload);
                rows.push(row);
            }
            plan = self
                .catalog
                .plan_articles(lease, &rows)
                .await?
                .ok_or(Stop::Fenced)?;
        }
        // The stored plan must describe this ciphertext article for article.
        let matches = plan.len() == spans.len()
            && (0u32..).zip(&plan).zip(&spans).all(|((idx, row), span)| {
                row.idx == idx && row.cipher_offset == span.start && row.cipher_len == span.len
            });
        if !matches {
            return Err(Stop::fail(FailClass::Internal));
        }
        Ok(plan)
    }

    async fn post_planned(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &[ArticleRow],
        cipher: &[u8],
        session: &mut ProviderSession<'_, C, N, T>,
    ) -> core::result::Result<(), Stop> {
        let total = u32::try_from(plan.len()).map_err(|_| Stop::fail(FailClass::Internal))?;
        for row in plan.iter().filter(|a| a.state == ArticleState::Planned) {
            session.keep(Some(lease)).await?;
            let payload = payload_of(cipher, row)
                .filter(|p| sha256(p) == row.payload_sha256)
                .ok_or(Stop::fail(FailClass::Internal))?;
            let article = render_article(row, total, extent.cipher_size, payload)
                .map_err(|_| Stop::fail(FailClass::Internal))?;
            post_one(session, lease, row, &article).await?;
            let provider = session.provider.id.as_str();
            if !self
                .catalog
                .mark_posted(lease, row.idx, provider, self.clock.now())
                .await?
            {
                return Err(Stop::Fenced);
            }
        }
        Ok(())
    }
}

/// POSTs one article. `Posted` and a confirmed `Duplicate` both mean the
/// provider has it. A stale connection is replaced and the same article
/// re-sent, at most [`MAX_POST_ATTEMPTS`] tries in all; the lease and the
/// permit are renewed before each reconnect. A server verdict is never
/// retried here.
async fn post_one<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: &Lease,
    row: &ArticleRow,
    article: &[u8],
) -> core::result::Result<(), Stop> {
    let mut attempt = 1;
    loop {
        let result = match session.session().await {
            Ok(s) => s.post(&row.message_id, article).await,
            Err(Stop::Session(e)) => Err(e),
            Err(stop) => return Err(stop),
        };
        let err = match result {
            Ok(PostOutcome::Posted | PostOutcome::Duplicate) => return Ok(()),
            Err(e) => e,
        };
        // Any session error: never reuse the session.
        session.discard();
        match err {
            BridgeError::Nntp(e) if is_retryable_post_error(&e) && attempt < MAX_POST_ATTEMPTS => {
                attempt += 1;
                session.keep(Some(lease)).await?;
            }
            // The server says "duplicate" (or a bare "posting failed") but
            // cannot show the article: come back later with the same
            // message-id, never a new one.
            BridgeError::Nntp(velmora::Error::NntpReply {
                code: 435 | 441, ..
            }) => return Err(Stop::fail(FailClass::DupUnconfirmed)),
            other => return Err(other.into()),
        }
    }
}
