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
//! - A job posts over several connections at once, spread over the
//!   `post` providers of one priority tier. Each article is posted once,
//!   to one provider; the other backbones get it by propagation, which
//!   the verify stage checks (and repairs, see `verify`).
//! - A provider that refuses the post or cannot be reached hands its
//!   articles to the other providers of the tier, then to the next tier,
//!   again under the stored message-ids: failover never mints an id.
//! - The lease and every provider permit are renewed on demand: before
//!   each call to a provider, when the last renewal is older than a set
//!   age. There is no timer; no call starts unless both were confirmed
//!   recently enough to outlast it.
//! - A job takes a slot on its first tier before it loads the extent,
//!   and gives its lease back at once when there is none.
//! - Every catalogue write carries the fenced [`Lease`]. A stale lease
//!   stops the job at once.

use core::cell::{Cell, RefCell};
use core::task::{Poll, Waker};
use std::collections::VecDeque;

use futures_util::future::{join_all, poll_fn};
use futures_util::lock::Mutex;
use sha2::{Digest, Sha256};
use velmora::article::{
    assemble_article, obfuscate_article, render_obfuscated_headers, OBFUSCATED_YENC_NAME_LEN,
};
use velmora::nntp::{is_retryable_post_error, NntpClient, PostOutcome, MAX_POST_ATTEMPTS};
use velmora::rng::{uniform_below, SystemRng};
use velmora::transport::Transport;
use velmora::yenc::{encode_segment, SegmentParams};

use crate::articles::article_spans;
use crate::fetch::{report_health, ProviderSession};
use crate::jobs::JOB_OVERHEAD_BYTES;
use crate::pool::Pool;
use crate::ports::{
    BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, Permit, PermitClass, LEASE_SECS, MAX_QUEUE_DELAY_SECS, NNTP_CALL_SECS,
    PERMIT_SECS,
};
use crate::recovery::write_article_plan;
use crate::types::{
    ArticleRow, ArticleState, BridgeError, ExtentRow, FailClass, Job, JobExtent, JobOutcome,
    OutboxStage, ProviderConfig, Result, SafetyState, UnixMs, JOB_VERSION,
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
    /// Every provider that could do the work is in a cooldown until then:
    /// free the lease until that time without spending an attempt.
    Cooling(UnixMs),
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
        Stop::Cooling(until) => {
            // Rounded up: a job that arrives early cannot claim the row.
            let secs = (until.0 - now.0).saturating_add(999).div_euclid(1000);
            let delay_secs = u32::try_from(secs)
                .unwrap_or(0)
                .clamp(1, MAX_QUEUE_DELAY_SECS);
            match catalog.defer(lease, until.max(now), now).await {
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
        // A job that comes back to an extent it has posted already (a
        // crash before the stage moved on, a revived obligation) needs no
        // provider: it only writes the recovery record again.
        let stored = self.catalog.articles(&extent.id).await?;
        if !stored.is_empty() && stored.iter().all(|a| a.state == ArticleState::Posted) {
            self.load_planned(lease, extent).await?;
            return self.to_verify(lease).await;
        }
        let holder = format!("post:{}", extent.id);
        let pool = Pool::load(&self.catalog, &self.cfg.providers, self.clock.now()).await?;
        let posters: Vec<&ProviderConfig> = self.cfg.providers.iter().filter(|p| p.post).collect();
        let cooling = pool.cooling_until(&posters);
        let order = pool.order(posters);
        // A slot first. Loading and hashing the extent is the expensive
        // part of the job: one that would only find every slot of its
        // first tier taken gives its lease back before it, not after.
        let Some(first_tier) = order.chunk_by(|a, b| a.priority == b.priority).next() else {
            return Err(match cooling {
                Some(until) => Stop::Cooling(until),
                None => Stop::fail(FailClass::Internal),
            });
        };
        let (mut held, _) = self.open_sessions(first_tier, &holder, 1, None).await?;
        let Some(first) = held.pop() else {
            return Err(Stop::NoPermit);
        };
        let (cipher, mut plan) = match self.load_planned(lease, extent).await {
            Ok(loaded) => loaded,
            Err(stop) => {
                first.close().await;
                return Err(stop);
            }
        };
        if plan.iter().any(|a| a.state == ArticleState::Planned) {
            self.post_with_failover(lease, extent, &mut plan, &cipher, &order, cooling, first)
                .await?;
        } else {
            first.close().await;
        }
        self.to_verify(lease).await
    }

    /// Every article is recorded as posted: the extent goes on to verify.
    async fn to_verify(&self, lease: &Lease) -> core::result::Result<(), Stop> {
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

    /// The verified ciphertext of the extent and its stored article plan,
    /// with the recovery record of the plan written.
    async fn load_planned(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
    ) -> core::result::Result<(Vec<u8>, Vec<ArticleRow>), Stop> {
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
        // The message-ids exist nowhere but the catalogue until this
        // record is stored: without it, a lost catalogue could not find
        // the extent on Usenet. Nothing is posted before it is durable.
        write_article_plan(&self.safety, &self.kek, extent, &plan)
            .await
            .map_err(|_| Stop::fail(FailClass::BlobError))?;
        Ok((cipher, plan))
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

    /// Posts the planned articles, priority tier by priority tier. The
    /// job opens up to `post_sockets` connections, each on its own permit,
    /// spread over the providers of the tier in pool order (a provider
    /// without a free slot is passed over), and every socket takes the
    /// next article from one shared queue: each article is posted once,
    /// by whichever socket is free. When a provider refuses the post or
    /// its connection fails, its article goes back to the queue for
    /// another socket, **under the same stored message-id and headers**:
    /// a provider that already has an article answers "duplicate", which
    /// is confirmed and recorded once, like any other accepted post.
    ///
    /// A lower tier is a backup for failure, not overflow: it is reached
    /// only when every provider of the tiers above was tried and failed.
    /// While one of them is merely busy the job waits for a slot.
    ///
    /// `order` is the posting providers in pool order and `first` a
    /// session the job already holds on its first tier.
    #[allow(clippy::too_many_arguments)]
    async fn post_with_failover<'a>(
        &'a self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &mut [ArticleRow],
        cipher: &[u8],
        order: &[&'a ProviderConfig],
        cooling: Option<UnixMs>,
        first: ProviderSession<'a, C, N, T>,
    ) -> core::result::Result<(), Stop> {
        let holder = format!("post:{}", extent.id);
        let mut first = Some(first);
        let mut failed = None;
        // Per article: a POST of it may have landed on a provider that
        // then failed, so the next provider is asked before it is sent.
        let mut unknown = vec![false; plan.len()];
        for tier in order.chunk_by(|a, b| a.priority == b.priority) {
            // Providers of the tier that have not posted for this job yet.
            let mut untried: Vec<&ProviderConfig> = tier.to_vec();
            // A provider of the tier refused a login because its account
            // is at its limit (or a permit was gone): it is not asked
            // again in this job, but it may do the work later.
            let mut busy = false;
            // A provider still untried had no slot in the catalogue when
            // the tier was last asked.
            let mut no_slot;
            loop {
                let todo: Vec<usize> = (0..plan.len())
                    .filter(|at| plan[*at].state == ArticleState::Planned)
                    .collect();
                let (sessions, without) = self
                    .open_sessions(&untried, &holder, todo.len(), first.take())
                    .await?;
                no_slot = without;
                if sessions.is_empty() {
                    break;
                }
                // Each provider gets one round: one that failed is not
                // asked again in this job, the rest of the tier is.
                untried.retain(|p| !sessions.iter().any(|s| s.provider.id == p.id));
                let round = Round::new(&self.catalog, &self.clock, lease, extent, cipher, plan);
                let ended = round
                    .run(sessions, todo.iter().map(|at| (*at, unknown[*at])), true)
                    .await;
                for (flag, landed) in unknown.iter_mut().zip(&ended.unknown) {
                    *flag |= *landed;
                }
                for (row, marked) in plan.iter_mut().zip(&ended.marked) {
                    if *marked {
                        row.state = ArticleState::Posted;
                    }
                }
                busy |= ended.busy;
                match ended.stop {
                    None if plan.iter().all(|a| a.state == ArticleState::Posted) => return Ok(()),
                    None => return Err(Stop::fail(FailClass::Internal)),
                    Some(stop @ Stop::Fail(FailClass::PostRefused | FailClass::NntpError, _)) => {
                        // A connection failed: what this provider took,
                        // now or in an earlier run, is not known.
                        if matches!(stop, Stop::Fail(FailClass::NntpError, _)) {
                            unknown.fill(true);
                        }
                        // The first failure is the one reported.
                        failed.get_or_insert(stop);
                    }
                    // Every socket of the round found no slot: the rest
                    // of the tier is asked first.
                    Some(Stop::NoPermit) => {}
                    Some(stop) => return Err(stop),
                }
            }
            if busy || no_slot {
                // A healthy provider of the tier had no slot: wait for it
                // rather than spend an attempt or fall to a backup.
                return Err(Stop::NoPermit);
            }
        }
        Err(match (failed, cooling) {
            (Some(stop), _) => stop,
            (None, Some(until)) => Stop::Cooling(until),
            (None, None) => Stop::fail(FailClass::Internal),
        })
    }

    /// Opens up to `post_sockets` posting sessions (never more than
    /// `articles`) over `providers`, one provider after the other in
    /// turns, so the sockets spread over every provider with a free slot.
    /// The flag says whether a provider had no slot at all. `first` is a
    /// session of one of them that the job holds already: it counts.
    pub(crate) async fn open_sessions<'a>(
        &'a self,
        providers: &[&'a ProviderConfig],
        holder: &str,
        articles: usize,
        first: Option<ProviderSession<'a, C, N, T>>,
    ) -> Result<(Vec<ProviderSession<'a, C, N, T>>, bool)> {
        let wanted = usize::try_from(self.cfg.post_sockets)
            .unwrap_or(1)
            .clamp(1, articles.max(1));
        let mut sessions = Vec::new();
        let mut busy = false;
        let mut open: Vec<&ProviderConfig> = providers.to_vec();
        let mut turn = 0;
        if let Some(first) = first {
            // The next socket goes to the provider after this one.
            let at = providers.iter().position(|p| p.id == first.provider.id);
            turn = at.map_or(0, |at| at + 1);
            sessions.push(first);
        }
        while sessions.len() < wanted && !open.is_empty() {
            let provider = open[turn % open.len()];
            let opened = ProviderSession::open(
                &self.catalog,
                &self.nntp,
                &self.clock,
                provider,
                PermitClass::Background,
                holder,
            )
            .await;
            match opened {
                Ok(Some(session)) => {
                    sessions.push(session);
                    turn += 1;
                }
                Ok(None) => {
                    busy |= !sessions.iter().any(|s| s.provider.id == provider.id);
                    open.remove(turn % open.len());
                }
                // Nothing may hold a slot the job will not use.
                Err(e) => {
                    for session in sessions {
                        session.close().await;
                    }
                    return Err(e);
                }
            }
        }
        Ok((sessions, busy))
    }

    /// Posts the articles `missing` (by `ArticleRow::idx`) of a posted
    /// extent once more, straight to `providers`, from the safety copy
    /// and under the stored message-ids and headers: a provider that has
    /// an article after all is not sent it again. The article rows are
    /// left as they are; the first provider stays the recorded one.
    ///
    /// `Ok(false)` = it cannot be done now (no provider that posts, no
    /// intact safety copy, or the providers refused): the caller carries
    /// on as if there were no repost.
    pub(crate) async fn repost(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &[ArticleRow],
        missing: &[u32],
        providers: &[&ProviderConfig],
    ) -> core::result::Result<bool, Stop> {
        if providers.is_empty() || extent.safety_state != SafetyState::Held {
            return Ok(false);
        }
        // Unlike the rest of its stage, a repost holds the whole extent. A
        // repost larger than the budget still has to run, alone: next to
        // what its own stage already holds.
        let room = self.budget.capacity().saturating_sub(JOB_OVERHEAD_BYTES);
        let bytes = extent
            .cipher_size
            .saturating_add(u64::from(self.cfg.post_sockets) * POST_SOCKET_BYTES)
            .min(room);
        let Ok(_charge) = self.budget.charge(bytes).await else {
            return Err(Stop::NoPermit);
        };
        let cipher = match self.safety.get(&extent.id.safety_key(), None).await {
            Ok(Some(cipher)) => cipher,
            _ => return Ok(false),
        };
        if cipher.len() as u64 != extent.cipher_size || sha256(&cipher) != extent.cipher_sha256 {
            return Ok(false);
        }
        let pool = Pool::load(&self.catalog, &self.cfg.providers, self.clock.now()).await?;
        let order = pool.order(providers.to_vec());
        if order.is_empty() {
            return match pool.cooling_until(providers) {
                Some(until) => Err(Stop::Cooling(until)),
                None => Ok(false),
            };
        }
        let todo: Vec<usize> = (0..plan.len())
            .filter(|at| missing.contains(&plan[*at].idx))
            .collect();
        let holder = format!("repost:{}", extent.id);
        let (sessions, _) = self
            .open_sessions(&order, &holder, todo.len(), None)
            .await?;
        if sessions.is_empty() {
            return Err(Stop::NoPermit);
        }
        let round = Round::new(&self.catalog, &self.clock, lease, extent, &cipher, plan);
        // `true`: each article is looked up before it is sent.
        let ended = round
            .run(sessions, todo.into_iter().map(|at| (at, true)), false)
            .await;
        match ended.stop {
            None => Ok(true),
            Some(stop @ (Stop::Fenced | Stop::Catalog | Stop::NoPermit)) => Err(stop),
            Some(_) => Ok(false),
        }
    }
}

/// A posting job holds one rendered article per socket.
pub(crate) const POST_SOCKET_BYTES: u64 = 1024 * 1024;

/// The lease and every permit of a posting job are renewed together, in
/// one catalogue round trip, once the last renewal is this old.
const KEEP_EVERY_MS: i64 = 20_000;
/// The longest one call to the connector may take ([`NNTP_CALL_SECS`])
/// plus a margin. No connect, lookup or POST starts with less than this
/// left on the lease or on its permit.
const POST_RESERVE_MS: i64 = 90_000;
const _: () = assert!(POST_RESERVE_MS >= NNTP_CALL_SECS as i64 * 1000 + 10_000);
// A renewal at most `KEEP_EVERY_MS` old leaves the reserve on both.
const _: () = assert!(PERMIT_SECS as i64 * 1000 - KEEP_EVERY_MS >= POST_RESERVE_MS);
const _: () = assert!(LEASE_SECS >= PERMIT_SECS);

/// Why a whole round stops: nothing more is posted or recorded.
#[derive(Clone, Copy)]
enum Fatal {
    Fenced,
    Catalog,
}

impl Fatal {
    fn stop(self) -> Stop {
        match self {
            Fatal::Fenced => Stop::Fenced,
            Fatal::Catalog => Stop::Catalog,
        }
    }
}

/// One socket of a round.
struct Socket {
    /// `None` = the permit is lost or given back.
    permit: Option<Permit>,
}

struct RoundState<'a> {
    /// Articles nobody has accepted yet: positions in the plan.
    queue: VecDeque<usize>,
    /// Per plan position: a POST of the article may have landed without
    /// anyone knowing (a lost reply, a broken connection), so it is
    /// looked up before it is sent again, on any provider.
    unknown: Vec<bool>,
    /// Articles a socket is posting right now.
    in_flight: usize,
    /// Sockets waiting for an article that may come back to the queue.
    idle: Vec<Waker>,
    /// The time of the last renewal that confirmed the lease.
    kept_at: Option<UnixMs>,
    fatal: Option<Fatal>,
    sockets: Vec<Socket>,
    /// Providers whose verdict another of their sockets would only repeat.
    closed: Vec<&'a str>,
    /// Per plan position: the provider that accepted the article.
    accepted: Vec<Option<&'a str>>,
    /// Per plan position: recorded as posted in the catalogue.
    marked: Vec<bool>,
}

/// How a round ended.
pub(crate) struct Ended {
    /// `None` = every article of the round was accepted (and, when the
    /// round records, recorded). Otherwise why articles are left.
    pub(crate) stop: Option<Stop>,
    /// Per plan position: recorded as posted in the catalogue.
    pub(crate) marked: Vec<bool>,
    /// Per plan position: a POST may have landed (see [`post_one`]).
    pub(crate) unknown: Vec<bool>,
    /// A socket found no slot: its permit was gone, or the provider
    /// refused the login because the account is at its limit.
    pub(crate) busy: bool,
}

/// One pass of a job over its open sockets. The sockets share the queue,
/// the time of the last renewal and the pending catalogue writes; the job runs on
/// one thread, so the state is only ever borrowed between two awaits.
pub(crate) struct Round<'a, C: Catalog, T: Clock> {
    catalog: &'a C,
    clock: &'a T,
    lease: &'a Lease,
    extent: &'a ExtentRow,
    cipher: &'a [u8],
    plan: &'a [ArticleRow],
    /// Whether accepted articles are recorded as posted.
    record: Cell<bool>,
    /// Serialises renewals: one socket renews, the others wait for it.
    tick: Mutex<()>,
    state: RefCell<RoundState<'a>>,
}

impl<'a, C: Catalog, T: Clock> Round<'a, C, T> {
    pub(crate) fn new(
        catalog: &'a C,
        clock: &'a T,
        lease: &'a Lease,
        extent: &'a ExtentRow,
        cipher: &'a [u8],
        plan: &'a [ArticleRow],
    ) -> Self {
        Round {
            catalog,
            clock,
            lease,
            extent,
            cipher,
            plan,
            record: Cell::new(false),
            tick: Mutex::new(()),
            state: RefCell::new(RoundState {
                queue: VecDeque::new(),
                unknown: vec![false; plan.len()],
                in_flight: 0,
                idle: Vec::new(),
                kept_at: None,
                fatal: None,
                sockets: Vec::new(),
                closed: Vec::new(),
                accepted: vec![None; plan.len()],
                marked: vec![false; plan.len()],
            }),
        }
    }

    /// Posts the articles of `todo` (positions in the plan, each with its
    /// `unknown` flag, see [`post_one`]) over `sessions`, all sockets at
    /// once, and closes every session. With `record` the accepted
    /// articles are marked posted in the catalogue, under the lease.
    pub(crate) async fn run<N: NntpConnector>(
        self,
        sessions: Vec<ProviderSession<'a, C, N, T>>,
        todo: impl Iterator<Item = (usize, bool)>,
        record: bool,
    ) -> Ended {
        self.record.set(record);
        let mut providers: Vec<&'a str> = Vec::new();
        {
            let mut state = self.state.borrow_mut();
            for (at, unknown) in todo {
                state.queue.push_back(at);
                state.unknown[at] |= unknown;
            }
            for session in &sessions {
                let provider = session.provider.id.as_str();
                if !providers.contains(&provider) {
                    providers.push(provider);
                }
                state.sockets.push(Socket {
                    permit: Some(session.permit().clone()),
                });
            }
        }
        let work = sessions
            .into_iter()
            .enumerate()
            .map(|(slot, session)| self.work(slot, session));
        let ended = join_all(work).await;
        // Also after the catalogue failed once: what the providers
        // accepted is recorded if the catalogue answers now. The write is
        // fenced like every other, so a stale lease still writes nothing.
        self.flush(true).await;

        // One strike or one recovery per provider, however many sockets:
        // a provider that answered one socket in order is in order.
        for provider in providers {
            let mine = || ended.iter().filter(|e| e.0 == provider);
            let healthy = match mine().any(|e| e.2 == Some(true)) {
                true => Some(true),
                false => mine().find_map(|e| e.2),
            };
            report_health(self.catalog, self.clock, provider, healthy).await;
        }
        let busy = ended.iter().any(|e| matches!(e.1, Some(Stop::NoPermit)));
        let state = self.state.into_inner();
        let left = state.queue.len() + state.in_flight;
        let stop = match (state.fatal, left) {
            (Some(fatal), _) => Some(fatal.stop()),
            (None, 0) => None,
            // Articles are left: the first provider in order says why. A
            // socket that only found no slot does not outweigh one that
            // failed.
            (None, _) => {
                let mut stops = ended.into_iter().filter_map(|e| e.1);
                let mut stop = stops.next().unwrap_or(Stop::fail(FailClass::Internal));
                if matches!(stop, Stop::NoPermit) {
                    stop = stops.find(|s| !matches!(s, Stop::NoPermit)).unwrap_or(stop);
                }
                Some(stop)
            }
        };
        Ended {
            stop,
            marked: state.marked,
            unknown: state.unknown,
            busy,
        }
    }

    /// One socket: takes the next article until none is left or the
    /// socket fails, then ends the session and frees its slot. A failed
    /// article goes back to the queue for another socket. Returns the
    /// provider, why the socket stopped early, and the session's health.
    async fn work<N: NntpConnector>(
        &self,
        slot: usize,
        mut session: ProviderSession<'a, C, N, T>,
    ) -> (&'a str, Option<Stop>, Option<bool>) {
        let provider = session.provider.id.as_str();
        let stop = loop {
            let Some(at) = self.take(provider).await else {
                break None;
            };
            let posted = self.post_at(slot, &mut session, at).await;
            let mut state = self.state.borrow_mut();
            state.in_flight -= 1;
            // Whatever happened, a waiting socket has to look again.
            state.idle.drain(..).for_each(Waker::wake);
            match posted {
                Ok(()) => {
                    // The provider has the article, so it is recorded.
                    state.accepted[at] = Some(provider);
                    // The slot went to someone else during the call (a
                    // renewal by another socket found it gone): nothing
                    // more is sent on this socket.
                    if state.sockets[slot].permit.is_none() {
                        session.discard();
                        break Some(Stop::NoPermit);
                    }
                }
                Err(stop) => {
                    let stop = match stop {
                        Stop::Session(e) => e.into(),
                        stop => stop,
                    };
                    // A broken connection: the article may have landed.
                    let landed = matches!(stop, Stop::Fail(FailClass::NntpError, _));
                    state.unknown[at] |= landed;
                    state.queue.push_front(at);
                    // Only "no slot" and a broken connection are this
                    // socket's own trouble; any other verdict would be
                    // repeated to every socket of the provider.
                    if !(landed || matches!(stop, Stop::NoPermit)) {
                        state.closed.push(provider);
                    }
                    break Some(stop);
                }
            }
        };
        self.state.borrow_mut().sockets[slot].permit = None;
        let healthy = session.finish().await;
        (provider, stop, healthy)
    }

    /// The next article for a socket of `provider`. With an empty queue
    /// it waits while another socket is still posting, because that
    /// article may come back; `None` = nothing is left for this socket.
    async fn take(&self, provider: &str) -> Option<usize> {
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            if state.fatal.is_some() || state.closed.contains(&provider) {
                return Poll::Ready(None);
            }
            if let Some(next) = state.queue.pop_front() {
                state.in_flight += 1;
                return Poll::Ready(Some(next));
            }
            if state.in_flight == 0 {
                return Poll::Ready(None);
            }
            state.idle.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    async fn post_at<N: NntpConnector>(
        &self,
        slot: usize,
        session: &mut ProviderSession<'a, C, N, T>,
        at: usize,
    ) -> core::result::Result<(), Stop> {
        let row = &self.plan[at];
        let total = u32::try_from(self.plan.len()).map_err(|_| Stop::fail(FailClass::Internal))?;
        self.keep(slot, session).await?;
        let payload = payload_of(self.cipher, row)
            .filter(|p| sha256(p) == row.payload_sha256)
            .ok_or(Stop::fail(FailClass::Internal))?;
        let article = render_article(row, total, self.extent.cipher_size, payload)
            .map_err(|_| Stop::fail(FailClass::Internal))?;
        post_one(self, slot, session, at, &article).await
    }

    /// Call it before every connect, lookup and POST. It returns
    /// `Ok` only while the lease and the permit of `slot` were both
    /// confirmed by the catalogue less than [`KEEP_EVERY_MS`] ago, which
    /// leaves [`POST_RESERVE_MS`] on each: no POST and no new socket
    /// starts on a lease or a slot that could pass to someone else before
    /// the POST ends. On any refusal the socket is dropped at once.
    async fn keep<N: NntpConnector>(
        &self,
        slot: usize,
        session: &mut ProviderSession<'a, C, N, T>,
    ) -> core::result::Result<(), Stop> {
        let kept = self.kept(slot).await;
        if kept.is_err() {
            session.discard();
        }
        kept
    }

    async fn kept(&self, slot: usize) -> core::result::Result<(), Stop> {
        let _one_at_a_time = self.tick.lock().await;
        // A second try covers a renewal that itself took too long.
        for _ in 0..2 {
            let now = self.clock.now();
            {
                let state = self.state.borrow();
                if let Some(fatal) = state.fatal {
                    return Err(fatal.stop());
                }
                let fresh = state
                    .kept_at
                    .is_some_and(|at| (0..KEEP_EVERY_MS).contains(&(now.0 - at.0)));
                if fresh {
                    return match state.sockets[slot].permit {
                        Some(_) => Ok(()),
                        None => Err(Stop::NoPermit),
                    };
                }
            }
            self.renew(now).await;
        }
        // The catalogue is too slow to prove the lease: come back later.
        Err(Stop::Catalog)
    }

    /// Renews the lease and every held permit in one round trip, then
    /// records the articles accepted since the last time.
    async fn renew(&self, now: UnixMs) {
        let (slots, permits): (Vec<usize>, Vec<Permit>) = {
            let state = self.state.borrow();
            (0..)
                .zip(&state.sockets)
                .filter_map(|(slot, s)| s.permit.clone().map(|p| (slot, p)))
                .unzip()
        };
        let renewed = self.catalog.renew_all(self.lease, &permits, now).await;
        {
            let mut state = self.state.borrow_mut();
            match renewed {
                Ok((true, held)) if held.len() == slots.len() => {
                    for (slot, held) in slots.into_iter().zip(held) {
                        // A socket that ended meanwhile stays ended.
                        if !held {
                            state.sockets[slot].permit = None;
                        }
                    }
                    state.kept_at = Some(now);
                }
                Ok((false, _)) => state.fatal = Some(Fatal::Fenced),
                _ => state.fatal = Some(Fatal::Catalog),
            }
        }
        self.flush(false).await;
    }

    /// Records the articles accepted so far as posted, all in one fenced
    /// write. A stale lease writes nothing and stops the round. `last` =
    /// the round is over: one more try even after a catalogue failure.
    async fn flush(&self, last: bool) {
        let due: Vec<(usize, u32, &str)> = {
            let state = self.state.borrow();
            let stopped = match state.fatal {
                None => false,
                Some(Fatal::Catalog) => !last,
                Some(Fatal::Fenced) => true,
            };
            if stopped || !self.record.get() {
                return;
            }
            (0..self.plan.len())
                .filter(|at| !state.marked[*at])
                .filter_map(|at| Some((at, self.plan[at].idx, state.accepted[at]?)))
                .collect()
        };
        if due.is_empty() {
            return;
        }
        let rows: Vec<(u32, &str)> = due.iter().map(|(_, idx, p)| (*idx, *p)).collect();
        let now = self.clock.now();
        let marked = self.catalog.mark_posted_many(self.lease, &rows, now).await;
        let mut state = self.state.borrow_mut();
        match marked {
            Ok(true) => due.iter().for_each(|(at, ..)| state.marked[*at] = true),
            Ok(false) => state.fatal = Some(Fatal::Fenced),
            Err(_) => state.fatal = Some(Fatal::Catalog),
        }
    }
}

/// One try at one article: connect if there is no session, look the
/// message-id up when the article may be there already, then POST. Each
/// of the three is one call to the connector, which ends within
/// [`NNTP_CALL_SECS`]; the lease and the permit are checked again
/// ([`Round::keep`]) before the lookup and before the POST, so every
/// call starts with [`POST_RESERVE_MS`] left however long the calls
/// before it took. The inner result is the session's own verdict.
async fn exchange<'a, C: Catalog, N: NntpConnector, T: Clock>(
    round: &Round<'a, C, T>,
    slot: usize,
    session: &mut ProviderSession<'a, C, N, T>,
    row: &ArticleRow,
    article: &[u8],
    unknown: bool,
) -> core::result::Result<Result<()>, Stop> {
    session.session().await?;
    round.keep(slot, session).await?;
    if unknown {
        match session.session().await?.stat(&row.message_id).await {
            Ok(true) => return Ok(Ok(())),
            Ok(false) => {}
            Err(e) => return Ok(Err(e)),
        }
        round.keep(slot, session).await?;
    }
    let posted = session
        .session()
        .await?
        .post(&row.message_id, article)
        .await;
    Ok(posted.map(|_| ()))
}

/// POSTs one article. `Posted` and a confirmed `Duplicate` both mean the
/// provider has it. A stale connection is replaced and the same article
/// re-sent, at most [`MAX_POST_ATTEMPTS`] tries in all; the lease and the
/// permit are checked ([`Round::keep`]) before each reconnect. A server verdict is never
/// retried here.
///
/// A POST whose reply never arrived is **unknown**, not failed: the
/// provider may have stored the article. So before the article is sent
/// again, on the reconnected provider or (`unknown`) on a failover
/// provider, the message-id is looked up with `STAT`. An article that is
/// there counts as posted; only an absent one is posted again, under the
/// same message-id.
async fn post_one<'a, C: Catalog, N: NntpConnector, T: Clock>(
    round: &Round<'a, C, T>,
    slot: usize,
    session: &mut ProviderSession<'a, C, N, T>,
    at: usize,
    article: &[u8],
) -> core::result::Result<(), Stop> {
    let row = &round.plan[at];
    let mut attempt = 1;
    loop {
        // The flag is the round's, not this call's: it stays with the
        // article when this socket gives up on it.
        let unknown = round.state.borrow().unknown[at];
        let result = match exchange(round, slot, session, row, article, unknown).await {
            Ok(result) => result,
            Err(Stop::Session(e)) => Err(e),
            Err(stop) => return Err(stop),
        };
        let err = match result {
            // Posted, a confirmed duplicate, or found by the lookup.
            Ok(()) => {
                session.note_ok();
                return Ok(());
            }
            Err(e) => e,
        };
        session.note_err(&err);
        // Any session error: never reuse the session.
        session.discard();
        if matches!(&err, BridgeError::Nntp(e) if is_retryable_post_error(e)) {
            round.state.borrow_mut().unknown[at] = true;
        }
        match err {
            BridgeError::Nntp(e) if is_retryable_post_error(&e) && attempt < MAX_POST_ATTEMPTS => {
                attempt += 1;
                round.keep(slot, session).await?;
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
