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
//!   `post` providers of one priority tier, all under one permit holder:
//!   a provider that limits source addresses (`max_ips`) counts the job
//!   once. Each article is posted once,
//!   to one provider; the other backbones get it by propagation, which
//!   the verify stage checks (and repairs, see `verify`).
//! - A provider that refuses the post or cannot be reached hands its
//!   articles to the other providers of the tier, then to the next tier,
//!   again under the stored message-ids: failover never mints an id.
//! - The lease and every provider permit are renewed on demand: before
//!   each call to a provider, when the last renewal is older than a set
//!   age. There is no timer; no call starts unless both were confirmed
//!   recently enough to outlast it.
//! - A job takes its slots on its first tier before it loads the extent,
//!   and gives its lease back at once when there is none. Its sockets
//!   connect while the extent loads; the first POST waits for the stored
//!   plan record.
//! - Every catalogue write carries the fenced [`Lease`]. A stale lease
//!   stops the job at once.

use core::cell::{Cell, RefCell};
use core::task::{Poll, Waker};
use std::collections::VecDeque;

use futures_util::future::{join, join_all, poll_fn};
use futures_util::lock::Mutex;
use sha2::{Digest, Sha256};
use velmora::article::{assemble_article_with, OBFUSCATED_YENC_NAME_LEN};
use velmora::nntp::{is_retryable_post_error, NntpClient, PostOutcome, MAX_POST_ATTEMPTS};
use velmora::rng::{uniform_below, SystemRng};
use velmora::transport::Transport;
use velmora::yenc::{encode_segment_vec, SegmentParams};

use crate::articles::article_spans;
use crate::fetch::{forgiven, job_holder, report_health, Health, ProviderSession};
use crate::ingress::{Charge, Lent};
use crate::jobs::{parity_job_bytes, JOB_OVERHEAD_BYTES};
use crate::parity::{self, ParityPlan};
use crate::plan::{draw, pack_seeded, StoredPlan};
use crate::pool::Pool;
use crate::ports::{
    BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, Permit, PermitClass, SizeOutcome, LEASE_SECS, MAX_QUEUE_DELAY_SECS,
    NNTP_CALL_SECS, PERMIT_SECS,
};
use crate::recovery::write_stored_plan;
use crate::types::{
    valid_yenc_name, ArticleRow, ArticleState, BridgeError, ExtentRow, FailClass, JobExtent,
    JobOutcome, OutboxStage, ProviderConfig, Result, SafetyState, SizeCommand, UnixMs,
};

/// Asks a provider whether it has an article and for the size it reports
/// for it ([`SizeCommand`]), in one command.
///
/// - `430`: [`SizeOutcome::Missing`].
/// - The command's own `2xx`: the article is there. The size is taken
///   only from an answer that is about this article: a `HEAD` whose
///   reply line names the message-id, an `OVER` line whose message-id
///   field is the one asked for, an `HDR` answer of exactly one line.
///   An answer without a size that can be read is `Present(None)`.
/// - Any other reply (the provider does not know the command, or wants a
///   group first): the article is asked for with `STAT`, so the answer
///   is `Present(None)` or `Missing`, or the session's own error.
///
/// An `Err` leaves the session in an unknown state: drop it.
pub async fn stored_size<T: Transport>(
    client: &mut NntpClient<T>,
    message_id: &str,
    how: SizeCommand,
) -> Result<SizeOutcome> {
    let mut sizes = stored_sizes(client, &[message_id], Some(how)).await?;
    sizes.pop().ok_or(BridgeError::Invalid("message-id"))
}

/// [`stored_size`] (or `STAT`, when `how` is `None`) for each of
/// `message_ids`, in that order, with the commands written ahead of
/// their replies: one round trip for all of them instead of one each.
/// The answers are those of the commands sent one by one. Those that
/// need a `STAT` after their own answer are asked again, together, once
/// every reply has been read.
///
/// An `Err` leaves the session in an unknown state, with replies that
/// may still be on their way: drop it. No answer of the call counts.
pub async fn stored_sizes<T: Transport>(
    client: &mut NntpClient<T>,
    message_ids: &[&str],
    how: Option<SizeCommand>,
) -> Result<Vec<SizeOutcome>> {
    let plain = |c: char| c == '<' || c == '>' || c.is_whitespace() || c.is_control();
    // Before anything is written: a refused id must not leave commands
    // with unread replies behind it.
    for id in message_ids {
        if id.is_empty() || id.chars().any(plain) {
            return Err(BridgeError::Invalid("message-id"));
        }
    }
    let Some(how) = how else {
        let found = client.stat_many(message_ids).await?;
        return Ok(found
            .into_iter()
            .map(|there| match there {
                true => SizeOutcome::Present(None),
                false => SizeOutcome::Missing,
            })
            .collect());
    };
    let (verb, expect) = match how {
        SizeCommand::Hdr => ("HDR :bytes", 225),
        SizeCommand::Over => ("OVER", 224),
        SizeCommand::Head => ("HEAD", 221),
    };
    for id in message_ids {
        client.raw_send(&format!("{verb} <{id}>")).await?;
    }
    // `None` = to be asked with `STAT`.
    let mut out: Vec<Option<SizeOutcome>> = Vec::with_capacity(message_ids.len());
    let mut block = Vec::new();
    for id in message_ids {
        let reply = client.raw_reply().await?;
        if reply.code == 430 {
            out.push(Some(SizeOutcome::Missing));
            continue;
        }
        if reply.code != expect {
            out.push(None);
            continue;
        }
        block.clear();
        client.raw_dot_block(&mut block).await?;
        let named = format!("<{id}>");
        if how == SizeCommand::Head && !head_names(&reply.text, &named) {
            // Not an answer about this article.
            return Err(
                velmora::Error::Malformed("HEAD reply names another article".into()).into(),
            );
        }
        out.push(match reported_size(&block, &named, how) {
            Some(Reported::Own(size)) => Some(SizeOutcome::Present(Some(size))),
            Some(Reported::Carried(size)) => Some(SizeOutcome::Carried(size)),
            // The headers of the article asked for: it is there.
            None if how == SizeCommand::Head => Some(SizeOutcome::Present(None)),
            // An `HDR` or `OVER` answer that cannot be tied to the
            // article (no line, more than one, another message-id) does
            // not say the article is there either: `STAT` does.
            None => None,
        });
    }
    // Those are asked together too: a provider that refuses the size
    // command refuses it for every article.
    let asked = message_ids.iter().zip(&out);
    let again: Vec<&str> = asked
        .filter(|(_, answer)| answer.is_none())
        .map(|(id, _)| *id)
        .collect();
    let mut found = Vec::new();
    if !again.is_empty() {
        found = client.stat_many(&again).await?;
    }
    if found.len() != again.len() {
        return Err(BridgeError::Invalid("STAT answers"));
    }
    let mut found = found.into_iter();
    let sizes = out.into_iter().map(|answer| match answer {
        Some(answer) => answer,
        None => match found.next() {
            Some(true) => SizeOutcome::Present(None),
            _ => SizeOutcome::Missing,
        },
    });
    Ok(sizes.collect())
}

/// A size in a provider's answer, and whose count it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reported {
    /// The provider's own count of the article it stores.
    Own(u64),
    /// A count that came with the article (`X-Received-Bytes:`).
    Carried(u64),
}

/// Whether the text of a `221` reply (`n <message-id> ...`) names the
/// article `named`: in its second field, where `STAT` is read too. The
/// same id further on in the line is free text.
fn head_names(text: &str, named: &str) -> bool {
    text.split_whitespace().nth(1) == Some(named)
}

/// The size in the data block of a size command's answer, if it has one.
/// `named` is the message-id in angle brackets.
fn reported_size(block: &[u8], named: &str, how: SizeCommand) -> Option<Reported> {
    let text = core::str::from_utf8(block).ok()?;
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let number = |v: &str| {
        let v = v.trim();
        (!v.is_empty() && v.len() <= 15 && v.bytes().all(|b| b.is_ascii_digit()))
            .then(|| v.parse::<u64>().ok())
            .flatten()
    };
    match how {
        SizeCommand::Hdr => {
            let mut lines = lines.filter(|l| !l.is_empty());
            let (line, more) = (lines.next()?, lines.next());
            let mut words = line.split_whitespace();
            let (_, value, rest) = (words.next()?, words.next()?, words.next());
            match (more, rest) {
                (None, None) => number(value).map(Reported::Own),
                _ => None,
            }
        }
        SizeCommand::Over => {
            // One line, as for `HDR`: two are not an answer about one
            // article.
            let mut lines = lines.filter(|l| !l.is_empty());
            let (line, more) = (lines.next()?, lines.next());
            let fields: Vec<&str> = line.split('\t').collect();
            match more.is_none() && fields.get(4).map(|f| f.trim()) == Some(named) {
                true => number(fields.get(6)?).map(Reported::Own),
                false => None,
            }
        }
        SizeCommand::Head => {
            // The headers end at the first empty line. `Bytes:` is the
            // provider's own count; `X-Received-Bytes:` came with the
            // article.
            let (mut own, mut carried) = (None, None);
            for line in lines.by_ref().take_while(|l| !l.is_empty()) {
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                if name.eq_ignore_ascii_case("bytes") {
                    own = own.or(Some(number(value)));
                } else if name.eq_ignore_ascii_case("x-received-bytes") {
                    carried = carried.or(Some(number(value)));
                }
            }
            match own {
                Some(own) => own.map(Reported::Own),
                None => carried.flatten().map(Reported::Carried),
            }
        }
    }
}

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

    async fn size(&mut self, message_id: &str, how: SizeCommand) -> Result<SizeOutcome> {
        stored_size(self, message_id, how).await
    }

    async fn ask_many(
        &mut self,
        message_ids: &[&str],
        how: Option<SizeCommand>,
    ) -> Result<Vec<SizeOutcome>> {
        stored_sizes(self, message_ids, how).await
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
    /// A provider refused the connection or the login, and not for a
    /// connection limit ([`ProviderSession::session`]). The session has
    /// the strike. It is not connected again in this run; a run that
    /// failed in no other way frees the lease without spending an
    /// attempt, so a refusal that lasts never uses the attempts up: the
    /// strikes cool the provider down and the job waits for that.
    Refused,
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
            // refuses this account. A refused connect never comes here
            // (see `ProviderSession::session`).
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
    settle_at(catalog, clock, lease, stop, None).await
}

/// [`settle`] for a job that got further than its row says: `cursor`
/// is the resume point it reached, stored with the write that gives the
/// lease back, or just before it. Nothing is stored where nothing is
/// written (a lost lease, a failing catalogue): the next job then
/// starts where this one did, and only repeats work.
pub(crate) async fn settle_at<C: Catalog, T: Clock>(
    catalog: &C,
    clock: &T,
    lease: &Lease,
    stop: Stop,
    cursor: Option<u32>,
) -> JobOutcome {
    let now = clock.now();
    // A put-off stores the resume point in its own write.
    let defer = |next_at: UnixMs| async move {
        match cursor {
            Some(cursor) => catalog.defer_at(lease, cursor, next_at, now).await,
            None => catalog.defer(lease, next_at, now).await,
        }
    };
    let stop = match stop {
        Stop::Session(e) => e.into(),
        stop => stop,
    };
    match stop {
        Stop::Fenced | Stop::Session(_) => JobOutcome::Ack,
        Stop::Catalog => JobOutcome::Retry {
            delay_secs: CATALOG_RETRY_SECS,
        },
        Stop::NoPermit | Stop::Refused => {
            let jitter = uniform_below(&mut SystemRng, u64::from(NO_PERMIT_SPREAD_SECS))
                .ok()
                .and_then(|j| u32::try_from(j).ok())
                .unwrap_or(0);
            let delay_secs = NO_PERMIT_MIN_SECS + jitter;
            match defer(now.plus_secs(delay_secs)).await {
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
            match defer(until.max(now)).await {
                Ok(false) => JobOutcome::Ack,
                _ => JobOutcome::Retry { delay_secs },
            }
        }
        Stop::Fail(class, delay) => {
            let delay_secs = delay.unwrap_or_else(|| backoff_secs(lease.attempts));
            // A failure keeps its own write. The resume point goes
            // first, under the lease: if it is not stored, the failure
            // is recorded all the same.
            if let Some(cursor) = cursor {
                let _ = catalog.set_cursor(lease, cursor, now).await;
            }
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

/// Out of line, so that the hashing code is in the Worker once for all
/// its callers.
#[inline(never)]
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The payload an article row describes, if it is in bounds: a slice of
/// `cipher` for a data article. A parity article is addressed past the
/// ciphertext, one shard length per article
/// ([`ParityPlan::articles`]): its payload is that shard of `parity`,
/// which holds the shards in the order of the addendum.
fn payload_of<'a>(cipher: &'a [u8], parity: &'a [Vec<u8>], row: &ArticleRow) -> Option<&'a [u8]> {
    let start = usize::try_from(row.cipher_offset).ok()?;
    let len = usize::try_from(row.cipher_len).ok()?;
    match start.checked_sub(cipher.len()) {
        Some(past) if !parity.is_empty() => {
            if len == 0 || past % len != 0 {
                return None;
            }
            let shard = parity.get(past / len)?;
            (shard.len() == len).then_some(shard.as_slice())
        }
        _ => cipher.get(start..start.checked_add(len)?),
    }
}

/// The parity shards `rows` of the ciphertext of an extent: the stripe
/// is its articles, one data shard each.
fn parity_shards(cipher: &[u8], rows: &[u16]) -> Option<Vec<Vec<u8>>> {
    let data: Option<Vec<&[u8]>> = article_spans(cipher.len() as u64)
        .iter()
        .map(|span| {
            let start = usize::try_from(span.start).ok()?;
            let end = usize::try_from(span.end()).ok()?;
            cipher.get(start..end)
        })
        .collect();
    velmora::rs::encode(&data?, rows).ok()
}

/// The parity shards of a stored addendum, computed again from the
/// ciphertext. `None` = one of them is not the shard the addendum
/// describes (its length, its SHA-256): the addendum is not of this
/// ciphertext, and nothing of it may be posted.
fn stored_shards(cipher: &[u8], parity: &ParityPlan) -> Option<Vec<Vec<u8>>> {
    let shards = parity_shards(cipher, &parity.rows)?;
    let same = shards.len() == parity.articles.len()
        && shards.iter().zip(&parity.articles).all(|(shard, a)| {
            shard.len() as u64 == a.cipher_len && sha256(shard) == a.payload_sha256
        });
    same.then_some(shards)
}

/// The addendum a job drew for a new plan, and the shards it describes.
struct DrawnParity {
    addendum: Vec<u8>,
    shards: Vec<Vec<u8>>,
}

/// What a post job holds once its extent is loaded.
struct Loaded<'c> {
    /// The verified ciphertext, in the buffer of the job's charge.
    cipher: Lent<'c>,
    /// The stored plan: the data articles, then the parity articles.
    plan: Vec<ArticleRow>,
    /// The parity shards, in the order of the parity articles.
    parity: Vec<Vec<u8>>,
    /// This job drew the plan, so no article of it was ever sent.
    drawn: bool,
}

/// Renders the complete article for a stored row. Everything on the wire
/// is a function of the stored row and the ciphertext, so a repost is
/// byte-identical.
///
/// A row with its own yEnc name is a standalone single-part yEnc file:
/// `=ybegin line=128 size=<payload> name=<name>`, the payload, then
/// `=yend size=<payload> crc32=<payload crc>`. No part number, no range
/// and no extent size: nothing on the wire ties the articles of one
/// extent together. A row without one was planned before standalone
/// articles and keeps the multi-part form it was posted in: part
/// `idx + 1` of `total`, the extent's ciphertext range, `size=` of the
/// whole extent, and the name taken from the head of the message-id.
///
/// Reads never depend on the form: they decode either one and accept only
/// the stored length and SHA-256 (`fetch::check_payload`).
fn render_article(row: &ArticleRow, total: u32, file_size: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let params = match &row.yenc_name {
        Some(name) if valid_yenc_name(name) => SegmentParams::single(name.clone()),
        Some(_) => return Err(BridgeError::Invalid("stored yEnc name is malformed")),
        None => SegmentParams {
            name: row
                .message_id
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .take(OBFUSCATED_YENC_NAME_LEN)
                .collect(),
            part: row.idx + 1,
            total,
            begin: row.cipher_offset + 1,
            end: row.cipher_offset + row.cipher_len,
            file_size,
        },
    };
    // Headers, blank line and yEnc body go into one buffer; the bytes are
    // the ones `encode_segment` + `assemble_article` give.
    // The hint covers the usual output plus the encoder's working room for
    // its last block, so the buffer is not moved near the end.
    Ok(assemble_article_with(
        &row.headers,
        payload.len() + payload.len() / 16 + 10 * 1024,
        |out| encode_segment_vec(out, &params, payload),
    )?)
}

/// [`sha256`] for the CPU benchmark (`velmora-cpu-bench`). Not an API.
#[doc(hidden)]
pub fn bench_sha256(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

/// [`render_article`] for the CPU benchmark (`velmora-cpu-bench`), which
/// times the code the post stage runs. Not an API.
#[doc(hidden)]
pub fn bench_render_article(
    row: &ArticleRow,
    total: u32,
    file_size: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    render_article(row, total, file_size, payload)
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
        self.post_stage_in(lease, job, None).await
    }

    /// [`Self::post_stage`] under the job's budget charge, whose extent
    /// buffer ([`Charge::lend`]) the extent is read into.
    pub(crate) async fn post_stage_in(
        &self,
        lease: &Lease,
        job: &JobExtent,
        charge: Option<&Charge>,
    ) -> JobOutcome {
        let done = self.post_extent(lease, job, charge).await;
        // A slot that came to the job while it waited and that it did
        // not take: it stopped first.
        self.catalog.leave_line(&job_holder(lease));
        match done {
            Ok(()) => JobOutcome::Ack,
            Err(stop) => settle(&self.catalog, &self.clock, lease, stop).await,
        }
    }

    async fn post_extent(
        &self,
        lease: &Lease,
        job: &JobExtent,
        charge: Option<&Charge>,
    ) -> core::result::Result<(), Stop> {
        let extent = &job.extent;
        // A job that comes back to an extent it has posted already (a
        // crash before the stage moved on, a revived obligation) needs no
        // provider: it only writes the recovery record again.
        let stored = self.catalog.stored_plan(&extent.id).await?;
        if !stored.rows.is_empty() && stored.rows.iter().all(|a| a.state == ArticleState::Posted) {
            self.load_planned(lease, extent, stored, charge).await?;
            return self.to_verify(lease).await;
        }
        let holder = job_holder(lease);
        // The articles left to post are known before the extent is read:
        // every one of a new plan, the planned ones of a stored plan.
        // The parity articles of a plan are posted with it.
        let todo = match stored.rows.is_empty() {
            true => {
                let data = article_spans(extent.cipher_size).len();
                match self.cfg.packed_plans && self.cfg.parity {
                    true => data + parity::parity_count(data),
                    false => data,
                }
            }
            false => {
                let planned = |a: &&ArticleRow| a.state == ArticleState::Planned;
                let data = stored.rows.iter().filter(planned).count();
                match data {
                    0 => 0,
                    _ => data + job.parity_count.unwrap_or(0) as usize,
                }
            }
        };
        let asked = self.clock.now();
        let mut waited = false;
        // The slots first. Loading and hashing the extent is the expensive
        // part of the job: one that would only find every slot of its
        // first tier taken gives its lease back before it, not after.
        // Before that it waits for one under the claim for a bounded time
        // ([`crate::jobs::SLOT_WAIT_MS`]). Each ask reads the pool again,
        // so a cooldown or a login refusal that begins during the wait is
        // met as a job claimed then meets it. A catalogue error of a
        // later ask ends the wait as a put-off, not as a spent attempt.
        let (cooling, probing, order, mut held) = loop {
            let pool = match Pool::load(&self.catalog, &self.cfg.providers, self.clock.now()).await
            {
                Err(_) if waited => return Err(Stop::NoPermit),
                pool => pool?,
            };
            let posters: Vec<&ProviderConfig> =
                self.cfg.providers.iter().filter(|p| p.post).collect();
            let cooling = pool.cooling_until(&posters);
            let probing = pool.refusing(&posters);
            let order = pool.order(posters, PermitClass::Background);
            let Some(first_tier) = order.chunk_by(|a, b| a.priority == b.priority).next() else {
                return Err(match cooling {
                    Some(until) => Stop::Cooling(until),
                    None => Stop::fail(FailClass::Internal),
                });
            };
            let held = match self
                .open_sessions(first_tier, &holder, todo, &probing)
                .await
            {
                Err(_) if waited => return Err(Stop::NoPermit),
                opened => opened?.0,
            };
            if !held.is_empty() {
                break (cooling, probing, order, held);
            }
            // Only a poster in this tier or a preferred one can change
            // the next ask. Keep the full cooldown for stage settlement.
            let relevant: Vec<_> = self
                .cfg
                .providers
                .iter()
                .filter(|p| p.post && p.priority <= first_tier[0].priority)
                .collect();
            let back = pool.cooling_until(&relevant);
            // The first tier can change while a grant is on its way.
            // None of the refreshed tier's providers yielded a session.
            if waited {
                self.catalog.leave_line(&holder);
            }
            if !self.slot_wait(lease, first_tier, back).await {
                break (cooling, probing, order, held);
            }
            waited = true;
        };
        let permits_ms = self.clock.now().0 - asked.0;
        crate::trace::note(&lease.extent, |t| {
            t.permits_ms = permits_ms;
            t.sockets = u32::try_from(held.len()).unwrap_or(u32::MAX);
            t.articles = u32::try_from(todo).unwrap_or(u32::MAX);
        });
        if held.is_empty() {
            return Err(Stop::NoPermit);
        }
        // The lease and every permit are confirmed before any connect,
        // as `Round::keep` does. A claim less than a renewal interval
        // old is that confirmation, with nothing written: the lease
        // holds from it, and every slot was taken after it, so each
        // holds at least as long as after a renewal at the claim's
        // time. Past that (a wait for memory, a slow catalogue) one
        // renewal confirms them all, and a lease that is gone stops the
        // job here, before it reads the extent.
        let kept_at = match lease.fresh_at(self.clock.now()) {
            true => Some(lease.claimed_at),
            false => match self.renew_held(lease, &held).await {
                Ok(kept_at) => kept_at,
                Err(stop) => {
                    close_all(held).await;
                    return Err(stop);
                }
            },
        };
        // The sockets connect while the extent is read, checked and
        // planned and its record stored. Nothing is posted before that
        // record is durable: posting starts only once both are done. The
        // round renews before its first call once `kept_at` is older than
        // the renewal interval, as after any renewal.
        let (turned_away, loaded) = join(
            self.connect_all(lease, &mut held, kept_at),
            self.load_planned(lease, extent, stored, charge),
        )
        .await;
        let mut loaded = match loaded {
            Ok(loaded) => loaded,
            Err(stop) => {
                close_all(held).await;
                return Err(stop);
            }
        };
        if loaded.plan.iter().any(|a| a.state == ArticleState::Planned) {
            let started = self.clock.now();
            let opened = Opened {
                sessions: held,
                kept_at,
                turned_away,
                probing,
            };
            let posted = self
                .post_with_failover(lease, extent, &mut loaded, &order, cooling, opened)
                .await;
            let post_ms = self.clock.now().0 - started.0;
            crate::trace::note(&lease.extent, |t| t.post_ms = post_ms);
            posted?;
        } else {
            close_all(held).await;
        }
        let advancing = self.clock.now();
        let advanced = self.to_verify(lease).await;
        let advance_ms = self.clock.now().0 - advancing.0;
        crate::trace::note(&lease.extent, |t| t.advance_ms = advance_ms);
        advanced
    }

    /// Renews the lease and the permits of `sessions` in one round trip.
    /// `Ok(Some(at))`: both were confirmed at `at` by a renewal that came
    /// back within the renewal interval (as in `Round::kept`), so the
    /// sessions may connect now and the first round counts it as its own.
    /// `Ok(None)`: not confirmed in time (a slow catalogue, a lost
    /// permit); nothing connects early and the round renews first.
    /// `Err(Fenced)`: the lease is gone.
    async fn renew_held<'a>(
        &self,
        lease: &Lease,
        sessions: &[ProviderSession<'a, C, N, T>],
    ) -> core::result::Result<Option<UnixMs>, Stop> {
        let now = self.clock.now();
        let permits: Vec<Permit> = sessions.iter().map(|s| s.permit().clone()).collect();
        let confirmed = match self.catalog.renew_all(lease, &permits, now).await {
            Ok((false, _)) => return Err(Stop::Fenced),
            Ok((true, held)) => held.len() == permits.len() && held.iter().all(|h| *h),
            Err(_) => false,
        };
        let in_time = (0..KEEP_EVERY_MS).contains(&(self.clock.now().0 - now.0));
        Ok((confirmed && in_time).then_some(now))
    }

    /// Connects every held session at once when `kept_at` says the lease
    /// and their permits were confirmed: by the claim and the taking of
    /// the slots, or by a renewal ([`Self::renew_held`]).
    /// Returns the providers that turned a connect away.
    ///
    /// A session whose connect the provider refused is ended at once and
    /// its slot given back, as the round would do:
    /// - for its limit ("no slot"): that session alone;
    /// - for the account, while another session of the job is logged in
    ///   to the same provider: that session alone, without a strike. An
    ///   account that takes one login is not refused, whatever the words
    ///   of the reply: it is at a limit;
    /// - for the account, with no session logged in: every session of
    ///   the provider, with one strike. None of them connects again.
    ///
    /// Any other failed connect is left to the round: the session stays
    /// unconnected, and the round connects it again and decides what the
    /// failure means, as it does for any session.
    async fn connect_all<'a>(
        &self,
        lease: &Lease,
        sessions: &mut Vec<ProviderSession<'a, C, N, T>>,
        kept_at: Option<UnixMs>,
    ) -> TurnedAway<'a> {
        let mut away = TurnedAway::default();
        if kept_at.is_none() {
            return away;
        }
        let now = self.clock.now();
        // A connect ends within `NNTP_CALL_SECS` like any call, and the
        // round could not end before it either: it would wait for the
        // article that socket had taken.
        let stops = join_all(
            sessions
                .iter_mut()
                .map(|session| async move { session.session().await.err() }),
        )
        .await;
        let connect_ms = self.clock.now().0 - now.0;
        crate::trace::note(&lease.extent, |t| t.connect_ms = connect_ms);
        let logged_in: Vec<&'a str> = sessions
            .iter()
            .filter(|s| s.connected())
            .map(|s| s.provider.id.as_str())
            .collect();
        for (session, stop) in sessions.iter_mut().zip(&stops) {
            let id = session.provider.id.as_str();
            let list = match stop {
                Some(Stop::NoPermit) => &mut away.busy,
                Some(Stop::Refused) if logged_in.contains(&id) => {
                    session.forgive_refusal();
                    &mut away.busy
                }
                Some(Stop::Refused) => &mut away.refused,
                _ => continue,
            };
            if !list.contains(&id) {
                list.push(id);
            }
        }
        if away.busy.is_empty() && away.refused.is_empty() {
            return away;
        }
        let (out, kept): (Vec<_>, Vec<_>) =
            sessions.drain(..).zip(stops).partition(|(session, stop)| {
                matches!(stop, Some(Stop::NoPermit | Stop::Refused))
                    || away.refused.contains(&session.provider.id.as_str())
            });
        sessions.extend(kept.into_iter().map(|(s, _)| s));
        close_all(out.into_iter().map(|(s, _)| s).collect()).await;
        away
    }

    /// Every article is recorded as posted: the extent goes on to verify.
    async fn to_verify(&self, lease: &Lease) -> core::result::Result<(), Stop> {
        let due = self.clock.now().plus_secs(self.cfg.verify_delay_secs);
        self.advance_notify(lease, OutboxStage::Verify, due).await
    }

    /// The verified ciphertext of the extent and its stored article plan,
    /// with the recovery record of the plan written.
    ///
    /// A plan with a parity addendum comes with its parity shards. They
    /// are computed from the ciphertext here, also for an addendum that
    /// was stored before this job (a retry, a lost race), and each must
    /// be the shard the stored addendum describes: one that is not fails
    /// the job before anything is posted.
    async fn load_planned<'c>(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        stored: StoredPlan,
        charge: Option<&'c Charge>,
    ) -> core::result::Result<Loaded<'c>, Stop> {
        let started = self.clock.now();
        let len =
            usize::try_from(extent.cipher_size).map_err(|_| Stop::fail(FailClass::Corrupt))?;
        let mut cipher = match charge {
            Some(charge) => charge.lend(len),
            None => Lent::own(len),
        };
        if !self
            .safety
            .get_into(&extent.id.safety_key(), &mut cipher)
            .await?
        {
            return Err(Stop::fail(FailClass::BlobError));
        }
        // Only the exact sealed ciphertext is ever posted.
        if cipher.len() as u64 != extent.cipher_size || sha256(&cipher) != extent.cipher_sha256 {
            return Err(Stop::fail(FailClass::Corrupt));
        }
        let (plan, drawn, mine) = self.stored_plan(lease, extent, &cipher, stored).await?;
        let corrupt = Stop::fail(FailClass::Corrupt);
        let parity = plan
            .parity_plan(&extent.id, extent.cipher_size)
            .map_err(|_| Stop::fail(FailClass::Corrupt))?;
        // The shards this job built a moment ago, when the stored
        // addendum is the one it built from them. Any others are dropped
        // before the shards are computed again, so the job never holds
        // two sets: its memory charge counts one encode.
        let mine = mine
            .filter(|mine| plan.parity.as_deref() == Some(&mine.addendum[..]))
            .map(|mine| mine.shards);
        let (parity, shards) = match (parity, mine) {
            (None, _) => (Vec::new(), Vec::new()),
            (Some(parity), Some(shards)) => (parity.articles, shards),
            (Some(parity), None) => {
                let shards = stored_shards(&cipher, &parity).ok_or(corrupt)?;
                (parity.articles, shards)
            }
        };
        // The message-ids exist nowhere but the catalogue until this
        // record is stored: without it, a lost catalogue could not find
        // the extent on Usenet. Nothing is posted before it is durable.
        write_stored_plan(&self.safety, &self.kek, &self.cfg.records, extent, &plan)
            .await
            .map_err(|_| Stop::fail(FailClass::BlobError))?;
        let load_ms = self.clock.now().0 - started.0;
        crate::trace::note(&lease.extent, |t| t.load_ms = load_ms);
        let mut rows = plan.rows;
        rows.extend(parity);
        Ok(Loaded {
            cipher,
            plan: rows,
            parity: shards,
            drawn,
        })
    }

    /// The parity addendum of a new plan (`packed`) of the extent: the
    /// parity shards of its ciphertext, each with its SHA-256, under
    /// identifiers from a fresh seed.
    fn draw_parity(
        &self,
        extent: &ExtentRow,
        cipher: &[u8],
        packed: &[u8],
        groups: &[&str],
        now_secs: i64,
    ) -> Option<DrawnParity> {
        let rows = parity::new_rows(article_spans(extent.cipher_size).len());
        let shards = parity_shards(cipher, &rows)?;
        let hashed: Vec<(u16, [u8; 32])> = rows
            .iter()
            .zip(&shards)
            .map(|(row, shard)| (*row, sha256(shard)))
            .collect();
        let addendum = parity::build(
            &mut SystemRng,
            now_secs,
            groups,
            &extent.id,
            extent.cipher_size,
            packed,
            &hashed,
        )
        .ok()?;
        Some(DrawnParity { addendum, shards })
    }

    /// The authoritative stored plan, created first when the extent has
    /// none. Whatever this job planned in memory is discarded: a planner
    /// that lost the insert race posts the winner's message-ids.
    ///
    /// `stored` is the plan this job read from the catalogue under its
    /// lease. Only the lease holder writes a plan, so it is still the
    /// stored one; a stale job that planned meanwhile is answered by the
    /// fenced insert, which returns the plan that won.
    ///
    /// The flag: the stored plan is the one this job drew just now. Any
    /// other plan was there before this job, and a run before it may
    /// have sent articles of it that the catalogue does not know of.
    ///
    /// With the parity switch on, a new packed plan is stored with its
    /// parity addendum, in the same write. The addendum this job built
    /// is returned with its shards; it is the stored one only if this
    /// job's plan won.
    async fn stored_plan(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        cipher: &[u8],
        stored: StoredPlan,
    ) -> core::result::Result<(StoredPlan, bool, Option<DrawnParity>), Stop> {
        let spans = article_spans(extent.cipher_size);
        let mut plan = stored;
        let mut drawn = false;
        let mut mine = None;
        if plan.rows.is_empty() {
            let groups: Vec<&str> = self.cfg.newsgroups.iter().map(String::as_str).collect();
            let now_secs = self.clock.now().secs().0;
            // Every new plan is drawn from a fresh seed. With the switch
            // on it is stored packed; a plan that cannot be packed (a
            // newsgroup list the form does not hold) is stored as rows,
            // like every plan with the switch off.
            let (seed, rows) = draw(
                &mut SystemRng,
                now_secs,
                &groups,
                &extent.id,
                extent.cipher_size,
                |span| {
                    let start = usize::try_from(span.start).ok()?;
                    let end = usize::try_from(span.end()).ok()?;
                    cipher.get(start..end).map(sha256)
                },
            )
            .map_err(|_| Stop::fail(FailClass::Internal))?;
            let packed = match self.cfg.packed_plans {
                true => pack_seeded(&seed, &extent.id, extent.cipher_size, &rows).ok(),
                false => None,
            };
            plan = match packed {
                Some(packed) => {
                    // Parity is stored beside a packed plan only. An
                    // extent whose parity cannot be built is not posted
                    // without it: the job fails instead.
                    if self.cfg.parity {
                        let parity = self
                            .draw_parity(extent, cipher, &packed, &groups, now_secs)
                            .ok_or(Stop::fail(FailClass::Internal))?;
                        mine = Some(parity);
                    }
                    let addendum = mine.as_ref().map(|m| m.addendum.as_slice());
                    self.catalog
                        .plan_packed(lease, extent.cipher_size, &packed, addendum)
                        .await?
                        .ok_or(Stop::Fenced)?
                }
                None => StoredPlan {
                    rows: self
                        .catalog
                        .plan_articles(lease, &rows)
                        .await?
                        .ok_or(Stop::Fenced)?,
                    packed: None,
                    parity: None,
                },
            };
            drawn = plan.rows.first().map(|a| &a.message_id) == rows.first().map(|a| &a.message_id);
        }
        // The stored plan must describe this ciphertext article for article.
        let matches = plan.rows.len() == spans.len()
            && (0u32..)
                .zip(&plan.rows)
                .zip(&spans)
                .all(|((idx, row), span)| {
                    row.idx == idx && row.cipher_offset == span.start && row.cipher_len == span.len
                });
        if !matches {
            return Err(Stop::fail(FailClass::Internal));
        }
        Ok((plan, drawn, mine))
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
    /// only when every provider of the tiers above was tried and failed
    /// or refused the connection. While one of them is merely busy the
    /// job waits for a slot.
    ///
    /// When no tier is left, the first failure is the job's and costs an
    /// attempt. A run in which providers only refused the connection or
    /// the login ends as [`Stop::Refused`], without one.
    ///
    /// `order` is the posting providers in pool order and `first` the
    /// sessions the job already holds on its first tier: they are the
    /// first round.
    async fn post_with_failover<'a>(
        &'a self,
        lease: &Lease,
        extent: &ExtentRow,
        loaded: &mut Loaded<'_>,
        order: &[&'a ProviderConfig],
        cooling: Option<UnixMs>,
        first: Opened<'a, C, N, T>,
    ) -> core::result::Result<(), Stop> {
        let Loaded {
            cipher,
            plan,
            parity,
            drawn,
        } = loaded;
        let (cipher, parity, drawn) = (cipher.as_slice(), parity.as_slice(), *drawn);
        let holder = job_holder(lease);
        let probing = first.probing.clone();
        let mut first = Some(first);
        let mut failed = None;
        // A provider refused the connection or the login. That alone
        // spends no attempt: see `Stop::Refused`.
        let mut refused = false;
        // Per article: a POST of it may have landed on a provider that
        // then failed, so the next provider is asked before it is sent.
        //
        // Which articles a run posted is kept in the job, not in the
        // catalogue, until all of them are posted. A job that finds a
        // plan it did not draw itself comes after a run that failed,
        // died or was put off (which spends no attempt): it finds every
        // article planned, and asks before it sends any of them.
        let mut unknown = vec![!drawn; plan.len()];
        // Per article: the provider that took it in this job.
        let mut posted_by: Vec<Option<String>> = vec![None; plan.len()];
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
                // The first round runs on the sessions the job opened
                // before it loaded the extent; the renewal they were
                // connected under is the round's first.
                let (sessions, kept_at) = match first.take() {
                    Some(opened) => {
                        // A provider that turned a connect away is not
                        // asked again in this job, as after a round.
                        no_slot = false;
                        let away = opened.turned_away;
                        busy |= !away.busy.is_empty();
                        refused |= !away.refused.is_empty();
                        untried.retain(|p| {
                            let id = p.id.as_str();
                            !away.busy.contains(&id) && !away.refused.contains(&id)
                        });
                        if opened.sessions.is_empty() {
                            continue;
                        }
                        (opened.sessions, opened.kept_at)
                    }
                    None => {
                        let (sessions, without) = self
                            .open_sessions(&untried, &holder, todo.len(), &probing)
                            .await?;
                        no_slot = without;
                        (sessions, None)
                    }
                };
                if sessions.is_empty() {
                    break;
                }
                // Each provider gets one round: one that failed is not
                // asked again in this job, the rest of the tier is.
                untried.retain(|p| !sessions.iter().any(|s| s.provider.id == p.id));
                let round = Round::new(&self.catalog, &self.clock, lease, extent, cipher, plan)
                    .parity(parity)
                    .kept_at(kept_at);
                let ended = round
                    .run(
                        sessions,
                        todo.iter().map(|at| (*at, unknown[*at])),
                        Record::Posted,
                    )
                    .await;
                for (flag, landed) in unknown.iter_mut().zip(&ended.unknown) {
                    *flag |= *landed;
                }
                for (at, by) in ended.accepted.into_iter().enumerate() {
                    if by.is_some() {
                        plan[at].state = ArticleState::Posted;
                        posted_by[at] = by;
                    }
                }
                busy |= ended.busy;
                match ended.stop {
                    None if plan.iter().all(|a| a.state == ArticleState::Posted) => {
                        return self.record_posted(lease, plan, &posted_by).await;
                    }
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
                    // No socket got further than a refused connect: the
                    // rest of the tier, then the next one.
                    Some(Stop::Refused) => refused = true,
                    Some(stop) => return Err(stop),
                }
            }
            if busy || no_slot {
                // A healthy provider of the tier had no slot: wait for it
                // rather than spend an attempt or fall to a backup.
                return Err(Stop::NoPermit);
            }
        }
        Err(match (failed, refused, cooling) {
            (Some(stop), ..) => stop,
            (None, true, _) => Stop::Refused,
            (None, false, Some(until)) => Stop::Cooling(until),
            (None, false, None) => Stop::fail(FailClass::Internal),
        })
    }

    /// Records the whole plan as posted: every article this job posted,
    /// data and parity, in one fenced write. Until here the catalogue has every one of
    /// them as planned, so a job that dies before this write posts the
    /// plan again, under the same message-ids, and the providers answer
    /// that they have it.
    ///
    /// A catalogue failure gets one more try: the providers took the
    /// articles, and the write is what spares a second run.
    async fn record_posted(
        &self,
        lease: &Lease,
        plan: &[ArticleRow],
        posted_by: &[Option<String>],
    ) -> core::result::Result<(), Stop> {
        let rows: Vec<(u32, &str)> = plan
            .iter()
            .zip(posted_by)
            .filter_map(|(a, by)| Some((a.idx, by.as_deref()?)))
            .collect();
        let mut tries = 0;
        loop {
            tries += 1;
            let now = self.clock.now();
            match self.catalog.mark_posted_many(lease, &rows, now).await {
                Ok(true) => return Ok(()),
                Ok(false) => return Err(Stop::Fenced),
                Err(e) if tries == 2 => return Err(e.into()),
                Err(_) => {}
            }
        }
    }

    /// Opens up to `post_sockets` posting sessions (never more than
    /// `articles`) over `providers`, one provider after the other in
    /// turns, so the sockets spread over every provider with a free slot.
    /// Every slot is taken under the one `holder` of the job run, so on a
    /// provider with `max_ips` the job counts as one address however many
    /// sockets it opens there. The flag says whether a provider had no
    /// slot at all.
    ///
    /// The slots are asked for in passes, one catalogue call each, all
    /// calls of a pass at once, in turns over the providers. A provider
    /// that has given the job no slot yet is asked for one per pass, so a
    /// provider with no free slot costs one call. One that gave a slot
    /// is asked for its full turn in the next pass, and each slot it no
    /// longer has costs a refused call. A provider that refuses is not
    /// asked again, and what it did not give goes to the others in the
    /// next pass.
    ///
    /// A provider in `probing` ([`Pool::refusing`]) gets one socket: its
    /// last word was a refusal, and one login shows whether it still
    /// refuses.
    pub(crate) async fn open_sessions<'a>(
        &'a self,
        providers: &[&'a ProviderConfig],
        holder: &str,
        articles: usize,
        probing: &[&str],
    ) -> Result<(Vec<ProviderSession<'a, C, N, T>>, bool)> {
        let wanted = usize::try_from(self.cfg.post_sockets)
            .unwrap_or(1)
            .clamp(1, articles.max(1));
        let mut busy = false;
        let mut open: Vec<&ProviderConfig> = providers.to_vec();
        let mut turn = 0;
        let mut sessions: Vec<ProviderSession<'a, C, N, T>> = Vec::new();
        while sessions.len() < wanted && !open.is_empty() {
            let need = wanted - sessions.len();
            let mut asked: Vec<&ProviderConfig> = Vec::with_capacity(need);
            for i in 0..need * open.len() {
                if asked.len() == need {
                    break;
                }
                let provider = open[(turn + i) % open.len()];
                let gave = sessions.iter().any(|s| s.provider.id == provider.id);
                if gave || !asked.iter().any(|a| a.id == provider.id) {
                    asked.push(provider);
                }
            }
            let opened = join_all(asked.iter().map(|provider| {
                ProviderSession::open(
                    &self.catalog,
                    &self.nntp,
                    &self.clock,
                    provider,
                    PermitClass::Background,
                    holder,
                )
            }))
            .await;
            let mut failed = None;
            let mut refused: Vec<&str> = Vec::new();
            for (provider, opened) in asked.iter().zip(opened) {
                match opened {
                    Ok(Some(session)) => sessions.push(session),
                    Ok(None) => refused.push(provider.id.as_str()),
                    Err(e) => {
                        failed.get_or_insert(e);
                    }
                }
            }
            // Nothing may hold a slot the job will not use.
            if let Some(e) = failed {
                close_all(sessions).await;
                return Err(e);
            }
            let next = asked.last().map(|p| p.id.as_str());
            for id in refused {
                busy |= !sessions.iter().any(|s| s.provider.id == id);
                open.retain(|p| p.id != id);
            }
            open.retain(|p| {
                let id = p.id.as_str();
                !(probing.contains(&id) && sessions.iter().any(|s| s.provider.id == id))
            });
            turn = next
                .and_then(|id| open.iter().position(|p| p.id == id))
                .map_or(0, |at| at + 1);
        }
        Ok((sessions, busy))
    }

    /// Posts the articles `missing` (by `ArticleRow::idx`) of a posted
    /// extent once more, straight to `providers`, from the safety copy
    /// and under the stored message-ids and headers: a provider that has
    /// an article after all is not sent it again. The first provider
    /// stays the recorded one; the articles are stamped as posted again
    /// (`ArticleRow::reposted_at`), because the minimum age of the safety
    /// copy counts from the newest post. The stamp is written before
    /// anything is sent, so a job that dies after a POST leaves it
    /// behind, and again as each article is accepted.
    ///
    /// `parity` is the extent's parity plan, when `missing` may name
    /// parity articles of it (their `idx` follows the data articles').
    /// A parity article is posted again from its shard, computed again
    /// from the safety copy; every shard must be the one the addendum
    /// describes. If one is not, no parity article is sent and the job
    /// fails, after the data articles among `missing` were posted: they
    /// do not depend on the addendum.
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
        parity: Option<&ParityPlan>,
    ) -> core::result::Result<bool, Stop> {
        let mut other_shards = false;
        let done = self
            .repost_from_copy(
                lease,
                extent,
                plan,
                missing,
                providers,
                parity,
                &mut other_shards,
            )
            .await;
        match (other_shards, done) {
            // The data articles are dealt with; the addendum is not
            // one of this ciphertext.
            (true, Ok(_)) => Err(Stop::fail(FailClass::Corrupt)),
            (_, done) => done,
        }
    }

    /// [`Self::repost`]. `other_shards` is set when the shards of the
    /// safety copy are not the ones the addendum describes: then only
    /// the data articles are posted.
    #[allow(clippy::too_many_arguments)] // `repost` and its one flag
    async fn repost_from_copy(
        &self,
        lease: &Lease,
        extent: &ExtentRow,
        plan: &[ArticleRow],
        missing: &[u32],
        providers: &[&ProviderConfig],
        parity: Option<&ParityPlan>,
        other_shards: &mut bool,
    ) -> core::result::Result<bool, Stop> {
        if providers.is_empty() || extent.safety_state != SafetyState::Held {
            return Ok(false);
        }
        let data = plan.len();
        // The parity plan counts only when one of its articles is asked
        // for: the shards are computed for nothing else.
        let parity = parity.filter(|p| p.articles.iter().any(|a| missing.contains(&a.idx)));
        let with_parity: Vec<ArticleRow>;
        let plan = match parity {
            Some(parity) => {
                with_parity = [plan, &parity.articles].concat();
                &with_parity[..]
            }
            None => plan,
        };
        let shard_bytes = parity.map_or(0, |p| {
            parity_job_bytes(extent.cipher_size, p.articles.len())
        });
        // Unlike the rest of its stage, a repost holds the whole extent. A
        // repost larger than the budget still has to run, alone: next to
        // what its own stage already holds.
        let room = self
            .budget
            .job_capacity()
            .saturating_sub(JOB_OVERHEAD_BYTES);
        let bytes = extent
            .cipher_size
            .saturating_add(u64::from(self.cfg.post_sockets) * POST_SOCKET_BYTES)
            .saturating_add(shard_bytes)
            .min(room);
        let Ok(charge) = self
            .budget
            .charge_job_extent(bytes, extent.cipher_size)
            .await
        else {
            return Err(Stop::NoPermit);
        };
        let Ok(len) = usize::try_from(extent.cipher_size) else {
            return Ok(false);
        };
        let mut cipher = charge.lend(len);
        match self
            .safety
            .get_into(&extent.id.safety_key(), &mut cipher)
            .await
        {
            Ok(true) => {}
            _ => return Ok(false),
        }
        if cipher.len() as u64 != extent.cipher_size || sha256(&cipher) != extent.cipher_sha256 {
            return Ok(false);
        }
        let shards = match parity.map(|parity| stored_shards(&cipher, parity)) {
            Some(Some(shards)) => shards,
            Some(None) => {
                *other_shards = true;
                Vec::new()
            }
            None => Vec::new(),
        };
        let pool = Pool::load(&self.catalog, &self.cfg.providers, self.clock.now()).await?;
        let order = pool.order(providers.to_vec(), PermitClass::Background);
        if order.is_empty() {
            return match pool.cooling_until(providers) {
                Some(until) => Err(Stop::Cooling(until)),
                None => Ok(false),
            };
        }
        let todo: Vec<usize> = (0..plan.len())
            .filter(|at| missing.contains(&plan[*at].idx))
            .filter(|at| *at < data || !*other_shards)
            .collect();
        if todo.is_empty() {
            return Ok(false);
        }
        let holder = job_holder(lease);
        let probing = pool.refusing(&order);
        let (sessions, _) = self
            .open_sessions(&order, &holder, todo.len(), &probing)
            .await?;
        if sessions.is_empty() {
            return Err(Stop::NoPermit);
        }
        // Stamped before the first POST: without the stamp nothing may
        // be sent, or a release could follow the repost at once.
        let idxs: Vec<u32> = todo.iter().map(|at| plan[*at].idx).collect();
        let stamped = self
            .catalog
            .mark_reposted_many(lease, &idxs, self.clock.now())
            .await;
        if !matches!(stamped, Ok(true)) {
            close_all(sessions).await;
            return Err(match stamped {
                Ok(_) => Stop::Fenced,
                Err(_) => Stop::Catalog,
            });
        }
        let round =
            Round::new(&self.catalog, &self.clock, lease, extent, &cipher, plan).parity(&shards);
        // `true`: each article is looked up before it is sent.
        let todo = todo.into_iter().map(|at| (at, true));
        let ended = round.run(sessions, todo, Record::Reposted).await;
        match ended.stop {
            None => Ok(true),
            Some(stop @ (Stop::Fenced | Stop::Catalog | Stop::NoPermit)) => Err(stop),
            Some(_) => Ok(false),
        }
    }

    /// Posts the articles `missing` of a posted extent once more, to
    /// every provider that posts: its data articles and, by their
    /// `idx`, the parity articles of its addendum. `Err` = the job
    /// stopped, with the failure class when it failed. For tests of the
    /// repost alone. Never compiled into the Worker.
    #[cfg(feature = "testkit")]
    pub async fn repost_run(
        &self,
        lease: &Lease,
        job: &JobExtent,
        missing: &[u32],
    ) -> core::result::Result<bool, Option<FailClass>> {
        let extent = &job.extent;
        let run = async {
            let stored = self.catalog.stored_plan(&extent.id).await?;
            let parity = stored
                .parity_plan(&extent.id, extent.cipher_size)
                .map_err(|_| Stop::fail(FailClass::Corrupt))?;
            let posters: Vec<&ProviderConfig> = self
                .cfg
                .providers
                .iter()
                .filter(|p| p.post && p.enabled)
                .collect();
            self.repost(
                lease,
                extent,
                &stored.rows,
                missing,
                &posters,
                parity.as_ref(),
            )
            .await
        };
        run.await.map_err(|stop| match stop {
            Stop::Fail(class, _) => Some(class),
            _ => None,
        })
    }
}

/// What a posting job holds per socket: the rendered article and, while
/// it is written, its dot-stuffed copy (`write_dot_block`), each about
/// 0.74 MiB for a full article. Measured on a deployed Worker, three post
/// jobs at 6 sockets charged at 1 MiB a socket held 3.6 MiB a job more
/// than they charged.
pub(crate) const POST_SOCKET_BYTES: u64 = 3 * 512 * 1024;

/// The sessions a job opened before it loaded its extent, the time of the
/// renewal they were connected under (`None` = not connected yet), the
/// providers that turned a connect away meanwhile (those sessions are
/// ended), and the providers the job probes with one socket.
struct Opened<'a, C: Catalog, N: NntpConnector, T: Clock> {
    sessions: Vec<ProviderSession<'a, C, N, T>>,
    kept_at: Option<UnixMs>,
    turned_away: TurnedAway<'a>,
    probing: Vec<&'a str>,
}

/// The providers that turned a connect of the job away.
#[derive(Default)]
struct TurnedAway<'a> {
    /// For a limit: the account takes no more connections now.
    busy: Vec<&'a str>,
    /// For the account, with no session of the job logged in.
    refused: Vec<&'a str>,
}

/// Ends every session and frees its slot, with one health report per
/// provider however many sessions it had, as at the end of a round.
async fn close_all<C: Catalog, N: NntpConnector, T: Clock>(
    sessions: Vec<ProviderSession<'_, C, N, T>>,
) {
    ProviderSession::close_all(sessions).await;
}

/// The lease and every permit of a posting job are renewed together, in
/// one catalogue round trip, once the last renewal is this old. A job that
/// reads (verify, repost) renews its lease and its permit at the same
/// age ([`ProviderSession::keep`]).
pub(crate) const KEEP_EVERY_MS: i64 = 20_000;
/// The longest one call to the connector may take ([`NNTP_CALL_SECS`])
/// plus a margin. No connect, lookup or POST starts with less than this
/// left on the lease or on its permit.
pub(crate) const POST_RESERVE_MS: i64 = 90_000;
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
struct Socket<'a> {
    provider: &'a str,
    /// `None` = the permit is lost or given back.
    permit: Option<Permit>,
    /// The socket was logged in at some time since the job opened it.
    logged_in: bool,
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
    /// How many of them are data articles.
    data_in_flight: usize,
    /// Sockets waiting for an article that may come back to the queue.
    idle: Vec<Waker>,
    /// The time of the last renewal that confirmed the lease.
    kept_at: Option<UnixMs>,
    fatal: Option<Fatal>,
    sockets: Vec<Socket<'a>>,
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
    /// Per plan position: the provider that took the article in this
    /// round.
    pub(crate) accepted: Vec<Option<String>>,
    /// Per plan position: a POST may have landed (see [`post_one`]).
    pub(crate) unknown: Vec<bool>,
    /// A socket found no slot: its permit was gone, or the provider
    /// refused the connect because the account is at its limit.
    pub(crate) busy: bool,
}

/// How a round records an article a provider accepted.
#[derive(Clone, Copy)]
pub(crate) enum Record {
    /// The first post: the row becomes `posted`, with the provider and
    /// the time.
    Posted,
    /// A repost of a posted article: only the time of the repost is
    /// stamped. The first provider stays the recorded one.
    Reposted,
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
    /// The parity shards of the plan's parity articles, in their order.
    parity: &'a [Vec<u8>],
    plan: &'a [ArticleRow],
    /// How accepted articles are recorded.
    record: Cell<Record>,
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
            parity: &[],
            plan,
            record: Cell::new(Record::Posted),
            tick: Mutex::new(()),
            state: RefCell::new(RoundState {
                queue: VecDeque::new(),
                unknown: vec![false; plan.len()],
                in_flight: 0,
                data_in_flight: 0,
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

    /// The plan ends with parity articles: `shards` holds their
    /// payloads, in the same order.
    pub(crate) fn parity(mut self, shards: &'a [Vec<u8>]) -> Self {
        self.parity = shards;
        self
    }

    /// Whether the article at plan position `at` is a data article: its
    /// payload is in the ciphertext, not past it.
    fn is_data(&self, at: usize) -> bool {
        self.plan[at].cipher_offset < self.extent.cipher_size
    }

    /// Counts a renewal at `at` that confirmed the lease and the permit of
    /// every session the round will run on as the round's own, so that
    /// its first call does not renew again. `None` changes nothing.
    pub(crate) fn kept_at(self, at: Option<UnixMs>) -> Self {
        self.state.borrow_mut().kept_at = at;
        self
    }

    /// Posts the articles of `todo` (positions in the plan, each with its
    /// `unknown` flag, see [`post_one`]) over `sessions`, all sockets at
    /// once, and closes every session. The accepted articles are
    /// recorded in the catalogue as `record` says, under the lease.
    pub(crate) async fn run<N: NntpConnector>(
        self,
        sessions: Vec<ProviderSession<'a, C, N, T>>,
        todo: impl Iterator<Item = (usize, bool)>,
        record: Record,
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
                    provider,
                    permit: Some(session.permit().clone()),
                    logged_in: session.connected(),
                });
            }
        }
        let work = sessions
            .into_iter()
            .enumerate()
            .map(|(slot, session)| self.work(slot, session));
        let mut ended = join_all(work).await;
        // A provider that took one login of the round does not refuse
        // the account, whatever the words of its reply: a refused
        // connect of another of its sockets is its limit. "No slot", and
        // no strike.
        let logged_in: Vec<&'a str> = ended
            .iter()
            .zip(&self.state.borrow().sockets)
            .filter(|(_, socket)| socket.logged_in)
            .map(|(end, _)| end.0)
            .collect();
        for end in ended.iter_mut().filter(|e| logged_in.contains(&e.0)) {
            if matches!(end.1, Some(Stop::Refused)) {
                end.1 = Some(Stop::NoPermit);
            }
            end.2 = forgiven(end.2);
        }
        // Also after the catalogue failed once: what the providers
        // accepted is recorded if the catalogue answers now. The write is
        // fenced like every other, so a stale lease still writes nothing.
        self.flush(true).await;

        // One strike or one recovery per provider, however many sockets:
        // a provider that answered one socket in order is in order.
        for provider in providers {
            let mine = || ended.iter().filter(|e| e.0 == provider);
            let health = match mine().any(|e| e.2 == Some(Ok(()))) {
                true => Some(Ok(())),
                false => mine().find_map(|e| e.2),
            };
            report_health(self.catalog, self.clock, provider, health).await;
        }
        let busy = ended.iter().any(|e| matches!(e.1, Some(Stop::NoPermit)));
        let state = self.state.into_inner();
        let left = state.queue.len() + state.in_flight;
        let stop = match (state.fatal, left) {
            (Some(fatal), _) => Some(fatal.stop()),
            (None, 0) => None,
            // Articles are left: the first provider in order says why. A
            // socket that only found no slot does not outweigh one that
            // was refused, and neither outweighs one that failed.
            (None, _) => {
                let weight = |stop: &Stop| match stop {
                    Stop::NoPermit => 2,
                    Stop::Refused => 1,
                    _ => 0,
                };
                // The first of the lightest.
                let stop = ended
                    .into_iter()
                    .filter_map(|e| e.1)
                    .min_by_key(weight)
                    .unwrap_or(Stop::fail(FailClass::Internal));
                Some(stop)
            }
        };
        Ended {
            stop,
            accepted: state
                .accepted
                .iter()
                .map(|by| by.map(str::to_owned))
                .collect(),
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
    ) -> (&'a str, Option<Stop>, Health) {
        let provider = session.provider.id.as_str();
        let stop = loop {
            let Some(at) = self.take(provider).await else {
                break None;
            };
            let posted = self.post_at(slot, &mut session, at).await;
            let mut state = self.state.borrow_mut();
            state.in_flight -= 1;
            state.data_in_flight -= usize::from(self.is_data(at));
            // Whatever happened, a waiting socket has to look again.
            state.idle.drain(..).for_each(Waker::wake);
            match posted {
                Ok(()) => {
                    // The provider has the article, so it is recorded.
                    state.accepted[at] = Some(provider);
                    // The slot went to someone else during the call (a
                    // renewal by another socket found it gone): nothing
                    // more is sent on this socket. The check before the
                    // next call (`keep`) would stop the socket as well,
                    // so no test can tell this exit from that one by its
                    // outcome; it drops the socket at once, without
                    // taking another article from the queue first.
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
                    // Only "no slot", a refused connect and a broken
                    // connection are this socket's own trouble; any
                    // other verdict would be repeated to every socket of
                    // the provider. (A refused connect may be the
                    // provider's limit: that is known when the round is
                    // over, see `run`.)
                    if !(landed || matches!(stop, Stop::NoPermit | Stop::Refused)) {
                        state.closed.push(provider);
                    }
                    break Some(stop);
                }
            }
        };
        {
            let mut state = self.state.borrow_mut();
            state.sockets[slot].permit = None;
            // A socket that held back for this provider (`take`) has to
            // look again.
            state.idle.drain(..).for_each(Waker::wake);
        }
        let health = session.finish().await;
        (provider, stop, health)
    }

    /// The next article for a socket of `provider`. With an empty queue
    /// it waits while another socket is still posting, because that
    /// article may come back; `None` = nothing is left for this socket.
    ///
    /// Data articles go first. A parity article is left to the provider
    /// that took the fewest data articles of the round, so that one
    /// provider losing its articles does not take the data and the
    /// parity with it: a socket of a provider that took more holds back
    /// while the other has a socket in the round. No socket takes one
    /// while a data article is still being posted: which provider took
    /// fewer is known when each data article has its provider, and the
    /// socket that posts the last one wakes the others when it is done
    /// (an article that fails goes back to the queue, and data goes
    /// first). That is a preference only. A provider counts while one of its sockets still holds its
    /// slot and the provider is not closed; when its last socket is gone
    /// the sockets that held back take the parity themselves. The
    /// provider with the fewest never holds back, and each of its
    /// sockets is posting or about to take, so the round always goes on.
    async fn take(&self, provider: &str) -> Option<usize> {
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            if state.fatal.is_some() || state.closed.contains(&provider) {
                return Poll::Ready(None);
            }
            let data = state.queue.iter().position(|at| self.is_data(*at));
            if let Some(next) = data.and_then(|at| state.queue.remove(at)) {
                state.in_flight += 1;
                state.data_in_flight += 1;
                return Poll::Ready(Some(next));
            }
            if !state.queue.is_empty() && !self.holds_back(&state, provider) {
                if let Some(next) = state.queue.pop_front() {
                    state.in_flight += 1;
                    return Poll::Ready(Some(next));
                }
            }
            if state.queue.is_empty() && state.in_flight == 0 {
                return Poll::Ready(None);
            }
            state.idle.push(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Whether a socket of `provider` leaves a parity article for now:
    /// to the socket that is posting a data article, until it is done,
    /// and then to another provider, one with a socket in the round
    /// that took fewer data articles of it. Only a first post is placed; a repost goes to
    /// the providers that miss the article.
    fn holds_back(&self, state: &RoundState<'a>, provider: &str) -> bool {
        if !matches!(self.record.get(), Record::Posted) {
            return false;
        }
        // Not before every data article has its provider.
        if state.data_in_flight > 0 {
            return true;
        }
        let took = |provider: &str| {
            (0..self.plan.len())
                .filter(|at| self.is_data(*at) && state.accepted[*at] == Some(provider))
                .count()
        };
        let mine = took(provider);
        state.sockets.iter().any(|socket| {
            socket.permit.is_some()
                && socket.provider != provider
                && !state.closed.contains(&socket.provider)
                && took(socket.provider) < mine
        })
    }

    async fn post_at<N: NntpConnector>(
        &self,
        slot: usize,
        session: &mut ProviderSession<'a, C, N, T>,
        at: usize,
    ) -> core::result::Result<(), Stop> {
        let row = &self.plan[at];
        // The articles of the extent's ciphertext: parity is not a part
        // of it.
        let data = (0..self.plan.len()).filter(|at| self.is_data(*at)).count();
        let total = u32::try_from(data).map_err(|_| Stop::fail(FailClass::Internal))?;
        self.keep(slot, session).await?;
        let payload = payload_of(self.cipher, self.parity, row)
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
                            // A socket that held back for its provider
                            // (`take`) has to look again.
                            state.idle.drain(..).for_each(Waker::wake);
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

    /// Records the articles accepted so far ([`Record`]), all in one fenced
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
            if stopped {
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
        let now = self.clock.now();
        let marked = match self.record.get() {
            // A first post is recorded once, when the whole plan is
            // posted, by the job (`Bridge::record_posted`): until then
            // which articles are posted is kept here, not in the
            // catalogue.
            Record::Posted => Ok(true),
            Record::Reposted => {
                let idxs: Vec<u32> = due.iter().map(|(_, idx, _)| *idx).collect();
                self.catalog
                    .mark_reposted_many(self.lease, &idxs, now)
                    .await
            }
        };
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
    round.state.borrow_mut().sockets[slot].logged_in = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    const NAMED: &str = "<a1@example.invalid>";

    #[test]
    fn a_head_reply_names_its_article_in_the_second_field() {
        assert!(head_names(&format!("0 {NAMED}"), NAMED));
        assert!(head_names(&format!("7 {NAMED} article"), NAMED));
        // Another article, with the one asked for in the free text.
        assert!(!head_names(
            &format!("7 <b2@example.invalid> {NAMED}"),
            NAMED
        ));
        assert!(!head_names(NAMED, NAMED));
        assert!(!head_names("", NAMED));
    }

    #[test]
    fn head_takes_the_providers_own_size_first() {
        let head = |block: &str| reported_size(block.as_bytes(), NAMED, SizeCommand::Head);
        assert_eq!(
            head("Subject: x\r\nBytes: 744918\r\n"),
            Some(Reported::Own(744_918))
        );
        assert_eq!(head("subject: x\nbytes:12\n"), Some(Reported::Own(12)));
        // The size that came with the article, where the provider adds
        // none of its own: told apart, it is no count of what is stored.
        assert_eq!(
            head("X-Received-Bytes: 1883\r\nPath: a!b\r\n"),
            Some(Reported::Carried(1_883))
        );
        assert_eq!(
            head("X-Received-Bytes: 1883\r\nBytes: 1900\r\n"),
            Some(Reported::Own(1_900))
        );
        // The first header of a name counts; one that is no number is no
        // size, and the other name does not stand in for it.
        assert_eq!(head("Bytes: 7\r\nBytes: 9\r\n"), Some(Reported::Own(7)));
        assert_eq!(head("Bytes: many\r\nX-Received-Bytes: 5\r\n"), None);
        assert_eq!(head("Bytes: -5\r\n"), None);
        assert_eq!(head("Bytes: 1e3\r\n"), None);
        assert_eq!(head("Bytes: 9999999999999999\r\n"), None);
        assert_eq!(head("Subject: Bytes: 5\r\n"), None);
        assert_eq!(head(""), None);
        // Nothing after the header block is read.
        assert_eq!(head("Subject: x\r\n\r\nBytes: 5\r\n"), None);
        assert_eq!(reported_size(&[0xff, 0xfe], NAMED, SizeCommand::Head), None);
    }

    #[test]
    fn hdr_takes_one_line_with_one_value() {
        let hdr = |block: &str| reported_size(block.as_bytes(), NAMED, SizeCommand::Hdr);
        assert_eq!(hdr("0 744918\r\n"), Some(Reported::Own(744_918)));
        assert_eq!(hdr("3000234 12\r\n"), Some(Reported::Own(12)));
        assert_eq!(hdr(""), None);
        assert_eq!(hdr("0\r\n"), None);
        assert_eq!(hdr("0 12 13\r\n"), None);
        assert_eq!(hdr("0 twelve\r\n"), None);
        // Two lines are not an answer about one article.
        assert_eq!(hdr("1 12\r\n2 13\r\n"), None);
    }

    #[test]
    fn over_takes_the_size_of_the_article_asked_for() {
        let over = |block: &str| reported_size(block.as_bytes(), NAMED, SizeCommand::Over);
        let line = |id: &str, bytes: &str| {
            format!("0\tsubject\tfrom\tdate\t{id}\t\t{bytes}\t17\tXref: x\r\n")
        };
        assert_eq!(over(&line(NAMED, "744918")), Some(Reported::Own(744_918)));
        // The line of another article says nothing about this one.
        assert_eq!(over(&line("<other@example.invalid>", "744918")), None);
        assert_eq!(over(&line(NAMED, "")), None);
        assert_eq!(over(&line(NAMED, "big")), None);
        assert_eq!(over("0\tsubject\r\n"), None);
        assert_eq!(over(""), None);
        // Two lines are not an answer about one article.
        let two = line(NAMED, "744918") + &line("<other@example.invalid>", "12");
        assert_eq!(over(&two), None);
    }
}
