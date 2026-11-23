//! NNTP reads: permit-scoped provider sessions, the checked article read
//! shared by verify, release and cold reads, and the cold read itself.
//!
//! Every NNTP path holds a provider connection slot before it opens a
//! socket ("no permit, no socket"). Every article is read with one `BODY`,
//! decoded, and compared with the SHA-256 stored in its plan row before
//! anything uses its bytes.

use core::future::{poll_fn, Future};
use futures_util::future::{join_all, select, Either, LocalBoxFuture};
use velmora::rng::{FillRandom, SystemRng};
use velmora::rs::{reconstruct, DataShard, ParityShard};
use velmora::transport::is_article_limit_error;
use velmora::yenc::decode_part_to;

use crate::articles::article_spans;
use crate::ingress::{ByteBudget, Charge, Sleeper};
use crate::plan::StoredPlan;
use crate::pool::Pool;
use crate::ports::{
    BlobMeta, BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, Permit, PermitClass, SizeOutcome, ASK_MANY, QUIT_SECS, READ_PERMIT_SECS,
    READ_SLACK_SECS,
};
use crate::post::{sha256, Stop, KEEP_EVERY_MS};
use crate::types::{
    ArticleRow, BridgeError, ExtentRow, FailClass, ProviderConfig, ProviderFault, Result,
    SizeCommand, UnixMs,
};

/// Runs `f` and, beside it, the cache write that is under way, if any.
pub(crate) async fn beside<F: Future>(put: &mut Option<LocalBoxFuture<'_, ()>>, f: F) -> F::Output {
    let mut f = core::pin::pin!(f);
    poll_fn(|cx| {
        if let Some(writing) = put.as_mut() {
            if writing.as_mut().poll(cx).is_ready() {
                *put = None;
            }
        }
        f.as_mut().poll(cx)
    })
    .await
}

/// One provider connection slot and the session opened under it.
///
/// The session connects lazily and is replaced after [`Self::discard`], so
/// a caller reconnects by discarding and asking for the session again; the
/// slot stays the same, so reconnects never add a connection. Call
/// [`Self::close`] on every exit path: there is no async drop. If the job
/// dies first, the slot frees itself when the permit expires.
pub(crate) struct ProviderSession<'a, C: Catalog, N: NntpConnector, T: Clock> {
    catalog: &'a C,
    nntp: &'a N,
    clock: &'a T,
    pub(crate) provider: &'a ProviderConfig,
    permit: Permit,
    session: Option<N::Session>,
    /// How the last connect or command went ([`Health`]).
    health: Health,
    /// The host's timer, if the caller has one: bounds a renewal.
    timer: Option<Sleeper>,
    /// When the catalogue last confirmed the permit (the time read
    /// before that round trip), and whether it confirmed a job's lease
    /// with it. See [`Self::keep`].
    kept: Option<(UnixMs, bool)>,
    /// The time the permit's expiry counts from: the one it was taken
    /// with, or its last renewal that succeeded.
    held_from: UnixMs,
    /// The slot was given back ([`Self::finish`]).
    freed: bool,
    /// Connects that broke off before any read used this session (the
    /// first login of a drill): the next read counts them among its
    /// reconnects, so a pass never dials a provider more often for
    /// having logged in first.
    broke_early: u32,
}

impl<C: Catalog, N: NntpConnector, T: Clock> Drop for ProviderSession<'_, C, N, T> {
    /// A session dropped before it was closed (its job was abandoned)
    /// leaves nothing open towards the catalogue for its permit.
    fn drop(&mut self) {
        if !self.freed {
            self.catalog.forget_permit(&self.permit);
        }
    }
}

/// The permit holder of a job run. One claim of an outbox row is one
/// Worker invocation, whose connections all leave from one address: every
/// slot the run takes, on any provider and for any step (post, verify,
/// repost), carries this name, and a provider with `max_ips` counts the
/// run once. A later run of the job claims again, so it gets a new name.
pub(crate) fn job_holder(lease: &Lease) -> String {
    format!(
        "job:{}:{}:{}",
        lease.extent,
        lease.stage.as_str(),
        lease.token
    )
}

/// A permit holder for work done inside one request (a cold read, a
/// drill): `kind` and 128 random bits, so no two requests share a name
/// and each counts as an address of its own.
pub(crate) fn request_holder(kind: &str) -> Result<String> {
    let mut id = [0u8; 16];
    SystemRng.fill_bytes(&mut id)?;
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{kind}:{hex}"))
}

/// What a provider meant when it refused a connection or a login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The account (or the address) is at its limit of connections: "no
    /// slot". It ends when a connection is closed.
    Limit,
    /// Anything else: the service or the address is turned away at the
    /// greeting, or the account is denied, suspended, out of quota, or
    /// the login is wrong. Waiting for a slot does not end it. The fault
    /// says at which of the two the provider refused.
    Account(ProviderFault),
}

/// Sorts a failed connect that is the provider's refusal.
///
/// - A reply that states a connection limit
///   ([`velmora::nntp::is_limit_reply`]) is [`Refusal::Limit`], whatever
///   its code and whether it came at the greeting or in the login.
/// - Any other `502`, `480`, `481` or `482` is [`Refusal::Account`].
/// - A connect that none of the provider's proxies let through
///   ([`crate::hosts::proxy_failure`]) is [`Refusal::Account`] with
///   [`ProviderFault::ProxyFailed`]: the provider was not asked, and the
///   next connect would end the same way. The caller defers as it does
///   for a refused account, and no attempt is spent.
/// - `None` = not such a refusal (no connection, another reply code).
///
/// The login gives `NoPermission`, `AuthFailed` and, for every other
/// code, a plain reply whose text is replaced
/// ([`velmora::nntp::REDACTED_REPLY`]). A plain reply with the server's
/// own text is the greeting's: the connector hands a refused greeting on
/// that way, a `502` too ([`crate::hosts::DialError::classify`]).
fn refusal(e: &BridgeError) -> Option<Refusal> {
    use velmora::nntp::{is_limit_reply, REDACTED_REPLY};
    use velmora::Error as E;
    if crate::hosts::proxy_failure(e) {
        return Some(Refusal::Account(ProviderFault::ProxyFailed));
    }
    let (code, text, login) = match e {
        BridgeError::Nntp(E::NoPermission(text)) => (502, text, true),
        BridgeError::Nntp(E::AuthFailed(text)) => (481, text, true),
        BridgeError::Nntp(E::NntpReply { code, text }) => (*code, text, text == REDACTED_REPLY),
        _ => return None,
    };
    if is_limit_reply(text) {
        return Some(Refusal::Limit);
    }
    matches!(code, 480..=482 | 502).then_some(Refusal::Account(match login {
        true => ProviderFault::LoginRefused,
        false => ProviderFault::ConnectRefused,
    }))
}

/// Whether an error says the provider itself is in trouble: a failed
/// connect or login, a broken connection, an unexpected reply. A missing
/// article, a refused or duplicate POST, "too many connections" and an
/// oversized body say nothing about its health. (A refused connect is
/// sorted before this is asked: see [`refusal`].)
fn is_provider_fault(e: &BridgeError) -> bool {
    use velmora::Error as E;
    match e {
        BridgeError::Nntp(E::Io(io)) => !is_article_limit_error(io),
        BridgeError::Nntp(
            E::ArticleNotFound(_)
            | E::PostProhibited(_)
            | E::NoPermission(_)
            | E::NntpReply {
                code: 435 | 441, ..
            },
        ) => false,
        BridgeError::Nntp(_) => true,
        _ => false,
    }
}

impl<'a, C: Catalog, N: NntpConnector, T: Clock> ProviderSession<'a, C, N, T> {
    /// Takes a slot for `provider`. `None` = every slot of this class is
    /// held, or the provider's addresses are all in use by other holders:
    /// the caller backs off without opening a socket. `holder` names the
    /// caller's invocation ([`job_holder`], [`request_holder`]); a caller
    /// that opens several sessions passes the same name for each.
    pub(crate) async fn open(
        catalog: &'a C,
        nntp: &'a N,
        clock: &'a T,
        provider: &'a ProviderConfig,
        class: PermitClass,
        holder: &str,
    ) -> Result<Option<Self>> {
        // The slot is held from this time on, as after a renewal at it:
        // a background job does not write the same expiry a second time
        // before its first call ([`Self::keep`]).
        let asked = clock.now();
        let permit = catalog
            .acquire_permit(provider, class, holder, asked)
            .await?;
        Ok(permit.map(|permit| ProviderSession {
            catalog,
            nntp,
            clock,
            provider,
            permit,
            session: None,
            health: None,
            timer: None,
            // A read renews once after it connected, as it always did:
            // its permit is short and the connect is not.
            kept: (class == PermitClass::Background).then_some((asked, false)),
            held_from: asked,
            freed: false,
            broke_early: 0,
        }))
    }

    /// With the host's timer, a renewal that is bounded for the permit's
    /// class ([`PermitClass::renew_secs`]) is given up when the bound
    /// passes, and not only found late once it returns: a catalogue call
    /// that hangs cannot keep the socket open past the slot's expiry.
    pub(crate) fn with_timer(mut self, timer: Option<&Sleeper>) -> Self {
        self.timer = timer.cloned();
        self
    }

    /// Renews the job's lease (if it has one) and then the permit. Call it
    /// before every article and before every reconnect: no POST, read or
    /// new socket happens on a lease or a slot that now belongs to someone
    /// else. On a lost permit the socket is dropped at once, and so it is
    /// when the renewal of a read's permit did not come back in time
    /// ([`PermitClass::renew_secs`]).
    ///
    /// A background job is not renewed again while its last renewal is
    /// less than [`KEEP_EVERY_MS`] old. That renewal holds the slot for
    /// [`PERMIT_SECS`](crate::ports::PERMIT_SECS) and the lease for longer
    /// ([`LEASE_SECS`](crate::ports::LEASE_SECS)), each counted from the
    /// time read before its round trip, so a call that starts now ends
    /// with [`POST_RESERVE_MS`](crate::post::POST_RESERVE_MS) minus its
    /// own time to spare on both, as
    /// in a post job. Nobody else can be given the slot or the row before
    /// then.
    ///
    /// The permit of a read is short, and so is the time its renewal is
    /// counted on: [`READ_RENEW_SECS`](crate::ports::READ_RENEW_SECS),
    /// from the time read before the round trip. That is the bound a
    /// renewal that was slow has always had (a call that starts this
    /// long after that time ends with the goodbye and
    /// [`READ_SLACK_SECS`](crate::ports::READ_SLACK_SECS) to spare), so
    /// the articles that follow within it need no round trip each.
    pub(crate) async fn keep(&mut self, lease: Option<&Lease>) -> core::result::Result<(), Stop> {
        let now = self.clock.now();
        let every = match self.permit.class.renew_secs() {
            None => KEEP_EVERY_MS,
            Some(secs) => i64::from(secs) * 1000,
        };
        // The claim of the lease and the acquisition of the slot each
        // count as a renewal at the time they were made with.
        let fresh = self.kept.is_some_and(|(at, leased)| {
            (0..every).contains(&(now.0 - at.0))
                && (leased || lease.is_none_or(|l| l.fresh_at(now)))
        });
        if fresh {
            return Ok(());
        }
        // Not counted on again unless the renewal below succeeds.
        self.kept = None;
        if let Some(lease) = lease {
            if !self.catalog.renew(lease, now).await? {
                return Err(Stop::Fenced);
            }
        }
        let renewed = {
            let renewal = self.catalog.renew_permit(&self.permit, now);
            match (self.permit.class.renew_secs(), &self.timer) {
                (Some(secs), Some(sleep)) => {
                    let renewal = core::pin::pin!(renewal);
                    // Started only if the renewal does not return at once.
                    let limit = core::pin::pin!(async { sleep(secs * 1000).await });
                    match select(renewal, limit).await {
                        Either::Left((renewed, _)) => renewed,
                        // Given up. If it lands after all, the slot is
                        // extended once and then released or left to
                        // expire: nothing here counts on it.
                        Either::Right(_) => Ok(false),
                    }
                }
                _ => renewal.await,
            }
        };
        // The new expiry counts from `now`. A renewal that took too long
        // has used up the time the next call needs. Without a timer, or
        // with one that fired late, this is the only check.
        let late =
            self.permit.class.renew_secs().is_some_and(|secs| {
                self.clock.now().0.saturating_sub(now.0) > i64::from(secs) * 1000
            });
        match renewed {
            Ok(true) if !late => {
                self.kept = Some((now, lease.is_some()));
                self.held_from = now;
                Ok(())
            }
            Ok(_) => {
                self.session = None;
                Err(Stop::NoPermit)
            }
            Err(e) => {
                self.session = None;
                Err(e.into())
            }
        }
    }

    /// The live session, connecting first when there is none.
    ///
    /// A provider that refuses the connection or the login with a text
    /// that states a connection limit is reported as "no slot"
    /// ([`Stop::NoPermit`]): no strike, and the caller waits as it does
    /// for a permit. Those are the replies of an account at a limit:
    /// "too many connections", and the address limit (`502 max number of
    /// simultaneous IPs (3) reached`, `482 Already connected from
    /// different IP`), which another client of the account or an address
    /// the provider still counts can cause below `max_ips`.
    ///
    /// Any other refusal with `502`, `480`, `481` or `482` is about the
    /// account itself (denied, suspended, out of quota, a wrong login) or
    /// the service. It is a strike, with the stage as its reason
    /// ([`ProviderFault::LoginRefused`], [`ProviderFault::ConnectRefused`]),
    /// and [`Stop::Refused`]: asking again at once gets the same answer,
    /// so the caller does not reconnect and goes on to another provider.
    pub(crate) async fn session(&mut self) -> core::result::Result<&mut N::Session, Stop> {
        if self.session.is_none() {
            let session = match self.nntp.connect(self.provider, &self.permit).await {
                Ok(session) => session,
                Err(e) => {
                    return Err(match refusal(&e) {
                        Some(Refusal::Limit) => Stop::NoPermit,
                        Some(Refusal::Account(fault)) => {
                            self.health = Some(Err(fault));
                            Stop::Refused
                        }
                        None => {
                            self.note_err(&e);
                            Stop::Session(e)
                        }
                    });
                }
            };
            self.session = Some(session);
        }
        self.session.as_mut().ok_or(Stop::fail(FailClass::Internal))
    }

    /// Takes back the strike of a refused connect
    /// ([`Stop::Refused`]): the caller knows it for a limit, because
    /// another of its sockets is logged in to the same provider.
    pub(crate) fn forgive_refusal(&mut self) {
        self.health = forgiven(self.health);
    }

    /// Whether a session is open: `false` = the next
    /// [`session`](Self::session) connects first.
    pub(crate) fn connected(&self) -> bool {
        self.session.is_some()
    }

    /// The slot this session holds.
    pub(crate) fn permit(&self) -> &Permit {
        &self.permit
    }

    /// Drops the session without reuse or `QUIT` (after any session error).
    pub(crate) fn discard(&mut self) {
        self.session = None;
    }

    /// Records a command the provider answered in order (a `430` too).
    pub(crate) fn note_ok(&mut self) {
        self.health = Some(Ok(()));
    }

    /// Records a failed connect or command, if it is the provider's fault.
    pub(crate) fn note_err(&mut self, e: &BridgeError) {
        if is_provider_fault(e) {
            self.health = Some(Err(ProviderFault::SessionFailed));
        }
    }

    /// Ends the session and frees the slot. The release is fenced by the
    /// permit token, so a holder that lost its slot frees nothing.
    ///
    /// A session whose last word from the provider was a failure is one
    /// strike against it; a good session clears the strikes. The catalogue
    /// decides on the provider's state at that moment, so a session that
    /// started before another one failed still clears that failure.
    pub(crate) async fn close(self) {
        let (catalog, clock, id) = (self.catalog, self.clock, self.provider.id.as_str());
        let health = self.finish().await;
        report_health(catalog, clock, id, health).await;
    }

    /// Ends every session and frees its slot, then reports each
    /// provider's health once: one session that went well clears its
    /// strikes, otherwise the first failure is one strike. Several
    /// sockets that failed together are one strike, not one each.
    pub(crate) async fn close_all(sessions: Vec<Self>) {
        let Some(first) = sessions.first() else {
            return;
        };
        let (catalog, clock) = (first.catalog, first.clock);
        // Every session ends first, then every slot is freed in one
        // round: a catalogue that batches calls made together
        // ([`crate::gate`]) frees them with one request.
        let mut sessions = sessions;
        join_all(sessions.iter_mut().map(|session| async move {
            if let Some(open) = session.session.take() {
                open.quit().await;
            }
        }))
        .await;
        let ended = join_all(sessions.into_iter().map(|session| {
            let id = session.provider.id.as_str();
            async move { (id, session.finish().await) }
        }))
        .await;
        let mut ids: Vec<&str> = Vec::new();
        for (id, _) in &ended {
            if !ids.contains(id) {
                ids.push(id);
            }
        }
        for id in ids {
            let mine = || ended.iter().filter(|e| e.0 == id);
            let health = match mine().any(|e| e.1 == Some(Ok(()))) {
                true => Some(Ok(())),
                false => mine().find_map(|e| e.1),
            };
            report_health(catalog, clock, id, health).await;
        }
    }

    /// [`close`](Self::close) without the health report: ends the session,
    /// frees the slot and returns how the session went. Several sessions
    /// of one job on one provider are one strike or one recovery, which
    /// the caller reports once with [`report_health`].
    pub(crate) async fn finish(mut self) -> Health {
        if let Some(session) = self.session.take() {
            session.quit().await;
        }
        // A failed release is safe: the permit expires on its own.
        self.freed = self.catalog.release_permit(&self.permit).await.is_ok();
        self.health
    }
}

/// How a session with a provider went: `None` = nothing ran, `Ok` = in
/// order, `Err` = one strike, and why.
pub(crate) type Health = Option<core::result::Result<(), ProviderFault>>;

/// `health` without the strike of a refused connect: nothing ran.
pub(crate) fn forgiven(health: Health) -> Health {
    match health {
        Some(Err(fault)) if fault.is_refusal() => None,
        health => health,
    }
}

/// Records how a provider's session went (`None` = nothing ran).
pub(crate) async fn report_health<C: Catalog, T: Clock>(
    catalog: &C,
    clock: &T,
    id: &str,
    health: Health,
) {
    let now = clock.now();
    // Health is advice: a write that fails here costs nothing.
    let _ = match health {
        Some(Err(fault)) => catalog.provider_failed(id, fault, now).await,
        Some(Ok(())) => catalog.provider_recovered(id, now).await,
        None => Ok(()),
    };
}

/// Reconnects one pass over a provider may spend on broken sessions.
pub(crate) const MAX_READ_RECONNECTS: u32 = 2;

/// What one pass over a set of articles found. Indexes are `ArticleRow::idx`.
#[derive(Debug, Default)]
pub(crate) struct ReadTally {
    /// Articles whose decoded payload matched the stored SHA-256; in a
    /// `STAT` pass ([`stat_articles`]), articles the provider said it has.
    pub(crate) ok: u32,
    /// Still `430` after the in-pass retry.
    pub(crate) missing: Vec<u32>,
    /// Present, but not the planned bytes; in a size pass
    /// ([`ask_articles_together`]), present with a size no posted article of
    /// that plan can have.
    pub(crate) corrupt: Vec<u32>,
    /// In a size pass: the articles of `ok` whose reported size fits.
    /// The others of `ok` are only known to be present.
    pub(crate) sized: u32,
}

enum Checked {
    Good(Vec<u8>),
    /// A `STAT` found the article. Nothing was read, so nothing is known
    /// about its bytes.
    Present,
    /// A `BODY` is in the caller's buffer, not yet decoded or checked.
    Wire,
    /// The provider has the article and reports a size that fits it.
    Sized,
    Missing,
    Corrupt,
}

/// How one article is asked of a provider.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ask {
    /// `BODY`, decoded and compared with the planned SHA-256.
    Body,
    /// `STAT`: whether the provider says it has the article.
    Stat,
    /// `BODY`, left in the caller's buffer for it to decode and check.
    Wire,
    /// Presence and the size the provider reports, compared with
    /// [`size_bounds`].
    Size(SizeCommand),
}

/// What one command found, before it is checked.
enum Got {
    Body(BodyOutcome),
    Present,
    Size(Option<u64>),
    Carried(u64),
}

/// The sizes, in bytes, a provider may report for the stored article of
/// `row`: `(least, most)`, both inclusive.
///
/// What is compared. The catalogue keeps the length of an article's
/// payload (`cipher_len`, ciphertext) and its header block, not the
/// length of its yEnc text, so the reported size is held against the
/// range that text can have:
/// - the payload itself, `cipher_len` bytes;
/// - one more byte for every escaped byte. yEnc escapes 4 of the 256
///   byte values everywhere, and ciphertext is uniform, so their number
///   is `cipher_len / 64` give or take a few standard deviations: 8 are
///   allowed each way (`8 * sqrt(cipher_len / 64) + 8`). An encoder may
///   also escape a dot, a tab or a space at the edge of a line: up to 2
///   more per line are allowed upward;
/// - a line end (2 bytes) for each line of at most 128 characters;
/// - upward only: the `=ybegin` and `=yend` lines (256 bytes), the
///   header block that was posted, and 8192 bytes for the headers the
///   servers on the way add (`Path`, `Xref` and the like).
///
/// `least` counts no header at all, so a provider that reports the size
/// of the body alone passes too. It does count a line end as 2 bytes: a
/// provider that counts it as 1 reports less than `least` for a whole
/// article, which is recorded as corrupt and releases nothing. Such a
/// provider is not given a size command. An article cut short by more than the
/// slack (about 0.1 % of a full article plus its headers) is below
/// `least`; one that is another, larger article is above `most`.
pub fn size_bounds(row: &ArticleRow) -> (u64, u64) {
    let n = row.cipher_len;
    let escapes = n / 64;
    let spread = 8 * escapes.isqrt() + 8;
    let least_lines = n / 129;
    let least = n + escapes.saturating_sub(spread) + 2 * least_lines;
    let most_text = n + escapes + spread;
    let most_lines = most_text / 127 + 1;
    let headers = u64::try_from(row.headers.len()).unwrap_or(u64::MAX);
    let most = (most_text + 4 * most_lines + 256 + 8192).saturating_add(headers);
    (least, most)
}

/// Decodes a `BODY` reply and accepts it only if it is exactly the planned
/// payload: right length, right SHA-256.
fn check_payload(row: &ArticleRow, wire: &[u8]) -> Checked {
    let Ok(len) = usize::try_from(row.cipher_len) else {
        return Checked::Corrupt;
    };
    let mut payload = vec![0u8; len];
    match decode_part_to(&row.message_id, wire, &mut payload) {
        Ok(part) if part.written == len && sha256(&payload) == row.payload_sha256 => {
            Checked::Good(payload)
        }
        _ => Checked::Corrupt,
    }
}

/// Decodes a `BODY` reply straight into `place`, the article's bytes of
/// the extent's ciphertext, and says whether it is exactly the planned
/// payload: right length, right SHA-256. `place` is `cipher_len` long.
fn place_payload(row: &ArticleRow, wire: &[u8], place: &mut [u8]) -> bool {
    let len = place.len();
    decode_part_to(&row.message_id, wire, place).is_ok_and(|part| part.written == len)
        && sha256(place) == row.payload_sha256
}

/// [`check_payload`] for the CPU benchmark (`velmora-cpu-bench`): the
/// payload if the reply is the planned one. Not an API.
#[doc(hidden)]
pub fn bench_check_payload(row: &ArticleRow, wire: &[u8]) -> Option<Vec<u8>> {
    match check_payload(row, wire) {
        Checked::Good(payload) => Some(payload),
        _ => None,
    }
}

/// [`place_payload`] for the CPU benchmark (`velmora-cpu-bench`). Not an
/// API.
#[doc(hidden)]
pub fn bench_place_payload(row: &ArticleRow, wire: &[u8], place: &mut [u8]) -> bool {
    place_payload(row, wire, place)
}

/// One `BODY`, checked, or one `STAT` (`ask`). A `430` leaves the session in use. Any session
/// error drops the session and resumes at the same message-id on a new
/// one, while `reconnects` lasts. A connect the provider refused is not
/// tried again: the pass ends with [`Stop::NoPermit`] or
/// [`Stop::Refused`].
///
/// The lease and the permit are renewed before each connect and again
/// after it, before the `BODY`: each of the two may take a whole call
/// ([`PermitClass::call_secs`]), and a permit is not counted on for more
/// than one call past its last renewal.
async fn read_one<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    row: &ArticleRow,
    ask: Ask,
    wire: &mut Vec<u8>,
    reconnects: &mut u32,
) -> core::result::Result<Checked, Stop> {
    loop {
        wire.clear();
        let fresh = !session.connected();
        let connected = match session.session().await {
            Ok(_) => Ok(()),
            Err(Stop::Session(e)) => Err(e),
            Err(stop) => return Err(stop),
        };
        if fresh && connected.is_ok() {
            session.keep(lease).await?;
        }
        let result = match connected {
            Ok(()) => match session.session().await {
                Ok(s) => match ask {
                    Ask::Body | Ask::Wire => s.body(&row.message_id, wire).await.map(Got::Body),
                    Ask::Stat => s.stat(&row.message_id).await.map(|there| match there {
                        true => Got::Present,
                        false => Got::Body(BodyOutcome::Missing),
                    }),
                    Ask::Size(how) => s.size(&row.message_id, how).await.map(|o| match o {
                        SizeOutcome::Present(size) => Got::Size(size),
                        SizeOutcome::Carried(size) => Got::Carried(size),
                        SizeOutcome::Missing => Got::Body(BodyOutcome::Missing),
                    }),
                },
                Err(Stop::Session(e)) => Err(e),
                Err(stop) => return Err(stop),
            },
            Err(e) => Err(e),
        };
        let err = match result {
            Ok(found) => {
                session.note_ok();
                return Ok(match found {
                    Got::Body(BodyOutcome::Found) if ask == Ask::Wire => Checked::Wire,
                    Got::Body(BodyOutcome::Found) => check_payload(row, wire),
                    Got::Body(BodyOutcome::Missing) => Checked::Missing,
                    Got::Present => Checked::Present,
                    Got::Size(size) => check_size(row, SizeOutcome::Present(size)),
                    Got::Carried(size) => check_size(row, SizeOutcome::Carried(size)),
                });
            }
            Err(e) => e,
        };
        session.note_err(&err);
        session.discard();
        match err {
            // A body over the article limit is not an article we posted.
            BridgeError::Nntp(velmora::Error::Io(io)) if is_article_limit_error(&io) => {
                return Ok(Checked::Corrupt);
            }
            BridgeError::Nntp(_) if *reconnects < MAX_READ_RECONNECTS => {
                *reconnects += 1;
                session.keep(lease).await?;
            }
            BridgeError::Nntp(_) => return Err(Stop::fail(FailClass::NntpError)),
            other => return Err(other.into()),
        }
    }
}

/// What a provider's answer about the article of `row` comes to.
fn check_size(row: &ArticleRow, answer: SizeOutcome) -> Checked {
    let fits = |size: u64| {
        let (least, most) = size_bounds(row);
        (least..=most).contains(&size)
    };
    match answer {
        SizeOutcome::Missing => Checked::Missing,
        SizeOutcome::Present(None) => Checked::Present,
        SizeOutcome::Present(Some(size)) if fits(size) => Checked::Sized,
        // A size that came with the article: one that cannot be the
        // article that was posted is a failure, one that can says
        // nothing of what is stored here.
        SizeOutcome::Carried(size) if fits(size) => Checked::Present,
        SizeOutcome::Present(Some(_)) | SizeOutcome::Carried(_) => Checked::Corrupt,
    }
}

/// Reads `rows` one `BODY` at a time on `session` and hands every verified
/// payload to `sink`. Unverified bytes never reach the sink.
///
/// A `430` is retried once at the end of the pass, on the same session
/// (a fresh article can be invisible for a moment). With a `lease`, the
/// lease is renewed with the slot ([`ProviderSession::keep`]) and a stale
/// lease stops the read.
pub(crate) async fn read_articles<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
    sink: impl FnMut(&ArticleRow, Vec<u8>),
) -> core::result::Result<ReadTally, Stop> {
    ask_articles(session, lease, rows, Ask::Body, false, sink).await
}

/// Asks the provider with `STAT` whether it has each of `rows`: no article
/// is read, so `ReadTally::ok` counts what the provider claims to hold and
/// `corrupt` stays empty. The retry of a `430` and the lease are as in
/// [`read_articles`].
///
/// This is not a check of the bytes. A provider can answer `STAT` for an
/// article whose `BODY` it does not serve; only [`read_articles`] proves
/// an article can be read back.
pub(crate) async fn stat_articles<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
) -> core::result::Result<ReadTally, Stop> {
    ask_articles(session, lease, rows, Ask::Stat, false, |_, _| {}).await
}

/// Asks the provider whether it has each of `rows`, with `STAT` (`how`
/// is `None`, as [`stat_articles`]) or with its size command `how`,
/// which also gives the size it reports: no article is read.
/// `ReadTally::ok` counts the articles it has, `sized` those of them
/// whose reported size fits ([`size_bounds`]), and `corrupt` those with
/// a size that does not. The retry of a `430` and the lease are as in
/// [`read_articles`].
///
/// The commands of up to [`ASK_MANY`] articles are written ahead of
/// their replies ([`NntpSession::ask_many`]): a round trip for an extent
/// instead of one per article.
///
/// This is not a check of the bytes: only [`read_articles`] proves an
/// article can be read back.
///
/// The lease and the slot are renewed before every such call. A call
/// that fails counts for nothing: the session is dropped, and its
/// articles and those after them are asked one by one, as in
/// [`stat_articles`], with the reconnects and the errors of that way.
pub(crate) async fn ask_articles_together<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
    how: Option<SizeCommand>,
) -> core::result::Result<ReadTally, Stop> {
    let ask = how.map_or(Ask::Stat, Ask::Size);
    ask_articles(session, lease, rows, ask, true, |_, _| {}).await
}

async fn ask_articles<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
    ask: Ask,
    together: bool,
    mut sink: impl FnMut(&ArticleRow, Vec<u8>),
) -> core::result::Result<ReadTally, Stop> {
    let mut tally = ReadTally::default();
    let mut wire = Vec::new();
    let mut reconnects = 0;
    let mut retry: Vec<&ArticleRow> = Vec::new();
    // The articles the calls for several did not answer for.
    let mut first = rows;
    let how = match ask {
        Ask::Stat => Some(None),
        Ask::Size(how) => Some(Some(how)),
        Ask::Body | Ask::Wire => None,
    };
    if let (true, Some(how)) = (together, how) {
        while !first.is_empty() {
            let (now, later) = first.split_at(first.len().min(ASK_MANY));
            let Some(answers) = ask_together(session, lease, now, how).await? else {
                break;
            };
            for (row, answer) in now.iter().zip(answers) {
                match check_size(row, answer) {
                    Checked::Sized => {
                        tally.ok += 1;
                        tally.sized += 1;
                    }
                    Checked::Corrupt => tally.corrupt.push(row.idx),
                    Checked::Missing => retry.push(row),
                    Checked::Present | Checked::Wire | Checked::Good(_) => tally.ok += 1,
                }
            }
            first = later;
        }
    }
    for pass in 0..2 {
        let todo = if pass == 0 {
            first.to_vec()
        } else {
            core::mem::take(&mut retry)
        };
        for row in todo {
            session.keep(lease).await?;
            match read_one(session, lease, row, ask, &mut wire, &mut reconnects).await? {
                Checked::Good(payload) => {
                    tally.ok += 1;
                    sink(row, payload);
                }
                Checked::Present | Checked::Wire => tally.ok += 1,
                Checked::Sized => {
                    tally.ok += 1;
                    tally.sized += 1;
                }
                Checked::Corrupt => tally.corrupt.push(row.idx),
                Checked::Missing if pass == 0 => retry.push(row),
                Checked::Missing => tally.missing.push(row.idx),
            }
        }
    }
    Ok(tally)
}

/// One [`NntpSession::ask_many`] for `rows` (at most [`ASK_MANY`]):
/// their answers in order, or `None` when the call counts for nothing
/// and the rows are to be asked one by one. The session connects first
/// if it has to, renewed before and after as in [`read_one`]; a session
/// that failed is dropped with its strike.
async fn ask_together<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
    how: Option<SizeCommand>,
) -> core::result::Result<Option<Vec<SizeOutcome>>, Stop> {
    session.keep(lease).await?;
    let fresh = !session.connected();
    match session.session().await {
        Ok(_) => {}
        // Its strike is noted. The one-by-one way connects again and
        // counts its reconnects.
        Err(Stop::Session(_)) => {
            session.discard();
            return Ok(None);
        }
        Err(stop) => return Err(stop),
    }
    if fresh {
        session.keep(lease).await?;
    }
    let ids: Vec<&str> = rows.iter().map(|r| r.message_id.as_str()).collect();
    let answers = match session.session().await {
        Ok(s) => s.ask_many(&ids, how).await,
        Err(Stop::Session(_)) => {
            session.discard();
            return Ok(None);
        }
        Err(stop) => return Err(stop),
    };
    match answers {
        Ok(answers) if answers.len() == rows.len() => {
            session.note_ok();
            Ok(Some(answers))
        }
        Ok(_) => {
            session.discard();
            Ok(None)
        }
        Err(e @ BridgeError::Nntp(_)) => {
            session.note_err(&e);
            session.discard();
            Ok(None)
        }
        Err(other) => {
            session.discard();
            Err(other.into())
        }
    }
}

/// Longest a cold read keeps retrying while every provider slot it could
/// use is taken, before `503 SlowDown`. Clients fan one download out into
/// many concurrent range reads, more than a provider has connections.
/// It is longer than a read's permit: a waiter outlasts the slot of a
/// read that was dropped and released nothing.
pub const COLD_WAIT_MS: u32 = 40_000;
const _: () = assert!(COLD_WAIT_MS > crate::ports::READ_PERMIT_SECS * 1000);

/// Base poll interval while a cold read waits for a provider slot.
pub const COLD_POLL_MS: u32 = 50;

/// Most jitter added to [`COLD_POLL_MS`], so waiters that started together
/// do not retry in lockstep.
pub const COLD_JITTER_MS: u32 = 25;

/// The next poll interval of a waiting cold read: [`COLD_POLL_MS`] plus a
/// jitter in `0..=COLD_JITTER_MS` drawn from `seed` (any value that differs
/// between waiters and between their attempts).
pub fn cold_poll_ms(seed: u64) -> u32 {
    // splitmix64 finaliser: spreads nearby seeds over the whole range.
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    // The remainder is at most COLD_JITTER_MS, so it fits a u32.
    COLD_POLL_MS + (z % u64::from(COLD_JITTER_MS + 1)) as u32
}

/// Result of a cold read of one extent from Usenet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColdFetch {
    /// The complete ciphertext, equal to the catalogue's digest.
    /// [`Bridge::fetch_cold`] has written it to the cache already.
    Filled(Vec<u8>),
    /// A provider that could still hold missing articles had no free
    /// connection slot: worth waiting for one.
    Busy,
    /// A provider read broke off in transit: retry later, not at once.
    Interrupted,
    /// No provider could supply every article intact.
    Unavailable,
    /// `extent-unrecoverable`: articles are lost on every provider and
    /// the extent's parity cannot make up for them (more are lost than
    /// parity articles can be read intact, or the parity addendum cannot
    /// be read). Nothing of the extent is returned.
    Unrecoverable,
}

/// Bytes one socket of a cold read holds beside the extent it fills: the
/// wire text of the article it is reading. An article's wire text is its
/// payload plus the yEnc overhead of a few percent; the buffer that
/// takes it may have grown to twice that.
pub const COLD_SOCKET_BYTES: u64 = 1536 * 1024;

/// What a cold read of one extent of `cipher_size` bytes over `sockets`
/// connections charges to the byte budget. Two extents' worth is live at
/// the peak (the ciphertext and its copy for the cache while that is
/// written, then the ciphertext and the plaintext), and the wire text on
/// every socket after the first; the first socket's was never charged.
pub fn cold_read_bytes(cipher_size: u64, sockets: u32) -> u64 {
    cipher_size
        .saturating_mul(2)
        .saturating_add(u64::from(sockets.saturating_sub(1)) * COLD_SOCKET_BYTES)
}

/// What one extent read for a body charges while the cache write of the
/// extent before it may still be under way ([`cold_read_bytes`] counts
/// that write's copy instead): the ciphertext, and beside it the larger
/// of the wire text on the sockets after the first (while it is read)
/// and the plaintext (while it is opened), which is never larger than
/// the ciphertext.
pub fn cold_step_bytes(cipher_size: u64, sockets: u32) -> u64 {
    let wire = u64::from(sockets.saturating_sub(1)) * COLD_SOCKET_BYTES;
    cipher_size.saturating_add(cipher_size.max(wire))
}

/// The part of [`cold_step_bytes`] that is live while the extent is
/// read: the ciphertext and the wire text on the sockets after the
/// first. The rest is needed only to open it.
pub fn cold_fetch_bytes(cipher_size: u64, sockets: u32) -> u64 {
    let wire = u64::from(sockets.saturating_sub(1)) * COLD_SOCKET_BYTES;
    cipher_size
        .saturating_add(wire)
        .min(cold_step_bytes(cipher_size, sockets))
}

/// What rebuilding `lost` data articles of an extent charges to the byte
/// budget, on top of what the read of the extent holds: as many parity
/// articles of `shard_len` bytes each as articles are lost (no more are
/// kept at a time), the rebuilt articles, and the working memory of the
/// codec ([`velmora::rs`]: `lost + 2` shards and two small matrices).
pub fn cold_rebuild_bytes(shard_len: u64, lost: u64) -> u64 {
    let shards = lost.saturating_mul(3).saturating_add(2);
    shards
        .saturating_mul(shard_len)
        .saturating_add(lost.saturating_mul(lost).saturating_mul(4))
}

/// The most [`cold_rebuild_bytes`] is for an extent of `cipher_size`
/// bytes: as many articles lost as a new extent of that size gets
/// parity articles ([`crate::parity::parity_count`]). Nothing for a size
/// that has no stripe.
pub fn cold_rebuild_most(cipher_size: u64) -> u64 {
    match crate::parity::stripe_of(cipher_size) {
        Some((k, shard)) => {
            let most = crate::parity::parity_count(usize::from(k)) as u64;
            cold_rebuild_bytes(u64::from(shard), most)
        }
        None => 0,
    }
}

/// Times one provider may answer `430` for one article within one cold
/// read before the article is asked of the next: the second ask comes
/// after the provider's other articles (a fresh article can be invisible
/// for a moment).
const MISSING_ASKS: u8 = 2;

/// What a cold reader did, for the logs: no article names, no bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColdStats {
    /// Extents read whole and found equal to their digest.
    pub extents: u32,
    /// Slots taken (each is one connection) and sessions that ended on an
    /// error.
    pub opened: u32,
    pub broken: u32,
    /// Milliseconds spent taking slots and opening their connections
    /// (those opened together count once): how far away the providers
    /// are.
    pub open_ms: i64,
    /// Connections that were ended for being far slower than the others.
    pub slow: u32,
    /// Verified articles and their payload bytes, per provider id.
    pub share: Vec<(String, u32, u64)>,
    /// Articles a provider did not have or had with other bytes, which
    /// were then asked of another.
    pub refetched: u32,
    /// Data articles no provider had intact, which were rebuilt from the
    /// extent's parity articles and found equal to their planned SHA-256.
    /// Each is an article that wants posting again.
    pub rebuilt: u32,
    /// Extents that lost more than their parity could rebuild
    /// (`extent-unrecoverable`).
    pub unrecoverable: u32,
}

impl ColdStats {
    fn count(&mut self, provider: &str, bytes: u64) {
        match self.share.iter_mut().find(|s| s.0 == provider) {
            Some(s) => {
                s.1 += 1;
                s.2 += bytes;
            }
            None => self.share.push((provider.to_owned(), 1, bytes)),
        }
    }
}

impl core::fmt::Display for ColdStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "extents={} opened={} open_ms={} broken={} slow={} refetched={}",
            self.extents, self.opened, self.open_ms, self.broken, self.slow, self.refetched
        )?;
        for (id, articles, bytes) in &self.share {
            write!(f, " {id}={articles}/{bytes}")?;
        }
        // Only when it happened: a read that lost nothing logs the line
        // it always did.
        if self.rebuilt > 0 {
            write!(f, " rebuilt={}", self.rebuilt)?;
        }
        if self.unrecoverable > 0 {
            write!(f, " extent-unrecoverable={}", self.unrecoverable)?;
        }
        Ok(())
    }
}

/// The shared state of the sockets that read one extent together. It is
/// borrowed only between awaits.
struct Board {
    cipher: Vec<u8>,
    /// Per article: where its payload begins in `cipher`. A data
    /// article is at its offset in the ciphertext; a parity article is
    /// given a place when it is asked for.
    starts: Vec<usize>,
    /// Per article: its bytes are in `cipher` and matched their SHA-256.
    have: Vec<bool>,
    /// Per article: a socket is reading it now.
    taken: Vec<bool>,
    /// Per article and provider (`article * providers + provider`): how
    /// often the provider failed to supply it. [`MISSING_ASKS`] = it is
    /// not asked again.
    asks: Vec<u8>,
    providers: usize,
    /// Counts the articles that sockets gave back, read or not.
    turn: u64,
    /// Sockets with nothing to read that wait for the next turn.
    waiting: Vec<core::task::Waker>,
}

impl Board {
    /// A board of `bytes` bytes for one article per entry of `starts`
    /// (where each begins), read from `providers` providers.
    fn new(bytes: usize, starts: Vec<usize>, providers: usize) -> Self {
        let articles = starts.len();
        Board {
            cipher: vec![0u8; bytes],
            starts,
            have: vec![false; articles],
            taken: vec![false; articles],
            asks: vec![0u8; articles * providers],
            providers,
            turn: 0,
            waiting: Vec::new(),
        }
    }

    /// Whether any socket is reading an article now. Until none is, the
    /// pass goes on, and every socket in it stays logged in.
    fn reading(&self) -> bool {
        self.taken.iter().any(|taken| *taken)
    }

    /// An article is no longer being read: the sockets that wait are
    /// woken. They are returned to be woken once the board is free.
    #[must_use]
    fn give_back(&mut self, article: usize) -> Vec<core::task::Waker> {
        self.taken[article] = false;
        self.turn += 1;
        core::mem::take(&mut self.waiting)
    }

    fn asks(&self, article: usize, provider: usize) -> u8 {
        self.asks[article * self.providers + provider]
    }

    /// Whether `provider` may still be asked for `article`.
    fn open(&self, article: usize, provider: usize) -> bool {
        !self.have[article] && self.asks(article, provider) < MISSING_ASKS
    }

    /// The next article for a socket of `provider`: one nobody is
    /// reading, that `wanted` allows; those it has not been asked for
    /// come before those it answered `430` for once.
    fn take(&mut self, provider: usize, wanted: impl Fn(usize) -> bool) -> Option<usize> {
        let free = |b: &Board, a: usize| !b.taken[a] && b.open(a, provider) && wanted(a);
        let all = 0..self.have.len();
        let next = all
            .clone()
            .find(|&a| free(self, a) && self.asks(a, provider) == 0)
            .or_else(|| all.clone().find(|&a| free(self, a)))?;
        self.taken[next] = true;
        Some(next)
    }
}

/// The catalogue error of a cold read during which a statement failed.
pub(crate) const CATALOGUE_FAILED: &str = "catalogue failed during a cold read";

/// Which articles a provider is asked for in one phase of a cold read.
#[derive(Clone, Copy)]
enum Phase {
    /// Those inside the retention it states.
    Retained,
    /// Those past the stated retention of every enabled reader.
    Orphan,
    /// All that are still missing.
    Any,
}

/// Whether this phase counts the provider for the article, regardless
/// of cooldown or slots. Retention is an estimate: when no enabled
/// reader retains the article, every enabled reader may still hold it.
fn can_answer(
    provider: &ProviderConfig,
    article: &ArticleRow,
    now: UnixMs,
    readers: &[&ProviderConfig],
    phase: Phase,
) -> bool {
    let retains = |p: &ProviderConfig| p.enabled && p.retains(article.posted_at, now);
    provider.enabled
        && match phase {
            Phase::Retained => retains(provider),
            Phase::Orphan => !readers.iter().copied().any(retains),
            Phase::Any => true,
        }
}

/// Why a provider gets no (more) work in one cold read of an extent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Out {
    /// It gave no slot, or refused a connection for a stated limit.
    Busy,
    /// Its last session broke off, or it refused the account.
    Broken,
}

/// The data articles of an extent and which of them were read.
struct Lost<'p> {
    /// The plan as the catalogue holds it, with its parity addendum.
    stored: &'p StoredPlan,
    /// Per data article: its verified bytes are in the ciphertext.
    have: &'p [bool],
    /// How the read ends without a rebuild. [`ColdFetch::Unavailable`] =
    /// every reader that may hold a lost article answered for it.
    end: &'p ColdFetch,
}

/// What the passes over one extent know of the providers they read from.
struct Desk<'a> {
    /// The providers that may be asked, best first.
    order: Vec<&'a ProviderConfig>,
    /// Per provider of `order`: why it gets no more work.
    out: Vec<Option<Out>>,
    /// Per provider: it gave no further slot.
    full: Vec<bool>,
    /// Per provider: sessions that broke off in this read.
    breaks: Vec<u32>,
    /// Whether the reader is a drill's ([`ColdReader::drill`]).
    drill: bool,
}

impl Desk<'_> {
    /// How a read ends that could not get every article of `rows`.
    /// For each missing article, a counted provider must have answered
    /// missing for that article, not just answered some other request.
    fn short(
        &self,
        readers: &[&ProviderConfig],
        rows: &[ArticleRow],
        board: &Board,
        now: UnixMs,
    ) -> ColdFetch {
        let mut busy = false;
        let mut unasked = false;
        for &provider in readers {
            let index = self.order.iter().position(|p| p.id == provider.id);
            for (a, row) in rows.iter().enumerate() {
                if board.have[a] || index.is_some_and(|i| !board.open(a, i)) {
                    continue;
                }
                let can = |phase| can_answer(provider, row, now, readers, phase);
                let retained = can(Phase::Retained);
                let orphan = !retained && can(Phase::Orphan);
                if !(retained || orphan || self.drill && can(Phase::Any)) {
                    continue;
                }
                if orphan {
                    // A counted provider has not answered for the orphan.
                    return ColdFetch::Interrupted;
                }
                match index.and_then(|i| self.out[i]) {
                    Some(Out::Busy) => busy = true,
                    Some(Out::Broken) => return ColdFetch::Interrupted,
                    // A cooling or shunned provider is not in the order.
                    None => unasked = true,
                }
            }
        }
        // A drill waits for a slot before spending a try on a provider
        // it could not ask, so a slot that frees up can still be used.
        if unasked && !(self.drill && busy) {
            ColdFetch::Interrupted
        } else if busy {
            ColdFetch::Busy
        } else {
            ColdFetch::Unavailable
        }
    }
}

/// Reads extents from Usenet over several connections at once.
///
/// One reader belongs to one invocation: every slot it takes carries one
/// holder name, so a provider with `max_ips` counts it once. It keeps up
/// to `sockets` sessions and reuses them for the next extent, so a run
/// of extents costs one login per socket, not one per extent. Call
/// [`Self::close`] on every exit path. A reader must not sit idle with
/// open sessions for longer than [`Self::idle_ms`]: between extents a
/// slot is not renewed, so a caller that waits for something else ends
/// the sessions when that time is over.
pub(crate) struct ColdReader<'a, C: Catalog, N: NntpConnector, T: Clock> {
    catalog: &'a C,
    nntp: &'a N,
    clock: &'a T,
    providers: &'a [ProviderConfig],
    timer: Option<Sleeper>,
    sockets: usize,
    holder: String,
    sessions: Vec<ProviderSession<'a, C, N, T>>,
    /// Slow connections that may still be replaced ([`SLOW_REPLACEMENTS`]).
    replacements: u32,
    stats: std::rc::Rc<core::cell::RefCell<ColdStats>>,
    /// Whether this is the reader of a drill ([`Bridge::drill_reader`]).
    drill: bool,
    /// Providers that refused this drill's login. They are not asked
    /// again by this reader: each ask would be one more refused login
    /// on the account's record, and a cooldown begins only after
    /// several. Always empty for a read.
    shunned: Vec<String>,
    /// The byte budget a rebuild from parity is charged to
    /// ([`cold_rebuild_bytes`]).
    room: std::rc::Rc<ByteBudget>,
    /// Room taken ahead for a rebuild ([`Self::fund`]).
    reserve: Option<Charge>,
    /// What the last rebuild found no room for, in bytes.
    lacked: u64,
}

/// The tier a reader asks `p` in, lowest first. A read: its `priority`.
/// A drill: the providers with drill connections first, as one tier
/// whatever their `priority` (the drill is to read over all of them at
/// once, and takes nothing from a read on any); then the others by
/// `priority`, for what the first tier could not supply.
fn tier_of(drill: bool, p: &ProviderConfig) -> u16 {
    match (drill, p.drill_conns) {
        (false, _) => u16::from(p.priority),
        (true, 0) => 1 + u16::from(p.priority),
        (true, _) => 0,
    }
}

fn pool_siblings(a: &ProviderConfig, b: &ProviderConfig) -> bool {
    a.id != b.id && a.pool.is_some() && a.pool == b.pool
}

/// A slot is being given back: a sibling that could not get one can ask
/// again. Providers already out for this extent still stay out.
fn free_pool_slot(provider: &ProviderConfig, order: &[&ProviderConfig], full: &mut [bool]) {
    for (p, full) in order.iter().zip(full) {
        if *full && pool_siblings(p, provider) {
            *full = false;
        }
    }
}

/// A session's slot kept, or its first login made.
type Kept<'s> = LocalBoxFuture<'s, core::result::Result<(), Stop>>;

/// Orders `order` by tier; the providers of a tier keep their order.
/// An insertion sort: a handful of providers, and the library's stable
/// sort for this one type is 6 KB of the Worker's wasm, which has a
/// size budget.
fn by_tier(order: &mut [&ProviderConfig], drill: bool) {
    for i in 1..order.len() {
        let mut j = i;
        while j > 0 && tier_of(drill, order[j - 1]) > tier_of(drill, order[j]) {
            order.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// The class of the slots a reader takes on `p`.
fn class_of(drill: bool, p: &ProviderConfig) -> PermitClass {
    if drill && p.drill_conns > 0 {
        PermitClass::Drill
    } else {
        PermitClass::Read
    }
}

/// The most connections a reader holds on `p` at once. A read: as many
/// as it has sockets. A drill: the provider's drill connections; on a
/// provider without them one, taken from `max_conns` as the drill
/// always took it, so that a drill of many sockets is not that many
/// connections fewer for reads.
fn cap_of(drill: bool, p: &ProviderConfig) -> usize {
    match (drill, p.drill_conns) {
        (false, _) => usize::MAX,
        (true, 0) => 1,
        (true, n) => usize::try_from(n).unwrap_or(usize::MAX),
    }
}

impl<'a, C: Catalog, N: NntpConnector, T: Clock> ColdReader<'a, C, N, T> {
    /// Charges a rebuild to `room`, the budget handle of the request
    /// this reader reads for: what a rebuild holds then counts as held
    /// by that request when it takes its turn for more.
    pub(crate) fn charged_to(mut self, room: std::rc::Rc<ByteBudget>) -> Self {
        self.room = room;
        self
    }

    /// Hands the reader room for a rebuild that the next
    /// [`Self::fetch`] may need. It is used only if it is enough.
    pub(crate) fn fund(&mut self, room: Charge) {
        self.reserve = Some(room);
    }

    /// After a [`Self::fetch`]: releases what is left of
    /// [`Self::fund`], and says how many bytes a rebuild needed and
    /// found no room for (0 = it was not refused). A read that ended
    /// [`ColdFetch::Busy`] for that reason is worth another try only
    /// once there is room for these bytes beside the extent.
    pub(crate) fn settle(&mut self) -> u64 {
        self.reserve = None;
        core::mem::take(&mut self.lacked)
    }

    /// Ends every session and frees its slot.
    pub(crate) async fn close(mut self) {
        ProviderSession::close_all(core::mem::take(&mut self.sessions)).await;
    }

    /// Ends every session and frees its slot; the reader can be used
    /// again and opens new ones. For a caller that is about to wait.
    pub(crate) async fn hang_up(&mut self) {
        ProviderSession::close_all(core::mem::take(&mut self.sessions)).await;
    }

    /// The most connections the reader holds at once.
    pub(crate) fn sockets(&self) -> u32 {
        u32::try_from(self.sockets).unwrap_or(u32::MAX)
    }

    /// How long the reader may still sit with its sessions open and
    /// read nothing, in milliseconds: until the slot that was renewed
    /// longest ago has only the goodbye and the slack left. `None`: no
    /// session is open. A caller that waits for anything else ends the
    /// sessions when this is over ([`Self::close`]).
    pub(crate) fn idle_ms(&self) -> Option<u32> {
        let oldest = self.sessions.iter().map(|s| s.held_from.0).min()?;
        let life = i64::from(READ_PERMIT_SECS - QUIT_SECS - READ_SLACK_SECS) * 1000;
        let left = oldest
            .saturating_add(life)
            .saturating_sub(self.clock.now().0);
        Some(u32::try_from(left.clamp(0, life)).unwrap_or(0))
    }

    /// What the reader did so far.
    pub(crate) fn stats(&self) -> ColdStats {
        self.stats.borrow().clone()
    }

    /// Whether a session of the reader is logged in to `provider`.
    fn logged_in(&self, provider: &ProviderConfig) -> bool {
        self.sessions
            .iter()
            .any(|s| s.provider.id == provider.id && s.connected())
    }

    fn held(&self, provider: &ProviderConfig) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.provider.id == provider.id)
            .count()
    }

    /// Renews the slot of every session before a connect, which may
    /// take as long as a call: none runs out while its socket is open.
    /// One that lost its slot is ended. Says whether the catalogue
    /// failed. (Boxed, like [`Self::first_logins`]: sessions are moved
    /// here, and a future that moves them in place makes every read's
    /// larger by each move.)
    fn renew_all<'s>(
        &'s mut self,
        order: &'s [&'a ProviderConfig],
        full: &'s mut [bool],
    ) -> LocalBoxFuture<'s, bool> {
        Box::pin(async move {
            // Boxed, here and in the first logins: one kind of future,
            // so one copy of the join in the Worker's wasm.
            let kept = join_all(
                self.sessions
                    .iter_mut()
                    .map(|s| -> Kept<'_> { Box::pin(s.keep(None)) }),
            )
            .await;
            let mut lost = Vec::new();
            let mut fatal = false;
            for (n, kept) in kept.into_iter().enumerate().rev() {
                if let Err(stop) = kept {
                    fatal |= matches!(stop, Stop::Fenced | Stop::Catalog);
                    let session = self.sessions.remove(n);
                    free_pool_slot(session.provider, order, full);
                    lost.push(session);
                }
            }
            self.stats.borrow_mut().broken += lost.len() as u32;
            ProviderSession::close_all(lost).await;
            fatal
        })
    }

    /// The first logins of a drill: each session of `first` (its
    /// provider's place in the order, its own in `sessions`) logs in
    /// now, its slot renewed first as before any connect. One the
    /// provider refuses is ended and its provider is out, as after a
    /// read with no other session there; the next turn gives a provider
    /// that took the login the rest of its sessions. A connect that only
    /// broke off is not the provider's answer: that session stays, and
    /// the read connects it again as it does any session that broke,
    /// counting this connect. Says whether the catalogue failed.
    fn first_logins<'s>(
        &'s mut self,
        first: &'s [(usize, usize)],
        order: &'s [&'a ProviderConfig],
        out: &'s mut [Option<Out>],
        full: &'s mut [bool],
    ) -> LocalBoxFuture<'s, bool> {
        Box::pin(async move {
            let logins = join_all(
                self.sessions
                    .iter_mut()
                    .enumerate()
                    .filter(|(n, _)| first.iter().any(|f| f.1 == *n))
                    .map(|(_, s)| -> Kept<'_> {
                        Box::pin(async move {
                            s.keep(None).await?;
                            s.session().await.map(|_| ())
                        })
                    }),
            )
            .await;
            let mut fatal = false;
            let mut ended = Vec::new();
            // From the last: taking one out moves only those after it.
            for (&(i, n), login) in first.iter().zip(logins).rev() {
                let stop = match login {
                    Ok(()) => continue,
                    Err(Stop::Session(_)) => {
                        self.sessions[n].broke_early += 1;
                        continue;
                    }
                    Err(stop) => stop,
                };
                let session = self.sessions.remove(n);
                if session.health == Some(Err(ProviderFault::LoginRefused))
                    && !self.shunned.contains(&session.provider.id)
                {
                    self.shunned.push(session.provider.id.clone());
                }
                fatal |= matches!(stop, Stop::Fenced | Stop::Catalog);
                out[i] = Some(match stop {
                    Stop::NoPermit => Out::Busy,
                    _ => Out::Broken,
                });
                free_pool_slot(session.provider, order, full);
                ended.push(session);
            }
            self.stats.borrow_mut().broken += ended.len() as u32;
            ProviderSession::close_all(ended).await;
            fatal
        })
    }

    /// Gives the providers of `order` that have work (`work[i]` articles
    /// they may still be asked for) sessions, up to `sockets` in all and
    /// never more on one provider than it has articles to read.
    ///
    /// Only the best tier that has work is staffed (`priority`, lowest
    /// first), in turns over its providers, so the sockets spread over
    /// the providers of a tier and a lower tier is asked only for what
    /// the tiers above could not supply. A provider that gives no slot
    /// while the reader holds none there is out for this extent
    /// ([`Out::Busy`]); one that gives fewer than asked keeps what it
    /// gave. A provider stays eligible if a session of this reader on
    /// another provider in the same pool may be holding its slot.
    /// When every socket is in use and a provider with work has none,
    /// a session of a provider without work is closed for it.
    async fn staff(
        &mut self,
        order: &[&'a ProviderConfig],
        work: &[usize],
        out: &mut [Option<Out>],
        full: &mut [bool],
    ) -> Result<()> {
        let drill = self.drill;
        loop {
            // A drill opens several connections on one account at once,
            // and an account that refuses the login would refuse each of
            // them: that many strikes against a provider reads use too.
            // So on a provider where this reader has no login yet, the
            // drill logs one connection in before it takes the others.
            let unproven: Vec<bool> = order.iter().map(|p| drill && !self.logged_in(p)).collect();
            // Sessions a provider may be given: one per article it has to
            // read, and no more than the reader may hold there.
            let room = |i: usize| {
                let most = if unproven[i] {
                    1
                } else {
                    cap_of(drill, order[i])
                };
                work[i].min(most)
            };
            let tier = (0..order.len())
                .filter(|&i| work[i] > 0 && out[i].is_none())
                .map(|i| tier_of(drill, order[i]))
                .min();
            let needy: Vec<usize> = (0..order.len())
                .filter(|&i| {
                    Some(tier_of(drill, order[i])) == tier
                        && work[i] > 0
                        && out[i].is_none()
                        && !full[i]
                        && self.held(order[i]) < room(i)
                        // Refused since this extent's order was made: a
                        // session it still has reads on, no other logs in.
                        && !self.shunned.contains(&order[i].id)
                })
                .collect();
            if needy.is_empty() {
                return Ok(());
            }
            if self.sessions.len() >= self.sockets {
                if !needy.iter().any(|&i| self.held(order[i]) == 0) {
                    return Ok(());
                }
                let idle = self.sessions.iter().position(|s| {
                    !(0..order.len())
                        .any(|i| order[i].id == s.provider.id && work[i] > 0 && out[i].is_none())
                });
                let Some(idle) = idle else {
                    return Ok(());
                };
                let idle = self.sessions.swap_remove(idle);
                free_pool_slot(idle.provider, order, full);
                idle.close().await;
            }
            let need = self.sockets - self.sessions.len();
            let mut asked: Vec<usize> = Vec::with_capacity(need);
            for turn in 0..need {
                for &i in &needy {
                    let mine = asked.iter().filter(|&&a| a == i).count();
                    if asked.len() < need && mine == turn && self.held(order[i]) + mine < room(i) {
                        asked.push(i);
                    }
                }
            }
            // A connect may take as long as a call. The sessions that
            // wait for it have their slots renewed first, so none runs
            // out while its socket is open; one that lost its slot is
            // ended.
            if !asked.is_empty() && !self.sessions.is_empty() && self.renew_all(order, full).await {
                return Err(BridgeError::Sql(CATALOGUE_FAILED.into()));
            }
            let began = self.clock.now();
            let opened = join_all(asked.iter().map(|&i| {
                ProviderSession::open(
                    self.catalog,
                    self.nntp,
                    self.clock,
                    order[i],
                    class_of(drill, order[i]),
                    &self.holder,
                )
            }))
            .await;
            self.stats.borrow_mut().open_ms += self.clock.now().0 - began.0;
            let mut failed = None;
            // The first sessions of a drill on their providers: the
            // provider's place in `order`, the session's in `sessions`.
            let mut first = Vec::new();
            for (&i, opened) in asked.iter().zip(opened) {
                match opened {
                    Ok(Some(session)) => {
                        self.stats.borrow_mut().opened += 1;
                        if unproven[i] {
                            first.push((i, self.sessions.len()));
                        }
                        self.sessions.push(session.with_timer(self.timer.as_ref()));
                    }
                    Ok(None) => full[i] = true,
                    Err(e) => {
                        failed.get_or_insert(e);
                    }
                }
            }
            if let Some(e) = failed {
                return Err(e);
            }
            if !first.is_empty() && self.first_logins(&first, order, out, full).await {
                return Err(BridgeError::Sql(CATALOGUE_FAILED.into()));
            }
            for &i in &needy {
                if full[i]
                    && self.held(order[i]) == 0
                    && !self
                        .sessions
                        .iter()
                        .any(|s| pool_siblings(s.provider, order[i]))
                {
                    out[i] = Some(Out::Busy);
                }
            }
        }
    }

    /// Reads the articles of `rows` that `chosen` allows onto `board`,
    /// over the sessions of the reader, until every one of them is there
    /// or no provider of the desk can be asked for what is lacking. What
    /// the providers did is noted on `desk`.
    async fn read_rows(
        &mut self,
        desk: &mut Desk<'a>,
        readers: &[&'a ProviderConfig],
        now: UnixMs,
        plan: &[ArticleRow],
        chosen: &[bool],
        board: &core::cell::RefCell<Board>,
    ) -> Result<()> {
        let drill = self.drill;
        let Desk {
            order,
            out,
            full,
            breaks,
            ..
        } = desk;
        let order = &*order;
        let stats = std::rc::Rc::clone(&self.stats);
        let stats = &*stats;
        let mut failure = None;
        // A drill has a third: its answer says whether Usenet has the
        // object, so before it says no, every reader is asked for what is
        // still missing, whatever retention it states. (A reader past its
        // stated retention often has the article; the other readers'
        // retention says nothing about that.)
        let phases: &[Phase] = match drill {
            true => &[Phase::Retained, Phase::Orphan, Phase::Any],
            false => &[Phase::Retained, Phase::Orphan],
        };
        'phases: for &phase in phases {
            let wanted = |provider: usize, article: usize| {
                chosen[article] && can_answer(order[provider], &plan[article], now, readers, phase)
            };
            loop {
                let work: Vec<usize> = (0..order.len())
                    .map(|i| {
                        let b = board.borrow();
                        (0..plan.len())
                            .filter(|&a| b.open(a, i) && wanted(i, a))
                            .count()
                    })
                    .collect();
                if !(0..order.len()).any(|i| work[i] > 0 && out[i].is_none()) {
                    break;
                }
                // Only the best tier that has work reads: a session of
                // another tier, kept from the extent before or from an
                // article only its tier had, is ended, not left idle and
                // not given articles the better tier has.
                let tier = (0..order.len())
                    .filter(|&i| work[i] > 0 && out[i].is_none())
                    .map(|i| tier_of(drill, order[i]))
                    .min();
                // Nor is a session of a provider that is out kept: it
                // would read nothing, with nobody renewing its slot, and
                // would count among the sockets a provider with work may
                // open.
                let index = |s: &ProviderSession<'a, C, N, T>| {
                    order.iter().position(|p| p.id == s.provider.id)
                };
                let lends_slot =
                    |s: &ProviderSession<'a, C, N, T>, out: &[Option<Out>], full: &[bool]| {
                        index(s).is_some_and(|i| work[i] == 0)
                            && (0..order.len()).any(|i| {
                                work[i] > 0
                                    && out[i].is_none()
                                    && full[i]
                                    && pool_siblings(s.provider, order[i])
                            })
                    };
                loop {
                    let (kept, other): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sessions)
                        .into_iter()
                        .partition(|s| {
                            Some(tier_of(drill, s.provider)) == tier
                                && index(s).is_some_and(|i| out[i].is_none())
                                && !lends_slot(s, out, full)
                        });
                    self.sessions = kept;
                    // A closed session frees its own slot and makes
                    // room in its pool for any sibling waiting for one.
                    for s in &other {
                        if let Some(i) = index(s) {
                            full[i] = false;
                        }
                        free_pool_slot(s.provider, order, full);
                    }
                    ProviderSession::close_all(other).await;
                    if let Err(e) = self.staff(order, &work, out, full).await {
                        failure = Some(e);
                        break 'phases;
                    }
                    // Staffing may just have found a sibling blocked by
                    // an idle session kept from the previous pass. Give
                    // up that slot before deciding that no one can read.
                    // Each repeat closes a session with no work, which
                    // cannot be reopened in this pass.
                    if !self.sessions.iter().any(|s| lends_slot(s, out, full)) {
                        break;
                    }
                }
                // No session for any of the work that is left: nothing
                // would be read, and the same pass would come again. The
                // providers of the tier are out instead, so every pass
                // either reads or ends with fewer providers.
                let staffed = self
                    .sessions
                    .iter()
                    .any(|s| index(s).is_some_and(|i| work[i] > 0 && out[i].is_none()));
                if !staffed {
                    for i in 0..order.len() {
                        if Some(tier_of(drill, order[i])) == tier && work[i] > 0 && out[i].is_none()
                        {
                            out[i] = Some(Out::Busy);
                        }
                    }
                    continue;
                }
                // A provider may have gone out while sockets were
                // opened: its sessions are ended as above.
                let (kept, other): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sessions)
                    .into_iter()
                    .partition(|s| index(s).is_some_and(|i| out[i].is_none()));
                self.sessions = kept;
                for s in &other {
                    free_pool_slot(s.provider, order, full);
                }
                ProviderSession::close_all(other).await;
                let ended = join_all(self.sessions.iter_mut().map(|session| {
                    let (plan, wanted, out) = (plan, &wanted, &*out);
                    let provider = index(session);
                    async move {
                        let Some(provider) = provider.filter(|&i| out[i].is_none()) else {
                            return Ok(Pace::default());
                        };
                        read_shared(session, provider, plan, board, stats, |a| {
                            wanted(provider, a)
                        })
                        .await
                    }
                }))
                .await;
                // A session that stopped is closed; its provider is out
                // once it has no session left, or once more of its
                // sessions broke off than one session may reconnect.
                let mut live = Vec::with_capacity(self.sessions.len());
                let mut dead = Vec::new();
                let mut stops: Vec<(usize, Stop)> = Vec::new();
                let lagging = stragglers(&ended);
                let mut slow = Vec::new();
                let sessions = core::mem::take(&mut self.sessions);
                for ((session, end), lags) in sessions.into_iter().zip(ended).zip(lagging) {
                    match (end, index(&session)) {
                        (Err(stop), Some(i)) => {
                            let refused = session.health == Some(Err(ProviderFault::LoginRefused));
                            if drill && refused && !self.shunned.contains(&session.provider.id) {
                                self.shunned.push(session.provider.id.clone());
                            }
                            stops.push((i, stop));
                            dead.push(session);
                        }
                        (Ok(_), _) if lags => slow.push(session),
                        _ => live.push(session),
                    }
                }
                self.sessions = live;
                stats.borrow_mut().broken += dead.len() as u32;
                for s in &dead {
                    free_pool_slot(s.provider, order, full);
                }
                ProviderSession::close_all(dead).await;
                let mut fatal = false;
                for (i, stop) in stops {
                    fatal |= matches!(stop, Stop::Fenced | Stop::Catalog);
                    breaks[i] += 1;
                    let spent = self.held(order[i]) == 0 || breaks[i] > MAX_READ_RECONNECTS;
                    if spent && out[i].is_none() {
                        out[i] = Some(match stop {
                            // The provider is at its connection limit.
                            Stop::NoPermit => Out::Busy,
                            // The read broke off, or the provider refused
                            // the account: it may still have the rest.
                            _ => Out::Broken,
                        });
                    }
                }
                if fatal {
                    failure = Some(BridgeError::Sql(CATALOGUE_FAILED.into()));
                    break 'phases;
                }
                // A connection far slower than the others holds up every
                // extent for the one article it reads. It is ended, and
                // the next pass opens another in its place while the
                // reader has replacements left; after that the reader
                // goes on with one connection less.
                // Its slot is free again: the provider is not full.
                for i in 0..order.len() {
                    full[i] &= !slow.iter().any(|s| s.provider.id == order[i].id);
                }
                (self.sockets, self.replacements) =
                    after_slow(self.sockets, self.replacements, slow.len());
                stats.borrow_mut().slow += slow.len() as u32;
                for s in &slow {
                    free_pool_slot(s.provider, order, full);
                }
                ProviderSession::close_all(slow).await;
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Waits only for the caller's own previous cache write. While it
    /// settles, end any sessions that cannot safely stay idle, making
    /// their slots eligible for staffing the parity pass again.
    async fn settle_prior_write(
        &mut self,
        put: &mut Option<LocalBoxFuture<'_, ()>>,
        desk: &mut Desk<'a>,
    ) {
        if let Some((idle, sleep)) = self.idle_ms().zip(self.timer.as_ref()) {
            if let Some(writing) = put.as_mut() {
                if matches!(select(writing, sleep(idle)).await, Either::Left(_)) {
                    *put = None;
                    // The write wins if both are ready on the same
                    // poll. Still close sessions past the idle limit.
                    if self.idle_ms() != Some(0) {
                        return;
                    }
                }
            }
        }
        let sessions = core::mem::take(&mut self.sessions);
        for session in &sessions {
            let provider = session.provider;
            if let Some(i) = desk.order.iter().position(|p| p.id == provider.id) {
                desk.full[i] = false;
            }
            free_pool_slot(provider, &desk.order, &mut desk.full);
        }
        beside(put, ProviderSession::close_all(sessions)).await;
        if let Some(writing) = put.take() {
            writing.await;
        }
    }

    /// Rebuilds the lost data articles of `extent` from its parity
    /// articles. `None` = every lost article is in its place and equal to
    /// the SHA-256 of its plan row; otherwise how the read ends, with
    /// `cipher` as it was.
    ///
    /// The parity articles are read like the data articles: each with one
    /// `BODY` from the providers of the desk, accepted only when it is
    /// exactly the payload the addendum names (length and SHA-256). As
    /// many are asked for as articles are lost, and another for each
    /// that no provider has intact, while the addendum has more; one
    /// that was not read leaves its place to the next. The codec is
    /// given verified shards only, and cannot tell a wrong one
    /// ([`velmora::rs`]); what it rebuilds is used only once every
    /// rebuilt article matches its own planned SHA-256.
    ///
    /// A rebuild is tried while a reader could not be asked, too
    /// (`lost.end` is not [`ColdFetch::Unavailable`]): what the readers
    /// that answered lack may be within the parity. Only then, a rebuild
    /// that cannot be done ends the read as `lost.end`, never as
    /// [`ColdFetch::Unrecoverable`]: the reader that was not asked may
    /// have the articles.
    ///
    /// Nothing is written or posted for the extent being rebuilt.
    async fn rebuild(
        &mut self,
        extent: &ExtentRow,
        lost: Lost<'_>,
        cipher: &mut [u8],
        desk: &mut Desk<'a>,
        readers: &[&'a ProviderConfig],
        put: &mut Option<LocalBoxFuture<'_, ()>>,
    ) -> Result<Option<ColdFetch>> {
        let Lost { stored, have, end } = lost;
        let plan = &stored.rows[..];
        let now = self.clock.now();
        // Every reader answered: what parity cannot make up for is lost.
        let sure = *end == ColdFetch::Unavailable;
        let unrecoverable = |stats: &core::cell::RefCell<ColdStats>| {
            if !sure {
                return Ok(Some(end.clone()));
            }
            stats.borrow_mut().unrecoverable += 1;
            Ok(Some(ColdFetch::Unrecoverable))
        };
        let parity = match stored.parity_plan(&extent.id, extent.cipher_size) {
            // No parity: the read ends as it always did.
            Ok(None) => return Ok(Some(end.clone())),
            Ok(Some(parity)) => parity,
            Err(_) => return unrecoverable(&self.stats),
        };
        let gaps: Vec<usize> = (0..plan.len()).filter(|&a| !have[a]).collect();
        let (m, t) = (parity.articles.len(), gaps.len());
        let len = parity.shard_len as usize;
        let laid_out = parity.rows.len() == m
            && parity
                .articles
                .iter()
                .all(|a| a.cipher_len == u64::from(parity.shard_len));
        if !laid_out || t > m {
            return unrecoverable(&self.stats);
        }
        // The rebuild is held beside the extent. Without room for it the
        // read is tried again later, like one that got no connection;
        // the caller is told how much was lacking ([`Self::settle`]).
        let need = cold_rebuild_bytes(u64::from(parity.shard_len), t as u64);
        let funded = self.reserve.take().filter(|room| room.bytes() >= need);
        let mut room = funded.or_else(|| self.room.try_charge(need));
        if room.is_none() && put.is_some() {
            // That write already holds its room; it does not wait for
            // budget. Settle it and try once more without waiting for
            // room held by any other request.
            self.settle_prior_write(put, desk).await;
            room = self.room.try_charge(need);
        }
        let Some(_room) = room else {
            self.lacked = need;
            return Ok(Some(ColdFetch::Busy));
        };
        // Room for as many parity articles as articles are lost, not for
        // all the extent has: a parity article gets one of the `t`
        // places when it is asked for, and gives it up when no provider
        // had it intact.
        let board = core::cell::RefCell::new(Board::new(t * len, vec![0; m], desk.order.len()));
        let mut free: Vec<usize> = (0..t).rev().collect();
        let mut seat = vec![0usize; m];
        let (mut chosen, mut tried) = (vec![false; m], vec![false; m]);
        loop {
            {
                let b = board.borrow();
                for slot in 0..m {
                    if chosen[slot] && !b.have[slot] {
                        chosen[slot] = false;
                        free.push(seat[slot]);
                    }
                }
            }
            let more: Vec<usize> = (0..m)
                .filter(|&slot| !tried[slot])
                .take(free.len())
                .collect();
            if more.is_empty() {
                break;
            }
            for slot in more {
                let Some(place) = free.pop() else { break };
                (tried[slot], chosen[slot], seat[slot]) = (true, true, place);
                board.borrow_mut().starts[slot] = place * len;
            }
            let read = self.read_rows(desk, readers, now, &parity.articles, &chosen, &board);
            beside(put, read).await?;
        }
        let board = board.into_inner();
        let usable: Vec<usize> = (0..m).filter(|&slot| board.have[slot]).collect();
        if usable.len() < t {
            if !sure {
                return Ok(Some(end.clone()));
            }
            // A provider that could not be asked may have the rest.
            return match desk.short(readers, &parity.articles, &board, now) {
                ColdFetch::Unavailable => unrecoverable(&self.stats),
                end => Ok(Some(end)),
            };
        }
        let shards = board.cipher;
        let rebuilt = {
            // Every shard passed in was compared with its SHA-256 when it
            // was read: the present data articles with their plan rows,
            // the parity articles with the addendum.
            let data: Vec<DataShard<'_>> = plan
                .iter()
                .zip(have)
                .map(|(row, have)| match have {
                    true => {
                        let start = row.cipher_offset as usize;
                        DataShard::Present(&cipher[start..start + row.cipher_len as usize])
                    }
                    false => DataShard::Lost {
                        len: row.cipher_len as usize,
                    },
                })
                .collect();
            let parity: Vec<ParityShard<'_>> = usable
                .iter()
                .map(|&slot| ParityShard {
                    row: parity.rows[slot],
                    bytes: &shards[seat[slot] * len..(seat[slot] + 1) * len],
                })
                .collect();
            reconstruct(&data, &parity)
        };
        let Ok(rebuilt) = rebuilt else {
            return unrecoverable(&self.stats);
        };
        // Nothing of a rebuild is used unless all of it is what the plan
        // says: one article that differs means the stripe is not the one
        // the parity was made of.
        let whole = rebuilt.len() == t
            && gaps.iter().zip(&rebuilt).all(|(&a, bytes)| {
                bytes.len() as u64 == plan[a].cipher_len && sha256(bytes) == plan[a].payload_sha256
            });
        if !whole {
            return unrecoverable(&self.stats);
        }
        for (&a, bytes) in gaps.iter().zip(&rebuilt) {
            let start = plan[a].cipher_offset as usize;
            cipher[start..start + bytes.len()].copy_from_slice(bytes);
        }
        Ok(None)
    }

    /// Reads one extent: every article with one `BODY`, each on whichever
    /// socket is free, decoded into its place and compared with the
    /// SHA-256 of its plan row; then the whole ciphertext against the
    /// extent's digest. Nothing is returned that did not pass both.
    ///
    /// An article goes to the best tier of `read` providers that retains
    /// it. One that a provider does not have, or has with other bytes, is
    /// asked of the next provider; one whose connection broke goes back
    /// to the other sockets, and the broken session reconnects (through
    /// the next proxy, if the provider has several) while its reconnects
    /// last ([`MAX_READ_RECONNECTS`]). A provider is not asked for an
    /// article older than its retention unless it is past every reader's
    /// retention. Then every reader counts, including those that cannot
    /// be asked because they are cooling.
    ///
    /// Articles that were asked for but not found intact can be rebuilt
    /// from the extent's parity articles, when it has any ([`Self::rebuild`]);
    /// an extent that lost none reads no parity.
    pub(crate) async fn fetch(&mut self, extent: &ExtentRow) -> Result<ColdFetch> {
        self.fetch_beside(extent, &mut None).await
    }

    /// [`Self::fetch`] beside this request's previous cache write. Only
    /// if a rebuild cannot charge its room does the read wait for it.
    pub(crate) async fn fetch_beside(
        &mut self,
        extent: &ExtentRow,
        put: &mut Option<LocalBoxFuture<'_, ()>>,
    ) -> Result<ColdFetch> {
        // The plan and the parity addendum beside it come with one
        // read of the catalogue. The addendum is looked at only when an
        // article is lost.
        let stored = beside(put, self.catalog.stored_plan(&extent.id)).await?;
        self.fetch_planned_beside(extent, stored, put).await
    }

    /// [`Self::fetch`] with the extent's plan already read.
    pub(crate) async fn fetch_planned(
        &mut self,
        extent: &ExtentRow,
        stored: StoredPlan,
    ) -> Result<ColdFetch> {
        self.fetch_planned_beside(extent, stored, &mut None).await
    }

    async fn fetch_planned_beside(
        &mut self,
        extent: &ExtentRow,
        stored: StoredPlan,
        put: &mut Option<LocalBoxFuture<'_, ()>>,
    ) -> Result<ColdFetch> {
        let drill = self.drill;
        let plan = &stored.rows[..];
        let size =
            usize::try_from(extent.cipher_size).map_err(|_| BridgeError::Invalid("extent size"))?;
        let spans = article_spans(extent.cipher_size);
        let planned = plan.len() == spans.len()
            && (0u32..).zip(plan).zip(&spans).all(|((idx, row), span)| {
                row.idx == idx && row.cipher_offset == span.start && row.cipher_len == span.len
            });
        if plan.is_empty() || !planned {
            return Ok(ColdFetch::Unavailable);
        }

        let now = self.clock.now();
        let pool = beside(put, Pool::load(self.catalog, self.providers, now)).await?;
        let readers: Vec<&'a ProviderConfig> = self.providers.iter().filter(|p| p.read).collect();
        // A provider that refused this drill's login is not asked again
        // by it, and is not the one a fallback below is spent on.
        let askable: Vec<&'a ProviderConfig> = readers
            .iter()
            .copied()
            .filter(|p| !self.shunned.contains(&p.id))
            .collect();
        let mut order = pool.order(askable.clone(), PermitClass::Read);
        by_tier(&mut order, drill);
        if order.is_empty() {
            // Every reader is cooling: a read is worth one attempt on the
            // provider that is due back first, unless that one refused
            // the login. A refused account answers no read: it is asked
            // again when its cooldown ends, not on every read.
            order.extend(pool.soonest_cooling(&askable));
        }
        // A session on a provider that is no longer in the order (it is
        // cooling now) is not used.
        let (kept, gone): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sessions)
            .into_iter()
            .partition(|s| order.iter().any(|p| p.id == s.provider.id));
        self.sessions = kept;
        beside(put, ProviderSession::close_all(gone)).await;

        let mut desk = Desk {
            drill,
            out: vec![None; order.len()],
            full: vec![false; order.len()],
            breaks: vec![0; order.len()],
            order,
        };
        let starts = spans.iter().map(|span| span.start as usize).collect();
        let board = core::cell::RefCell::new(Board::new(size, starts, desk.order.len()));
        let all = vec![true; plan.len()];
        // On the heap too: a body nests many futures above this one.
        let read = self.read_rows(&mut desk, &readers, now, plan, &all, &board);
        Box::pin(beside(put, read)).await?;
        let mut board = board.into_inner();
        let lost = board.have.iter().filter(|have| !**have).count();
        if lost > 0 {
            let end = desk.short(&readers, plan, &board, now);
            // The extent's parity, if it has any, is read only for
            // articles that are lost where they were asked for: each by
            // a provider that said it has it not, or sent other bytes.
            // An article nobody answered for (no reader, or none that
            // could be asked) is not known to be lost.
            let answered =
                |article: usize| (0..board.providers).any(|i| board.asks(article, i) > 0);
            if !(0..plan.len()).all(|a| board.have[a] || answered(a)) {
                return Ok(end);
            }
            let lost = Lost {
                stored: &stored,
                have: &board.have,
                end: &end,
            };
            // On the heap: the rebuild is rare, and what it holds across
            // its awaits is not carried by every read that never needs it.
            let rebuild = self.rebuild(extent, lost, &mut board.cipher, &mut desk, &readers, put);
            let rebuilt = Box::pin(rebuild).await?;
            if let Some(end) = rebuilt {
                return Ok(end);
            }
        }
        let cipher = board.cipher;
        if sha256(&cipher) != extent.cipher_sha256 {
            return Ok(ColdFetch::Unavailable);
        }
        let mut stats = self.stats.borrow_mut();
        // Counted once the whole extent is what its digest says.
        stats.rebuilt += lost as u32;
        stats.extents += 1;
        drop(stats);
        Ok(ColdFetch::Filled(cipher))
    }
}

/// How many articles one socket asked for in one pass over an extent,
/// and how long that took it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pace {
    articles: u32,
    ms: i64,
}

/// How long a socket with nothing to read waits for an article to come
/// back before it looks at its slot again. Under
/// [`READ_RENEW_SECS`](crate::ports::READ_RENEW_SECS), so a slot is
/// renewed at twice this age at most.
const IDLE_KEEP_MS: u32 = 4_000;

/// A connection is slow when an article takes it this many times as long
/// as it takes the connection in the middle, and longer than
/// [`SLOW_ARTICLE_MS`].
const SLOW_FACTOR: i64 = 3;

/// An article of full size that takes this long arrives at under
/// 1 MiB/s. Below it no connection counts as slow, whatever the others
/// do.
const SLOW_ARTICLE_MS: i64 = 1_000;

/// Slow connections one reader replaces. Each replacement is a login to
/// the provider; a reader that used them up goes on with fewer
/// connections instead.
pub(crate) const SLOW_REPLACEMENTS: u32 = 8;

/// Which of the connections that read one extent together were far
/// slower than the others, by the time each took per article. All the
/// connections wait for the last article of an extent, so one slow
/// connection sets the pace of all. The measure is the connection in
/// the middle (the lower one of two), so at most half are ever named,
/// connections that are all equally slow are left alone, and so is a
/// single one.
fn stragglers(ended: &[core::result::Result<Pace, Stop>]) -> Vec<bool> {
    let per = |pace: &Pace| pace.ms / i64::from(pace.articles.max(1));
    let mut all: Vec<i64> = ended
        .iter()
        .filter_map(|end| end.as_ref().ok())
        .filter(|pace| pace.articles > 0)
        .map(per)
        .collect();
    all.sort_unstable();
    let Some(&mid) = all.get(all.len().saturating_sub(1) / 2) else {
        return vec![false; ended.len()];
    };
    ended
        .iter()
        .map(|end| {
            end.as_ref().is_ok_and(|pace| {
                pace.articles > 0
                    && per(pace) > SLOW_ARTICLE_MS
                    && per(pace) > mid.saturating_mul(SLOW_FACTOR)
            })
        })
        .collect()
}

/// The connections a reader keeps and the replacements it has left once
/// `slow` connections were ended: each one is replaced while there are
/// replacements, and costs the reader a connection after that. One
/// connection always stays.
fn after_slow(sockets: usize, replacements: u32, slow: usize) -> (usize, u32) {
    let slow = u32::try_from(slow).unwrap_or(u32::MAX);
    let replaced = slow.min(replacements);
    let lost = (slow - replaced) as usize;
    (sockets.saturating_sub(lost).max(1), replacements - replaced)
}

/// One socket's share of an extent: takes articles off the board until
/// there is none left for its provider, and puts every verified payload
/// in its place. An article the provider does not have, or has with
/// other bytes, is counted against the provider and left to the others.
/// On a stop the article in hand goes back to the board untouched.
async fn read_shared<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    provider: usize,
    plan: &[ArticleRow],
    board: &core::cell::RefCell<Board>,
    stats: &core::cell::RefCell<ColdStats>,
    wanted: impl Fn(usize) -> bool,
) -> core::result::Result<Pace, Stop> {
    let mut wire = Vec::new();
    let mut reconnects = core::mem::take(&mut session.broke_early);
    let mut pace = Pace::default();
    loop {
        let Some(article) = board.borrow_mut().take(provider, &wanted) else {
            // Nothing is free for this provider. While another socket
            // still reads, of this provider or not, the pass is not
            // over: its article may come back to this socket, and this
            // socket stays logged in until the pass ends either way. A
            // host with a timer waits, and renews the slot meanwhile:
            // the socket must not sit there while its slot runs out
            // (another socket may be on its third attempt of a `BODY`).
            let timer = match board.borrow().reading() {
                true => session.timer.clone(),
                false => None,
            };
            let Some(sleep) = timer else {
                return Ok(pace);
            };
            let seen = board.borrow().turn;
            let turned = core::future::poll_fn(|cx| {
                let mut b = board.borrow_mut();
                if b.turn != seen {
                    return core::task::Poll::Ready(());
                }
                b.waiting.push(cx.waker().clone());
                core::task::Poll::Pending
            });
            select(core::pin::pin!(turned), sleep(IDLE_KEEP_MS)).await;
            session.keep(None).await?;
            continue;
        };
        let row = &plan[article];
        let read = match session.keep(None).await {
            Ok(()) => {
                // The pace of a connection is what its articles take
                // once it stands: a login is not counted, nor is an
                // article that was not delivered.
                let stands = session.session.is_some();
                let began = session.clock.now();
                let read =
                    read_one(session, None, row, Ask::Wire, &mut wire, &mut reconnects).await;
                if stands && matches!(read, Ok(Checked::Wire)) {
                    pace.articles += 1;
                    pace.ms += session.clock.now().0 - began.0;
                }
                read
            }
            Err(stop) => Err(stop),
        };
        let woken = board.borrow_mut().give_back(article);
        for socket in woken {
            socket.wake();
        }
        let mut b = board.borrow_mut();
        let slot = article * b.providers + provider;
        match read? {
            Checked::Wire => {
                // Spans were checked against the plan by the caller.
                let start = b.starts[article];
                let len = row.cipher_len as usize;
                // Another socket may have supplied it meanwhile only if
                // it was not taken, and it was: the place is this one's.
                let place = &mut b.cipher[start..start + len];
                let good = place_payload(row, &wire, place);
                if good {
                    b.have[article] = true;
                    stats
                        .borrow_mut()
                        .count(&session.provider.id, row.cipher_len);
                } else {
                    b.asks[slot] = MISSING_ASKS;
                    stats.borrow_mut().refetched += 1;
                }
            }
            Checked::Corrupt => {
                b.asks[slot] = MISSING_ASKS;
                stats.borrow_mut().refetched += 1;
            }
            Checked::Missing => {
                b.asks[slot] += 1;
                if b.asks[slot] == MISSING_ASKS {
                    stats.borrow_mut().refetched += 1;
                }
            }
            // Not asked for.
            Checked::Good(_) | Checked::Present | Checked::Sized => b.asks[slot] = MISSING_ASKS,
        }
    }
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
    /// A reader for this invocation's cold reads, with up to
    /// `COLD_SOCKETS` connections.
    pub(crate) fn cold_reader(&self) -> Result<ColdReader<'_, C, N, T>> {
        Ok(ColdReader {
            catalog: &self.catalog,
            nntp: &self.nntp,
            clock: &self.clock,
            providers: &self.cfg.providers,
            timer: self.budget.sleeper().cloned(),
            sockets: usize::try_from(self.cfg.cold_sockets).unwrap_or(1).max(1),
            holder: request_holder("get")?,
            sessions: Vec::new(),
            replacements: SLOW_REPLACEMENTS,
            stats: Default::default(),
            room: std::rc::Rc::new(self.budget.for_request()),
            reserve: None,
            lacked: 0,
            drill: false,
            shunned: Vec::new(),
        })
    }

    /// A reader for one drill (`POST /_admin/drill`), with up to
    /// `sockets` connections and never more than `COLD_SOCKETS`.
    ///
    /// It reads as a cold read does, with these differences. It takes
    /// its connections from the providers' drill connections
    /// ([`ProviderConfig::drill_conns`]), over all such providers at
    /// once whatever their `priority`, and holds no slot of `max_conns`
    /// there. A provider without drill connections is asked after
    /// those, for what they lack, over one connection of `max_conns`.
    /// With no drill connections on any reader the drill has one socket
    /// in all: it then reads as it always did, one connection of
    /// `max_conns` at a time.
    pub(crate) fn drill_reader(&self, sockets: u32) -> Result<ColdReader<'_, C, N, T>> {
        let dedicated = self
            .cfg
            .providers
            .iter()
            .any(|p| p.read && p.enabled && p.drill_conns > 0);
        let sockets = match dedicated {
            true => sockets.clamp(1, self.cfg.cold_sockets.max(1)),
            false => 1,
        };
        Ok(ColdReader {
            sockets: usize::try_from(sockets).unwrap_or(1),
            holder: request_holder("drill")?,
            drill: true,
            ..self.cold_reader()?
        })
    }

    /// Writes a verified extent to the cache and counts it.
    ///
    /// The fill is counted before it is written and again after:
    /// - before, so that a request cancelled right after the write
    ///   leaves a counted copy;
    /// - after, so that an eviction that ran between the two cannot
    ///   leave this copy uncounted.
    ///
    /// Without the first count nothing is written: an uncounted copy
    /// could outlive the cap. `false` = not written for that reason.
    pub(crate) async fn cache_fill(&self, extent: &ExtentRow, cipher: Vec<u8>) -> Result<bool> {
        let meta = BlobMeta {
            bucket: &extent.bucket_id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        let count = || self.catalog.record_cache_fill(&extent.id, self.clock.now());
        if count().await.is_err() {
            return Ok(false);
        }
        self.cache
            .put(&extent.id.cache_key(), cipher, &meta)
            .await?;
        let _ = count().await;
        Ok(true)
    }

    /// Reads `extents` from Usenet one after the other with one reader,
    /// as the body of a GET does, and caches nothing: what each read
    /// gave, and what the reader did.
    #[cfg(feature = "testkit")]
    pub async fn fetch_cold_run(
        &self,
        extents: &[ExtentRow],
    ) -> Result<(Vec<ColdFetch>, ColdStats)> {
        let mut reader = self.cold_reader()?;
        let mut read = Vec::new();
        for extent in extents {
            match reader.fetch(extent).await {
                Ok(one) => read.push(one),
                Err(e) => {
                    reader.close().await;
                    return Err(e);
                }
            }
        }
        let stats = reader.stats();
        reader.close().await;
        Ok((read, stats))
    }

    /// Rebuilds an extent's ciphertext from Usenet when neither blob store
    /// has it ([`ColdReader::fetch`]). The assembled extent is checked
    /// against `cipher_sha256` and written to the cache before it is
    /// returned, so nothing unverified is ever served or cached. The
    /// bytes are verified whether or not the cache took them, so the
    /// read itself succeeds either way.
    pub async fn fetch_cold(&self, extent: &ExtentRow) -> Result<ColdFetch> {
        let mut reader = self.cold_reader()?;
        let read = reader.fetch(extent).await;
        reader.close().await;
        match read? {
            ColdFetch::Filled(cipher) => {
                // Verified already: a cache that does not take the copy
                // does not fail the read.
                let _ = self.cache_fill(extent, cipher.clone()).await;
                Ok(ColdFetch::Filled(cipher))
            }
            other => Ok(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora::nntp::{REDACTED_LIMIT, REDACTED_REPLY};
    use velmora::Error as E;

    fn plain(code: u16, text: &str) -> BridgeError {
        BridgeError::Nntp(E::NntpReply {
            code,
            text: text.into(),
        })
    }

    fn paced(ms: &[i64]) -> Vec<core::result::Result<Pace, Stop>> {
        ms.iter()
            .map(|&ms| {
                Ok(Pace {
                    articles: 3,
                    ms: ms * 3,
                })
            })
            .collect()
    }

    /// What the drill showed: most connections take 150 to 200 ms for an
    /// article and one or two take over three seconds. Those are named,
    /// and nobody else.
    /// A full extent that lost as many articles as it has parity: the
    /// rebuild fits the request budget beside the read of the extent.
    #[test]
    fn a_rebuild_is_charged_its_parity_its_articles_and_the_codec() {
        let shard = velmora::article::ARTICLE_ZERO_PAYLOAD_BYTES;
        // 4 parity shards kept, 4 rebuilt, 4 + 2 of working memory.
        // The extent's other parity articles are not held beside them.
        let need = cold_rebuild_bytes(shard, 4);
        assert_eq!(need, 14 * shard + 64);
        assert_eq!(cold_rebuild_bytes(shard, 1), 5 * shard + 4);
        assert_eq!(cold_rebuild_bytes(shard, 2), 8 * shard + 16);
        // Beside what a GET holds while it reads the extent over eight
        // sockets, under a budget of 48 MiB.
        let extent = 24 * shard;
        assert!(cold_step_bytes(extent, 8) + need <= 48 * 1024 * 1024);
        assert_eq!(cold_rebuild_bytes(u64::MAX, 4), u64::MAX);
    }

    /// The log line of a read that rebuilt nothing is what it was.
    #[test]
    fn a_rebuild_is_named_in_the_log_line_only_when_there_was_one() {
        let mut stats = ColdStats::default();
        let plain = stats.to_string();
        assert!(!plain.contains("rebuilt") && !plain.contains("unrecoverable"));
        stats.rebuilt = 3;
        stats.unrecoverable = 1;
        assert_eq!(
            stats.to_string(),
            format!("{plain} rebuilt=3 extent-unrecoverable=1")
        );
    }

    #[test]
    fn a_connection_far_slower_than_the_middle_one_is_a_straggler() {
        let ended = paced(&[150, 3_300, 200, 180, 3_400, 160, 170, 190]);
        assert_eq!(
            stragglers(&ended),
            [false, true, false, false, true, false, false, false]
        );
    }

    /// Slow in common is the provider's pace, not a connection's fault:
    /// replacing connections would only add logins. The same holds below
    /// the absolute floor, however uneven the connections are, and for a
    /// connection that is alone.
    #[test]
    fn connections_that_are_slow_together_or_fast_enough_are_left_alone() {
        assert_eq!(
            stragglers(&paced(&[3_000, 3_300, 3_100, 4_000])),
            [false; 4]
        );
        assert_eq!(stragglers(&paced(&[10, 900, 20, 1_000])), [false; 4]);
        assert_eq!(stragglers(&paced(&[5_000])), [false]);
        assert_eq!(stragglers(&[]), Vec::<bool>::new());
    }

    /// The measure is the lower middle, so half the connections at most
    /// are named: of two, the slower one; of four with two slow, both.
    #[test]
    fn at_most_half_the_connections_are_stragglers() {
        assert_eq!(stragglers(&paced(&[200, 3_000])), [false, true]);
        assert_eq!(
            stragglers(&paced(&[3_000, 200, 3_500, 150])),
            [true, false, true, false]
        );
        assert_eq!(stragglers(&paced(&[3_000, 200, 3_500, 3_200])), [false; 4]);
    }

    /// A connection that broke off is not a straggler (it is handled as
    /// broken) and does not count towards the middle, nor does one that
    /// read nothing in this pass.
    #[test]
    fn broken_and_idle_connections_do_not_set_the_pace() {
        let mut ended = paced(&[200, 3_000, 180]);
        ended.push(Err(Stop::NoPermit));
        ended.push(Ok(Pace {
            articles: 0,
            ms: 9_000,
        }));
        assert_eq!(stragglers(&ended), [false, true, false, false, false]);
    }

    /// A reader replaces slow connections while it has replacements and
    /// then goes on with fewer, never with none.
    #[test]
    fn slow_connections_are_replaced_until_the_replacements_are_spent() {
        assert_eq!(
            after_slow(8, SLOW_REPLACEMENTS, 2),
            (8, SLOW_REPLACEMENTS - 2)
        );
        assert_eq!(after_slow(8, 1, 3), (6, 0));
        assert_eq!(after_slow(6, 0, 1), (5, 0));
        assert_eq!(after_slow(2, 0, 5), (1, 0));
        assert_eq!(after_slow(4, 3, 0), (4, 3));
    }

    const LOGIN: Option<Refusal> = Some(Refusal::Account(ProviderFault::LoginRefused));
    const GREETING: Option<Refusal> = Some(Refusal::Account(ProviderFault::ConnectRefused));

    /// A refused connect that states a connection limit is a limit
    /// whatever its code and its stage: the login's `AuthFailed` and
    /// `NoPermission`, what the login leaves of any other code, and the
    /// greeting's plain reply.
    #[test]
    fn a_stated_limit_is_a_limit_under_any_code() {
        let limit = "Too many connections for user";
        for e in [
            E::NoPermission(limit.into()).into(),
            E::AuthFailed(limit.into()).into(),
            plain(480, limit),
            plain(481, limit),
            plain(482, limit),
            plain(502, limit),
            plain(400, limit),
            plain(482, REDACTED_LIMIT),
            plain(400, REDACTED_LIMIT),
            plain(451, REDACTED_LIMIT),
            plain(503, REDACTED_LIMIT),
        ] {
            assert_eq!(refusal(&e), Some(Refusal::Limit), "{e:?}");
        }
    }

    /// Any other refusal is the account's, and the reason says where the
    /// provider refused: at the login, or at the greeting before it.
    #[test]
    fn a_refusal_is_sorted_by_its_stage() {
        let account = "Account suspended";
        assert_eq!(refusal(&E::NoPermission(account.into()).into()), LOGIN);
        assert_eq!(refusal(&E::AuthFailed(account.into()).into()), LOGIN);
        assert_eq!(refusal(&E::NoPermission(String::new()).into()), LOGIN);
        // What the login leaves of a `482` without a limit.
        assert_eq!(refusal(&plain(482, REDACTED_REPLY)), LOGIN);
        // The server's own words: the greeting.
        for code in [480, 481, 482, 502] {
            assert_eq!(refusal(&plain(code, account)), GREETING, "{code}");
            assert_eq!(refusal(&plain(code, "")), GREETING, "{code}");
        }
    }

    /// Another code without a stated limit, a connection that broke and a
    /// reply to a command are no refusal: `is_provider_fault` decides.
    #[test]
    fn another_failure_is_not_a_refusal() {
        for e in [
            plain(400, "Service temporarily unavailable"),
            plain(400, REDACTED_REPLY),
            plain(451, REDACTED_REPLY),
            plain(500, "What?"),
            plain(503, REDACTED_REPLY),
            E::Io(std::io::Error::other("reset")).into(),
            E::ArticleNotFound("a@x".into()).into(),
            BridgeError::Invalid("permit is for another provider"),
        ] {
            assert_eq!(refusal(&e), None, "{e:?}");
        }
    }

    #[test]
    fn only_the_strike_of_a_refusal_is_forgiven() {
        let strike = |fault| Some(Err(fault));
        assert_eq!(forgiven(strike(ProviderFault::LoginRefused)), None);
        assert_eq!(forgiven(strike(ProviderFault::ConnectRefused)), None);
        assert_eq!(
            forgiven(strike(ProviderFault::SessionFailed)),
            strike(ProviderFault::SessionFailed)
        );
        assert_eq!(forgiven(Some(Ok(()))), Some(Ok(())));
        assert_eq!(forgiven(None), None);
    }
}
