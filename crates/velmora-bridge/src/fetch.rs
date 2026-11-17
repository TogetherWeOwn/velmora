//! NNTP reads: permit-scoped provider sessions, the checked article read
//! shared by verify, release and cold reads, and the cold read itself.
//!
//! Every NNTP path holds a provider connection slot before it opens a
//! socket ("no permit, no socket"). Every article is read with one `BODY`,
//! decoded, and compared with the SHA-256 stored in its plan row before
//! anything uses its bytes.

use futures_util::future::{join_all, select, Either};
use velmora::rng::{FillRandom, SystemRng};
use velmora::transport::is_article_limit_error;
use velmora::yenc::decode_part_to;

use crate::articles::article_spans;
use crate::ingress::Sleeper;
use crate::pool::Pool;
use crate::ports::{
    BlobMeta, BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, Permit, PermitClass, QUIT_SECS, READ_PERMIT_SECS, READ_SLACK_SECS,
};
use crate::post::{sha256, Stop, KEEP_EVERY_MS};
use crate::types::{
    ArticleRow, BridgeError, ExtentRow, FailClass, ProviderConfig, ProviderFault, Result, UnixMs,
};

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
        let _ = self.catalog.release_permit(&self.permit).await;
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
    /// Present, but not the planned bytes.
    pub(crate) corrupt: Vec<u32>,
}

enum Checked {
    Good(Vec<u8>),
    /// A `STAT` found the article. Nothing was read, so nothing is known
    /// about its bytes.
    Present,
    /// A `BODY` is in the caller's buffer, not yet decoded or checked.
    Wire,
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
                    Ask::Body | Ask::Wire => s.body(&row.message_id, wire).await.map(Some),
                    Ask::Stat => match s.stat(&row.message_id).await {
                        Ok(true) => Ok(None),
                        Ok(false) => Ok(Some(BodyOutcome::Missing)),
                        Err(e) => Err(e),
                    },
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
                    Some(BodyOutcome::Found) if ask == Ask::Wire => Checked::Wire,
                    Some(BodyOutcome::Found) => check_payload(row, wire),
                    Some(BodyOutcome::Missing) => Checked::Missing,
                    None => Checked::Present,
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
    ask_articles(session, lease, rows, Ask::Body, sink).await
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
    ask_articles(session, lease, rows, Ask::Stat, |_, _| {}).await
}

async fn ask_articles<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    rows: &[&ArticleRow],
    ask: Ask,
    mut sink: impl FnMut(&ArticleRow, Vec<u8>),
) -> core::result::Result<ReadTally, Stop> {
    let mut tally = ReadTally::default();
    let mut wire = Vec::new();
    let mut reconnects = 0;
    let mut retry: Vec<&ArticleRow> = Vec::new();
    for pass in 0..2 {
        let todo = if pass == 0 {
            rows.to_vec()
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
                Checked::Corrupt => tally.corrupt.push(row.idx),
                Checked::Missing if pass == 0 => retry.push(row),
                Checked::Missing => tally.missing.push(row.idx),
            }
        }
    }
    Ok(tally)
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
#[derive(Debug, PartialEq, Eq)]
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
        Ok(())
    }
}

/// The shared state of the sockets that read one extent together. It is
/// borrowed only between awaits.
struct Board {
    cipher: Vec<u8>,
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
    /// Whether a socket of `provider` may still get an article that
    /// another socket is reading now: that one may give it back.
    fn pending(&self, provider: usize, wanted: impl Fn(usize) -> bool) -> bool {
        (0..self.have.len()).any(|a| self.taken[a] && self.open(a, provider) && wanted(a))
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

/// Why a provider gets no (more) work in one cold read of an extent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Out {
    /// It gave no slot, or refused a connection for a stated limit.
    Busy,
    /// Its last session broke off, or it refused the account.
    Broken,
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
}

impl<'a, C: Catalog, N: NntpConnector, T: Clock> ColdReader<'a, C, N, T> {
    /// Ends every session and frees its slot.
    pub(crate) async fn close(mut self) {
        ProviderSession::close_all(core::mem::take(&mut self.sessions)).await;
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

    fn held(&self, provider: &ProviderConfig) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.provider.id == provider.id)
            .count()
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
    /// gave. When every socket is in use and a provider with work has
    /// none, a session of a provider without work is closed for it.
    async fn staff(
        &mut self,
        order: &[&'a ProviderConfig],
        work: &[usize],
        out: &mut [Option<Out>],
        full: &mut [bool],
    ) -> Result<()> {
        loop {
            let tier = (0..order.len())
                .filter(|&i| work[i] > 0 && out[i].is_none())
                .map(|i| order[i].priority)
                .min();
            let needy: Vec<usize> = (0..order.len())
                .filter(|&i| {
                    Some(order[i].priority) == tier
                        && work[i] > 0
                        && out[i].is_none()
                        && !full[i]
                        && self.held(order[i]) < work[i]
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
                self.sessions.swap_remove(idle).close().await;
            }
            let need = self.sockets - self.sessions.len();
            let mut asked: Vec<usize> = Vec::with_capacity(need);
            for turn in 0..need {
                for &i in &needy {
                    let mine = asked.iter().filter(|&&a| a == i).count();
                    if asked.len() < need && mine == turn && self.held(order[i]) + mine < work[i] {
                        asked.push(i);
                    }
                }
            }
            // A connect may take as long as a call. The sessions that
            // wait for it have their slots renewed first, so none runs
            // out while its socket is open; one that lost its slot is
            // ended.
            if !asked.is_empty() && !self.sessions.is_empty() {
                let kept = join_all(self.sessions.iter_mut().map(|s| s.keep(None))).await;
                let mut lost = Vec::new();
                let mut fatal = false;
                for (session, kept) in core::mem::take(&mut self.sessions).into_iter().zip(kept) {
                    match kept {
                        Ok(()) => self.sessions.push(session),
                        Err(stop) => {
                            fatal |= matches!(stop, Stop::Fenced | Stop::Catalog);
                            lost.push(session);
                        }
                    }
                }
                self.stats.borrow_mut().broken += lost.len() as u32;
                ProviderSession::close_all(lost).await;
                if fatal {
                    return Err(BridgeError::Sql(
                        "catalogue failed during a cold read".into(),
                    ));
                }
            }
            let began = self.clock.now();
            let opened = join_all(asked.iter().map(|&i| {
                ProviderSession::open(
                    self.catalog,
                    self.nntp,
                    self.clock,
                    order[i],
                    PermitClass::Read,
                    &self.holder,
                )
            }))
            .await;
            self.stats.borrow_mut().open_ms += self.clock.now().0 - began.0;
            let mut failed = None;
            for (&i, opened) in asked.iter().zip(opened) {
                match opened {
                    Ok(Some(session)) => {
                        self.stats.borrow_mut().opened += 1;
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
            for &i in &needy {
                if full[i] && self.held(order[i]) == 0 {
                    out[i] = Some(Out::Busy);
                }
            }
        }
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
    /// article older than its retention, and a provider in a cooldown is
    /// not asked at all. An article past every reader's stated retention
    /// is asked of every reader before the read gives up.
    pub(crate) async fn fetch(&mut self, extent: &ExtentRow) -> Result<ColdFetch> {
        let plan = self.catalog.articles(&extent.id).await?;
        let size =
            usize::try_from(extent.cipher_size).map_err(|_| BridgeError::Invalid("extent size"))?;
        let spans = article_spans(extent.cipher_size);
        let planned = plan.len() == spans.len()
            && (0u32..).zip(&plan).zip(&spans).all(|((idx, row), span)| {
                row.idx == idx && row.cipher_offset == span.start && row.cipher_len == span.len
            });
        if plan.is_empty() || !planned {
            return Ok(ColdFetch::Unavailable);
        }

        let now = self.clock.now();
        let pool = Pool::load(self.catalog, self.providers, now).await?;
        let readers: Vec<&'a ProviderConfig> = self.providers.iter().filter(|p| p.read).collect();
        let mut order = pool.order(readers.clone(), PermitClass::Read);
        if order.is_empty() {
            // Every reader is cooling: a read is worth one attempt on the
            // provider that is due back first, unless that one refused
            // the login. A refused account answers no read: it is asked
            // again when its cooldown ends, not on every read.
            order.extend(pool.soonest_cooling(&readers));
        }
        // A session on a provider that is no longer in the order (it is
        // cooling now) is not used.
        let (kept, gone): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sessions)
            .into_iter()
            .partition(|s| order.iter().any(|p| p.id == s.provider.id));
        self.sessions = kept;
        ProviderSession::close_all(gone).await;

        // An article past every reader's stated retention may still be
        // there: a second phase asks for those before giving up.
        let orphan = |a: &ArticleRow| {
            !readers
                .iter()
                .any(|p| p.enabled && p.retains(a.posted_at, now))
        };
        let board = core::cell::RefCell::new(Board {
            cipher: vec![0u8; size],
            have: vec![false; plan.len()],
            taken: vec![false; plan.len()],
            asks: vec![0u8; plan.len() * order.len()],
            providers: order.len(),
            turn: 0,
            waiting: Vec::new(),
        });
        let mut out: Vec<Option<Out>> = vec![None; order.len()];
        let mut full = vec![false; order.len()];
        // Providers that answered for every article they were asked for.
        let mut asked = vec![false; order.len()];
        let stats = std::rc::Rc::clone(&self.stats);
        let stats = &*stats;
        // Sessions of a provider that broke off in this read.
        let mut breaks = vec![0u32; order.len()];
        let mut failure = None;
        'phases: for expired in [false, true] {
            let wanted = |provider: usize, article: usize| match expired {
                false => order[provider].retains(plan[article].posted_at, now),
                true => orphan(&plan[article]),
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
                    .map(|i| order[i].priority)
                    .min();
                let (kept, other): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sessions)
                    .into_iter()
                    .partition(|s| Some(s.provider.priority) == tier);
                self.sessions = kept;
                ProviderSession::close_all(other).await;
                if let Err(e) = self.staff(&order, &work, &mut out, &mut full).await {
                    failure = Some(e);
                    break 'phases;
                }
                let index = |s: &ProviderSession<'a, C, N, T>| {
                    order.iter().position(|p| p.id == s.provider.id)
                };
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
                        if Some(order[i].priority) == tier && work[i] > 0 && out[i].is_none() {
                            out[i] = Some(Out::Busy);
                        }
                    }
                    continue;
                }
                let ended = join_all(self.sessions.iter_mut().map(|session| {
                    let (board, plan, wanted, out) = (&board, &plan, &wanted, &out);
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
                            stops.push((i, stop));
                            dead.push(session);
                        }
                        (Ok(_), _) if lags => slow.push(session),
                        _ => live.push(session),
                    }
                }
                self.sessions = live;
                stats.borrow_mut().broken += dead.len() as u32;
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
                    failure = Some(BridgeError::Sql(
                        "catalogue failed during a cold read".into(),
                    ));
                    break 'phases;
                }
                for i in 0..order.len() {
                    asked[i] |= out[i].is_none()
                        && (self.held(order[i]) > 0
                            || slow.iter().any(|s| s.provider.id == order[i].id));
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
                ProviderSession::close_all(slow).await;
            }
        }
        if let Some(e) = failure {
            return Err(e);
        }
        let Board { cipher, have, .. } = board.into_inner();
        if have.contains(&false) {
            // A cooling provider that retains a missing article and was
            // not asked may hold what the others lack: retry later.
            let lacks = |p: &ProviderConfig| {
                plan.iter()
                    .any(|a| !have[a.idx as usize] && p.retains(a.posted_at, now))
            };
            let was_asked = |p: &ProviderConfig| {
                order
                    .iter()
                    .position(|o| o.id == p.id)
                    .is_some_and(|i| asked[i] && out[i].is_none())
            };
            let waiting: Vec<&ProviderConfig> = readers
                .iter()
                .copied()
                .filter(|p| !was_asked(p) && lacks(p))
                .collect();
            let interrupted =
                out.contains(&Some(Out::Broken)) || pool.cooling_until(&waiting).is_some();
            return Ok(if interrupted {
                ColdFetch::Interrupted
            } else if out.contains(&Some(Out::Busy)) {
                ColdFetch::Busy
            } else {
                ColdFetch::Unavailable
            });
        }
        if sha256(&cipher) != extent.cipher_sha256 {
            return Ok(ColdFetch::Unavailable);
        }
        self.stats.borrow_mut().extents += 1;
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
    let mut reconnects = 0;
    let mut pace = Pace::default();
    loop {
        let Some(article) = board.borrow_mut().take(provider, &wanted) else {
            // Nothing is free for this provider. An article another
            // socket is reading may still come back. A host with a timer
            // waits for that, and renews the slot meanwhile: the socket
            // must not sit there logged in while its slot runs out
            // (another socket may be on its third attempt of a `BODY`).
            let timer = match board.borrow().pending(provider, &wanted) {
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
                let start = row.cipher_offset as usize;
                let len = row.cipher_len as usize;
                // Another socket may have supplied it meanwhile only if
                // it was not taken, and it was: the place is this one's.
                let place = &mut b.cipher[start..start + len];
                let good = decode_part_to(&row.message_id, &wire, place)
                    .is_ok_and(|part| part.written == len)
                    && sha256(place) == row.payload_sha256;
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
            Checked::Good(_) | Checked::Present => b.asks[slot] = MISSING_ASKS,
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
