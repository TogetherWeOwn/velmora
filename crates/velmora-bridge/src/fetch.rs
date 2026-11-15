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
    NntpSession, Permit, PermitClass,
};
use crate::post::{sha256, Stop};
use crate::types::{
    ArticleRow, BridgeError, ExtentRow, FailClass, ProviderConfig, ProviderFault, Result,
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
        let permit = catalog
            .acquire_permit(provider, class, holder, clock.now())
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
    pub(crate) async fn keep(&mut self, lease: Option<&Lease>) -> core::result::Result<(), Stop> {
        let now = self.clock.now();
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
            Ok(true) if !late => Ok(()),
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
                    Ask::Body => s.body(&row.message_id, wire).await.map(Some),
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
/// lease is renewed before every article and a stale lease stops the read.
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
                Checked::Present => tally.ok += 1,
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
    /// The complete, verified ciphertext. It is already in the cache.
    Filled(Vec<u8>),
    /// A provider that could still hold missing articles had no free
    /// connection slot: worth waiting for one.
    Busy,
    /// A provider read broke off in transit: retry later, not at once.
    Interrupted,
    /// No provider could supply every article intact.
    Unavailable,
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
    /// Rebuilds an extent's ciphertext from Usenet when neither blob store
    /// has it. Each article is read from the first `read` provider, in
    /// pool order, that serves it intact; a provider is not asked for an
    /// article older than its retention, and a provider in a cooldown is
    /// not asked at all. The assembled extent is checked against
    /// `cipher_sha256` and written to the cache before it is returned, so
    /// nothing unverified is ever served or cached.
    pub async fn fetch_cold(&self, extent: &ExtentRow) -> Result<ColdFetch> {
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

        let mut cipher = vec![0u8; size];
        let mut have = vec![false; plan.len()];
        let mut busy = false;
        let holder = request_holder("get")?;
        let now = self.clock.now();
        let pool = Pool::load(&self.catalog, &self.cfg.providers, now).await?;
        let readers: Vec<&ProviderConfig> = self.cfg.providers.iter().filter(|p| p.read).collect();
        let mut interrupted = false;
        let mut order = pool.order(readers.clone(), PermitClass::Read);
        if order.is_empty() {
            // Every reader is cooling: a read is worth one attempt on the
            // provider that is due back first, unless that one refused
            // the login. A refused account answers no read: it is asked
            // again when its cooldown ends, not on every read.
            order.extend(pool.soonest_cooling(&readers));
        }
        // An article past every reader's stated retention may still be
        // there: a second pass asks for those before giving up.
        let orphan = |a: &ArticleRow| {
            !readers
                .iter()
                .any(|p| p.enabled && p.retains(a.posted_at, now))
        };
        let mut asked: Vec<&str> = Vec::new();
        let passes = [false, true];
        for (provider, expired) in passes
            .iter()
            .flat_map(|&expired| order.iter().map(move |&p| (p, expired)))
        {
            if !have.contains(&false) {
                break;
            }
            let wanted: Vec<&ArticleRow> = plan
                .iter()
                .filter(|a| !have[a.idx as usize])
                .filter(|a| match expired {
                    false => provider.retains(a.posted_at, now),
                    true => orphan(a),
                })
                .collect();
            if wanted.is_empty() {
                continue;
            }
            let Some(mut session) = ProviderSession::open(
                &self.catalog,
                &self.nntp,
                &self.clock,
                provider,
                PermitClass::Read,
                &holder,
            )
            .await?
            .map(|s| s.with_timer(self.budget.sleeper())) else {
                busy = true;
                continue;
            };
            let read = read_articles(&mut session, None, &wanted, |row, payload| {
                // Spans were checked against the plan above.
                let start = row.cipher_offset as usize;
                cipher[start..start + payload.len()].copy_from_slice(&payload);
                have[row.idx as usize] = true;
            })
            .await;
            session.close().await;
            match read {
                Ok(_) => asked.push(provider.id.as_str()),
                // The provider is at its connection limit.
                Err(Stop::NoPermit) => busy = true,
                // The read broke off, or the provider refused the account:
                // it may still have the rest.
                Err(Stop::Cooling(_) | Stop::Fail(..) | Stop::Session(_) | Stop::Refused) => {
                    interrupted = true;
                }
                Err(Stop::Fenced | Stop::Catalog) => {
                    return Err(BridgeError::Sql(
                        "catalogue failed during a cold read".into(),
                    ));
                }
            }
        }
        if have.contains(&false) {
            // A cooling provider that retains a missing article and was
            // not asked may hold what the others lack: retry later.
            let missing = |p: &ProviderConfig| {
                !asked.contains(&p.id.as_str())
                    && plan
                        .iter()
                        .any(|a| !have[a.idx as usize] && p.retains(a.posted_at, now))
            };
            let waiting: Vec<&ProviderConfig> =
                readers.into_iter().filter(|p| missing(p)).collect();
            interrupted |= pool.cooling_until(&waiting).is_some();
            return Ok(if interrupted {
                ColdFetch::Interrupted
            } else if busy {
                ColdFetch::Busy
            } else {
                ColdFetch::Unavailable
            });
        }
        if sha256(&cipher) != extent.cipher_sha256 {
            return Ok(ColdFetch::Unavailable);
        }
        let meta = BlobMeta {
            bucket: &extent.bucket_id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        // The fill is counted before it is written and again after:
        // - before, so that a request cancelled right after the write
        //   leaves a counted copy;
        // - after, so that an eviction that ran between the two cannot
        //   leave this copy uncounted.
        // Without the first count nothing is written: an uncounted copy
        // could outlive the cap. The bytes are verified either way, so
        // the read itself succeeds.
        let count = || self.catalog.record_cache_fill(&extent.id, self.clock.now());
        if count().await.is_ok() {
            let key = extent.id.cache_key();
            self.cache.put(&key, cipher.clone(), &meta).await?;
            let _ = count().await;
        }
        Ok(ColdFetch::Filled(cipher))
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
