//! NNTP reads: permit-scoped provider sessions, the checked article read
//! shared by verify, release and cold reads, and the cold read itself.
//!
//! Every NNTP path holds a provider connection slot before it opens a
//! socket ("no permit, no socket"). Every article is read with one `BODY`,
//! decoded, and compared with the SHA-256 stored in its plan row before
//! anything uses its bytes.

use velmora::transport::is_article_limit_error;
use velmora::yenc::decode_part_to;

use crate::articles::article_spans;
use crate::ports::{
    BlobMeta, BlobStore, BodyOutcome, Bridge, Catalog, Clock, JobSink, Kek, Lease, NntpConnector,
    NntpSession, Permit, PermitClass,
};
use crate::post::{sha256, Stop};
use crate::types::{ArticleRow, BridgeError, ExtentRow, FailClass, ProviderConfig, Result};

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
}

impl<'a, C: Catalog, N: NntpConnector, T: Clock> ProviderSession<'a, C, N, T> {
    /// Takes a slot for `provider`. `None` = every slot of this class is
    /// held: the caller backs off without opening a socket.
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
        }))
    }

    /// Renews the job's lease (if it has one) and then the permit. Call it
    /// before every article and before every reconnect: no POST, read or
    /// new socket happens on a lease or a slot that now belongs to someone
    /// else. On a lost permit the socket is dropped at once.
    pub(crate) async fn keep(&mut self, lease: Option<&Lease>) -> core::result::Result<(), Stop> {
        let now = self.clock.now();
        if let Some(lease) = lease {
            if !self.catalog.renew(lease, now).await? {
                return Err(Stop::Fenced);
            }
        }
        match self.catalog.renew_permit(&self.permit, now).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.session = None;
                Err(Stop::NoPermit)
            }
            Err(e) => {
                self.session = None;
                Err(e.into())
            }
        }
    }

    /// The live session, connecting first when there is none. A provider
    /// that refuses the connection with `502` ("too many connections") is
    /// reported as "no slot".
    pub(crate) async fn session(&mut self) -> core::result::Result<&mut N::Session, Stop> {
        if self.session.is_none() {
            let session = match self.nntp.connect(self.provider, &self.permit).await {
                Ok(session) => session,
                Err(BridgeError::Nntp(velmora::Error::NoPermission(_))) => {
                    return Err(Stop::NoPermit);
                }
                Err(e) => return Err(Stop::Session(e)),
            };
            self.session = Some(session);
        }
        self.session.as_mut().ok_or(Stop::fail(FailClass::Internal))
    }

    /// Drops the session without reuse or `QUIT` (after any session error).
    pub(crate) fn discard(&mut self) {
        self.session = None;
    }

    /// Ends the session and frees the slot. The release is fenced by the
    /// permit token, so a holder that lost its slot frees nothing.
    pub(crate) async fn close(mut self) {
        if let Some(session) = self.session.take() {
            session.quit().await;
        }
        // A failed release is safe: the permit expires on its own.
        let _ = self.catalog.release_permit(&self.permit).await;
    }
}

/// Reconnects one pass over a provider may spend on broken sessions.
pub(crate) const MAX_READ_RECONNECTS: u32 = 2;

/// What one pass over a set of articles found. Indexes are `ArticleRow::idx`.
#[derive(Debug, Default)]
pub(crate) struct ReadTally {
    /// Articles whose decoded payload matched the stored SHA-256.
    pub(crate) ok: u32,
    /// Still `430` after the in-pass retry.
    pub(crate) missing: Vec<u32>,
    /// Present, but not the planned bytes.
    pub(crate) corrupt: Vec<u32>,
}

enum Checked {
    Good(Vec<u8>),
    Missing,
    Corrupt,
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

/// One `BODY`, checked. A `430` leaves the session in use. Any session
/// error drops the session and resumes at the same message-id on a new
/// one, while `reconnects` lasts; the lease and the permit are renewed
/// before each reconnect.
async fn read_one<C: Catalog, N: NntpConnector, T: Clock>(
    session: &mut ProviderSession<'_, C, N, T>,
    lease: Option<&Lease>,
    row: &ArticleRow,
    wire: &mut Vec<u8>,
    reconnects: &mut u32,
) -> core::result::Result<Checked, Stop> {
    loop {
        wire.clear();
        let result = match session.session().await {
            Ok(s) => s.body(&row.message_id, wire).await,
            Err(Stop::Session(e)) => Err(e),
            Err(stop) => return Err(stop),
        };
        let err = match result {
            Ok(BodyOutcome::Found) => return Ok(check_payload(row, wire)),
            Ok(BodyOutcome::Missing) => return Ok(Checked::Missing),
            Err(e) => e,
        };
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
            match read_one(session, lease, row, &mut wire, &mut reconnects).await? {
                Checked::Good(payload) => {
                    tally.ok += 1;
                    sink(row, payload);
                }
                Checked::Corrupt => tally.corrupt.push(row.idx),
                Checked::Missing if pass == 0 => retry.push(row),
                Checked::Missing => tally.missing.push(row.idx),
            }
        }
    }
    Ok(tally)
}

/// Result of a cold read of one extent from Usenet.
#[derive(Debug, PartialEq, Eq)]
pub enum ColdFetch {
    /// The complete, verified ciphertext. It is already in the cache.
    Filled(Vec<u8>),
    /// A provider that could still hold missing articles had no free
    /// connection slot or failed in transit: retry shortly.
    Busy,
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
    /// has it. Each article is read from the first `read` provider that
    /// serves it intact. The assembled extent is checked against
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
        let holder = format!("get:{}", extent.id);
        for provider in self.cfg.providers.iter().filter(|p| p.read) {
            let wanted: Vec<&ArticleRow> = plan.iter().filter(|a| !have[a.idx as usize]).collect();
            if wanted.is_empty() {
                break;
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
            else {
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
                Ok(_) => {}
                // The read broke off: this provider may still have the rest.
                Err(Stop::NoPermit | Stop::Fail(..) | Stop::Session(_)) => busy = true,
                Err(Stop::Fenced | Stop::Catalog) => {
                    return Err(BridgeError::Sql(
                        "catalogue failed during a cold read".into(),
                    ));
                }
            }
        }
        if have.contains(&false) {
            return Ok(if busy {
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
        self.cache
            .put(&extent.id.cache_key(), cipher.clone(), &meta)
            .await?;
        Ok(ColdFetch::Filled(cipher))
    }
}
