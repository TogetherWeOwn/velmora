//! The rollback stamp: how a catalogue that was restored to an earlier
//! point is found without trusting the catalogue.
//!
//! The catalogue holds a counter. The safety bucket holds one small
//! object per value the counter has reached, under
//! `rs/<catalogue id>/<counter>`. The objects are only ever put: no code
//! path deletes or overwrites one with another meaning, and
//! [`crate::ports::BlobStore::delete`] refuses the prefix. A restore of
//! the database takes the counter back and leaves the objects, so:
//!
//! - **rolled back** = an object exists after the one of the catalogue's
//!   counter (or any object exists while the catalogue has no counter).
//!   One list call of one key answers it, however many objects exist.
//!
//! Two rules keep the answer free of false alarms and of blind spots:
//!
//! - **The bucket is never ahead of the catalogue.** An object is put
//!   only for a value the catalogue has confirmed it holds.
//! - **Check before the counter moves.** Every raise reads the counter,
//!   runs the check against it, and only then moves it, with a
//!   compare-and-set from the value it checked. A raise on a rolled-back
//!   catalogue would otherwise bring the counter level with the newest
//!   object and hide the rollback for good.
//!
//! Who raises: the cron tick, once per run, and a write that must be
//! covered at once ([`Bridge::raise_stamp`]). A raise is safe at any
//! point; its place decides which rollbacks are found: one to any point
//! before it. After a confirmed commit and before the `200` it covers
//! that commit.
//!
//! Each object holds the time of its raise. The last step of a replay
//! reads the newest one: a catalogue that is behind an object raised
//! after that replay started was rolled back while the replay ran or
//! after it, and the replay does not hold what was written since. That
//! replay is not ended; a new one has to be started
//! ([`Bridge::stamp_level`]).
//!
//! The row keeps the catalogue id that its objects are keyed by. A
//! Worker that is configured with another id would list an empty
//! prefix and find no rollback, so every read of the row fails with
//! [`ERR_CATALOGUE_ID`] instead: no raise, no cron job, no delete by
//! garbage collection or eviction.
//!
//! What the stamp does not see: a commit that no raise followed before
//! the rollback (the handler was killed before its raise, or the raise
//! failed). The operations runbook lists both cases.
//!
//! # One algorithm for every catalogue
//!
//! [`Stamp`] is the algorithm. It takes the id its objects are keyed by
//! and the store of its counter ([`StampLedger`]) as arguments, so that
//! tenant 0's D1 (id `main`, the counter in the `rollback_stamp` table,
//! through [`Catalog`]) and a unit (id `<tenant>.<unit>`,
//! [`crate::unit_lease::UnitStampId`], the counter in the unit) run the
//! same rules (ADR-TENANCY §8.5). The methods on [`Bridge`] are tenant
//! 0's: they build a [`Stamp`] over the catalogue and the configured
//! `CATALOGUE_ID`.

// No `Send` bound is intended (see `ports`).
#![allow(async_fn_in_trait)]

use sha2::{Digest, Sha256};

use crate::ports::{BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{BridgeError, BucketId, ExtentId, Result, UnixMs};

/// Every stamp object lives under this prefix of the safety bucket.
pub const STAMP_PREFIX: &str = "rs/";

/// What a raise answers on a catalogue that is behind its stamp.
pub const ERR_ROLLED_BACK: BridgeError =
    BridgeError::Invalid("the catalogue is behind its rollback stamp");

/// The catalogue's stamp row was created under another catalogue id
/// than the one this Worker is configured with.
pub const ERR_CATALOGUE_ID: BridgeError = BridgeError::Invalid(CATALOGUE_ID);
const CATALOGUE_ID: &str =
    "CATALOGUE_ID is not the id this catalogue's rollback stamp was raised under";

/// Whether `e` is [`ERR_CATALOGUE_ID`].
pub fn is_catalogue_id_error(e: &BridgeError) -> bool {
    matches!(e, BridgeError::Invalid(text) if *text == CATALOGUE_ID)
}

/// Every round found the counter moved by another raise.
const MOVING: &str = "the rollback stamp counter kept moving";
const ERR_STAMP_KEY: BridgeError = BridgeError::Invalid("a rollback stamp key is malformed");
const ERR_STAMP_BODY: BridgeError = BridgeError::Invalid("a rollback stamp object is malformed");

/// Rounds of read, check and compare-and-set before a raise gives up.
/// A round is lost only to another raise that moved the counter.
const ADVANCE_ATTEMPTS: usize = 5;
/// Puts of the stamp object before a raise gives up.
const PUT_ATTEMPTS: usize = 3;
/// Keys per list call when the newest stamp is looked for.
const TOP_PAGE: u32 = 1000;

/// The stamp row of the catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StampRow {
    /// `None` = no row: the counter was never raised on this database.
    pub counter: Option<u64>,
    /// A rollback was found and no replay has ended since.
    pub rolled_back: bool,
}

/// What one raise came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advance {
    /// The check passed and the counter was moved to this value.
    Raised(u64),
    /// The check passed; another raise moved the counter up first.
    Checked,
    /// The catalogue is behind its stamp (now recorded).
    RolledBack,
}

/// Whether `key` names a stamp object.
pub fn is_stamp_key(key: &str) -> bool {
    key.starts_with(STAMP_PREFIX)
}

fn stamp_dir(catalogue: &str) -> String {
    format!("{STAMP_PREFIX}{catalogue}/")
}

/// The key of the stamp object for `counter`. Fixed width, so that key
/// order is counter order.
pub fn stamp_key(catalogue: &str, counter: u64) -> String {
    format!("{STAMP_PREFIX}{catalogue}/{counter:020}")
}

fn counter_of(dir: &str, key: &str) -> Result<u64> {
    key.strip_prefix(dir)
        .filter(|n| n.len() == 20 && n.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|n| n.parse().ok())
        .ok_or(ERR_STAMP_KEY)
}

/// Where a catalogue keeps its stamp counter: tenant 0's D1 through
/// [`Catalog`] ([`CatalogLedger`]), or a unit. `id` is the id the caller
/// keys the stamp objects by; the store keeps the id its row was created
/// with and fails every call with [`ERR_CATALOGUE_ID`] when the two
/// differ.
pub trait StampLedger {
    /// The stamp row.
    async fn stamp(&self, id: &str) -> Result<StampRow>;
    /// Moves the counter from `from` to the next value (`None` = creates
    /// the row at 1). `false` = the counter is not at `from`, or a
    /// rollback is recorded: nothing changed.
    async fn stamp_advance(&self, from: Option<u64>, id: &str) -> Result<bool>;
    /// Records that the catalogue was found behind its stamp, if its
    /// counter is still `seen` and no rollback is on record. `false` =
    /// nothing was recorded; the caller reads again.
    async fn stamp_rolled_back(&self, seen: Option<u64>, now: UnixMs, id: &str) -> Result<bool>;
}

/// Tenant 0's counter: the `rollback_stamp` table of the catalogue.
pub struct CatalogLedger<'a, C: Catalog>(pub &'a C);

impl<C: Catalog> StampLedger for CatalogLedger<'_, C> {
    async fn stamp(&self, id: &str) -> Result<StampRow> {
        self.0.stamp(id).await
    }
    async fn stamp_advance(&self, from: Option<u64>, id: &str) -> Result<bool> {
        self.0.stamp_advance(from, id).await
    }
    async fn stamp_rolled_back(&self, seen: Option<u64>, now: UnixMs, id: &str) -> Result<bool> {
        self.0.stamp_rolled_back(seen, now, id).await
    }
}

/// The stamp of one catalogue: its counter store, the safety bucket its
/// objects are in, a clock, and the id they are keyed by. See the
/// [module](self).
pub struct Stamp<'a, L: StampLedger, B: BlobStore, T: Clock> {
    pub ledger: L,
    pub safety: &'a B,
    pub clock: &'a T,
    pub id: &'a str,
}

impl<L: StampLedger, B: BlobStore, T: Clock> Stamp<'_, L, B, T> {
    /// The stamp row. Fails if it was created under another id: see the
    /// module text.
    pub async fn row(&self) -> Result<StampRow> {
        self.ledger.stamp(self.id).await
    }

    /// Whether a stamp object exists after the one of `counter`.
    pub async fn ahead(&self, counter: Option<u64>) -> Result<bool> {
        let dir = stamp_dir(self.id);
        let after = match counter {
            Some(c) => stamp_key(self.id, c),
            None => dir.clone(),
        };
        Ok(!self.safety.list(&dir, &after, 1).await?.is_empty())
    }

    /// Whether the catalogue was restored to an earlier point and no
    /// replay of the recovery records has ended since. One counter read
    /// and one list call of the safety bucket. A rollback that is found
    /// is recorded in the counter store.
    ///
    /// `Err` = the check could not be made. A caller that would delete
    /// something treats that like `true`.
    pub async fn rolled_back(&self) -> Result<bool> {
        Ok(self.checked().await?.is_none())
    }

    /// [`Self::rolled_back`], with what it compared: `Some` = not rolled
    /// back, and no stamp object exists after the one of the counter in
    /// it (`Some(None)` = no stamp row and no stamp object). A batch that
    /// acts on this answer holds the catalogue to that counter: a
    /// database restored after the check is below it.
    pub async fn checked(&self) -> Result<Option<Option<u64>>> {
        for _ in 0..ADVANCE_ATTEMPTS {
            let row = self.row().await?;
            if row.rolled_back {
                return Ok(None);
            }
            if !self.ahead(row.counter).await? {
                return Ok(Some(row.counter));
            }
            if self.behind(row.counter).await? {
                return Ok(None);
            }
        }
        Err(BridgeError::Invalid(MOVING))
    }

    /// An object was seen after the one of `seen`. Records the rollback
    /// if the counter still is `seen`. `false` = it is not: a raise ran
    /// between the read of the counter and the list call, and the
    /// object may be its own. Nothing is known then; the caller reads
    /// again.
    ///
    /// With the counter unchanged the object proves a rollback: an
    /// object is put only after the counter reached its value, and the
    /// counter of a catalogue that was not restored never moves down.
    async fn behind(&self, seen: Option<u64>) -> Result<bool> {
        self.ledger
            .stamp_rolled_back(seen, self.clock.now(), self.id)
            .await
    }

    /// Checks, then moves the counter by one.
    ///
    /// `must_raise`: the caller needs the object of a new value, so a
    /// round that another raise won is run again. Without it that round
    /// ends the call with [`Advance::Checked`]: the check was made, and
    /// the other raise moved the counter.
    pub async fn advance(&self, must_raise: bool) -> Result<Advance> {
        let mut last = BridgeError::Invalid(MOVING);
        for _ in 0..ADVANCE_ATTEMPTS {
            let row = match self.row().await {
                Ok(row) => row,
                // No other round would read anything else.
                Err(e) if is_catalogue_id_error(&e) => return Err(e),
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            if row.rolled_back {
                return Ok(Advance::RolledBack);
            }
            // Never without the check: see the module text.
            if self.ahead(row.counter).await? {
                if self.behind(row.counter).await? {
                    return Ok(Advance::RolledBack);
                }
                continue;
            }
            // An answer that was lost may have moved the counter. The
            // next round starts from what the catalogue holds then; a
            // value without an object is harmless.
            match self.ledger.stamp_advance(row.counter, self.id).await {
                Ok(true) => return Ok(Advance::Raised(row.counter.map_or(1, |c| c + 1))),
                Ok(false) if must_raise => {}
                // The row says what the round was lost to. A recorded
                // rollback; another raise, which moved the counter up;
                // or a restore of the database between the check and
                // here, which did not: the next round's check finds it.
                Ok(false) => {
                    let now = self.row().await?;
                    if now.rolled_back {
                        return Ok(Advance::RolledBack);
                    }
                    if now.counter > row.counter {
                        return Ok(Advance::Checked);
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Puts the object of a value the catalogue holds.
    pub async fn store(&self, counter: u64) -> Result<()> {
        let key = stamp_key(self.id, counter);
        // The body is the time of the raise: read by the last step of
        // a replay, and by the operator who looks for the restore point.
        let body = self.clock.now().0.to_string().into_bytes();
        let sha: [u8; 32] = Sha256::digest(&body).into();
        let bucket = BucketId::new("-");
        let meta = BlobMeta {
            bucket: &bucket,
            extent: &ExtentId::new("rollback-stamp"),
            cipher_sha256: &sha,
        };
        let mut last = Ok(());
        for _ in 0..PUT_ATTEMPTS {
            last = self.safety.put(&key, body.clone(), &meta).await;
            if last.is_ok() {
                break;
            }
        }
        last
    }

    /// Raises the stamp: checks, moves the counter by compare-and-set,
    /// then puts the object of the new value. See
    /// [`Bridge::raise_stamp`] for where a raise is placed.
    ///
    /// `Err` undoes nothing. [`ERR_ROLLED_BACK`] = the catalogue is
    /// behind its stamp (now recorded). Any other error = the stamp was
    /// not raised after several tries.
    pub async fn raise(&self) -> Result<()> {
        match self.advance(true).await? {
            Advance::Raised(counter) => self.store(counter).await,
            // Not reached with `must_raise`.
            Advance::Checked => Err(BridgeError::Invalid(MOVING)),
            Advance::RolledBack => Err(ERR_ROLLED_BACK),
        }
    }

    /// When the stamp object of `counter` was raised.
    async fn time(&self, counter: u64) -> Result<UnixMs> {
        let key = stamp_key(self.id, counter);
        let body = self.safety.get(&key, None).await?.ok_or(ERR_STAMP_BODY)?;
        std::str::from_utf8(&body)
            .ok()
            .and_then(|text| text.parse().ok())
            .map(UnixMs)
            .ok_or(ERR_STAMP_BODY)
    }

    /// For the last step of the replay that was started at `run`: the
    /// value its end brings the counter level with, and the counter it
    /// was chosen from. `None` = that replay must not be ended: see
    /// [`Bridge::stamp_level`].
    pub async fn level(&self, run: UnixMs) -> Result<Option<(u64, Option<u64>)>> {
        for _ in 0..ADVANCE_ATTEMPTS {
            let row = self.row().await?;
            let top = self.top(row.counter).await?;
            // Not behind: nothing to tell from the times. A replay that
            // has ended and whose last step is sent again is here.
            if top <= row.counter.unwrap_or(0) || self.time(top).await? <= run {
                return Ok(Some((top, row.counter)));
            }
            // `false` = a raise ran since the row was read, and the
            // newest object may be its own: read again.
            if row.rolled_back || self.behind(row.counter).await? {
                return Ok(None);
            }
        }
        Err(BridgeError::Invalid(MOVING))
    }

    /// The counter of the newest stamp object, `0` when there is none.
    /// Reads on from `counter` (the catalogue's), so that the number of
    /// list calls follows the raises since the restore point, not the
    /// age of the bucket.
    async fn top(&self, counter: Option<u64>) -> Result<u64> {
        let dir = stamp_dir(self.id);
        let mut top = 0;
        let mut after = match counter {
            // The object of the counter itself may be the newest one.
            Some(c) if c > 0 => stamp_key(self.id, c - 1),
            _ => dir.clone(),
        };
        loop {
            let page = self.safety.list(&dir, &after, TOP_PAGE).await?;
            let Some(last) = page.last() else {
                return Ok(top);
            };
            top = counter_of(&dir, last)?;
            if (page.len() as u64) < u64::from(TOP_PAGE) {
                return Ok(top);
            }
            after = last.clone();
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
    /// Tenant 0's stamp: the catalogue's counter and the configured
    /// `CATALOGUE_ID`.
    fn stamp(&self) -> Stamp<'_, CatalogLedger<'_, C>, B, T> {
        Stamp {
            ledger: CatalogLedger(&self.catalog),
            safety: &self.safety,
            clock: &self.clock,
            id: &self.cfg.catalogue_id,
        }
    }

    /// The stamp row. Fails if it was created under another catalogue
    /// id: see the module text.
    pub(crate) async fn stamp_row(&self) -> Result<StampRow> {
        self.stamp().row().await
    }

    /// Whether the catalogue was restored to an earlier point and no
    /// replay of the recovery records has ended since. One catalogue
    /// read and one list call of the safety bucket. A rollback that is
    /// found is recorded in the catalogue: from then on every write gate
    /// and every job refuses on the catalogue alone.
    ///
    /// `Err` = the check could not be made. A caller that would delete
    /// something treats that like `true`.
    pub async fn catalogue_rolled_back(&self) -> Result<bool> {
        self.stamp().rolled_back().await
    }

    /// [`Self::catalogue_rolled_back`], with what it compared: see
    /// [`Stamp::checked`].
    pub(crate) async fn stamp_checked(&self) -> Result<Option<Option<u64>>> {
        self.stamp().checked().await
    }

    /// Checks, then moves the counter by one: see [`Stamp::advance`].
    pub(crate) async fn stamp_advance(&self, must_raise: bool) -> Result<Advance> {
        self.stamp().advance(must_raise).await
    }

    /// Puts the object of a value the catalogue holds.
    pub(crate) async fn stamp_store(&self, counter: u64) -> Result<()> {
        self.stamp().store(counter).await
    }

    /// Raises the stamp: checks, moves the counter by compare-and-set,
    /// then puts the object of the new value.
    ///
    /// A raise is safe at any point of a request, before or after a
    /// commit and whatever the outcome of that commit: it depends on
    /// nothing but the counter, and the bucket is never ahead of the
    /// catalogue. Where it is placed decides only which rollbacks are
    /// found: one to any point before the raise. So a raise after a
    /// confirmed commit and before the `200` covers that commit, and a
    /// raise before a commit covers what was written up to there, not
    /// the commit.
    ///
    /// `Err` undoes nothing. [`ERR_ROLLED_BACK`] = the catalogue is
    /// behind its stamp (now recorded; writes are refused from here on).
    /// Any other error = the stamp was not raised after several tries:
    /// what the raise was to cover is covered by the next raise (at the
    /// latest the next cron tick). A caller that needs the cover before
    /// it goes on fails its request; a caller whose write is committed
    /// still answers `200`.
    pub async fn raise_stamp(&self) -> Result<()> {
        self.stamp().raise().await
    }

    /// For the last step of the replay that was started at `run`: the
    /// value its end brings the counter level with. `None` = that
    /// replay must not be ended, and the rollback is on record: the
    /// catalogue is behind a stamp object that was raised after the
    /// replay started. A raise is made only while no replay is under
    /// way and the catalogue is not behind, so the catalogue was rolled
    /// back after that raise, to a point where this replay still ran (or
    /// had ended), and the replay does not hold what was written between
    /// its end and the raise.
    ///
    /// Refuses in one harmless case too: a raise that was already under
    /// way when the replay was started. Its object is later than the
    /// start, and a new replay is asked for.
    ///
    /// With the value comes the counter it was chosen from, for
    /// [`Catalog::restore_finish`] to hold the catalogue to.
    pub(crate) async fn stamp_level(&self, run: UnixMs) -> Result<Option<(u64, Option<u64>)>> {
        self.stamp().level(run).await
    }
}
