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
//! covered at once ([`Bridge::raise_stamp`]: after its commit is
//! confirmed, before it answers `200`).
//!
//! What the stamp does not see: a commit that no raise followed before
//! the rollback (the handler was killed before its raise, or the raise
//! failed). The operations runbook lists both cases.

use sha2::{Digest, Sha256};

use crate::ports::{BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::types::{BridgeError, BucketId, ExtentId, Result};

/// Every stamp object lives under this prefix of the safety bucket.
pub const STAMP_PREFIX: &str = "rs/";

/// What a raise answers on a catalogue that is behind its stamp.
pub const ERR_ROLLED_BACK: BridgeError =
    BridgeError::Invalid("the catalogue is behind its rollback stamp");

const ERR_STAMP_KEY: BridgeError = BridgeError::Invalid("a rollback stamp key is malformed");

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

impl<C, B, N, J, K, T> Bridge<C, B, N, J, K, T>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    /// Whether a stamp object exists after the one of `counter`.
    async fn stamp_ahead(&self, counter: Option<u64>) -> Result<bool> {
        let dir = stamp_dir(&self.cfg.catalogue_id);
        let after = match counter {
            Some(c) => stamp_key(&self.cfg.catalogue_id, c),
            None => dir.clone(),
        };
        Ok(!self.safety.list(&dir, &after, 1).await?.is_empty())
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
        let row = self.catalog.stamp().await?;
        if row.rolled_back {
            return Ok(true);
        }
        if self.stamp_ahead(row.counter).await? {
            self.catalog.stamp_rolled_back(self.clock.now()).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Checks, then moves the counter by one. `None` = rolled back (and
    /// recorded); the counter was not moved.
    pub(crate) async fn stamp_advance(&self) -> Result<Option<u64>> {
        let mut last = BridgeError::Invalid("the rollback stamp counter kept moving");
        for _ in 0..ADVANCE_ATTEMPTS {
            let row = match self.catalog.stamp().await {
                Ok(row) => row,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            if row.rolled_back {
                return Ok(None);
            }
            // Never without the check: see the module text.
            if self.stamp_ahead(row.counter).await? {
                self.catalog.stamp_rolled_back(self.clock.now()).await?;
                return Ok(None);
            }
            // An answer that was lost may have moved the counter. The
            // next round starts from what the catalogue holds then; a
            // value without an object is harmless.
            match self.catalog.stamp_advance(row.counter).await {
                Ok(true) => return Ok(Some(row.counter.map_or(1, |c| c + 1))),
                Ok(false) => {}
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Puts the object of a value the catalogue holds.
    pub(crate) async fn stamp_store(&self, counter: u64) -> Result<()> {
        let key = stamp_key(&self.cfg.catalogue_id, counter);
        // The body is the time of the raise, for the operator who looks
        // for the restore point. Nothing reads it.
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

    /// Raises the stamp for a write that was just committed. Call it
    /// after the commit is confirmed and before the `200`: a rollback to
    /// any point before that commit is then found.
    ///
    /// Never call it for a commit whose outcome is unknown, and never
    /// before the commit.
    ///
    /// `Err` does not undo the write, which is committed: the caller
    /// still answers `200`. [`ERR_ROLLED_BACK`] = the catalogue is
    /// behind its stamp (now recorded; writes are refused from here on).
    /// Any other error = the stamp was not raised after
    /// several tries; the next raise (at the latest the next cron tick)
    /// covers this write too.
    pub async fn raise_stamp(&self) -> Result<()> {
        match self.stamp_advance().await? {
            Some(counter) => self.stamp_store(counter).await,
            None => Err(ERR_ROLLED_BACK),
        }
    }

    /// The counter of the newest stamp object, `0` when there is none.
    /// Reads on from the catalogue's counter, so that the number of list
    /// calls follows the raises since the restore point, not the age of
    /// the bucket.
    pub(crate) async fn stamp_top(&self) -> Result<u64> {
        let dir = stamp_dir(&self.cfg.catalogue_id);
        let row = self.catalog.stamp().await?;
        let mut top = 0;
        let mut after = match row.counter {
            // The object of the counter itself may be the newest one.
            Some(c) if c > 0 => stamp_key(&self.cfg.catalogue_id, c - 1),
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
