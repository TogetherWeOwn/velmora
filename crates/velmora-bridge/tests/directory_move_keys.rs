//! The move's key steps (AM-16, AM-31) and the P2 lines (AM-22, AM-25):
//! the direct key apply's guards, step 9's revoked-key check, the
//! give-up's revocations on the thawed D1, and the preflight counts.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use service_support::*;
use velmora_bridge::directory::move_keys::{
    apply_owner_keys, assert_revoked_closed, revocation_sweep, revocations_to_d1, KeyStepError,
    KeyUnit, OwnerKeys,
};
use velmora_bridge::directory::move_preflight::p2_lines;
use velmora_bridge::unit::keys::{Applied, KeyEntry, KeyKind, SubjectStatus, MAX_ENTRIES};
use velmora_bridge::*;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn entry(id: &str, status: SubjectStatus, seq: u64) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::S3,
        status,
        held: false,
        made_by: Some("PRowner".into()),
        grants: vec![],
        created_at: 1,
        secret_wrapped: (status == SubjectStatus::Active).then(|| vec![2; 40]),
        secret_kek_version: Some(1),
        owner_ref: None,
        last_seq: seq,
        rid: None,
    }
}

#[derive(Default)]
struct Keys {
    chain: RefCell<Vec<KeyEntry>>,
    /// The chain answers fewer records than its head (damage).
    short: Cell<bool>,
    flat: RefCell<BTreeSet<String>>,
    tenant: RefCell<BTreeSet<String>>,
    /// Flat revocations are listed in pages of this many.
    page: Cell<usize>,
}

impl OwnerKeys for Keys {
    async fn head(&self) -> Result<u64> {
        Ok(self.chain.borrow().len() as u64 + u64::from(self.short.get()))
    }
    async fn entries(&self, after: u64, limit: usize) -> Result<Vec<KeyEntry>> {
        Ok(self
            .chain
            .borrow()
            .iter()
            .skip(after as usize)
            .take(limit)
            .cloned()
            .collect())
    }
    async fn flat_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.flat.borrow().contains(akid))
    }
    async fn tenant_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.tenant.borrow().contains(akid))
    }
    async fn put_tenant_revocation(&self, akid: &str) -> Result<()> {
        self.tenant.borrow_mut().insert(akid.into());
        Ok(())
    }
    async fn revoke(&self, akid: &str) -> Result<()> {
        let seq = self.chain.borrow().len() as u64 + 1;
        self.chain
            .borrow_mut()
            .push(entry(akid, SubjectStatus::Revoked, seq));
        Ok(())
    }
    async fn revoke_grants(&self, _buckets: &[String]) -> Result<()> {
        Ok(())
    }
    async fn flat_revocations(&self, after: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        let page = self.page.get().max(1);
        let ids: Vec<String> = self
            .flat
            .borrow()
            .iter()
            .filter(|id| after.is_none_or(|a| id.as_str() > a))
            .take(page)
            .cloned()
            .collect();
        let next = (ids.len() == page).then(|| ids.last().unwrap().clone());
        Ok((ids, next))
    }
}

#[derive(Default)]
struct Unit {
    keys_seq: Cell<u64>,
    rows: RefCell<BTreeMap<String, SubjectStatus>>,
    /// The unit lost its key rows (a restore): the first apply above its
    /// seq answers `behind`.
    calls: RefCell<Vec<(u64, usize)>>,
}

impl KeyUnit for Unit {
    async fn apply_keys(&self, from_seq: u64, entries: &[KeyEntry]) -> Result<Applied> {
        self.calls.borrow_mut().push((from_seq, entries.len()));
        if from_seq > self.keys_seq.get() {
            return Ok(Applied::Behind {
                keys_seq: self.keys_seq.get(),
            });
        }
        for e in entries {
            if e.last_seq > self.keys_seq.get() {
                self.rows.borrow_mut().insert(e.id.clone(), e.status);
            }
        }
        let last = entries.last().map_or(0, |e| e.last_seq);
        self.keys_seq.set(self.keys_seq.get().max(last));
        Ok(Applied::Done {
            keys_seq: self.keys_seq.get(),
            applied: entries.len() as u64,
            skipped: 0,
            reserved: 0,
            kept: 0,
        })
    }
    async fn key_active(&self, akid: &str) -> Result<bool> {
        Ok(self.rows.borrow().get(akid) == Some(&SubjectStatus::Active))
    }
}

fn chain_of(n: u64) -> Keys {
    let k = Keys::default();
    for seq in 1..=n {
        k.chain.borrow_mut().push(entry(
            &format!("AKMOVE{seq:014}"),
            SubjectStatus::Active,
            seq,
        ));
    }
    k
}

#[test]
fn the_key_apply_sends_the_whole_chain_in_pages() {
    block_on(async {
        let n = MAX_ENTRIES as u64 * 2 + 7;
        let keys = chain_of(n);
        let unit = Unit::default();
        assert_eq!(apply_owner_keys(&keys, &unit).await.unwrap(), n);
        assert_eq!(unit.rows.borrow().len() as u64, n);
        assert_eq!(
            *unit.calls.borrow(),
            [
                (0, MAX_ENTRIES),
                (MAX_ENTRIES as u64, MAX_ENTRIES),
                (2 * MAX_ENTRIES as u64, 7)
            ]
        );
        // Again: nothing new, the unit skips what it has.
        assert_eq!(apply_owner_keys(&keys, &unit).await.unwrap(), n);
        // An empty chain sends nothing.
        let none = Keys::default();
        let fresh = Unit::default();
        assert_eq!(apply_owner_keys(&none, &fresh).await.unwrap(), 0);
        assert!(fresh.calls.borrow().is_empty());
    });
}

#[test]
fn the_key_apply_refuses_held_entries_and_a_short_chain() {
    block_on(async {
        let keys = chain_of(3);
        keys.chain.borrow_mut()[1].held = true;
        let unit = Unit::default();
        let r = apply_owner_keys(&keys, &unit).await;
        assert!(matches!(r, Err(KeyStepError::HeldEntry(_))), "{r:?}");
        assert!(unit.calls.borrow().is_empty());
        let keys = chain_of(3);
        keys.short.set(true);
        let r = apply_owner_keys(&keys, &unit).await;
        assert!(matches!(r, Err(KeyStepError::Diverged)), "{r:?}");
    });
}

#[test]
fn the_sweep_revokes_flat_revocations_and_step_9_checks_them() {
    block_on(async {
        let keys = chain_of(2);
        let moved: Vec<String> = keys.chain.borrow().iter().map(|e| e.id.clone()).collect();
        let unit = Unit::default();
        apply_owner_keys(&keys, &unit).await.unwrap();
        // A tenant-0 revoke during the window left a flat revocation.
        keys.flat.borrow_mut().insert(moved[0].clone());
        // Before the sweep, step 9's check finds the key active.
        let r = assert_revoked_closed(&keys, &unit, &moved).await;
        assert!(matches!(&r, Err(KeyStepError::RevokedActive(k)) if *k == moved[0]));
        let swept = revocation_sweep(&keys, &unit, &moved).await.unwrap();
        assert_eq!(swept, vec![moved[0].clone()]);
        assert!(keys.tenant.borrow().contains(&moved[0]));
        assert_eq!(unit.rows.borrow()[&moved[0]], SubjectStatus::Revoked);
        assert_eq!(unit.rows.borrow()[&moved[1]], SubjectStatus::Active);
        assert_revoked_closed(&keys, &unit, &moved).await.unwrap();
        // The owner's revocation alone also counts at step 9.
        keys.tenant.borrow_mut().insert(moved[1].clone());
        let r = assert_revoked_closed(&keys, &unit, &moved).await;
        assert!(matches!(&r, Err(KeyStepError::RevokedActive(k)) if *k == moved[1]));
    });
}

#[test]
fn the_give_up_disables_every_revoked_key_on_the_thawed_d1() {
    block_on(async {
        let rig = rig();
        let (vault, _) = rig.standard("vault").await;
        for akid in [
            "AKMOVE00000000000001",
            "AKMOVE00000000000002",
            "AKDROP00000000000003",
        ] {
            rig.key(akid, secret(), KeyStatus::Active).await;
            rig.grant(akid, &vault, Perm::Rw).await;
        }
        let keys = Keys::default();
        keys.page.set(1);
        // A flat revocation (a drop key, a tenant-0 revoke), and a moved
        // key revoked under the owner's name only.
        keys.flat.borrow_mut().insert("AKDROP00000000000003".into());
        keys.flat.borrow_mut().insert("not a key id".into());
        keys.tenant
            .borrow_mut()
            .insert("AKMOVE00000000000002".into());
        let moved = vec![
            "AKMOVE00000000000001".to_string(),
            "AKMOVE00000000000002".to_string(),
        ];
        let sql = &rig.bridge.catalog.sql;
        let done = revocations_to_d1(sql, &keys, &moved).await.unwrap();
        assert_eq!(done, ["AKDROP00000000000003", "AKMOVE00000000000002"]);
        let status = |akid: &str| {
            let rows = velmora_bridge::unit::object::poll_once(sql.query(
                "SELECT status, (SELECT count(*) FROM grants WHERE access_key_id = ?1) \
                 FROM access_keys WHERE access_key_id = ?1",
                &[SqlValue::Text(akid.into())],
            ))
            .unwrap()
            .unwrap();
            rows[0].clone()
        };
        let disabled = vec![SqlValue::Text("disabled".into()), SqlValue::Int(0)];
        assert_eq!(status("AKDROP00000000000003"), disabled);
        assert_eq!(status("AKMOVE00000000000002"), disabled);
        assert_eq!(
            status("AKMOVE00000000000001"),
            vec![SqlValue::Text("active".into()), SqlValue::Int(1)]
        );
        // Idempotent.
        revocations_to_d1(sql, &keys, &moved).await.unwrap();
        assert_eq!(status("AKDROP00000000000003"), disabled);
    });
}

#[test]
fn p2_counts_bucket_ids_and_integer_cells_that_stop_the_move() {
    block_on(async {
        let rig = rig();
        let (_, signer) = rig.standard("vault").await;
        for i in 0..5 {
            rig.put(&signer, "vault", &format!("k{i}"), &pattern(i, 100))
                .await
                .expect(200);
        }
        let sql = &rig.bridge.catalog.sql;
        let excluded = BTreeSet::from(["b_00000000000000ee".to_string()]);
        let clean = p2_lines(sql, &excluded, 2).await.unwrap();
        assert!(!clean.stops(), "{clean:?}");
        assert_eq!(clean.nonconforming_count, 0);
        assert_eq!(clean.excluded, excluded);
        assert!(clean
            .cells
            .iter()
            .any(|c| c.table == "extents" && c.column == "cipher_size"));
        assert!(clean
            .cells
            .iter()
            .all(|c| c.real_whole + c.real_other + c.int_unsafe == 0));
        // A fraction, a REAL past 2^63, and an integer past 2^53 - 1 (also
        // its negative) stop the move. A whole REAL in range cannot stay
        // REAL in an INTEGER column (SQLite's affinity stores it as an
        // integer), so it is never counted here.
        sql.inner
            .apply(
                "UPDATE generations SET size = 100.0 WHERE rowid = (SELECT min(rowid) FROM generations);\n\
                 UPDATE extents SET seq = 1.0e19 WHERE rowid = (SELECT min(rowid) FROM extents);\n\
                 UPDATE generations SET created_at = 1.5 WHERE rowid = (SELECT max(rowid) FROM generations);\n\
                 UPDATE extents SET cipher_size = 9007199254740992 WHERE rowid = (SELECT min(rowid) FROM extents);\n\
                 UPDATE extents SET plain_size = -9223372036854775808 WHERE rowid = (SELECT max(rowid) FROM extents);\n\
                 INSERT INTO buckets (id, name, owner, bdk_wrapped, kek_version, disposable, created_at) \
                 SELECT 'vault-old', 'old', owner, bdk_wrapped, kek_version, disposable, created_at FROM buckets LIMIT 1;",
            )
            .unwrap();
        let lines = p2_lines(sql, &excluded, 2).await.unwrap();
        assert!(lines.stops());
        assert_eq!(lines.nonconforming_count, 1);
        assert_eq!(lines.nonconforming_ids, ["vault-old"]);
        let cell = |t: &str, c: &str| {
            lines
                .cells
                .iter()
                .find(|l| l.table == t && l.column == c)
                .unwrap()
                .clone()
        };
        assert_eq!(cell("generations", "size").real_whole, 0);
        assert_eq!(cell("generations", "size").real_other, 0);
        assert_eq!(cell("extents", "seq").real_other, 1);
        assert_eq!(cell("generations", "created_at").real_other, 1);
        assert_eq!(cell("generations", "created_at").samples.len(), 1);
        assert_eq!(cell("extents", "cipher_size").int_unsafe, 1);
        assert_eq!(cell("extents", "plain_size").int_unsafe, 1);
        // The receipt line serializes.
        let json = serde_json::to_string(&lines).unwrap();
        assert!(json.contains("vault-old"));
    });
}

#[test]
fn p2_records_an_unreadable_key_or_bucket_id_as_a_stop_line() {
    block_on(async {
        let rig = rig();
        let (_, signer) = rig.standard("vault").await;
        rig.put(&signer, "vault", "k", &pattern(1, 100))
            .await
            .expect(200);
        let sql = &rig.bridge.catalog.sql;
        sql.inner
            .apply(
                "INSERT INTO usage_hours (hour, posts, verifies, releases, dead, failures) \
                 VALUES (5, 0, 0, 0, 0, 0), (1152921504606846976, 0, 0, 0, 0, 0);\n\
                 INSERT INTO buckets (id, name, owner, bdk_wrapped, kek_version, disposable, created_at) \
                 SELECT NULL, 'nullid', owner, bdk_wrapped, kek_version, disposable, created_at FROM buckets LIMIT 1;",
            )
            .unwrap();
        let lines = p2_lines(sql, &BTreeSet::new(), 1).await.unwrap();
        assert!(lines.stops());
        assert_eq!(lines.nonconforming_count, 1);
        assert!(lines.nonconforming_ids[0].starts_with("<null at rowid"));
        let hour = lines
            .cells
            .iter()
            .find(|l| l.table == "usage_hours" && l.column == "hour")
            .unwrap();
        assert_eq!(hour.int_unsafe, 1);
        assert_eq!(hour.samples.len(), 1);
        // Both scans stopped there and say so; every later table was read.
        assert_eq!(lines.unreadable_keys, ["buckets", "usage_hours"]);
        assert!(lines.cells.iter().any(|l| l.table == "usage_recounts"));
    });
}

/// A key lane that answers one record per page still finishes.
#[test]
fn the_key_apply_finishes_with_short_pages() {
    struct Short(Keys);
    impl OwnerKeys for Short {
        async fn head(&self) -> Result<u64> {
            self.0.head().await
        }
        async fn entries(&self, after: u64, _limit: usize) -> Result<Vec<KeyEntry>> {
            self.0.entries(after, 1).await
        }
        async fn flat_revoked(&self, a: &str) -> Result<bool> {
            self.0.flat_revoked(a).await
        }
        async fn tenant_revoked(&self, a: &str) -> Result<bool> {
            self.0.tenant_revoked(a).await
        }
        async fn put_tenant_revocation(&self, a: &str) -> Result<()> {
            self.0.put_tenant_revocation(a).await
        }
        async fn revoke(&self, a: &str) -> Result<()> {
            self.0.revoke(a).await
        }
        async fn revoke_grants(&self, b: &[String]) -> Result<()> {
            self.0.revoke_grants(b).await
        }
        async fn flat_revocations(
            &self,
            after: Option<&str>,
        ) -> Result<(Vec<String>, Option<String>)> {
            self.0.flat_revocations(after).await
        }
    }
    block_on(async {
        let keys = Short(chain_of(150));
        let unit = Unit::default();
        assert_eq!(apply_owner_keys(&keys, &unit).await.unwrap(), 150);
        assert_eq!(unit.calls.borrow().len(), 150);
    });
}
