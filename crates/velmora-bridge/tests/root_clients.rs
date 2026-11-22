//! The composition root's unit clients (package L6-5b, AM-71): the key
//! feed a unit's `sync` reads (entries in head state, marker items in
//! place, openings held until the directory has them, fail closed with no
//! key locations), the key chain's finisher (`apply_control(tenant,
//! keys)`, never inline), one renewal state per isolate, and the router's
//! clients reaching the routed unit's object with the head's numbers.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::config::Maintenance;
use velmora_bridge::crypto::scheme2::{
    tk_blob_name, wrap_secret_v2, wrap_tenant_key, TenantId, TenantKey,
};
use velmora_bridge::directory::chain::Written;
use velmora_bridge::directory::record::{Tenant, TenantDoor};
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::jobmsg::ControlIntent;
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::ports::ApplyEntry as ChainItem;
use velmora_bridge::keys::record::{
    key_chain, seal_key_record, seal_marker_record, Access, Entry, Grant, KeyOp, Marker, OneKey,
    Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::tenant_revocation_prefix;
use velmora_bridge::keys::tk::KeyBuckets;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::root::{unit_item, ControlSend, Root, RootCache, RootPorts, UnitPorts};
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::types::{BridgeError, Result};
use velmora_bridge::unit::keys::{ApplyEntry as UnitItem, KeyMarker, MarkerKind};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, Unit, UnitAnswer, UnitCall, UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::Synced;
use velmora_bridge::unit_lease::client::{KeyFeed, KeyFinisher, UnitReplies};
use velmora_bridge::unit_router::{RequestClients, Routed, UnitRouter};
use velmora_bridge::UnixMs;
use velmora_bridge::{Sql, SqlValue};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const T1: &str = "t_00000000000000a1";

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn id() -> TenantId {
    TenantId::parse(T1).unwrap()
}

fn unit_id() -> velmora_bridge::unit::TenantId {
    velmora_bridge::unit::TenantId::parse(T1).unwrap()
}

fn key() -> TenantKey {
    TenantKey::from_bytes(&id(), 1, derived("tenant key 1")).unwrap()
}

/// What the fake unit object saw, and answers.
#[derive(Default)]
struct Objects {
    calls: RefCell<Vec<UnitCall>>,
}

struct Object {
    seen: Rc<Objects>,
    name: UnitName,
    /// The real unit, when the ports have one: it answers instead.
    real: Option<Rc<Unit<RusqliteSql>>>,
}

impl UnitReplies for Object {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        assert_eq!(call.name, self.name, "a client calls its own unit");
        if let Some(unit) = &self.real {
            self.seen.calls.borrow_mut().push(call.clone());
            return Ok(unit.reply(call, NOW));
        }
        self.seen.calls.borrow_mut().push(call.clone());
        Ok(UnitReply {
            answer: UnitAnswer::Ok {
                seqs: call.seqs.unwrap_or(Seqs {
                    state_seq: 0,
                    keys_seq: 0,
                }),
                body: serde_json::json!({ "pong": true }),
            },
            lease_left_ms: 600_000,
            revoked: Some(0),
        })
    }
}

/// The control intents sent.
#[derive(Default)]
struct Control {
    sent: RefCell<Vec<String>>,
    fail: bool,
}

impl ControlSend for Control {
    async fn send_control(&self, intent: &ControlIntent) -> Result<()> {
        if self.fail {
            return Err(BridgeError::Queue("send failed".into()));
        }
        self.sent.borrow_mut().push(intent.message().to_json());
        Ok(())
    }
}

struct Ports {
    records: Rc<MemRecords>,
    keys_a: MemRecords,
    keys_b: MemRecords,
    kek: TestKek,
    directory: Option<RusqliteSql>,
    clock: FixedClock,
    objects: Rc<Objects>,
    safety: MemBlobStore,
    control: Control,
    unit: Option<Rc<Unit<RusqliteSql>>>,
}

impl RootPorts for Ports {
    type Records = MemRecords;
    type KeyStore = MemRecords;
    type Kek = TestKek;
    type Sql = RusqliteSql;
    type Clock = FixedClock;

    fn records(&self) -> &MemRecords {
        &self.records
    }
    fn key_buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![("KEYS_A", &self.keys_a), ("KEYS_B", &self.keys_b)],
        }
    }
    fn kek(&self) -> &TestKek {
        &self.kek
    }
    fn directory(&self) -> Option<&RusqliteSql> {
        self.directory.as_ref()
    }
    fn clock(&self) -> &FixedClock {
        &self.clock
    }
}

impl UnitPorts for Ports {
    type Object = Object;
    type Safety = MemBlobStore;
    type Control = Control;

    fn object(&self, name: &UnitName) -> Result<Object> {
        Ok(Object {
            seen: self.objects.clone(),
            name: name.clone(),
            real: self.unit.clone(),
        })
    }
    fn safety(&self) -> &MemBlobStore {
        &self.safety
    }
    fn control(&self) -> &Control {
        &self.control
    }
}

fn directory_db() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0002_tenant_events.sql"
    ))
    .unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0003_pending_chains_and_caps.sql"
    ))
    .unwrap();
    db
}

/// Ports over `records`, with tenant key 1 in both key buckets.
fn ports(records: Rc<MemRecords>, directory: Option<RusqliteSql>) -> Ports {
    let ports = Ports {
        records,
        keys_a: MemRecords::default(),
        keys_b: MemRecords::default(),
        kek: TestKek::new(),
        directory,
        clock: FixedClock::new(NOW),
        objects: Rc::default(),
        safety: MemBlobStore::default(),
        control: Control::default(),
        unit: None,
    };
    let (kek_v, blob) = wrap_tenant_key(&ports.kek, &key(), &mut TestRng(7)).unwrap();
    let name = tk_blob_name(&id(), 1, kek_v);
    for store in [&ports.keys_a, &ports.keys_b] {
        assert!(block_on(store.put_if_absent(&name, blob.clone())).unwrap());
    }
    ports
}

async fn wrote(root: &Root<'_, Ports, TestRng>, change: Change) {
    let w = root
        .chain()
        .write(
            &Tenant::Managed(id()),
            &change,
            Actor::TenantCreation,
            NOW,
            0,
        )
        .await;
    assert!(matches!(w, Ok(Written::Wrote(_))), "{change:?}: {w:?}");
}

/// A tenant made active under key 1, with the key locations recorded
/// when `locations`.
fn active_records(locations: bool) -> Rc<MemRecords> {
    let records = Rc::new(MemRecords::default());
    // The commit's writer needs the key locations: without `locations`
    // the chain is written through a copy that has them, and only the
    // chain is kept.
    let written = match locations {
        true => records.clone(),
        false => Rc::new(MemRecords::default()),
    };
    let p = ports(written.clone(), None);
    block_on(async {
        assert!(
            write_locations(&*written, &p.kek, &two_in_account(), &mut TestRng(1))
                .await
                .unwrap()
        );
        make_active(&p).await;
        if !locations {
            for name in written.list("m/t/", "m/t/", 1000).await.unwrap() {
                let bytes = written.get(&name).await.unwrap().unwrap();
                records.plant(&name, bytes);
            }
        }
    });
    records
}

async fn make_active(p: &Ports) {
    let cache = RootCache::new();
    let root = Root::new(p, &cache, TestRng(2));
    wrote(
        &root,
        Change::Create {
            jurisdiction: "us".into(),
            location_hint: None,
            synthetic: false,
            limits: BTreeMap::new(),
            rate_json: Default::default(),
            features_json: Default::default(),
        },
    )
    .await;
    wrote(&root, Change::ClaimKeyVersion { version: 1 }).await;
    root.load_key(&id(), 1, key().check_value()).await.unwrap();
    wrote(
        &root,
        Change::CommitKeyVersion {
            version: 1,
            kcv: key().check_value(),
        },
    )
    .await;
    wrote(
        &root,
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
    )
    .await;
}

fn principal(id: &str) -> Subject {
    let mut s = Subject {
        door: SubjectDoor {
            id: id.to_owned(),
            kind: SubjectKind::Principal,
            status: SubjectStatus::Active,
            made_by: None,
            grants: Vec::new(),
            created_at: 1_000,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some(format!("member-of-{id}")),
            label: Some("a label".into()),
            grants: Vec::new(),
            secret_wrapped: None,
        },
    };
    s.set_grants(&[Grant {
        bucket_id: "b_00000000000000b1".into(),
        access: Access::Rw,
        expires_at: Some(9_000),
        prefix: Some("photos/".into()),
        ip_list: vec!["10.0.0.0/8".into()],
    }]);
    s
}

/// Plants key-chain record `seq` for `subject`.
fn plant(records: &MemRecords, seq: u64, op: KeyOp, subject: &Subject, closes: bool) {
    let bytes = seal_key_record(
        &TestKek::new(),
        &OneKey(key()),
        &id(),
        seq,
        op,
        10 + seq,
        &subject.door,
        Some(&subject.private),
        closes,
        None,
        &mut TestRng(100 + seq),
    )
    .unwrap();
    records.plant(&key_chain(&id()).name(seq), bytes);
}

fn plant_marker(records: &MemRecords, seq: u64, marker: Marker) {
    let bytes = seal_marker_record(
        &TestKek::new(),
        &OneKey(key()),
        &id(),
        seq,
        10 + seq,
        marker,
        &mut TestRng(100 + seq),
    )
    .unwrap();
    records.plant(&key_chain(&id()).name(seq), bytes);
}

/// The chain: PR0001 created (1), PR0002 created (2), frozen (3), thawed
/// (4), PR0001 disabled (5).
fn key_chain_records(records: &MemRecords) {
    let one = principal("PR0001");
    plant(records, 1, KeyOp::Create, &one, false);
    plant(records, 2, KeyOp::Create, &principal("PR0002"), false);
    plant_marker(records, 3, Marker::KeysFrozen);
    plant_marker(records, 4, Marker::KeysThawed { ends: 2 });
    let mut off = one.clone();
    off.door.status = SubjectStatus::Disabled;
    plant(records, 5, KeyOp::Status, &off, true);
}

fn keys(items: &[UnitItem]) -> Vec<(u64, Option<(&str, bool)>)> {
    items
        .iter()
        .map(|i| match i {
            UnitItem::Marker(m) => (m.seq, None),
            UnitItem::Key(e) => (e.last_seq, Some((e.id.as_str(), e.held))),
        })
        .collect()
}

fn entry_of(items: &[UnitItem], seq: u64) -> &velmora_bridge::unit::keys::KeyEntry {
    items
        .iter()
        .find_map(|i| match i {
            UnitItem::Key(e) if e.last_seq == seq => Some(e),
            _ => None,
        })
        .unwrap()
}

#[test]
fn the_feed_answers_every_record_after_the_unit_in_head_state_with_markers_in_place() {
    let records = active_records(true);
    key_chain_records(&records);
    let p = ports(records, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let batch = block_on(root.key_feed().after(&unit_id(), 0)).unwrap();
    assert_eq!(batch.head, 5);
    assert!(batch.answers.is_empty());
    // No directory bound: nothing to wait for, nothing held.
    assert_eq!(
        keys(&batch.entries),
        vec![
            (1, Some(("PR0001", false))),
            (2, Some(("PR0002", false))),
            (3, None),
            (4, None),
            (5, Some(("PR0001", false))),
        ]
    );
    // The markers keep their kind (a thaw's `ends` is not on the wire).
    assert_eq!(
        batch.entries[2],
        UnitItem::Marker(KeyMarker {
            marker: MarkerKind::KeysFrozen,
            seq: 3
        })
    );
    assert_eq!(
        batch.entries[3],
        UnitItem::Marker(KeyMarker {
            marker: MarkerKind::KeysThawed,
            seq: 4
        })
    );
    // Head state (AM-62): PR0001's entry at seq 1 already says disabled.
    let first = entry_of(&batch.entries, 1);
    assert_eq!(
        first.status,
        velmora_bridge::unit::keys::SubjectStatus::Disabled
    );
    assert_eq!(first.owner_ref.as_deref(), Some("member-of-PR0001"));
    assert_eq!(first.grants.len(), 1);
    assert_eq!(first.grants[0].prefix.as_deref(), Some("photos/"));
    assert_eq!(first.grants[0].ip_list, vec!["10.0.0.0/8".to_string()]);
    assert_eq!(first.grants[0].expires_at, Some(9_000));
    // From the unit's own seq: only what follows it.
    let later = block_on(root.key_feed().after(&unit_id(), 3)).unwrap();
    assert_eq!(later.head, 5);
    assert_eq!(
        keys(&later.entries),
        vec![(4, None), (5, Some(("PR0001", false)))]
    );
    // At the head: nothing, and a seq above the chain is refused.
    let none = block_on(root.key_feed().after(&unit_id(), 5)).unwrap();
    assert_eq!((none.head, none.entries.len()), (5, 0));
    assert!(block_on(root.key_feed().after(&unit_id(), 6)).is_err());
}

#[test]
fn the_feed_pages_past_one_apply() {
    let records = active_records(true);
    for seq in 1..=230 {
        plant(
            &records,
            seq,
            KeyOp::Create,
            &principal(&format!("PR{seq:04}")),
            false,
        );
    }
    let p = ports(records, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let batch = block_on(root.key_feed().after(&unit_id(), 7)).unwrap();
    assert_eq!(batch.head, 230);
    let seqs: Vec<u64> = batch.entries.iter().map(UnitItem::seq).collect();
    assert_eq!(seqs, (8..=230).collect::<Vec<_>>());
}

#[test]
fn with_a_directory_an_opening_it_has_not_acknowledged_is_held() {
    let records = active_records(true);
    key_chain_records(&records);
    let p = ports(records, Some(directory_db()));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    // No row yet: nothing acknowledged, every opening held.
    let batch = block_on(root.key_feed().after(&unit_id(), 0)).unwrap();
    assert_eq!(
        keys(&batch.entries),
        vec![
            (1, Some(("PR0001", true))),
            (2, Some(("PR0002", true))),
            (3, None),
            (4, None),
            (5, Some(("PR0001", true))),
        ]
    );
    // A held entry keeps its identity (AM-72) and carries no secret, no
    // KEK version, no label and no grant limit; its grants' buckets and
    // access stay.
    let held = entry_of(&batch.entries, 2);
    assert!(held.held);
    assert_eq!(held.owner_ref.as_deref(), Some("member-of-PR0002"));
    assert_eq!(held.secret_wrapped, None);
    assert_eq!(held.secret_kek_version, None);
    assert_eq!(held.grants[0].prefix, None);
    assert!(held.grants[0].ip_list.is_empty());
    assert_eq!(held.grants[0].bucket_id, "b_00000000000000b1");
    // The directory acknowledges seq 1: PR0001 (opened at 1) is sent
    // open, PR0002 (opened at 2) stays held.
    let dir = SqlDirectory {
        sql: p.directory.as_ref().unwrap(),
    };
    let door: TenantDoor = block_on(root.heads().head(&Tenant::Managed(id()), 0))
        .unwrap()
        .unwrap()
        .door;
    block_on(dir.apply_tenant(&door, NOW)).unwrap();
    assert!(block_on(dir.raise_keys_seq(&Tenant::Managed(id()), 1)).unwrap());
    let batch = block_on(root.key_feed().after(&unit_id(), 0)).unwrap();
    assert_eq!(
        keys(&batch.entries),
        vec![
            (1, Some(("PR0001", false))),
            (2, Some(("PR0002", true))),
            (3, None),
            (4, None),
            (5, Some(("PR0001", false))),
        ]
    );
}

#[test]
fn a_revocation_in_force_is_sent_as_revoked_and_never_held() {
    let records = active_records(true);
    key_chain_records(&records);
    // PR0002 revoked in m/rk/ only (the chain does not record it yet).
    records.plant(
        &format!("{}PR0002", tenant_revocation_prefix(&id())),
        b"r".to_vec(),
    );
    let p = ports(records, Some(directory_db()));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let batch = block_on(root.key_feed().after(&unit_id(), 1)).unwrap();
    let two = entry_of(&batch.entries, 2);
    assert_eq!(
        two.status,
        velmora_bridge::unit::keys::SubjectStatus::Revoked
    );
}

#[test]
fn the_feed_fails_closed_without_key_locations_but_an_empty_chain_reads_no_key() {
    let records = active_records(false);
    let p = ports(records.clone(), None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    // No key record: nothing to load, the batch is empty.
    let batch = block_on(root.key_feed().after(&unit_id(), 0)).unwrap();
    assert_eq!((batch.head, batch.entries.len()), (0, 0));
    // A record and no key locations: refused, never sent without its key.
    key_chain_records(&records);
    assert!(block_on(root.key_feed().after(&unit_id(), 0)).is_err());
    // Tenant 0 has no key feed here.
    let zero = velmora_bridge::unit::TenantId::parse(
        velmora_bridge::TenantScope::tenant_zero().tenant_id(),
    )
    .unwrap();
    assert!(block_on(root.key_feed().after(&zero, 0)).is_err());
}

/// The unit learns an opening only from the directory's acknowledgement,
/// never from its own seq: a subject opened at or below the unit's
/// `keys_seq` but not acknowledged is sent held in a later record.
#[test]
fn an_opening_below_the_units_seq_is_held_until_the_directory_has_it() {
    let records = active_records(true);
    key_chain_records(&records);
    // PR0002 narrowed at 6 (a closing change): its opening stays seq 2.
    let mut narrowed = principal("PR0002");
    narrowed.set_grants(&[Grant {
        bucket_id: "b_00000000000000b1".into(),
        access: Access::Ro,
        expires_at: Some(9_000),
        prefix: Some("photos/".into()),
        ip_list: vec!["10.0.0.0/8".into()],
    }]);
    plant(&records, 6, KeyOp::Grants, &narrowed, true);
    let p = ports(records, Some(directory_db()));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    // The unit holds up to 5 (PR0002 held there); nothing acknowledged.
    let batch = block_on(root.key_feed().after(&unit_id(), 5)).unwrap();
    assert_eq!(keys(&batch.entries), vec![(6, Some(("PR0002", true)))]);
}

/// A directory that cannot be read acknowledges nothing and opens
/// nothing: the feed fails, and the unit's `sync` is retried, rather than
/// holding keys the unit may hold open.
#[test]
fn a_failed_directory_read_fails_the_feed() {
    let records = active_records(true);
    key_chain_records(&records);
    // A database with no directory schema: every read of it fails.
    let p = ports(records, Some(RusqliteSql::open_in_memory().unwrap()));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    assert!(block_on(root.key_feed().after(&unit_id(), 0)).is_err());
    // Nothing after the unit: no read at all, so no failure.
    let none = block_on(root.key_feed().after(&unit_id(), 5)).unwrap();
    assert_eq!((none.head, none.entries.len()), (5, 0));
}

#[test]
fn held_items_keep_their_owner_and_lose_their_private_part() {
    let s = principal("PR0003");
    let open = Entry {
        door: s.door.clone(),
        private: Some(s.private.clone()),
        last_seq: 4,
        private_seq: 4,
        tk_version: 1,
        closes: false,
        opened_seq: 4,
        rid: None,
    };
    let UnitItem::Key(sent) = unit_item(&ChainItem::Subject(open.clone())).unwrap() else {
        panic!()
    };
    assert!(!sent.held);
    assert_eq!(sent.owner_ref.as_deref(), Some("member-of-PR0003"));
    let mut closed = open.clone();
    closed.private = None;
    let UnitItem::Key(unopened) = unit_item(&ChainItem::Subject(closed.clone())).unwrap() else {
        panic!()
    };
    assert!(unopened.held);
    assert_eq!(unopened.owner_ref, None);
    let UnitItem::Key(held) = unit_item(&ChainItem::Held {
        entry: closed,
        owner_ref: Some("member-of-PR0003".into()),
    })
    .unwrap() else {
        panic!()
    };
    assert!(held.held);
    assert_eq!(held.owner_ref.as_deref(), Some("member-of-PR0003"));
    assert_eq!(held.secret_wrapped, None);
    assert_eq!(held.secret_kek_version, None);
    assert_eq!(held.grants[0].prefix, None);
    assert!(held.grants[0].ip_list.is_empty());
    // A held item that still carried its private part sends none of it.
    let UnitItem::Key(stripped) = unit_item(&ChainItem::Held {
        entry: open,
        owner_ref: None,
    })
    .unwrap() else {
        panic!()
    };
    assert!(stripped.held);
    assert_eq!(stripped.owner_ref, None);
    assert_eq!(stripped.grants[0].prefix, None);
}

#[test]
fn an_entry_whose_parts_name_other_buckets_is_damage() {
    let s = principal("PR0001");
    let mut private = s.private.clone();
    private.grants[0].bucket_id = "b_00000000000000b2".into();
    let e = Entry {
        door: s.door.clone(),
        private: Some(private),
        last_seq: 1,
        private_seq: 1,
        tk_version: 1,
        closes: false,
        opened_seq: 1,
        rid: None,
    };
    assert!(unit_item(&ChainItem::Subject(e.clone())).is_err());
    let mut fewer = e;
    fewer.private.as_mut().unwrap().grants.clear();
    assert!(unit_item(&ChainItem::Subject(fewer)).is_err());
}

#[test]
fn the_finisher_enqueues_apply_control_for_the_key_chain() {
    let records = active_records(true);
    let p = ports(records, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let client = root
        .unit_client(&UnitName::new(unit_id(), 0), true)
        .unwrap();
    block_on(client.finisher.revocations_unrecorded(&unit_id())).unwrap();
    assert_eq!(
        p.control.sent.borrow().as_slice(),
        [format!(
            r#"{{"t":"apply_control","v":2,"tenant":"{T1}","chain":"keys","seq":0}}"#
        )]
    );
    // Never a message for tenant 0; a failed send is the caller's error.
    let zero = velmora_bridge::unit::TenantId::parse(
        velmora_bridge::TenantScope::tenant_zero().tenant_id(),
    )
    .unwrap();
    assert!(block_on(client.finisher.revocations_unrecorded(&zero)).is_err());
    let mut failing = ports(Rc::new(MemRecords::default()), None);
    failing.control.fail = true;
    let cache = RootCache::new();
    let root = Root::new(&failing, &cache, TestRng(3));
    let client = root
        .unit_client(&UnitName::new(unit_id(), 0), true)
        .unwrap();
    assert!(block_on(client.finisher.revocations_unrecorded(&unit_id())).is_err());
}

#[test]
fn every_client_of_an_isolate_shares_one_renewal_state() {
    let p = ports(Rc::new(MemRecords::default()), None);
    let name = UnitName::new(unit_id(), 0);
    let cache = RootCache::new();
    // One root per invocation, the cache per isolate.
    let first = Root::new(&p, &cache, TestRng(3));
    let a = first.unit_client(&name, true).unwrap();
    let guard = a.flights.begin(&name).expect("no renewal runs yet");
    let second = Root::new(&p, &cache, TestRng(4));
    let b = second.unit_client(&name, false).unwrap();
    assert!(
        b.flights.begin(&name).is_none(),
        "the isolate's renewal runs"
    );
    assert!(!b.listed && a.listed);
    // Another isolate has its own.
    let other = RootCache::new();
    let third = Root::new(&p, &other, TestRng(5));
    let c = third.unit_client(&name, true).unwrap();
    assert!(c.flights.begin(&name).is_some());
    guard.done(true);
    assert!(b.flights.begin(&name).is_some());
}

#[test]
fn the_router_calls_the_routed_unit_with_the_heads_numbers() {
    let records = active_records(true);
    let p = ports(records, None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let clients = root.clients();
    let heads = root.heads();
    let router = root.router(Maintenance::Off, &clients, &heads);
    let floor = Seqs {
        state_seq: 0,
        keys_seq: 0,
    };
    let routed: Routed = block_on(router.route(&unit_id(), None, floor)).unwrap();
    assert_eq!(routed.unit, UnitName::new(unit_id(), 0));
    assert!(routed.listed);
    let (answered, pages) =
        block_on(router.call(&routed, CallKind::Request, true, UnitOp::Ping {}));
    assert!(pages.is_empty());
    let answered = answered.unwrap();
    assert!(matches!(answered.reply.answer, UnitAnswer::Ok { .. }));
    assert!(!answered.renew_due);
    let calls = p.objects.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, routed.unit);
    assert_eq!(calls[0].kind, CallKind::Request);
    assert_eq!(calls[0].seqs, Some(routed.seqs));
    assert!(calls[0].authenticated && calls[0].listed);
    // The clients are the root's: one per routed unit.
    assert!(clients.client(&routed).is_ok());
}

/// An S3 key of PR0002's (active), its secret wrapped for the tenant (scheme 2).
fn s3_key(akid: &str) -> Subject {
    let (version, wrapped) = wrap_secret_v2(
        &TestKek::new(),
        &id(),
        akid,
        format!("secret-of-{akid}").as_bytes(),
        &mut TestRng(900),
    )
    .unwrap();
    let mut s = principal(akid);
    s.door.kind = SubjectKind::S3;
    s.door.made_by = Some("PR0002".into());
    s.door.secret_kek_version = Some(version);
    s.private.owner_ref = None;
    s.private.secret_wrapped = Some(wrapped);
    s
}

/// A born root unit of the tenant, at the head's `state_seq`.
fn born_unit(state_seq: u64) -> Rc<Unit<RusqliteSql>> {
    let name = UnitName::new(unit_id(), 0);
    let unit = Unit::new(RusqliteSql::open_in_memory().unwrap(), name.clone(), "");
    let born = unit.handle(
        &UnitCall {
            name: name.clone(),
            kind: CallKind::Worker,
            seqs: Some(Seqs {
                state_seq,
                keys_seq: 0,
            }),
            authenticated: true,
            listed: true,
            op: UnitOp::Provision {
                token: BirthToken {
                    name,
                    jurisdiction: String::new(),
                    record_seq: state_seq,
                    schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                    key_scheme: 2,
                    kind: BirthKind::Birth,
                },
                sealed: vec![1],
            },
        },
        NOW,
    );
    assert!(matches!(born, UnitAnswer::Ok { .. }), "{born:?}");
    Rc::new(unit)
}

async fn no_born_marker(_: &TenantId, _: u32) -> Result<()> {
    panic!("held and bring_up do not write a born marker")
}

#[test]
fn tenant_held_reads_the_units_own_numbers_once_without_sync_or_renew() {
    let mut p = ports(active_records(true), None);
    p.unit = Some(born_unit(1));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let units = root.tenant_units(no_born_marker);
    let tenant = id();
    use velmora_bridge::directory::finish::{TenantUnits, UnitHolds};

    // The unit is behind the stored head. Read twice across independent
    // calls to prove the adapter neither syncs nor caches the first read.
    for count in 1..=2 {
        assert_eq!(
            block_on(units.held(&tenant, 0)).unwrap(),
            UnitHolds::Seq { state_seq: 1 },
        );
        let calls = p.objects.calls.borrow();
        assert_eq!(calls.len(), count);
        let call = &calls[count - 1];
        assert_eq!(call.name, UnitName::new(unit_id(), 0));
        assert_eq!(call.kind, CallKind::Request);
        assert_eq!(
            call.seqs,
            Some(Seqs {
                state_seq: 0,
                keys_seq: 0
            })
        );
        assert!(matches!(call.op, UnitOp::Ping {}));
        assert!(!call.authenticated);
    }
}

#[test]
fn tenant_bring_up_syncs_and_a_separate_marker_call_delegates() {
    use velmora_bridge::directory::finish::{TenantUnits, UnitHolds};
    let mut p = ports(active_records(true), None);
    p.unit = Some(born_unit(1));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let tenant = id();
    let marks = RefCell::new(Vec::new());
    let units = root.tenant_units(async |tenant: &TenantId, unit| {
        marks.borrow_mut().push((tenant.clone(), unit));
        Ok(())
    });
    block_on(async {
        let head = root
            .heads()
            .head(&Tenant::Managed(tenant.clone()), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            units.bring_up(&tenant, 0).await.unwrap(),
            UnitHolds::Seq {
                state_seq: head.door.seq
            }
        );
        assert!(marks.borrow().is_empty());
        units.mark_born(&tenant, 0).await.unwrap();
        assert_eq!(*marks.borrow(), [(tenant, 0)]);
    });
}

thread_local! {
    static CONTROL_ALERTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn capture_control_alerts() {
    CONTROL_ALERTS.with(|lines| lines.borrow_mut().clear());
    velmora_bridge::trace::log_alerts(|line| {
        CONTROL_ALERTS.with(|lines| lines.borrow_mut().push(line.into()));
    });
}

#[test]
fn bound_directory_key_target_writes_routes_and_drains_refusal_pages() {
    use velmora_bridge::directory::store::{KeyRoute, RouteKind, RoutePut};
    use velmora_bridge::keys::ports::{Applied, KeyTarget};
    let records = active_records(true);
    let first = s3_key("AKVL00000001");
    let second = s3_key("AKVL00000002");
    plant(&records, 1, KeyOp::Create, &first, false);
    plant(&records, 2, KeyOp::Create, &second, false);
    let p = ports(records, Some(directory_db()));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let tenant = id();
    let managed = Tenant::Managed(tenant.clone());
    let dir = root.directory().unwrap();
    let entry = |seq, s: Subject| {
        ChainItem::Subject(Entry {
            door: s.door,
            private: Some(s.private),
            last_seq: seq,
            private_seq: seq,
            tk_version: 1,
            closes: false,
            opened_seq: seq,
            rid: None,
        })
    };
    capture_control_alerts();
    block_on(async {
        let door = root.heads().head(&managed, 0).await.unwrap().unwrap().door;
        dir.apply_tenant(&door, NOW).await.unwrap();
        let ring = root.tenant_keys(&tenant).await.unwrap();
        let target = root.directory_key_target(&tenant, &ring);
        assert_eq!(target.keys_seq().await.unwrap(), 0);
        assert_eq!(
            target.apply(0, &[entry(1, first)]).await.unwrap(),
            Applied::Done { keys_seq: 1 }
        );
        assert_eq!(
            dir.route("AKVL00000001").await.unwrap().unwrap().tenant,
            managed
        );
        assert_eq!(
            dir.put_route(&KeyRoute {
                akid: second.door.id.clone(),
                tenant: managed,
                kind: RouteKind::Internal,
                owner_ref: None,
                created_at: NOW,
            })
            .await
            .unwrap(),
            RoutePut::Inserted
        );
        assert!(target.apply(1, &[entry(2, second)]).await.is_err());
        assert_eq!(target.keys_seq().await.unwrap(), 1);
        // No additional page from a later successful no-op.
        target.apply(1, &[]).await.unwrap();
    });
    CONTROL_ALERTS
        .with(|lines| assert_eq!(*lines.borrow(), ["key finisher (directory_route_conflict)"]));
}

#[test]
fn unbound_directory_key_target_acknowledges_without_reading_records() {
    use velmora_bridge::keys::ports::{Applied, KeyTarget};
    let p = ports(Rc::new(MemRecords::default()), None);
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let tenant = id();
    let ring = OneKey(key());
    let target = root.directory_key_target(&tenant, &ring);
    block_on(async {
        assert_eq!(target.keys_seq().await.unwrap(), u64::MAX);
        assert!(target.closed().await.unwrap().is_empty());
        assert_eq!(
            target
                .apply(
                    0,
                    &[ChainItem::Marker {
                        seq: 1,
                        marker: Marker::KeysFrozen
                    }]
                )
                .await
                .unwrap(),
            Applied::Done { keys_seq: u64::MAX }
        );
    });
}

#[test]
fn tenant_finish_pages_reach_the_alert_sink() {
    use velmora_bridge::directory::finish::{finish_tenant, StoreStep, TenantFinisher};
    use velmora_bridge::keys::ports::ControlChain;
    use velmora_bridge::pending::{ChainFinisher, ChainKey};
    let mut p = ports(active_records(true), Some(directory_db()));
    let tenant = id();
    p.unit = Some(Rc::new(Unit::new(
        RusqliteSql::open_in_memory().unwrap(),
        UnitName::new(unit_id(), 0),
        "",
    )));
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let units = root.tenant_units(no_born_marker);
    block_on(root.tenant_head(&tenant)).unwrap().unwrap();
    capture_control_alerts();
    let run = block_on(finish_tenant(
        &root.chain(),
        root.directory().as_ref(),
        &units,
        &tenant,
        NOW,
    ))
    .unwrap();
    assert_eq!(run.units, [(0, StoreStep::Unborn)]);
    assert_eq!(run.pages, ["unit_unborn"]);
    // Management callers own the pages of a full report. The head-only
    // finisher delivers them itself so the sweep does not lose them.
    CONTROL_ALERTS.with(|lines| assert!(lines.borrow().is_empty()));
    let finisher = TenantFinisher {
        chain: root.chain(),
        dir: root.directory(),
        units: &units,
        now: NOW,
    };
    let chain = ChainKey {
        tenant: tenant.clone(),
        chain: ControlChain::Tenant,
    };
    assert_eq!(block_on(finisher.finish(&chain)).unwrap(), run.head);
    // An unborn answer carries no numbers. A read-only held probe must
    // report a failure without falling into sync or renewal.
    use velmora_bridge::directory::finish::TenantUnits;
    let reads = p.objects.calls.borrow().len();
    assert!(block_on(units.held(&tenant, 0)).is_err());
    assert_eq!(p.objects.calls.borrow().len(), reads + 1);
    CONTROL_ALERTS.with(|lines| assert_eq!(*lines.borrow(), ["tenant finisher (unit_unborn)"]));
}

#[test]
fn tenant_finish_pages_a_damaged_row_even_when_the_head_read_fails() {
    use velmora_bridge::directory::finish::{finish_tenant, ERR_KEY_NOT_HELD};
    let p = ports(active_records(true), Some(directory_db()));
    let tenant = id();
    let cache = RootCache::new();
    let root = Root::new(&p, &cache, TestRng(3));
    let dir = root.directory().unwrap();
    let units = root.tenant_units(no_born_marker);
    capture_control_alerts();
    block_on(async {
        // A doors-only read can seed a directory row without loading the
        // key the real finisher will need for the private part of the head.
        let managed = Tenant::Managed(tenant.clone());
        let door = root.heads().head(&managed, 0).await.unwrap().unwrap().door;
        dir.apply_tenant(&door, NOW).await.unwrap();
        p.directory
            .as_ref()
            .unwrap()
            .exec(
                "UPDATE tenants SET door_json = '{}' WHERE id = ?1",
                &[SqlValue::Text(tenant.as_str().into())],
            )
            .await
            .unwrap();
        let err = finish_tenant(&root.chain(), Some(&dir), &units, &tenant, NOW)
            .await
            .unwrap_err();
        let BridgeError::Invalid(expected) = ERR_KEY_NOT_HELD else {
            unreachable!()
        };
        assert!(matches!(err, BridgeError::Invalid(actual) if actual == expected));
        assert!(p.objects.calls.borrow().is_empty());
    });
    CONTROL_ALERTS.with(|lines| {
        assert_eq!(
            *lines.borrow(),
            ["tenant finisher (directory_row_unreadable)"]
        )
    });
}

/// The unit's key rows: (id, held, status, has an owner, has a secret).
fn unit_rows(unit: &Unit<RusqliteSql>) -> Vec<(String, i64, String, bool, bool)> {
    let rows = block_on(unit.sql().query(
        "SELECT id, held, status, owner_ref IS NOT NULL, secret_wrapped IS NOT NULL \
         FROM unit_keys ORDER BY id",
        &[],
    ))
    .unwrap();
    rows.iter()
        .map(|r| {
            let text = |i: usize| match &r[i] {
                SqlValue::Text(t) => t.clone(),
                other => panic!("{other:?}"),
            };
            let int = |i: usize| match &r[i] {
                SqlValue::Int(n) => *n,
                other => panic!("{other:?}"),
            };
            (text(0), int(1), text(2), int(3) == 1, int(4) == 1)
        })
        .collect()
}

/// The feed's items, applied by a real unit through the unit client's
/// `sync`: every record to the head, markers and an S3 key included; with
/// no directory every subject opens, and with a directory that has
/// acknowledged nothing every opening is held, owners kept, secrets not
/// sent.
#[test]
fn a_real_unit_syncs_to_the_head_from_the_feed() {
    for with_directory in [false, true] {
        let records = active_records(true);
        key_chain_records(&records);
        plant(&records, 6, KeyOp::Create, &s3_key("AKVL00000001"), false);
        let mut p = ports(records, with_directory.then(directory_db));
        let cache = RootCache::new();
        let state_seq = {
            let root = Root::new(&p, &cache, TestRng(3));
            block_on(root.heads().head(&Tenant::Managed(id()), 0))
                .unwrap()
                .unwrap()
                .door
                .seq
        };
        let unit = born_unit(state_seq);
        p.unit = Some(unit.clone());
        let root = Root::new(&p, &cache, TestRng(4));
        let client = root
            .unit_client(&UnitName::new(unit_id(), 0), false)
            .unwrap();
        let synced = block_on(client.sync(Seqs {
            state_seq,
            keys_seq: 0,
        }))
        .unwrap();
        let Synced::Synced { seqs } = synced else {
            panic!("{synced:?}")
        };
        assert_eq!(seqs.keys_seq, 6, "{with_directory}");
        let held = i64::from(with_directory);
        assert_eq!(
            unit_rows(&unit),
            vec![
                (
                    "AKVL00000001".into(),
                    held,
                    "active".into(),
                    false,
                    !with_directory
                ),
                ("PR0001".into(), held, "disabled".into(), true, false),
                ("PR0002".into(), held, "active".into(), true, false),
            ],
            "{with_directory}"
        );
    }
}
