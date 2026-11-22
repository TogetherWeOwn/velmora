use velmora_bridge::directory::chain::{record_key, TenantChain, Written};
use velmora_bridge::directory::gate::{
    admitted, chain_tenants, close, compare_tenants, is_open, pending_level, rebuild_tenants,
    run_gate, ClosingCall, Difference, GateSteps, ManagementCall, NotBuilt, PendingLevel,
    StepReport, PENDING_ALARM_MS, PENDING_PAGE_MS,
};
use velmora_bridge::directory::record::{
    DeletionReason, HoldMode, Lifecycle, OperatorReason, Placement, Restoring, TenantDoor,
    TenantId, TenantState,
};
use velmora_bridge::directory::store::{
    Applied, ChainKind, GateState, KeyRoute, PendingOp, RouteKind, RoutePut, SqlDirectory, UnitRow,
};
use velmora_bridge::directory::testing::{MemRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{Result, UnixMs};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;
const FAR_FUTURE: UnixMs = UnixMs(NOW.0 + 30 * DAY);
const A1: &str = "t_00000000000000a1";
const B2: &str = "t_00000000000000b2";
const D4: &str = "t_00000000000000d4";
const ROOT_UNIT: UnitRow = UnitRow {
    unit: 0,
    restoring_since: None,
};

type Chain<'a> = TenantChain<'a, MemRecords, PlainSeal>;
type Directory<'a> = SqlDirectory<'a, RusqliteSql>;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn database() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    db
}

async fn write(
    chain: &Chain<'_>,
    tenant: &TenantId,
    change: Change,
    actor: Actor,
    now: UnixMs,
    known: u64,
) -> TenantDoor {
    match chain
        .write(tenant, &change, actor, now, known)
        .await
        .unwrap()
    {
        Written::Wrote(record) => record.door,
        Written::Unchanged(_) => panic!("{change:?} did not write a record"),
    }
}

async fn active(chain: &Chain<'_>, tenant: &TenantId) {
    let mut known = 0;
    for change in [
        Change::Create {
            jurisdiction: "us".into(),
            location_hint: None,
            synthetic: false,
            limits: Default::default(),
            rate_json: Default::default(),
            features_json: Default::default(),
        },
        Change::ClaimKeyVersion { version: 1 },
        Change::CommitKeyVersion {
            version: 1,
            kcv: [1; KEY_CHECK_LEN],
        },
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
    ] {
        known = write(chain, tenant, change, Actor::TenantCreation, NOW, known)
            .await
            .seq;
    }
}

async fn head(chain: &Chain<'_>, tenant: &TenantId) -> TenantDoor {
    chain.head(tenant, 0).await.unwrap().unwrap().door
}

fn two_units(base_seq: u64) -> Change {
    Change::SetUnits {
        base_seq,
        units: vec![0, 1],
        placements: vec![Placement {
            bucket: "b_1".into(),
            unit: 1,
            epoch: 1,
        }],
    }
}

async fn billing_hold(
    chain: &Chain<'_>,
    tenant: &TenantId,
    mode: Option<HoldMode>,
    known: u64,
) -> TenantDoor {
    write(
        chain,
        tenant,
        Change::SetBillingHold { mode },
        Actor::Billing,
        NOW,
        known,
    )
    .await
}

async fn create_zero(chain: &Chain<'_>, tenant: &TenantId) -> TenantDoor {
    write(
        chain,
        tenant,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
        NOW,
        0,
    )
    .await
}

async fn populate_directory(chain: &Chain<'_>, dir: &Directory<'_>) -> [TenantId; 3] {
    let a = TenantId::parse(A1).unwrap();
    let b = TenantId::parse(B2).unwrap();
    let zero = TenantId::zero();
    active(chain, &a).await;
    billing_hold(chain, &a, Some(HoldMode::ReadOnly), 4).await;
    active(chain, &b).await;
    let expanded = write(chain, &b, two_units(4), Actor::Operator, NOW, 4).await;
    write(
        chain,
        &b,
        Change::SetRestoring { unit: 1 },
        Actor::Operator,
        NOW,
        expanded.seq,
    )
    .await;
    create_zero(chain, &zero).await;
    for tenant in [&a, &b, &zero] {
        assert_eq!(
            dir.apply_tenant(&head(chain, tenant).await, NOW)
                .await
                .unwrap(),
            Applied::Applied
        );
    }
    [a, b, zero]
}

fn pending(tenant: TenantId) -> PendingOp {
    PendingOp {
        tenant,
        chain: ChainKind::Tenant,
        seq: 5,
        kind: "set_billing_hold".into(),
        created_at: NOW,
    }
}

#[test]
fn applying_a_tenant_copies_its_head() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        let head = chain.head(&t, 0).await.unwrap().unwrap();

        assert_eq!(
            dir.apply_tenant(&head.door, NOW).await.unwrap(),
            Applied::Applied
        );
        let row = dir.tenant(&t).await.unwrap().unwrap();
        assert_eq!(row.record_seq, 4);
        assert_eq!(row.door, head.door);
        assert_eq!(dir.units(&t).await.unwrap(), [ROOT_UNIT]);
    });
}

#[test]
fn an_older_head_never_replaces_a_newer_one() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        let current = head(&chain, &t).await;
        let older = chain.read(&t, 3).await.unwrap().unwrap().door;

        assert_eq!(
            dir.apply_tenant(&current, NOW).await.unwrap(),
            Applied::Applied
        );
        assert_eq!(
            dir.apply_tenant(&older, NOW).await.unwrap(),
            Applied::NotNewer
        );
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().record_seq, 4);
        assert_eq!(
            dir.apply_tenant(&current, NOW).await.unwrap(),
            Applied::NotNewer
        );
    });
}

#[test]
fn unit_rows_follow_the_head() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        assert_eq!(
            dir.apply_tenant(&head(&chain, &t).await, NOW)
                .await
                .unwrap(),
            Applied::Applied
        );
        let second_unit = UnitRow {
            unit: 1,
            restoring_since: None,
        };
        let expanded = write(&chain, &t, two_units(4), Actor::Operator, NOW, 4).await;
        assert_eq!(
            dir.apply_tenant(&expanded, NOW).await.unwrap(),
            Applied::Applied
        );
        assert_eq!(
            dir.units(&t).await.unwrap(),
            [ROOT_UNIT, second_unit.clone()]
        );
        let restoring = write(
            &chain,
            &t,
            Change::SetRestoring { unit: 1 },
            Actor::Operator,
            NOW,
            expanded.seq,
        )
        .await;
        assert_eq!(
            dir.apply_tenant(&restoring, NOW).await.unwrap(),
            Applied::Applied
        );
        let since_seq = restoring.seq;
        assert_eq!(
            dir.units(&t).await.unwrap(),
            [
                ROOT_UNIT,
                UnitRow {
                    unit: 1,
                    restoring_since: Some(since_seq)
                }
            ]
        );

        let lifted = write(
            &chain,
            &t,
            Change::LiftRestoring { unit: 1, since_seq },
            Actor::RestoreTool,
            NOW,
            since_seq,
        )
        .await;
        assert_eq!(
            dir.apply_tenant(&lifted, NOW).await.unwrap(),
            Applied::Applied
        );
        assert_eq!(dir.units(&t).await.unwrap(), [ROOT_UNIT, second_unit]);
        let reduced = write(
            &chain,
            &t,
            Change::SetUnits {
                base_seq: lifted.seq,
                units: vec![0],
                placements: vec![],
            },
            Actor::Operator,
            NOW,
            lifted.seq,
        )
        .await;
        assert_eq!(
            dir.apply_tenant(&reduced, NOW).await.unwrap(),
            Applied::Applied
        );
        assert_eq!(dir.units(&t).await.unwrap(), [ROOT_UNIT]);
    });
}

#[test]
fn a_shredded_tenant_keeps_its_row_and_loses_its_routes() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        let other = TenantId::parse(B2).unwrap();
        for tenant in [&t, &other] {
            active(&chain, tenant).await;
            dir.apply_tenant(&head(&chain, tenant).await, NOW)
                .await
                .unwrap();
        }

        let route = KeyRoute {
            akid: "AKIA1".into(),
            tenant: t.clone(),
            kind: RouteKind::S3,
            owner_ref: Some("m1".into()),
            created_at: NOW,
        };
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::Inserted);
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::Same);
        for conflict in [
            KeyRoute {
                tenant: other,
                ..route.clone()
            },
            KeyRoute {
                kind: RouteKind::Internal,
                ..route.clone()
            },
        ] {
            assert_eq!(dir.put_route(&conflict).await.unwrap(), RoutePut::Conflict);
            assert_eq!(dir.route("AKIA1").await.unwrap().as_ref(), Some(&route));
        }

        let due = UnixMs(NOW.0 + 7 * DAY);
        let deleting = write(
            &chain,
            &t,
            Change::SetDeletion {
                shred_due_at: due,
                reason: DeletionReason::CustomerRequest,
                key_hash: "01".repeat(32),
            },
            Actor::Customer,
            NOW,
            4,
        )
        .await;
        let shredding = write(
            &chain,
            &t,
            Change::StartShred,
            Actor::ShredJob,
            due,
            deleting.seq,
        )
        .await;
        let shredded = write(
            &chain,
            &t,
            Change::FinishShred,
            Actor::ShredJob,
            due,
            shredding.seq,
        )
        .await;
        assert_eq!(
            dir.apply_tenant(&shredded, due).await.unwrap(),
            Applied::Applied
        );
        assert_eq!(
            dir.tenant(&t).await.unwrap().unwrap().door.state(),
            TenantState::Shredded
        );
        let state = db
            .with_conn(|c| {
                c.query_row(
                    "SELECT state FROM tenants WHERE id = ?1",
                    [t.as_str()],
                    |r| r.get::<_, String>(0),
                )
            })
            .unwrap();
        assert_eq!(state, "shredded");
        assert_eq!(dir.route("AKIA1").await.unwrap(), None);
    });
}

#[test]
fn pending_operations_are_deduplicated_filtered_and_cleared() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let first = pending(TenantId::parse(A1).unwrap());
        dir.add_pending(&first).await.unwrap();
        dir.add_pending(&first).await.unwrap();
        assert_eq!(dir.pending_before(FAR_FUTURE, 10).await.unwrap().len(), 1);

        let later = PendingOp {
            seq: 6,
            created_at: UnixMs(NOW.0 + DAY),
            ..first.clone()
        };
        dir.add_pending(&later).await.unwrap();
        assert_eq!(dir.oldest_pending().await.unwrap(), Some(first.created_at));
        assert_eq!(
            dir.pending_before(UnixMs(NOW.0 + DAY / 2), 10)
                .await
                .unwrap()
                .as_slice(),
            std::slice::from_ref(&first)
        );
        assert_eq!(
            dir.clear_pending(&first.tenant, ChainKind::Tenant, 6)
                .await
                .unwrap(),
            2
        );
        assert!(dir.pending_before(FAR_FUTURE, 10).await.unwrap().is_empty());
        assert_eq!(dir.oldest_pending().await.unwrap(), None);
    });
}

#[test]
fn the_key_sequence_only_grows() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        dir.apply_tenant(&head(&chain, &t).await, NOW)
            .await
            .unwrap();

        assert!(dir.raise_keys_seq(&t, 3).await.unwrap());
        assert!(!dir.raise_keys_seq(&t, 2).await.unwrap());
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().keys_seq, 3);
    });
}

#[test]
fn the_gate_checks_epochs_and_admits_closing_calls() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        assert_eq!(
            dir.gate().await.unwrap(),
            GateState {
                closed: true,
                epoch: 0
            }
        );
        assert!(!is_open(&store, &dir).await.unwrap());
        assert_eq!(close(&store, &dir, "first_rebuild", NOW).await.unwrap(), 1);
        assert!(store.raw("m/dg/00000000000000000001").is_some());
        assert_eq!(
            dir.gate().await.unwrap(),
            GateState {
                closed: true,
                epoch: 1
            }
        );
        assert!(dir.open_gate(1, NOW).await.unwrap());
        assert!(is_open(&store, &dir).await.unwrap());
        assert_eq!(close(&store, &dir, "second_rebuild", NOW).await.unwrap(), 2);
        assert!(!dir.open_gate(1, NOW).await.unwrap());
        assert!(!is_open(&store, &dir).await.unwrap());
        assert_eq!(
            dir.gate().await.unwrap(),
            GateState {
                closed: true,
                epoch: 2
            }
        );
    });

    for call in [
        ClosingCall::RevokeKey,
        ClosingCall::DisableKey,
        ClosingCall::NarrowKey,
        ClosingCall::ClearPublicFlag,
        ClosingCall::OperatorHold,
    ] {
        assert!(admitted(true, ManagementCall::Closing(call)), "{call:?}");
    }
    assert!(!admitted(true, ManagementCall::Other));
    assert!(admitted(false, ManagementCall::Other));
}

/// A restore of the directory database to a moment when the gate was open
/// does not open it: the anchor of the closing before the restore is in R2.
#[test]
fn a_restored_gate_row_does_not_open_the_gate() {
    block_on(async {
        let store = MemRecords::new();
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let epoch = close(&store, &dir, "rebuild", NOW).await.unwrap();
        assert!(dir.open_gate(epoch, NOW).await.unwrap());
        assert!(is_open(&store, &dir).await.unwrap());
        // The runbook closes the gate, then the database is restored to
        // the moment before (the row says open at the old epoch).
        let closed = close(&store, &dir, "before_restore", NOW).await.unwrap();
        assert_eq!(closed, epoch + 1);
        db.with_conn(|c| {
            c.execute(
                "UPDATE directory_gate SET closed = 0, epoch = ?1",
                [epoch as i64],
            )
        })
        .unwrap();
        assert!(!is_open(&store, &dir).await.unwrap());
        // The next closing takes an epoch above every anchor, not the
        // restored row's next.
        assert_eq!(close(&store, &dir, "gate", NOW).await.unwrap(), epoch + 2);
        // An anchor can only close: one put by hand at a higher epoch
        // closes an open gate.
        assert!(dir.open_gate(epoch + 2, NOW).await.unwrap());
        assert!(is_open(&store, &dir).await.unwrap());
        store.plant("m/dg/00000000000000000099", b"{}".to_vec());
        assert!(!is_open(&store, &dir).await.unwrap());
    });
}

#[test]
fn a_wiped_directory_rebuilt_from_the_chains_equals_the_old_one() {
    block_on(async {
        let original_db = database();
        let original = SqlDirectory { sql: &original_db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let tenants = populate_directory(&chain, &original).await;

        let rebuilt_db = database();
        let rebuilt = SqlDirectory { sql: &rebuilt_db };
        let step = rebuild_tenants(&chain, &rebuilt, NOW).await.unwrap();
        assert_eq!(step.chains, 3);
        assert_eq!(step.written, 3);
        for tenant in tenants {
            assert!(
                step.differences
                    .contains(&Difference::Missing(tenant.clone())),
                "{:?}",
                step.differences
            );
            let old = original.tenant(&tenant).await.unwrap().unwrap();
            let new = rebuilt.tenant(&tenant).await.unwrap().unwrap();
            assert_eq!(new.door, old.door);
            assert_eq!(new.record_seq, old.record_seq);
            assert_eq!(
                rebuilt.units(&tenant).await.unwrap(),
                original.units(&tenant).await.unwrap()
            );
        }
        assert!(compare_tenants(&chain, &rebuilt).await.unwrap().is_empty());
    });
}

#[test]
fn the_comparison_finds_behind_ahead_orphan_and_damaged_tenants() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        let [a, b, _] = populate_directory(&chain, &dir).await;
        let orphan = TenantId::parse("t_00000000000000c3").unwrap();
        let damaged = TenantId::parse(D4).unwrap();

        let old_a = head(&chain, &a).await;
        let new_a = billing_hold(&chain, &a, None, old_a.seq).await;
        let old_b = head(&chain, &b).await;
        let new_b = billing_hold(&chain, &b, Some(HoldMode::ReadOnly), old_b.seq).await;
        assert_eq!(
            dir.apply_tenant(&new_b, NOW).await.unwrap(),
            Applied::Applied
        );
        assert!(store.lose(&record_key(&b, new_b.seq)));

        let mut orphan_door = new_a.clone();
        orphan_door.tenant = orphan.clone();
        orphan_door.seq = 1;
        assert_eq!(
            dir.apply_tenant(&orphan_door, NOW).await.unwrap(),
            Applied::Applied
        );
        store.plant(&format!("m/t/{D4}/xyz"), vec![1]);

        let differences = compare_tenants(&chain, &dir).await.unwrap();
        for expected in [
            Difference::Behind {
                tenant: a,
                row_seq: old_a.seq,
                head_seq: new_a.seq,
            },
            Difference::Ahead {
                tenant: b.clone(),
                row_seq: new_b.seq,
                head_seq: old_b.seq,
            },
            Difference::Orphan(orphan.clone()),
        ] {
            assert!(
                differences.contains(&expected),
                "missing {expected:?} in {differences:?}"
            );
        }
        assert!(
            differences
                .iter()
                .any(|d| matches!(d, Difference::Damaged { tenant, .. } if tenant == &damaged)),
            "{differences:?}"
        );

        let rebuilt = rebuild_tenants(&chain, &dir, NOW).await.unwrap();
        assert_eq!(rebuilt.removed, 1);
        assert!(dir.tenant(&orphan).await.unwrap().is_none());
        assert_eq!(dir.tenant(&b).await.unwrap().unwrap().record_seq, old_b.seq);
        assert!(rebuilt.damaged());
    });
}

struct AllDone;

impl GateSteps for AllDone {
    async fn revocations(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_versions(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn root_units(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn finisher(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn sealed_days(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }
}

#[test]
fn the_gate_opens_only_when_every_step_is_done_and_chains_are_intact() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        dir.add_pending(&pending(t)).await.unwrap();

        let incomplete = run_gate(&chain, &dir, &NotBuilt, "rebuild", NOW)
            .await
            .unwrap();
        assert!(!incomplete.opened);
        assert_eq!(incomplete.steps.len(), 8);
        assert!(incomplete.steps.iter().all(|(_, report)| !report.done));
        assert!(dir.gate().await.unwrap().closed);
        assert!(dir.pending_before(FAR_FUTURE, 10).await.unwrap().is_empty());

        let complete = run_gate(&chain, &dir, &AllDone, "rebuild", NOW)
            .await
            .unwrap();
        assert!(complete.opened);
        assert_eq!(complete.epoch, incomplete.epoch + 1);
        assert!(!dir.gate().await.unwrap().closed);

        store.plant(&format!("m/t/{D4}/xyz"), vec![1]);
        let damaged = run_gate(&chain, &dir, &AllDone, "rebuild", NOW)
            .await
            .unwrap();
        assert!(!damaged.opened);
        assert!(damaged.tenants.damaged());
        assert!(dir.gate().await.unwrap().closed);
    });
}

#[test]
fn chain_tenants_lists_each_tenant_once_in_id_order() {
    block_on(async {
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        let a = TenantId::parse(A1).unwrap();
        let b = TenantId::parse(B2).unwrap();
        let zero = TenantId::zero();
        active(&chain, &b).await;
        active(&chain, &a).await;
        create_zero(&chain, &zero).await;
        let mut known = 4;
        for i in 0..1_196 {
            let mode = (i % 2 == 0).then_some(HoldMode::ReadOnly);
            known = billing_hold(&chain, &a, mode, known).await.seq;
        }
        assert_eq!(known, 1_200);

        let before = store.lists();
        let tenants = chain_tenants(&store).await.unwrap();
        assert_eq!(store.lists() - before, tenants.len() as u64 + 1);
        assert_eq!(tenants, [zero, a, b]);
    });
}

#[test]
fn the_pending_age_alarm() {
    assert_eq!(pending_level(None, NOW), PendingLevel::Ok);
    let at = |ago: i64| Some(UnixMs(NOW.0 - ago));
    assert_eq!(
        pending_level(at(PENDING_ALARM_MS - 1), NOW),
        PendingLevel::Ok
    );
    assert_eq!(
        pending_level(at(PENDING_ALARM_MS), NOW),
        PendingLevel::Alarm
    );
    assert_eq!(
        pending_level(at(PENDING_PAGE_MS - 1), NOW),
        PendingLevel::Alarm
    );
    assert_eq!(pending_level(at(PENDING_PAGE_MS), NOW), PendingLevel::Page);
}

/// The gate's write takes the head only over the row it saw: a newer head
/// applied meanwhile stays, and a row that changed is not removed.
#[test]
fn the_gate_does_not_overwrite_a_row_that_moved_on() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        let old = head(&chain, &t).await;
        let no_row = dir.row_seq(&t).await.unwrap();
        dir.apply_tenant(&old, NOW).await.unwrap();
        let at_old = dir.row_seq(&t).await.unwrap();
        let new = billing_hold(&chain, &t, Some(HoldMode::Locked), old.seq).await;
        dir.apply_tenant(&new, NOW).await.unwrap();
        let at_new = dir.row_seq(&t).await.unwrap();
        // The gate saw no row, or the old seq: either way the newer row stays.
        assert!(!dir.replace_tenant(&old, &no_row, NOW).await.unwrap());
        assert!(!dir.replace_tenant(&old, &at_old, NOW).await.unwrap());
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().record_seq, new.seq);
        // Over the row it saw, the gate's head is written, a lower seq too.
        assert!(dir.replace_tenant(&old, &at_new, NOW).await.unwrap());
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().record_seq, old.seq);
        // A removal of a row that changed since it was seen removes nothing.
        assert!(!dir.remove_tenant(&t, &at_new).await.unwrap());
        assert!(!dir.remove_tenant(&t, &no_row).await.unwrap());
        assert!(dir.tenant(&t).await.unwrap().is_some());
        assert!(dir.remove_tenant(&t, &at_old).await.unwrap());
        assert!(dir.tenant(&t).await.unwrap().is_none());
        // A row the gate saw that is gone since is not made again; one it
        // saw absent is.
        assert!(!dir.replace_tenant(&old, &at_old, NOW).await.unwrap());
        assert!(dir.tenant(&t).await.unwrap().is_none());
        assert!(dir.replace_tenant(&old, &no_row, NOW).await.unwrap());
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().record_seq, old.seq);
    });
}

/// Gate steps that write a tenant record while the gate runs, as an
/// admitted closing call would.
struct WritesDuringTheGate<'a> {
    chain: &'a Chain<'a>,
    dir: &'a Directory<'a>,
    tenant: TenantId,
    apply: bool,
}

impl GateSteps for WritesDuringTheGate<'_> {
    async fn revocations(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_versions(&self) -> Result<StepReport> {
        // An operator hold, written after the tenant step.
        let head = head(self.chain, &self.tenant).await;
        let w = write(
            self.chain,
            &self.tenant,
            Change::SetOperatorHold {
                hold: Some(OperatorHoldRequest {
                    mode: HoldMode::Locked,
                    reason: OperatorReason::Security,
                    preserve: None,
                }),
            },
            Actor::Operator,
            NOW,
            head.seq,
        )
        .await;
        if self.apply {
            self.dir.apply_tenant(&w, NOW).await?;
        }
        Ok(StepReport::done())
    }

    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn root_units(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn finisher(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn sealed_days(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }
}

#[test]
fn a_record_written_while_the_gate_runs_is_in_the_rows_when_it_opens() {
    for apply in [true, false] {
        block_on(async {
            let db = database();
            let dir = SqlDirectory { sql: &db };
            let store = MemRecords::new();
            let seal = PlainSeal::new();
            let chain = TenantChain {
                store: &store,
                seal: &seal,
            };
            let t = TenantId::parse(A1).unwrap();
            active(&chain, &t).await;
            let steps = WritesDuringTheGate {
                chain: &chain,
                dir: &dir,
                tenant: t.clone(),
                apply,
            };
            let run = run_gate(&chain, &dir, &steps, "rebuild", NOW)
                .await
                .unwrap();
            assert!(run.opened, "apply {apply}: {run:?}");
            let row = dir.tenant(&t).await.unwrap().unwrap();
            assert_eq!(row.door, head(&chain, &t).await, "apply {apply}");
            assert!(row.door.holds.operator.is_some());
            assert!(compare_tenants(&chain, &dir).await.unwrap().is_empty());
        });
    }
}

/// A row that does not parse, or whose columns disagree with its door, is
/// reported and written again; it does not stop the gate.
#[test]
fn a_damaged_row_is_rewritten_by_the_gate() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let a = TenantId::parse(A1).unwrap();
        let b = TenantId::parse(B2).unwrap();
        for t in [&a, &b] {
            active(&chain, t).await;
            dir.apply_tenant(&head(&chain, t).await, NOW).await.unwrap();
        }
        db.with_conn(|c| c.execute("UPDATE tenants SET door_json = '{' WHERE id = ?1", [A1]))
            .unwrap();
        db.with_conn(|c| c.execute("UPDATE tenants SET state = 'deleting' WHERE id = ?1", [B2]))
            .unwrap();
        // `tenant()` refuses a damaged row; the gate's read does not.
        assert!(dir.tenant(&a).await.is_err());
        let found = compare_tenants(&chain, &dir).await.unwrap();
        assert!(
            found.contains(&Difference::Unreadable(a.clone())),
            "{found:?}"
        );
        assert!(
            found.contains(&Difference::Unreadable(b.clone())),
            "{found:?}"
        );
        let step = rebuild_tenants(&chain, &dir, NOW).await.unwrap();
        assert_eq!(step.written, 2);
        assert!(compare_tenants(&chain, &dir).await.unwrap().is_empty());
        assert_eq!(
            dir.tenant(&b).await.unwrap().unwrap().door.state(),
            TenantState::Active
        );
    });
}

/// A stray name inside one tenant's chain is that tenant's damage; the
/// listing of tenants does not stall on it.
#[test]
fn a_stray_name_inside_a_chain_does_not_stall_the_listing() {
    block_on(async {
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        let a = TenantId::parse(A1).unwrap();
        let b = TenantId::parse(B2).unwrap();
        active(&chain, &a).await;
        active(&chain, &b).await;
        for stray in ["~x", "\u{7f}", "\u{e9}"] {
            store.plant(&format!("m/t/{A1}/{stray}"), vec![1]);
        }
        assert_eq!(chain_tenants(&store).await.unwrap(), [a.clone(), b.clone()]);
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let found = compare_tenants(&chain, &dir).await.unwrap();
        assert!(
            found
                .iter()
                .any(|d| matches!(d, Difference::Damaged { tenant, .. } if *tenant == a)),
            "{found:?}"
        );
        assert!(found.contains(&Difference::Missing(b)), "{found:?}");
    });
}

#[test]
fn a_route_needs_a_tenant_that_is_not_shredded() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let route = KeyRoute {
            akid: "APVL2".into(),
            tenant: TenantId::parse(A1).unwrap(),
            kind: RouteKind::AppPassword,
            owner_ref: None,
            created_at: NOW,
        };
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::NoTenant);
        assert_eq!(dir.route("APVL2").await.unwrap(), None);
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        active(&chain, &route.tenant).await;
        let mut door = head(&chain, &route.tenant).await;
        dir.apply_tenant(&door, NOW).await.unwrap();
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::Inserted);
        // A late route after the shred stays out.
        door.seq += 1;
        door.lifecycle = Lifecycle::Shredded;
        dir.apply_tenant(&door, NOW).await.unwrap();
        assert_eq!(dir.route("APVL2").await.unwrap(), None);
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::NoTenant);
    });
}

#[test]
fn the_gate_sets_the_key_seq_lower_too() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        dir.apply_tenant(&head(&chain, &t).await, NOW)
            .await
            .unwrap();
        assert!(dir.raise_keys_seq(&t, 9).await.unwrap());
        // Not over a value it did not see.
        assert!(!dir.set_keys_seq(&t, 4, 8).await.unwrap());
        assert!(dir.set_keys_seq(&t, 4, 9).await.unwrap());
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().keys_seq, 4);
    });
}

/// Another door at the seq a row already holds changes neither the row
/// nor its unit rows.
#[test]
fn another_door_at_the_same_seq_changes_no_unit_row() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let t = TenantId::parse(A1).unwrap();
        active(&chain, &t).await;
        let door = head(&chain, &t).await;
        dir.apply_tenant(&door, NOW).await.unwrap();
        let mut forged = door.clone();
        forged.units = vec![0, 1, 2];
        forged.restoring = vec![Restoring {
            unit: 0,
            since_seq: 1,
        }];
        assert_eq!(
            dir.apply_tenant(&forged, NOW).await.unwrap(),
            Applied::NotNewer
        );
        assert_eq!(dir.units(&t).await.unwrap(), [ROOT_UNIT]);
        assert_eq!(dir.tenant(&t).await.unwrap().unwrap().door, door);
    });
}

/// The open check is one short listing; a stray or a newer name there
/// keeps the gate closed, and a stray never stops a closing.
#[test]
fn the_open_check_is_one_short_listing_and_strays_keep_it_closed() {
    block_on(async {
        let store = MemRecords::new();
        let db = database();
        let dir = SqlDirectory { sql: &db };
        for _ in 0..5 {
            let e = close(&store, &dir, "rebuild", NOW).await.unwrap();
            assert!(dir.open_gate(e, NOW).await.unwrap());
        }
        let lists = store.lists();
        assert!(is_open(&store, &dir).await.unwrap());
        assert_eq!(store.lists() - lists, 1);
        // A stray name after the open epoch's anchor closes the gate.
        store.plant("m/dg/zz", vec![1]);
        assert!(!is_open(&store, &dir).await.unwrap());
        // An epoch beyond the range is a stray too: the next closing takes
        // the epoch after the newest real one, and the gate stays closed
        // while the stray is there.
        store.plant("m/dg/18000000000000000000", vec![1]);
        assert_eq!(close(&store, &dir, "rebuild", NOW).await.unwrap(), 6);
        assert!(dir.open_gate(6, NOW).await.unwrap());
        assert!(!is_open(&store, &dir).await.unwrap());
        assert!(store.lose("m/dg/zz") && store.lose("m/dg/18000000000000000000"));
        assert!(is_open(&store, &dir).await.unwrap());
    });
}

/// A row whose seq column holds no number, and unit rows that do not
/// read, are written again by the gate.
#[test]
fn rows_that_do_not_read_are_written_again() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let a = TenantId::parse(A1).unwrap();
        let b = TenantId::parse(B2).unwrap();
        for t in [&a, &b] {
            active(&chain, t).await;
            dir.apply_tenant(&head(&chain, t).await, NOW).await.unwrap();
        }
        db.with_conn(|c| c.execute("UPDATE tenants SET record_seq = 'x' WHERE id = ?1", [A1]))
            .unwrap();
        db.with_conn(|c| c.execute("INSERT INTO units (tenant, unit) VALUES (?1, 'y')", [B2]))
            .unwrap();
        let found = compare_tenants(&chain, &dir).await.unwrap();
        assert!(
            found.contains(&Difference::Unreadable(a.clone())),
            "{found:?}"
        );
        assert!(found.contains(&Difference::Changed(b.clone())), "{found:?}");
        let step = rebuild_tenants(&chain, &dir, NOW).await.unwrap();
        assert_eq!((step.written, step.raced), (2, 0));
        assert!(compare_tenants(&chain, &dir).await.unwrap().is_empty());
        assert_eq!(dir.units(&b).await.unwrap(), [ROOT_UNIT]);
    });
}

/// Gate steps whose finisher sees another run close the gate over this
/// one.
struct ClosedOver<'a> {
    store: &'a MemRecords,
    dir: &'a Directory<'a>,
    counted: std::cell::Cell<bool>,
}

impl GateSteps for ClosedOver<'_> {
    async fn revocations(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_locations_and_registry(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_versions(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn key_routes_and_labels(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn root_units(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }

    async fn finisher(&self) -> Result<StepReport> {
        close(self.store, self.dir, "second_run", NOW).await?;
        Ok(StepReport::done())
    }

    async fn counters(&self, _epoch: u64) -> Result<StepReport> {
        self.counted.set(true);
        Ok(StepReport::done())
    }

    async fn sealed_days(&self) -> Result<StepReport> {
        Ok(StepReport::done())
    }
}

#[test]
fn a_run_that_another_closed_over_stops_before_the_counters() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        let seal = PlainSeal::new();
        let chain = TenantChain {
            store: &store,
            seal: &seal,
        };
        let steps = ClosedOver {
            store: &store,
            dir: &dir,
            counted: std::cell::Cell::new(false),
        };
        let run = run_gate(&chain, &dir, &steps, "first_run", NOW)
            .await
            .unwrap();
        assert!(!run.opened);
        assert!(run.closed_over);
        assert!(!steps.counted.get());
        assert_eq!(dir.gate().await.unwrap().epoch, run.epoch + 1);
        assert!(!is_open(&store, &dir).await.unwrap());
    });
}

/// A stray anchor name keeps the gate closed, and the run says so.
#[test]
fn a_stray_anchor_keeps_the_run_from_saying_it_opened() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        store.plant("m/dg/zz", vec![1]);
        let run = run_gate(&chain, &dir, &AllDone, "rebuild", NOW)
            .await
            .unwrap();
        assert!(!run.opened, "{run:?}");
        assert_eq!(run.anchor_strays, 1);
        assert!(!is_open(&store, &dir).await.unwrap());
        assert!(store.lose("m/dg/zz"));
        let run = run_gate(&chain, &dir, &AllDone, "rebuild", NOW)
            .await
            .unwrap();
        assert!(run.opened, "{run:?}");
        assert_eq!(run.anchor_strays, 0);
    });
}

/// The pending table is emptied only while the gate is closed at the
/// run's own epoch.
#[test]
fn pending_operations_are_emptied_only_by_the_run_that_holds_the_gate() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let store = MemRecords::new();
        let op = pending(TenantId::parse(A1).unwrap());
        dir.add_pending(&op).await.unwrap();
        let e1 = close(&store, &dir, "first", NOW).await.unwrap();
        let e2 = close(&store, &dir, "second", NOW).await.unwrap();
        assert_eq!(dir.clear_pending_in_gate(e1).await.unwrap(), 0);
        assert!(dir.open_gate(e2, NOW).await.unwrap());
        assert_eq!(dir.clear_pending_in_gate(e2).await.unwrap(), 0);
        assert_eq!(dir.pending_before(FAR_FUTURE, 10).await.unwrap().len(), 1);
        let e3 = close(&store, &dir, "third", NOW).await.unwrap();
        assert_eq!(dir.clear_pending_in_gate(e3).await.unwrap(), 1);
    });
}

/// The move and its undo move a route between tenant 0 and another
/// tenant, only from the tenant it names, and the kind stays.
#[test]
fn a_route_moves_only_from_the_tenant_it_names() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let zero = TenantId::zero();
        let owner = TenantId::parse(A1).unwrap();
        let other = TenantId::parse(B2).unwrap();
        create_zero(&chain, &zero).await;
        active(&chain, &owner).await;
        active(&chain, &other).await;
        for t in [&zero, &owner, &other] {
            dir.apply_tenant(&head(&chain, t).await, NOW).await.unwrap();
        }
        let route = KeyRoute {
            akid: "APVL3".into(),
            tenant: zero.clone(),
            kind: RouteKind::AppPassword,
            owner_ref: None,
            created_at: NOW,
        };
        assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::Inserted);
        assert!(!dir.move_route("APVL3", &other, &owner).await.unwrap());
        assert!(dir.move_route("APVL3", &zero, &owner).await.unwrap());
        let moved = dir.route("APVL3").await.unwrap().unwrap();
        assert_eq!(
            (moved.tenant, moved.kind),
            (owner.clone(), RouteKind::AppPassword)
        );
        // Again from tenant 0: it no longer names it.
        assert!(!dir.move_route("APVL3", &zero, &owner).await.unwrap());
        // Between two tenants neither of which is tenant 0: no move.
        assert!(!dir.move_route("APVL3", &owner, &other).await.unwrap());
        assert_eq!(dir.route("APVL3").await.unwrap().unwrap().tenant, owner);
        // The undo moves it back.
        assert!(dir.move_route("APVL3", &owner, &zero).await.unwrap());
        let back = dir.route("APVL3").await.unwrap().unwrap();
        assert_eq!((back.tenant, back.kind), (zero, RouteKind::AppPassword));
    });
}

/// The id prefix fixes the kind: an `APVL` id is an app password, and an
/// app password has an `APVL` id.
#[test]
fn a_route_kind_must_fit_its_id() {
    block_on(async {
        let db = database();
        let dir = SqlDirectory { sql: &db };
        let chain = TenantChain {
            store: &MemRecords::new(),
            seal: &PlainSeal::new(),
        };
        let owner = TenantId::parse(A1).unwrap();
        active(&chain, &owner).await;
        dir.apply_tenant(&head(&chain, &owner).await, NOW)
            .await
            .unwrap();
        for (akid, kind) in [
            ("AKIA5", RouteKind::AppPassword),
            ("APVL5", RouteKind::S3),
            ("APVL6", RouteKind::Internal),
        ] {
            let route = KeyRoute {
                akid: akid.into(),
                tenant: owner.clone(),
                kind,
                owner_ref: None,
                created_at: NOW,
            };
            assert_eq!(dir.put_route(&route).await.unwrap(), RoutePut::WrongKind);
            assert_eq!(dir.route(akid).await.unwrap(), None);
        }
    });
}

/// A bare `m/t/<tenant>` beside an intact chain is a stray name: the
/// listing of tenants fails instead of skipping it.
#[test]
fn a_bare_tenant_name_is_a_stray() {
    block_on(async {
        let store = MemRecords::new();
        let chain = TenantChain {
            store: &store,
            seal: &PlainSeal::new(),
        };
        let a = TenantId::parse(A1).unwrap();
        active(&chain, &a).await;
        store.plant(&format!("m/t/{A1}"), vec![1]);
        assert!(chain_tenants(&store).await.is_err());
    });
}
