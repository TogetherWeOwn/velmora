use velmora_bridge::directory::chain::{record_key, TenantChain, Written};
use velmora_bridge::directory::gate::{
    admitted, chain_tenants, compare_tenants, rebuild_tenants, run_gate, ClosingCall, Difference,
    GateSteps, ManagementCall, NotBuilt, StepReport,
};
use velmora_bridge::directory::record::{
    DeletionReason, HoldMode, Placement, TenantDoor, TenantId, TenantState,
};
use velmora_bridge::directory::store::{
    Applied, ChainKind, GateState, KeyRoute, PendingOp, RouteKind, RoutePut, SqlDirectory, UnitRow,
};
use velmora_bridge::directory::testing::{MemRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change};
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
        Change::CommitKeyVersion { version: 1 },
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

fn two_units() -> Change {
    Change::SetUnits {
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
    let expanded = write(chain, &b, two_units(), Actor::Operator, NOW, 4).await;
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
        let expanded = write(&chain, &t, two_units(), Actor::Operator, NOW, 4).await;
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
        assert_eq!(
            dir.gate().await.unwrap(),
            GateState {
                closed: true,
                epoch: 0
            }
        );
        assert_eq!(dir.close_gate("first rebuild", NOW).await.unwrap(), 1);
        assert_eq!(
            dir.gate().await.unwrap(),
            GateState {
                closed: true,
                epoch: 1
            }
        );
        assert!(dir.open_gate(1, NOW).await.unwrap());
        assert!(!dir.gate().await.unwrap().closed);
        assert_eq!(dir.close_gate("second rebuild", NOW).await.unwrap(), 2);
        assert!(!dir.open_gate(1, NOW).await.unwrap());
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
