//! The unit's core rules (`docs/units.md`, rules 1 to 7, 11, 13 and 14),
//! on the native database. The same unit runs in a
//! Durable Object through `DoSql` (workers/unit); `workers/unit-suite`
//! runs this file against it as well.

mod unit_bucket_support;

use serde_json::json;
use unit_bucket_support::fixture_placements;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::call::{Closed, HoldMode};
use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::object::transact;
use velmora_bridge::unit::{
    poll_once, BirthKind, BirthToken, CallKind, ProvisionRefusal, Reader, Refused, Seqs, SyncHead,
    TenantId, TenantState, Unit, UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::{Sql, SqlValue, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const AKID: &str = "AKUNITCORE0000000001";

fn tenant() -> TenantId {
    TenantId::parse("t_0000000000000c01").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn unit() -> Unit<RusqliteSql> {
    Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "")
}

fn token(kind: BirthKind, record_seq: u64) -> BirthToken {
    BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind,
    }
}

fn seqs(state_seq: u64, keys_seq: u64) -> Option<Seqs> {
    Some(Seqs {
        state_seq,
        keys_seq,
    })
}

fn call(kind: CallKind, s: Option<Seqs>, authenticated: bool, op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind,
        seqs: s,
        authenticated,
        listed: true,
        op,
    }
}

fn provision(u: &Unit<RusqliteSql>, t: BirthToken, caller: Option<u64>) -> UnitAnswer {
    let op = UnitOp::Provision {
        token: t,
        sealed: b"sealed-by-the-worker".to_vec(),
    };
    let s = caller.map(|state_seq| Seqs {
        state_seq,
        keys_seq: 0,
    });
    u.handle(&call(CallKind::Worker, s, true, op), NOW)
}

fn sync(
    u: &Unit<RusqliteSql>,
    state_seq: u64,
    state: TenantState,
    mode: Option<HoldMode>,
) -> UnitAnswer {
    let op = UnitOp::Sync {
        head: SyncHead {
            seqs: Seqs {
                state_seq,
                keys_seq: 0,
            },
            tenant_state: state,
            tenant_mode: mode,
            restoring_since: None,
            lift: None,
            buckets: vec![],
            placed: fixture_placements(u.sql()),
        },
    };
    u.handle(&call(CallKind::Worker, None, true, op), NOW)
}

/// The Worker's renewal at `now` (rule 12; `unit_lease_wiring.rs` holds
/// its rules): the unit's lease then holds for T.
fn renew(u: &Unit<RusqliteSql>, now: UnixMs) {
    let seqs = u.head().unwrap().seqs;
    let op = UnitOp::Renew {
        proof_start: now,
        proven: Proven {
            state_seq: seqs.state_seq,
            keys_seq: seqs.keys_seq,
            stamp_counter: None,
            revoked: 0,
        },
        revocations: Vec::new(),
    };
    let a = u.handle(&call(CallKind::Worker, None, true, op), now);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "renew: {a:?}");
}

/// A born, active unit at seq 3 with one bucket, one object of two
/// extents and one key granted on the bucket, with a fresh lease.
fn ready() -> Unit<RusqliteSql> {
    let u = unit();
    assert!(matches!(
        provision(&u, token(BirthKind::Birth, 3), Some(3)),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        sync(&u, 3, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
    renew(&u, NOW);
    u.sql()
        .apply(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('b_00000000000000c1', 'alpha', 'o', x'02', 1, 1); \
             INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
               user_meta_json, extent_count, created_at) \
               VALUES ('g_0019a00000000c1c1c1c1c1c1c1c1', 'b_00000000000000c1', 'k', 'live', 20, \
                 '\"e\"', '{}', '{}', 2, 1); \
             INSERT INTO objects(bucket_id, key, generation_id) \
               VALUES ('b_00000000000000c1', 'k', 'g_0019a00000000c1c1c1c1c1c1c1c1'); \
             INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, plain_md5, plain_sha256, cipher_sha256, \
               safety_state, created_at) \
               VALUES ('x_000000000000000000000000c1', 'b_00000000000000c1', \
                 'g_0019a00000000c1c1c1c1c1c1c1c1', 'committed', 0, 0, 10, 10, zeroblob(48), zeroblob(16), \
                 zeroblob(32), zeroblob(32), 'held', 1), \
                      ('x_000000000000000000000000c2', 'b_00000000000000c1', \
                 'g_0019a00000000c1c1c1c1c1c1c1c1', 'committed', 1, 10, 10, 10, zeroblob(48), zeroblob(16), \
                 zeroblob(32), zeroblob(32), 'held', 1); \
             INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, \
               status, created_at) VALUES ('AKUNITCORE0000000001', 'p', x'02', 1, 'active', 1); \
             INSERT INTO grants(access_key_id, bucket_id, perm) \
               VALUES ('AKUNITCORE0000000001', 'b_00000000000000c1', 'ro');",
        )
        .unwrap();
    u
}

const GEN: &str = "g_0019a00000000c1c1c1c1c1c1c1c1";

fn read_plan(reader: Option<Reader>) -> UnitOp {
    // A fan-out piece names the generation its grant was made for.
    let generation = reader.as_ref().map(|_| GEN.to_string());
    UnitOp::ReadPlan {
        bucket: "alpha".into(),
        key: "k".into(),
        start: 0,
        end: 20,
        access_key_id: Some(AKID.into()),
        reader,
        generation,
    }
}

fn tables(u: &Unit<RusqliteSql>) -> i64 {
    u.sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)))
        .unwrap()
}

fn total_changes(u: &Unit<RusqliteSql>) -> u64 {
    u.sql().with_conn(|c| c.total_changes())
}

fn last_read(u: &Unit<RusqliteSql>) -> Vec<Option<i64>> {
    u.sql().with_conn(|c| {
        let mut s = c
            .prepare("SELECT last_read_at FROM extents ORDER BY id")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    })
}

// ---------------------------------------------------------------------------
// Rule 7: unborn is not empty
// ---------------------------------------------------------------------------

#[test]
fn an_unborn_unit_answers_unborn_and_writes_nothing() {
    let u = unit();
    for listed in [true, false] {
        for op in [
            UnitOp::Ping {},
            read_plan(None),
            UnitOp::KeyRow {
                access_key_id: AKID.into(),
                presigned: None,
            },
        ] {
            let mut c = call(CallKind::Request, seqs(3, 0), true, op);
            c.listed = listed;
            assert_eq!(u.handle(&c, NOW), UnitAnswer::Unborn { listed });
        }
        let sync_call = call(
            CallKind::Worker,
            None,
            true,
            UnitOp::Sync {
                head: SyncHead {
                    seqs: Seqs {
                        state_seq: 3,
                        keys_seq: 0,
                    },
                    tenant_state: TenantState::Active,
                    tenant_mode: None,
                    restoring_since: None,
                    lift: None,
                    buckets: vec![],
                    placed: vec![],
                },
            },
        );
        let mut c = sync_call.clone();
        c.listed = listed;
        assert_eq!(u.handle(&c, NOW), UnitAnswer::Unborn { listed });
    }
    // It never initialises itself: no table, no row.
    assert_eq!(tables(&u), 0);
    assert_eq!(total_changes(&u), 0);
}

// ---------------------------------------------------------------------------
// Rule 6: birth
// ---------------------------------------------------------------------------

#[test]
fn a_birth_makes_the_schema_the_certificate_and_the_numbers() {
    let u = unit();
    let answer = provision(&u, token(BirthKind::Birth, 3), Some(3));
    assert_eq!(
        answer,
        UnitAnswer::Ok {
            seqs: Seqs {
                state_seq: 3,
                keys_seq: 0
            },
            body: json!({ "born": "birth", "restoring": null }),
        }
    );
    let (tenant, unit_no, kind, token_blob, version): (String, i64, String, Vec<u8>, i64) = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT tenant, unit, kind, token, schema_version FROM unit_birth",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
        })
        .unwrap();
    assert_eq!(tenant, "t_0000000000000c01");
    assert_eq!(unit_no, 0);
    assert_eq!(kind, "birth");
    assert_eq!(token_blob, b"sealed-by-the-worker");
    assert_eq!(
        version,
        i64::from(velmora_bridge::unit::schema::SCHEMA_VERSION)
    );
    // Until the first sync the tenant is `provisioning`: 503 for S3.
    assert_eq!(
        u.handle(
            &call(CallKind::Request, seqs(3, 0), true, UnitOp::Ping {}),
            NOW
        ),
        UnitAnswer::Closed {
            seqs: Seqs {
                state_seq: 3,
                keys_seq: 0
            },
            why: Closed::Provisioning
        }
    );
}

#[test]
fn a_replayed_birth_token_is_refused_and_changes_nothing() {
    let u = ready();
    let before = total_changes(&u);
    for (t, caller) in [
        (token(BirthKind::Birth, 3), Some(3)),
        (token(BirthKind::Birth, 3), None),
        (token(BirthKind::Restore, 3), Some(9)),
    ] {
        assert_eq!(
            provision(&u, t, caller),
            UnitAnswer::Refused {
                reason: Refused::Provision(ProvisionRefusal::AlreadyBorn),
                alarm: false
            }
        );
    }
    assert_eq!(total_changes(&u), before);
    let rows: i64 = u
        .sql()
        .with_conn(|c| c.query_row("SELECT count(*) FROM extents", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(rows, 2, "the unit's data is untouched");
}

#[test]
fn a_birth_token_below_the_callers_seq_never_makes_an_empty_unit() {
    let u = unit();
    assert_eq!(
        provision(&u, token(BirthKind::Birth, 3), Some(4)),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::StaleBirth),
            alarm: false
        }
    );
    assert_eq!(tables(&u), 0);
}

#[test]
fn a_token_for_another_unit_or_scheme_or_schema_is_refused() {
    let u = unit();
    let mut other = token(BirthKind::Birth, 3);
    other.name = UnitName::new(tenant(), 1);
    assert_eq!(
        provision(&u, other, Some(3)),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::WrongName),
            alarm: true
        }
    );
    let mut scheme = token(BirthKind::Birth, 3);
    scheme.key_scheme = 1;
    assert_eq!(
        provision(&u, scheme, Some(3)),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::WrongScheme),
            alarm: false
        }
    );
    let mut schema = token(BirthKind::Birth, 3);
    schema.schema_version -= 1;
    assert_eq!(
        provision(&u, schema, Some(3)),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::WrongSchema),
            alarm: false
        }
    );
    assert_eq!(tables(&u), 0);
}

#[test]
fn a_provision_without_the_callers_numbers_is_refused() {
    let u = unit();
    assert_eq!(
        provision(&u, token(BirthKind::Birth, 3), None),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::NoNumbers),
            alarm: false
        }
    );
    assert_eq!(tables(&u), 0);
}

#[test]
fn a_token_for_another_jurisdiction_makes_no_object() {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "eu");
    assert_eq!(
        provision(&u, token(BirthKind::Birth, 3), Some(3)),
        UnitAnswer::Refused {
            reason: Refused::Provision(ProvisionRefusal::WrongName),
            alarm: true
        }
    );
    assert_eq!(tables(&u), 0);
}

#[test]
fn provision_is_a_worker_call_only() {
    let u = unit();
    let op = UnitOp::Provision {
        token: token(BirthKind::Birth, 3),
        sealed: vec![1],
    };
    for kind in [CallKind::Request, CallKind::Job, CallKind::Fanout] {
        assert_eq!(
            u.handle(&call(kind, seqs(3, 0), true, op.clone()), NOW),
            UnitAnswer::Refused {
                reason: Refused::Unauthenticated,
                alarm: false
            }
        );
    }
    assert_eq!(tables(&u), 0);
}

#[test]
fn a_restored_unit_starts_closed_and_a_sync_still_reaches_it() {
    let u = unit();
    let answer = provision(&u, token(BirthKind::Restore, 7), Some(9));
    assert!(matches!(answer, UnitAnswer::Ok { .. }), "{answer:?}");
    // Requests and jobs find it closed until the gate lifts the entry.
    for kind in [CallKind::Request, CallKind::Job] {
        assert_eq!(
            u.handle(&call(kind, seqs(7, 0), true, UnitOp::Ping {}), NOW),
            UnitAnswer::Closed {
                seqs: Seqs {
                    state_seq: 7,
                    keys_seq: 0
                },
                why: Closed::Restoring
            }
        );
    }
    // The record that still carries the entry keeps it closed.
    let keep = UnitOp::Sync {
        head: SyncHead {
            seqs: Seqs {
                state_seq: 9,
                keys_seq: 0,
            },
            tenant_state: TenantState::Active,
            tenant_mode: None,
            restoring_since: Some(7),
            lift: None,
            buckets: vec![],
            placed: vec![],
        },
    };
    assert!(matches!(
        u.handle(&call(CallKind::Worker, None, true, keep), NOW),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        u.handle(
            &call(CallKind::Request, seqs(9, 0), true, UnitOp::Ping {}),
            NOW
        ),
        UnitAnswer::Closed {
            why: Closed::Restoring,
            ..
        }
    ));
    // Its usage counters start off: the replay fills it and the gate
    // recounts.
    let armed: i64 = u
        .sql()
        .with_conn(|c| {
            c.query_row("SELECT all_x FROM usage_global WHERE id = 1", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(armed, 0);
}

// ---------------------------------------------------------------------------
// Rule 5: identity
// ---------------------------------------------------------------------------

#[test]
fn a_call_for_another_name_is_refused_with_an_alarm() {
    let u = ready();
    for name in [
        UnitName::new(tenant(), 1),
        UnitName::new(TenantId::parse("t_0000000000000c02").unwrap(), 0),
    ] {
        let mut c = call(CallKind::Request, seqs(3, 0), true, UnitOp::Ping {});
        c.name = name;
        assert_eq!(
            u.handle(&c, NOW),
            UnitAnswer::Refused {
                reason: Refused::Identity(Refusal::WrongName),
                alarm: true
            }
        );
    }
}

#[test]
fn numbers_above_the_units_need_a_sync_and_below_are_stale() {
    let u = ready();
    let own_seqs = Seqs {
        state_seq: 3,
        keys_seq: 0,
    };
    assert_eq!(
        u.handle(
            &call(CallKind::Request, seqs(4, 0), true, UnitOp::Ping {}),
            NOW
        ),
        UnitAnswer::SyncNeeded { seqs: own_seqs }
    );
    assert_eq!(
        u.handle(&call(CallKind::Job, seqs(3, 1), true, UnitOp::Ping {}), NOW),
        UnitAnswer::SyncNeeded { seqs: own_seqs }
    );
    assert_eq!(
        u.handle(
            &call(CallKind::Request, seqs(2, 0), true, read_plan(None)),
            NOW
        ),
        UnitAnswer::Stale { seqs: own_seqs }
    );
    // AM-50: a job behind the unit gets the unit's numbers; a job with
    // none is refused.
    assert_eq!(
        u.handle(&call(CallKind::Job, seqs(2, 0), true, UnitOp::Ping {}), NOW),
        UnitAnswer::Stale { seqs: own_seqs }
    );
    assert_eq!(
        u.handle(&call(CallKind::Job, None, true, UnitOp::Ping {}), NOW),
        UnitAnswer::Refused {
            reason: Refused::Identity(Refusal::StaleJob),
            alarm: false
        }
    );
    // A stale request did nothing: no read stamp.
    assert_eq!(last_read(&u), vec![None, None]);
}

#[test]
fn a_fanout_read_with_lower_numbers_is_served_while_its_reader_is_allowed() {
    let u = ready();
    // An unrelated change moves the tenant chain on.
    assert!(matches!(
        sync(&u, 4, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
    let reader = Some(Reader::Key {
        access_key_id: AKID.into(),
    });
    let fanout = call(
        CallKind::Fanout,
        seqs(3, 0),
        true,
        read_plan(reader.clone()),
    );
    let UnitAnswer::Ok { body, .. } = u.handle(&fanout, NOW) else {
        panic!("a fan-out read after an unrelated change is served");
    };
    assert_eq!(
        body["extents"],
        json!([
            "x_000000000000000000000000c1",
            "x_000000000000000000000000c2"
        ])
    );

    // Without a reader, lower numbers are not served.
    assert_eq!(
        u.handle(
            &call(CallKind::Fanout, seqs(3, 0), true, read_plan(None)),
            NOW
        ),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );
    // A public reader needs a public bucket; none is.
    assert_eq!(
        u.handle(
            &call(
                CallKind::Fanout,
                seqs(3, 0),
                true,
                read_plan(Some(Reader::Public))
            ),
            NOW
        ),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );

    // The reader's key is disabled: the same sub-request is refused.
    u.sql()
        .apply("UPDATE access_keys SET status = 'disabled' WHERE access_key_id = 'AKUNITCORE0000000001'")
        .unwrap();
    assert_eq!(
        u.handle(&fanout, NOW),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );
    // Active again but without the grant: refused too.
    u.sql()
        .apply(
            "UPDATE access_keys SET status = 'active'; \
             DELETE FROM grants WHERE access_key_id = 'AKUNITCORE0000000001'",
        )
        .unwrap();
    assert_eq!(
        u.handle(&fanout, NOW),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );
}

#[test]
fn a_fanout_piece_reads_the_generation_its_grant_names() {
    let u = ready();
    // The object is overwritten after the GET began: a new generation is
    // live for the key, with an extent of its own.
    u.sql()
        .apply(
            "UPDATE generations SET state = 'superseded' WHERE id = 'g_0019a00000000c1c1c1c1c1c1c1c1'; \
             INSERT INTO generations(id, bucket_id, key, state, size, etag, content_json, \
               user_meta_json, extent_count, created_at) \
               VALUES ('g_0019a00000001c2c2c2c2c2c2c2c2', 'b_00000000000000c1', 'k', 'live', 10, \
                 '\"f\"', '{}', '{}', 1, 2); \
             UPDATE objects SET generation_id = 'g_0019a00000001c2c2c2c2c2c2c2c2' WHERE key = 'k'; \
             INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
               plain_size, cipher_size, media_header, plain_md5, plain_sha256, cipher_sha256, \
               safety_state, created_at) \
               VALUES ('x_000000000000000000000000c3', 'b_00000000000000c1', \
                 'g_0019a00000001c2c2c2c2c2c2c2c2', 'committed', 0, 0, 10, 10, zeroblob(48), \
                 zeroblob(16), zeroblob(32), zeroblob(32), 'held', 2);",
        )
        .unwrap();
    let reader = Some(Reader::Key {
        access_key_id: AKID.into(),
    });
    let UnitAnswer::Ok { body, .. } = u.handle(
        &call(
            CallKind::Fanout,
            seqs(3, 0),
            true,
            read_plan(reader.clone()),
        ),
        NOW,
    ) else {
        panic!("a fan-out piece is served");
    };
    assert_eq!(body["generation"], json!(GEN));
    assert_eq!(
        body["extents"],
        json!([
            "x_000000000000000000000000c1",
            "x_000000000000000000000000c2"
        ])
    );
    // A request reads the live generation.
    let UnitAnswer::Ok { body, .. } = u.handle(
        &call(CallKind::Request, seqs(3, 0), true, read_plan(None)),
        NOW,
    ) else {
        panic!("a read is served");
    };
    assert_eq!(body["generation"], json!("g_0019a00000001c2c2c2c2c2c2c2c2"));
    // A generation of another key is not read through this key.
    let mut op = read_plan(reader.clone());
    if let UnitOp::ReadPlan { key, .. } = &mut op {
        *key = "other".into();
    }
    let UnitAnswer::Ok { body, .. } = u.handle(&call(CallKind::Fanout, seqs(3, 0), true, op), NOW)
    else {
        panic!("a fan-out piece for another key is answered");
    };
    assert_eq!(body["generation"], json!(null));
    assert!(body.get("extents").is_none());
    // A fan-out call names its reader and generation even with the
    // unit's own numbers.
    for op in [read_plan(None), UnitOp::Ping {}] {
        assert_eq!(
            u.handle(&call(CallKind::Fanout, seqs(3, 0), true, op), NOW),
            UnitAnswer::Refused {
                reason: Refused::AccessDenied,
                alarm: false
            }
        );
    }
    // A fan-out piece that names no generation is refused.
    let mut op = read_plan(reader);
    if let UnitOp::ReadPlan { generation, .. } = &mut op {
        *generation = None;
    }
    assert_eq!(
        u.handle(&call(CallKind::Fanout, seqs(3, 0), true, op), NOW),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );
}

#[test]
fn a_fanout_read_is_refused_when_the_tenant_may_no_longer_read() {
    let u = ready();
    assert!(matches!(
        sync(&u, 4, TenantState::Suspended, Some(HoldMode::Locked)),
        UnitAnswer::Ok { .. }
    ));
    let reader = Some(Reader::Key {
        access_key_id: AKID.into(),
    });
    // At equal numbers the state decides first: AccountProblem.
    assert_eq!(
        u.handle(
            &call(
                CallKind::Fanout,
                seqs(4, 0),
                true,
                read_plan(reader.clone())
            ),
            NOW
        ),
        UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            alarm: false
        }
    );
}

// ---------------------------------------------------------------------------
// Rule 11: unauthenticated calls are read-only
// ---------------------------------------------------------------------------

#[test]
fn an_unauthenticated_read_plan_writes_no_row() {
    let u = ready();
    let before = total_changes(&u);
    let c = call(CallKind::Request, seqs(3, 0), false, read_plan(None));
    let answer = u.handle(&c, NOW);
    let UnitAnswer::Ok { body, .. } = answer else {
        panic!("a cold read plan is served without authentication: {answer:?}");
    };
    assert_eq!(body["size"], json!(20));
    assert_eq!(body["key_row"]["key"]["access_key_id"], json!(AKID));
    assert_eq!(body["key_row"]["grant"], json!("ro"));
    assert_eq!(body["state"]["tenant_state"], json!("active"));
    assert_eq!(total_changes(&u), before, "no row written");
    assert_eq!(last_read(&u), vec![None, None], "no read stamp");

    // A fan-out piece names a grant: never a cold read, so never served
    // without authentication, even at the unit's own numbers.
    let fan = read_plan(Some(Reader::Key {
        access_key_id: AKID.into(),
    }));
    assert_eq!(
        u.handle(&call(CallKind::Fanout, seqs(3, 0), false, fan), NOW),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        }
    );

    // An empty range holds no extent and stamps none.
    let mut empty = read_plan(None);
    if let UnitOp::ReadPlan { start, end, .. } = &mut empty {
        (*start, *end) = (5, 5);
    }
    let UnitAnswer::Ok { body, .. } =
        u.handle(&call(CallKind::Request, seqs(3, 0), true, empty), NOW)
    else {
        panic!("an empty range is answered");
    };
    assert_eq!(body["extents"], json!([]));
    assert_eq!(last_read(&u), vec![None, None], "no read stamp");

    // The same call authenticated stamps the reads.
    let c = call(CallKind::Request, seqs(3, 0), true, read_plan(None));
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
    assert_eq!(last_read(&u), vec![Some(NOW.0), Some(NOW.0)]);
}

#[test]
fn an_unauthenticated_key_row_fetch_is_served_and_nothing_else_is() {
    let u = ready();
    let before = total_changes(&u);
    let c = call(
        CallKind::Request,
        seqs(3, 0),
        false,
        UnitOp::KeyRow {
            access_key_id: AKID.into(),
            presigned: None,
        },
    );
    let UnitAnswer::Ok { body, .. } = u.handle(&c, NOW) else {
        panic!("the key-row fetch is served");
    };
    assert_eq!(body["key"]["status"], json!("active"));
    assert_eq!(
        u.handle(
            &call(CallKind::Request, seqs(3, 0), false, UnitOp::Ping {}),
            NOW
        ),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        }
    );
    assert_eq!(total_changes(&u), before);
}

#[test]
fn an_unauthenticated_call_reports_the_state_and_is_not_refused_by_it() {
    let u = ready();
    assert!(matches!(
        sync(&u, 4, TenantState::Suspended, Some(HoldMode::Locked)),
        UnitAnswer::Ok { .. }
    ));
    // The Worker decides after the signature: the unit only reports.
    let c = call(CallKind::Request, seqs(4, 0), false, read_plan(None));
    let UnitAnswer::Ok { body, .. } = u.handle(&c, NOW) else {
        panic!("served with the state");
    };
    assert_eq!(
        body["state"],
        json!({ "tenant_state": "suspended", "tenant_mode": "locked" })
    );
}

// ---------------------------------------------------------------------------
// Tenant state, sync, and the Worker's calls
// ---------------------------------------------------------------------------

#[test]
fn the_tenant_state_decides_an_authenticated_call() {
    let u = ready();
    assert!(matches!(
        sync(&u, 4, TenantState::Suspended, Some(HoldMode::ReadOnly)),
        UnitAnswer::Ok { .. }
    ));
    assert!(matches!(
        u.handle(
            &call(CallKind::Request, seqs(4, 0), true, read_plan(None)),
            NOW
        ),
        UnitAnswer::Ok { .. }
    ));
    for (state, mode) in [
        (TenantState::Suspended, Some(HoldMode::Locked)),
        (TenantState::Deleting, None),
        (TenantState::Shredding, None),
        (TenantState::Shredded, None),
    ] {
        let u = ready();
        assert!(matches!(sync(&u, 4, state, mode), UnitAnswer::Ok { .. }));
        assert_eq!(
            u.handle(
                &call(CallKind::Request, seqs(4, 0), true, read_plan(None)),
                NOW
            ),
            UnitAnswer::Refused {
                reason: Refused::AccountProblem,
                alarm: false
            },
            "{state:?}"
        );
    }
}

#[test]
fn a_sync_never_moves_back_and_never_claims_keys_it_does_not_hold() {
    let u = ready();
    assert!(matches!(
        sync(&u, 5, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
    assert_eq!(
        sync(&u, 4, TenantState::Active, None),
        UnitAnswer::Refused {
            reason: Refused::StaleSync,
            alarm: false
        }
    );
    let keys = UnitOp::Sync {
        head: SyncHead {
            seqs: Seqs {
                state_seq: 5,
                keys_seq: 1,
            },
            tenant_state: TenantState::Active,
            tenant_mode: None,
            restoring_since: None,
            lift: None,
            buckets: vec![],
            placed: fixture_placements(u.sql()),
        },
    };
    assert_eq!(
        u.handle(&call(CallKind::Worker, None, true, keys), NOW),
        UnitAnswer::Refused {
            reason: Refused::KeysNotApplied,
            alarm: false
        }
    );
    // Only the Worker syncs, and the Worker only runs its own calls.
    let s = UnitOp::Sync {
        head: SyncHead {
            seqs: Seqs {
                state_seq: 6,
                keys_seq: 0,
            },
            tenant_state: TenantState::Active,
            tenant_mode: None,
            restoring_since: None,
            lift: None,
            buckets: vec![],
            placed: fixture_placements(u.sql()),
        },
    };
    assert_eq!(
        u.handle(&call(CallKind::Request, seqs(5, 0), true, s), NOW),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        }
    );
    assert_eq!(
        u.handle(&call(CallKind::Worker, None, true, read_plan(None)), NOW),
        UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        }
    );
    let head = u.head().unwrap();
    assert_eq!(head.seqs.state_seq, 5);
}

#[test]
fn a_missing_bucket_answers_with_the_key_row_and_a_missing_object_is_an_empty_plan() {
    let u = ready();
    let mut op = read_plan(None);
    if let UnitOp::ReadPlan { bucket, .. } = &mut op {
        *bucket = "nope".into();
    }
    // The Worker decides after the signature, so the key row comes back:
    // a caller who holds only a key id learns nothing of which buckets
    // exist.
    for authenticated in [false, true] {
        let answer = u.handle(
            &call(CallKind::Request, seqs(3, 0), authenticated, op.clone()),
            NOW,
        );
        let UnitAnswer::Ok { body, .. } = answer else {
            panic!("a missing bucket is answered, not refused: {answer:?}");
        };
        assert_eq!(body["bucket"], json!(null));
        assert_eq!(body["key_row"]["key"]["access_key_id"], json!(AKID));
        assert_eq!(body["key_row"]["grant"], json!(null));
    }
    // A fan-out read granted on a bucket that is gone is refused as the
    // full request would be.
    assert!(matches!(
        sync(&u, 4, TenantState::Active, None),
        UnitAnswer::Ok { .. }
    ));
    let mut fan = read_plan(Some(Reader::Key {
        access_key_id: AKID.into(),
    }));
    if let UnitOp::ReadPlan { bucket, .. } = &mut fan {
        *bucket = "nope".into();
    }
    assert_eq!(
        u.handle(&call(CallKind::Fanout, seqs(3, 0), true, fan), NOW),
        UnitAnswer::Refused {
            reason: Refused::AccessDenied,
            alarm: false
        }
    );
    let mut op = read_plan(None);
    if let UnitOp::ReadPlan { key, .. } = &mut op {
        *key = "missing".into();
    }
    let answer = u.handle(&call(CallKind::Request, seqs(4, 0), true, op), NOW);
    let UnitAnswer::Ok { body, .. } = answer else {
        panic!("an empty plan: {answer:?}");
    };
    assert_eq!(body["generation"], json!(null));
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

#[test]
fn a_call_reads_back_from_its_json_and_refuses_unknown_fields() {
    let c = call(
        CallKind::Fanout,
        seqs(3, 1),
        true,
        read_plan(Some(Reader::Key {
            access_key_id: AKID.into(),
        })),
    );
    let text = serde_json::to_string(&c).unwrap();
    assert_eq!(serde_json::from_str::<UnitCall>(&text).unwrap(), c);
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["elevated"] = json!(true);
    assert!(serde_json::from_value::<UnitCall>(v).is_err());
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["op"]["sneaky"] = json!(1);
    assert!(serde_json::from_value::<UnitCall>(v).is_err());
    // A name that is not canonical is not a call.
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["name"]["tenant"] = json!("main");
    assert!(serde_json::from_value::<UnitCall>(v).is_err());
    // Nor is a field the unit does not know, anywhere in it.
    for (path, extra) in [("seqs", "x"), ("name", "x")] {
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v[path][extra] = json!(1);
        assert!(serde_json::from_value::<UnitCall>(v).is_err(), "{path}");
    }
    let ping = call(CallKind::Request, seqs(3, 1), true, UnitOp::Ping {});
    let mut v = serde_json::to_value(&ping).unwrap();
    assert_eq!(v["op"], json!({ "op": "ping" }));
    v["op"]["evil"] = json!(1);
    assert!(serde_json::from_value::<UnitCall>(v).is_err());
}

#[test]
fn the_raw_sql_of_the_unit_is_the_catalogues() {
    // Rule 1: the unit's operations are the catalogue's code over its own
    // database; a born unit holds the whole catalogue schema.
    let u = ready();
    let rows = futures_executor_block(u.sql().query(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN \
           ('buckets', 'generations', 'extents', 'outbox', 'unit_birth', 'unit_head')",
        &[],
    ));
    assert_eq!(rows[0][0], SqlValue::Int(6));
}

fn futures_executor_block<T>(f: impl std::future::Future<Output = velmora_bridge::Result<T>>) -> T {
    velmora_bridge::unit::poll_once(f).unwrap().unwrap()
}

// ---------------------------------------------------------------------------
// Rules 3 and 4, in the source
// ---------------------------------------------------------------------------

/// The unit's code names no key, no seal, no network, no timer and no
/// queue: the unit module of the bridge, and the object crate.
#[test]
fn the_unit_code_holds_no_key_and_reaches_for_no_io() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let dirs = [
        format!("{root}/crates/velmora-bridge/src/unit"),
        format!("{root}/workers/unit/src"),
    ];
    let forbidden = [
        "crate::crypto",
        "velmora_bridge::crypto",
        "Kek",
        "KekRing",
        "unwrap_key",
        "Fetch",
        "fetch(",
        "connect(",
        "setTimeout",
        "set_alarm",
        "setAlarm",
        "Queue",
        "JobSink",
        "BlobStore",
    ];
    // The object class answers its own `fetch` handler; that is the way
    // in, not a request out.
    let allowed_lines = ["async fn fetch(&self", "One `POST` per call"];
    // The alarm (rules 4 and 8) is the one place that sends to a queue
    // and arms the alarm; it holds no key and opens no socket either.
    let alarm_file = "alarm.rs";
    let alarm_words = ["set_alarm", "setAlarm", "Queue"];
    let mut seen = 0;
    for dir in &dirs {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "rs" | "js") {
                continue;
            }
            seen += 1;
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                if allowed_lines.iter().any(|a| line.contains(a)) {
                    continue;
                }
                for word in forbidden {
                    let in_alarm = path.file_name().and_then(|f| f.to_str()) == Some(alarm_file)
                        && path
                            .parent()
                            .is_some_and(|d| d.ends_with("workers/unit/src"));
                    if in_alarm && alarm_words.contains(&word) {
                        continue;
                    }
                    assert!(
                        !line.contains(word),
                        "{}:{}: `{word}` in the unit's code: {line}",
                        path.display(),
                        n + 1
                    );
                }
            }
        }
    }
    assert!(seen >= 10, "the unit's files were found ({seen})");
}

/// Rule 11 under the workerd twin. The twin sends each statement of a
/// call as a request of its own, and the object's connection may not
/// live across requests: workerd evicts an object idle for about 10 s
/// (a host stall between two statements of one call is enough), and the
/// twin's rebuild empties it; either way its `total_changes()` restarts.
/// A read-only call whose object restarts between its two counter reads
/// is still answered, not refused as `wrote_without_authentication`: the
/// twin's counters are SQLite's, whose savepoint spans the call
/// (`testkit_shadow.rs`). Without that, this test is refused under the
/// twin as primary (`SUITE_PRIMARY=do`, the default); with SQLite as
/// primary, or without a twin, it passes either way.
#[test]
fn a_read_only_call_is_answered_when_the_twins_object_restarts_inside_it() {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply("CREATE TABLE t (n INTEGER NOT NULL)").unwrap();
    for n in 0..3 {
        let changed = poll_once(db.exec("INSERT INTO t (n) VALUES (?1)", &[SqlValue::Int(n)]))
            .unwrap()
            .unwrap();
        assert_eq!(changed, 1);
    }
    // Five rows changed and one left: the copy the rebuild writes changes
    // fewer rows than the connection had counted.
    assert_eq!(
        poll_once(db.exec("DELETE FROM t WHERE n < 2", &[]))
            .unwrap()
            .unwrap(),
        2
    );
    let before = db.twin_total_changes();
    let mut after = None;
    let mut op = || {
        after = db.restart_twin();
        let rows = poll_once(db.query("SELECT count(*) FROM t", &[]))??;
        Ok(Ok(match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(n)) => json!(n),
            other => json!(format!("{other:?}")),
        }))
    };
    let out = transact(&db, false, &mut op).unwrap();
    assert_eq!(out, Ok(json!(1)));
    // Under the twin the object's own counter moved with no write of the
    // call: the case the refusal must not see.
    if let (Some(b), Some(a)) = (before, after) {
        assert_ne!(a, b, "the twin's counter did not restart");
    }
    assert_eq!(before.is_some(), after.is_some());
}
