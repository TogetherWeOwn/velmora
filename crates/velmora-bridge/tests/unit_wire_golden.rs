//! The golden JSON of the unit's wire format (`docs/units.md`, "The
//! calls are JSON"; amendment AM-5).
//!
//! One sample of every variant of `UnitOp` and `UnitAnswer` (and of the
//! refusals), serialised, must equal `tests/golden/unit-wire.json` byte
//! for byte, and must read back to the same value. After the class is
//! bound (stage C(b)) these types only gain fields, in two deploys,
//! reader first: a change to this file is then a format change, made on
//! purpose. The `kind` functions are exhaustive matches, so a new variant
//! does not compile until it has a sample here.
//!
//! To write the file after a deliberate change: `UNIT_WIRE_GOLDEN=write`.

use serde_json::{json, Value};
use velmora_bridge::unit::buckets::{BucketChange, BucketRefusal};
use velmora_bridge::unit::call::{Closed, HoldMode};
use velmora_bridge::unit::export::{ExportMode, ExportRefusal, ExportTable, KeyTable};
use velmora_bridge::unit::identity::Refusal as IdentityRefusal;
use velmora_bridge::unit::identity::Refusal;
use velmora_bridge::unit::import::{
    ImportBatch, ImportCount, ImportRefusal, ImportTable, ImportValue, MoveHead,
};
use velmora_bridge::unit::jobcall::JobCall;
use velmora_bridge::unit::keys::{
    Access, ApplyEntry, KeptAnswer, KeyEntry, KeyGrant, KeyKind, KeyMarker, KeyRefusal, MarkerKind,
    SubjectStatus,
};
use velmora_bridge::unit::lift::{
    AckClass, ClassProof, FindingList, GateRefusal, GateSummary, LiftProof, ReplayId, ReportKind,
};
use velmora_bridge::unit::recount::{RecountCall, RecountRefusal};
use velmora_bridge::unit::request::{
    PresignRefusal, Presigned, Published, RecordWire, RequestCall, RequestRefusal,
};
use velmora_bridge::unit::reserve::{
    Acting, Admit, Binding, Hash32, Opening, PrincipalView, ReserveRefusal, Rid,
};
use velmora_bridge::unit::restore::{Bookmark, RestoreRefusal, RestoreTarget};
use velmora_bridge::unit::size::SizeRefusal;
use velmora_bridge::unit::UnitReply;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, ProvisionRefusal, Reader, Refused, Seqs, SyncHead, TenantId,
    TenantState, UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_lease::lease::{LeaseRefusal, Proven};
use velmora_bridge::{
    BucketId, CommitGeneration, CompleteUpload, CopyGeneration, ExtentId, ExtentPlacement,
    ExtentRow, ExtentState, GenerationId, GenerationRow, GenerationState, Job, Lease, ListQuery,
    OutboxStage, Precondition, SafetyState, UnixMs, UploadId, UploadListQuery, UploadPartRow,
    UploadRow, UploadState, WriteId, JOB_VERSION,
};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/unit-wire.json");

fn name() -> UnitName {
    UnitName::new(TenantId::parse("t_00000000000000f1").unwrap(), 0)
}

fn seqs() -> Seqs {
    Seqs {
        state_seq: 7,
        keys_seq: 3,
    }
}

fn rid() -> ReplayId {
    ReplayId {
        since: 7,
        ordinal: 4,
        nonce: "n1".into(),
    }
}

fn token() -> BirthToken {
    BirthToken {
        name: name(),
        jurisdiction: "eu".into(),
        record_seq: 7,
        schema_version: 26,
        key_scheme: 2,
        kind: BirthKind::Restore,
    }
}

/// Exhaustive: a new operation does not compile without a sample.
fn op_kind(op: &UnitOp) -> &'static str {
    match op {
        UnitOp::Provision { .. } => "provision",
        UnitOp::Sync { .. } => "sync",
        UnitOp::Renew { .. } => "renew",
        UnitOp::Ping {} => "ping",
        UnitOp::KeyRow { .. } => "key_row",
        UnitOp::ApplyKeys { .. } => "apply_keys",
        UnitOp::HeldKeys {} => "held_keys",
        UnitOp::Import { .. } => "import",
        UnitOp::ImportProgress {} => "import_progress",
        UnitOp::ImportSeal { .. } => "import_seal",
        UnitOp::Export { .. } => "export",
        UnitOp::RestorePrepare { .. } => "restore_prepare",
        UnitOp::Restore { .. } => "restore",
        UnitOp::GateOpen { .. } => "gate_open",
        UnitOp::GateOpenMove { .. } => "gate_open_move",
        UnitOp::GateReport { .. } => "gate_report",
        UnitOp::GateBlockers { .. } => "gate_blockers",
        UnitOp::GateAck { .. } => "gate_ack",
        UnitOp::GateStatus {} => "gate_status",
        UnitOp::Recount { .. } => "recount",
        UnitOp::Reserve { .. } => "reserve",
        UnitOp::ResolveActing { .. } => "resolve_acting",
        UnitOp::Release { .. } => "release",
        UnitOp::BindBucket { .. } => "bind_bucket",
        UnitOp::ReleaseBound { .. } => "release_bound",
        UnitOp::BucketBinding { .. } => "bucket_binding",
        UnitOp::BucketClose { .. } => "bucket_close",
        UnitOp::Job { .. } => "job",
        UnitOp::Request { .. } => "request",
        UnitOp::ReadPlan { .. } => "read_plan",
    }
}

/// Exhaustive: a new request call does not compile without a sample.
fn request_kind(c: &RequestCall) -> &'static str {
    match c {
        RequestCall::access_key { .. }
        | RequestCall::grant { .. }
        | RequestCall::bucket_by_name { .. }
        | RequestCall::buckets_for { .. }
        | RequestCall::bucket_in_use { .. }
        | RequestCall::live_object { .. }
        | RequestCall::live_generation { .. }
        | RequestCall::generation_by_id { .. }
        | RequestCall::extents_in { .. }
        | RequestCall::newest_id { .. }
        | RequestCall::unpublished_floor { .. }
        | RequestCall::key_heads { .. }
        | RequestCall::list { .. }
        | RequestCall::list_heads { .. }
        | RequestCall::object_status { .. }
        | RequestCall::replay_probe { .. }
        | RequestCall::restore_pending {}
        | RequestCall::articles { .. }
        | RequestCall::touch_read { .. }
        | RequestCall::record_cache_fill { .. }
        | RequestCall::upload { .. }
        | RequestCall::upload_state { .. }
        | RequestCall::list_uploads { .. }
        | RequestCall::upload_extents { .. }
        | RequestCall::upload_extents_held { .. }
        | RequestCall::outbox_stats {}
        | RequestCall::intent_stats { .. }
        | RequestCall::usage_counters {}
        | RequestCall::usage_snapshot { .. }
        | RequestCall::usage_buckets { .. }
        | RequestCall::usage_recounts {}
        | RequestCall::hot_stats {}
        | RequestCall::hot_seq { .. }
        | RequestCall::commit_generation { .. }
        | RequestCall::commit_sliced { .. }
        | RequestCall::copy_generation { .. }
        | RequestCall::open_intents { .. }
        | RequestCall::intents_generation { .. }
        | RequestCall::abandon_intents { .. }
        | RequestCall::raise_floor { .. }
        | RequestCall::settle_floor { .. }
        | RequestCall::raise_floors { .. }
        | RequestCall::settle_floors { .. }
        | RequestCall::delete_object_before { .. }
        | RequestCall::delete_object_if { .. }
        | RequestCall::delete_objects_before { .. }
        | RequestCall::create_upload { .. }
        | RequestCall::put_upload_part { .. }
        | RequestCall::put_upload_part_sliced { .. }
        | RequestCall::complete_upload { .. }
        | RequestCall::abort_upload { .. }
        | RequestCall::unmark_sent { .. }
        | RequestCall::fence_upload { .. } => c.name(),
    }
}

/// Exhaustive: a new answer does not compile without a sample.
fn answer_kind(a: &UnitAnswer) -> &'static str {
    match a {
        UnitAnswer::Ok { .. } => "ok",
        UnitAnswer::SyncNeeded { .. } => "sync_needed",
        UnitAnswer::Stale { .. } => "stale",
        UnitAnswer::RenewNeeded { .. } => "renew_needed",
        UnitAnswer::KeysBehind { .. } => "keys_behind",
        UnitAnswer::Refused { .. } => "refused",
        UnitAnswer::UndoBookmark { .. } => "undo_bookmark",
        UnitAnswer::Unborn { .. } => "unborn",
        UnitAnswer::Closed { .. } => "closed",
        UnitAnswer::Failed { .. } => "failed",
    }
}

/// Exhaustive over the refusal reasons.
fn refused_kind(r: &Refused) -> &'static str {
    match r {
        Refused::Identity(_) => "identity",
        Refused::Provision(_) => "provision",
        Refused::Unauthenticated => "unauthenticated",
        Refused::WroteWithoutAuthentication => "wrote_without_authentication",
        Refused::AwaitedInside => "awaited_inside",
        Refused::StaleSync => "stale_sync",
        Refused::KeysNotApplied => "keys_not_applied",
        Refused::AccountProblem => "account_problem",
        Refused::AccessDenied => "access_denied",
        Refused::NotFound => "not_found",
        Refused::Keys(_) => "keys",
        Refused::Import(_) => "import",
        Refused::Restore(_) => "restore",
        Refused::Gate(_) => "gate",
        Refused::Export(_) => "export",
        Refused::Recount(_) => "recount",
        Refused::Reserve(_) => "reserve",
        Refused::Size(_) => "size",
        Refused::Buckets(_) => "buckets",
        Refused::Request(_) => "request",
    }
}

fn ops() -> Vec<UnitOp> {
    vec![
        UnitOp::Provision {
            token: token(),
            sealed: vec![1, 2, 3],
        },
        UnitOp::Sync {
            head: SyncHead {
                seqs: seqs(),
                tenant_state: TenantState::Suspended,
                tenant_mode: Some(HoldMode::ReadOnly),
                restoring_since: None,
                lift: Some(LiftProof {
                    replay_id: rid(),
                    acknowledged: [(
                        AckClass::Damaged,
                        ClassProof {
                            count: 1,
                            sha256: "ab".into(),
                        },
                    )]
                    .into(),
                }),
            },
        },
        UnitOp::Renew {
            proof_start: UnixMs(1_795_000_000_000),
            proven: Proven {
                state_seq: 7,
                keys_seq: 3,
                stamp_counter: Some(12),
                revoked: 2,
            },
            revocations: vec!["AKGOLDEN000000000001".into(), "AKGOLDEN000000000002".into()],
        },
        UnitOp::Ping {},
        UnitOp::KeyRow {
            access_key_id: "AKGOLDEN000000000001".into(),
            presigned: None,
        },
        UnitOp::KeyRow {
            access_key_id: "AKGOLDENINTERNAL0001".into(),
            presigned: Some(Presigned {
                principal: "p_1".into(),
                bucket: "alpha".into(),
                create_only: true,
            }),
        },
        UnitOp::ApplyKeys {
            from_seq: 2,
            entries: vec![
                ApplyEntry::Key(KeyEntry {
                    id: "AKGOLDEN000000000001".into(),
                    kind: KeyKind::S3,
                    status: SubjectStatus::Active,
                    held: false,
                    made_by: Some("p_1".into()),
                    grants: vec![KeyGrant {
                        bucket_id: "b_00000000000000f1".into(),
                        access: Access::Ro,
                        expires_at: Some(9),
                        prefix: Some("a/".into()),
                        ip_list: vec!["192.0.2.0/24".into()],
                    }],
                    created_at: 5,
                    secret_wrapped: Some(vec![2, 9]),
                    secret_kek_version: Some(1),
                    owner_ref: Some("m_1".into()),
                    last_seq: 3,
                    rid: Some(Rid([0x11; 16])),
                }),
                // AM-62: the records that change no subject.
                ApplyEntry::Marker(KeyMarker {
                    marker: MarkerKind::KeysFrozen,
                    seq: 4,
                }),
                ApplyEntry::Marker(KeyMarker {
                    marker: MarkerKind::KeysThawed,
                    seq: 5,
                }),
            ],
            answers: vec![KeptAnswer {
                rid: Rid([0x11; 16]),
                status: 201,
                body: r#"{"id":"AKGOLDEN000000000001","secret_access_key":null}"#.into(),
            }],
        },
        UnitOp::HeldKeys {},
        UnitOp::Import {
            head: MoveHead {
                seq: 11,
                selector: "moving".into(),
                to: Some(name().tenant),
                flips: 0,
            },
            since: 7,
            batch: ImportBatch {
                table: ImportTable::UsageHours,
                columns: ImportTable::UsageHours
                    .columns()
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
                after: Some("c1".into()),
                cursor: "c2".into(),
                rows: vec![vec![
                    ImportValue::Int(1),
                    ImportValue::Null,
                    ImportValue::Text("t".into()),
                    ImportValue::Blob(vec![255]),
                    ImportValue::Int(0),
                    ImportValue::Int(0),
                ]],
            },
        },
        UnitOp::ImportProgress {},
        UnitOp::ImportSeal {
            head: MoveHead {
                seq: 12,
                selector: "moving".into(),
                to: Some(name().tenant),
                flips: 1,
            },
            since: 7,
            tables: vec![ImportCount {
                table: ImportTable::Objects,
                rows: 2,
            }],
        },
        UnitOp::Export {
            table: ExportTable::Data(ImportTable::Objects),
            after: Some(vec![
                ImportValue::Text("b_00000000000000f1".into()),
                ImportValue::Text("a/b".into()),
            ]),
            limit: 500,
            mode: ExportMode::Rows,
        },
        UnitOp::Export {
            table: ExportTable::Keys(KeyTable::UnitKeyGrants),
            after: None,
            limit: 100,
            mode: ExportMode::Hash,
        },
        UnitOp::RestorePrepare { since: 7 },
        UnitOp::Restore {
            token: token(),
            target: RestoreTarget::Time { at_ms: 1_000 },
            expect_undo: Bookmark("bm-1".into()),
            floor_ms: 900,
        },
        UnitOp::Restore {
            token: token(),
            target: RestoreTarget::Bookmark {
                bookmark: Bookmark("bm-0".into()),
            },
            expect_undo: Bookmark("bm-1".into()),
            floor_ms: 0,
        },
        UnitOp::GateOpen { replay_id: rid() },
        UnitOp::GateOpenMove {
            replay_id: rid(),
            head: MoveHead {
                seq: 12,
                selector: "moving".into(),
                to: Some(name().tenant),
                flips: 1,
            },
        },
        UnitOp::GateReport {
            replay_id: rid(),
            summary: GateSummary {
                complete: true,
                damaged_total: 1,
                other_bucket_total: 0,
                held_missing_total: 2,
                classified: true,
                lists: [(
                    FindingList::Damaged,
                    ClassProof {
                        count: 1,
                        sha256: "cd".into(),
                    },
                )]
                .into(),
            },
        },
        UnitOp::GateBlockers {
            replay_id: rid(),
            list: FindingList::HeldMissingLive,
            ids: vec!["x_1".into()],
        },
        UnitOp::GateAck {
            replay_id: rid(),
            class: AckClass::Damaged,
            ids: vec!["g_1".into()],
        },
        UnitOp::GateStatus {},
        UnitOp::Recount {
            call: RecountCall::Start {},
            head: None,
        },
        UnitOp::Recount {
            call: RecountCall::Step { chunk: 500 },
            head: Some(MoveHead {
                seq: 11,
                selector: "moving".into(),
                to: Some(name().tenant),
                flips: 0,
            }),
        },
        UnitOp::Reserve {
            key_hash: Hash32([0x22; 32]),
            fingerprint: Hash32([0x33; 32]),
            rid: Rid([0x44; 16]),
            acting: Some(Acting::OwnerRef("m_1".into())),
            opening: Opening::Key {
                kind: KeyKind::S3,
                id: "AKGOLDEN000000000002".into(),
                grants: vec![KeyGrant {
                    bucket_id: "b_00000000000000f1".into(),
                    access: Access::Ro,
                    expires_at: None,
                    prefix: None,
                    ip_list: vec![],
                }],
            },
        },
        UnitOp::Reserve {
            key_hash: Hash32([0x22; 32]),
            fingerprint: Hash32([0x33; 32]),
            rid: Rid([0x45; 16]),
            acting: None,
            opening: Opening::Principal {
                id: "p_2".into(),
                owner_ref: "m_2".into(),
                grants: vec![],
            },
        },
        UnitOp::Reserve {
            key_hash: Hash32([0x22; 32]),
            fingerprint: Hash32([0x33; 32]),
            rid: Rid([0x46; 16]),
            acting: Some(Acting::Principal("p_1".into())),
            opening: Opening::Grants {
                subject: "AKGOLDEN000000000001".into(),
                grants: vec![],
            },
        },
        UnitOp::Reserve {
            key_hash: Hash32([0x22; 32]),
            fingerprint: Hash32([0x33; 32]),
            rid: Rid([0x47; 16]),
            acting: Some(Acting::OwnerRef("m_1".into())),
            opening: Opening::Bucket {
                name: "alpha".into(),
                unit: 0,
            },
        },
        UnitOp::ResolveActing {
            acting: Acting::OwnerRef("m_1".into()),
        },
        UnitOp::Release {
            rid: Rid([0x44; 16]),
        },
        UnitOp::BindBucket {
            rid: Rid([0x47; 16]),
            expected: None,
            grant_seq: 4,
        },
        UnitOp::ReleaseBound {
            rid: Rid([0x47; 16]),
            bound: Some(4),
        },
        UnitOp::BucketBinding { grant_seq: 4 },
        UnitOp::BucketClose {
            bucket_id: "b_00000000000000f1".into(),
        },
        UnitOp::Job {
            call: JobCall::claim {
                extent: ExtentId::new("x_000000000000000000000000f1"),
                generation: GenerationId::new("g_0019a00000000f1f1f1f1f1f1f1f1"),
                stage: OutboxStage::Verify,
                owner: "job-1".into(),
                now: UnixMs(1_000),
            },
        },
        UnitOp::Job {
            call: JobCall::mark_posted_many {
                l: Lease {
                    extent: ExtentId::new("x_000000000000000000000000f1"),
                    generation: GenerationId::new("g_0019a00000000f1f1f1f1f1f1f1f1"),
                    stage: OutboxStage::Post,
                    token: 3,
                    attempts: 1,
                    cursor: 0,
                    claimed_at: UnixMs(900),
                },
                posted: vec![(0, "p0".into())],
                now: UnixMs(1_000),
            },
        },
        UnitOp::Request {
            call: Box::new(RequestCall::live_generation {
                bucket: bucket_id(),
                key: "k".into(),
            }),
        },
        UnitOp::ReadPlan {
            bucket: "alpha".into(),
            key: "k".into(),
            start: 0,
            end: 10,
            access_key_id: Some("AKGOLDEN000000000001".into()),
            reader: Some(Reader::Key {
                access_key_id: "AKGOLDEN000000000001".into(),
            }),
            generation: Some("g_1".into()),
        },
        UnitOp::ReadPlan {
            bucket: "alpha".into(),
            key: "k".into(),
            start: 0,
            end: 0,
            access_key_id: None,
            reader: Some(Reader::Public),
            generation: Some("g_1".into()),
        },
    ]
}

/// Every variant of a field-less enum, as a list and as an exhaustive
/// match: a new variant does not compile until it is listed here.
macro_rules! every {
    ($e:ident: $($v:ident),* $(,)?) => {{
        let all = vec![$($e::$v),*];
        for v in &all {
            match v {
                $($e::$v)|* => {}
            }
        }
        serde_json::to_value(&all).unwrap()
    }};
}

/// `ImportProgress`'s answer body as a real unit gives it (AM-47,
/// AM-67): before any import, and after a lift (`lifted_at` set). The
/// L3 move tool and the restore tool read `lifted_at` from it.
/// `schema_tables` is left out: it lists the unit's tables, so every
/// migration changes it.
fn import_progress_bodies() -> Value {
    use velmora_bridge::testkit::RusqliteSql;
    use velmora_bridge::unit::Unit;
    let now = UnixMs(1_795_000_000_000);
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), name(), "");
    let mut token = token();
    token.jurisdiction = String::new();
    token.schema_version = velmora_bridge::unit::schema::SCHEMA_VERSION;
    token.kind = BirthKind::Birth;
    let call = |op, s: Option<Seqs>| UnitCall {
        name: name(),
        kind: CallKind::Worker,
        seqs: s,
        authenticated: true,
        listed: true,
        op,
    };
    let born = u.handle(
        &call(
            UnitOp::Provision {
                token,
                sealed: b"sealed".to_vec(),
            },
            Some(seqs()),
        ),
        now,
    );
    assert!(matches!(born, UnitAnswer::Ok { .. }), "{born:?}");
    let body = || match u.handle(&call(UnitOp::ImportProgress {}, None), now) {
        UnitAnswer::Ok { mut body, .. } => {
            body.as_object_mut().unwrap().remove("schema_tables");
            body
        }
        other => panic!("{other:?}"),
    };
    let before = body();
    u.sql()
        .with_conn(|c| {
            c.execute(
                "INSERT INTO unit_import_move(id, t0_seq, since_seq, final, move_ordinal, \
                   move_lifted, lifted_at) VALUES (1, 11, 7, 1, 1, 1, ?1)",
                [now.0],
            )
        })
        .unwrap();
    json!({ "never_bound": before, "lifted": body() })
}

fn nested() -> Value {
    json!({
        "call_kind": every!(CallKind: Request, Job, Fanout, Worker),
        "identity_refusal": every!(IdentityRefusal: WrongName, StaleJob, NoNumbers),
        "tenant_state": every!(TenantState: Provisioning, Active, Suspended, Deleting, Shredding, Shredded),
        "hold_mode": every!(HoldMode: ReadOnly, Locked),
        "closed": every!(Closed: Restoring, Provisioning),
        "birth_kind": every!(BirthKind: Birth, Restore),
        "provision_refusal": every!(ProvisionRefusal: BornBefore, NotTheListingRecord, NotRestoring,
            WrongName, WrongScheme, WrongSchema, StaleBirth, AlreadyBorn, NoNumbers),
        "key_kind": every!(KeyKind: S3, AppPassword, Principal, Internal),
        "subject_status": every!(SubjectStatus: Active, Disabled, Revoked),
        "access": every!(Access: Ro, Rw),
        "key_refusal": every!(KeyRefusal: Gap, Malformed),
        "import_refusal": every!(ImportRefusal: NotBound, Shape, OutOfOrder, Sealed,
            CountMismatch),
        "export_refusal": every!(ExportRefusal: NotRestoring, HashOnly, Malformed),
        "export_mode": every!(ExportMode: Hash, Rows),
        "key_table": every!(KeyTable: UnitKeys, UnitKeyGrants),
        "report_kind": every!(ReportKind: Restore, Move),
        "import_table": every!(ImportTable: Buckets, Generations, Objects, Extents,
            GenerationExtents, Articles, Verifications, VerifyRaises, VerifyEscalations, Outbox,
            Uploads, UploadParts, UploadPartExtents, Gc, UsageHours, UsageRecounts),
        "ack_class": every!(AckClass: Damaged, HeldMissing, Unreadable, Unpublishable,
            DamagedUnpublished, Twins, OtherBucket),
        "finding_list": every!(FindingList: Damaged, Unreadable, Unpublishable,
            DamagedUnpublished, Twins, OtherBucket, HeldMissing, HeldMissingLive),
        "gate_refusal": every!(GateRefusal: NotRestoring, NoReport, StampNotLevelled, Closed,
            AckMismatch, CountersOff, ProofMismatch, ListMismatch, Malformed, MoveNotBound,
            ImportNotSealed, MoveNotEmpty),
        "restore_refusal": every!(RestoreRefusal: NotRestoring, WrongToken, LeaseLive,
            LeaseUnknown, TooSoon, Moved, Malformed, NoPointInTime, BeforeMoveLift, MoveNotLifted,
            BeforeBirth),
        "recount_refusal": every!(RecountRefusal: NotRestoring, ImportNotSealed, MoveNotBound),
        "reserve_refusal": every!(ReserveRefusal: CapReached, GrantNotHeld,
            GrantLimitsNotServed, TooManyGrants, ActingPrincipalUnknown,
            ActingPrincipalInactive, ActingPrincipalHeld, OwnerRefAmbiguous,
            BucketAlreadyExists, PrincipalExists, Conflict, InternalKeyRefused, NotFound, BucketNotFound, RidTaken,
            Malformed),
        "size_refusal": every!(SizeRefusal: DatabaseFull, TooManyExtents),
        "bucket_refusal": every!(BucketRefusal: NotEmpty, NotFound, PlacementsOff,
            CreatedConflict, Malformed),
        // AM-57: the bucket changes a `sync` carries (the `sync` arm is
        // L2's; the form is pinned here).
        "bucket_change": serde_json::to_value(vec![
            BucketChange::Created {
                seq: 8,
                bucket_id: "b_00000000000000f1".into(),
                grant_seq: 4,
                creator: "p_1".into(),
                name: "golden".into(),
                bdk_wrapped: vec![2, 7],
                tk_version: 1,
                written_at: 5,
            },
            BucketChange::Dropped {
                seq: 9,
                bucket_id: "b_00000000000000f1".into(),
            },
            BucketChange::Unplaced {
                seq: 10,
                buckets: vec!["b_00000000000000f2".into()],
            },
        ])
        .unwrap(),
        "reservation_bodies": reservation_bodies(),
        "lease_refusal": every!(LeaseRefusal: Restoring, RolledBack, NoLeaseTable, ProofTooOld,
            ProofAhead, NotProven, RevocationsUnapplied, BadList),
        "request_refusal": every!(RequestRefusal: OutOfBounds),
        "presign_refusal": every!(PresignRefusal: NotInternal, KeyInactive, Malformed, PrincipalUnknown,
            PrincipalInactive, PrincipalHeld, NoSuchBucket, NoGrant),
        "published": every!(Published: Applied, Refused, Fenced),
        "precondition": serde_json::to_value(vec![
            Precondition::Absent,
            Precondition::Exists,
            Precondition::Etag("\"e1\"".into()),
        ])
        .unwrap(),
    })
}

fn bucket_id() -> BucketId {
    BucketId::new("b_00000000000000f1")
}

fn gen_id() -> GenerationId {
    GenerationId::new("g_0019a00000000f1f1f1f1f1f1f1f1")
}

fn upload_id() -> UploadId {
    UploadId::new("u_00000000000000f1")
}

fn write_id() -> WriteId {
    WriteId::new("w_00000000000000f1")
}

fn record() -> RecordWire {
    RecordWire {
        generation: gen_id(),
        key: "r/g_0019a00000000f1f1f1f1f1f1f1f1".into(),
    }
}

fn generation_row() -> GenerationRow {
    GenerationRow {
        id: gen_id(),
        bucket_id: bucket_id(),
        key: "k".into(),
        state: GenerationState::Live,
        size: 3,
        etag: "\"e1\"".into(),
        checksum_json: None,
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        extent_count: 1,
        created_at: UnixMs(1_000),
        retired_at: None,
    }
}

fn extent_row() -> ExtentRow {
    ExtentRow {
        id: ExtentId::new("x_000000000000000000000000f1"),
        bucket_id: bucket_id(),
        generation_id: Some(gen_id()),
        state: ExtentState::Committed,
        seq: Some(0),
        plain_offset: Some(0),
        plain_size: 3,
        cipher_size: 19,
        media_header: vec![1, 2],
        key_mode: 1,
        wrapped_file_key: Some(vec![3, 4]),
        plain_md5: [5; 16],
        plain_sha256: [6; 32],
        cipher_sha256: [7; 32],
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: UnixMs(1_000),
    }
}

fn part_row() -> UploadPartRow {
    UploadPartRow {
        upload_id: upload_id(),
        part_number: 1,
        extent_id: ExtentId::new("x_000000000000000000000000f1"),
        size: 3,
        etag: "\"e1\"".into(),
        uploaded_at: UnixMs(1_000),
    }
}

fn list_query() -> ListQuery {
    ListQuery {
        prefix: "p/".into(),
        delimiter: Some("/".into()),
        after: Some("p/a".into()),
        skip_prefix: None,
        max_keys: 1_000,
    }
}

/// One sample of every request call (L1-5).
fn requests() -> Vec<RequestCall> {
    let b = bucket_id;
    let k = || "k".to_string();
    let x = || ExtentId::new("x_000000000000000000000000f1");
    vec![
        RequestCall::access_key {
            akid: "AKGOLDEN000000000001".into(),
        },
        RequestCall::grant {
            akid: "AKGOLDEN000000000001".into(),
            bucket: b(),
        },
        RequestCall::bucket_by_name {
            name: "alpha".into(),
        },
        RequestCall::buckets_for {
            akid: "AKGOLDEN000000000001".into(),
        },
        RequestCall::bucket_in_use { bucket: b() },
        RequestCall::live_object {
            bucket: b(),
            key: k(),
        },
        RequestCall::live_generation {
            bucket: b(),
            key: k(),
        },
        RequestCall::generation_by_id {
            bucket: b(),
            generation: gen_id(),
        },
        RequestCall::extents_in {
            generation: gen_id(),
            start: 0,
            end: 10,
        },
        RequestCall::newest_id {
            bucket: b(),
            key: k(),
        },
        RequestCall::unpublished_floor {
            bucket: b(),
            key: k(),
        },
        RequestCall::key_heads {
            bucket: b(),
            keys: vec![k(), "l".into()],
        },
        RequestCall::list {
            bucket: b(),
            q: list_query(),
        },
        RequestCall::list_heads {
            bucket: b(),
            q: list_query(),
        },
        RequestCall::object_status {
            bucket: b(),
            key: k(),
        },
        RequestCall::replay_probe {
            g: generation_row(),
        },
        RequestCall::restore_pending {},
        RequestCall::articles { extent: x() },
        RequestCall::touch_read {
            extent: x(),
            now: UnixMs(1_000),
            min_gap_ms: 60_000,
            from_cache: true,
        },
        RequestCall::record_cache_fill {
            extent: x(),
            now: UnixMs(1_000),
        },
        RequestCall::upload {
            bucket: b(),
            key: k(),
            upload: upload_id(),
        },
        RequestCall::upload_state {
            bucket: b(),
            key: k(),
            upload: upload_id(),
        },
        RequestCall::list_uploads {
            bucket: b(),
            q: UploadListQuery {
                prefix: "".into(),
                after: Some((k(), Some("u_1".into()))),
                skip_prefix: None,
                limit: 1_000,
            },
        },
        RequestCall::upload_extents {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            limit: 10_001,
        },
        RequestCall::upload_extents_held {
            upload: upload_id(),
            except: 2,
        },
        RequestCall::outbox_stats {},
        RequestCall::intent_stats {
            open_before: UnixMs(1_000),
        },
        RequestCall::usage_counters {},
        RequestCall::usage_snapshot { hours: 24 },
        RequestCall::usage_buckets {
            after: "".into(),
            limit: 200,
        },
        RequestCall::usage_recounts {},
        RequestCall::hot_stats {},
        RequestCall::hot_seq { extent: x() },
        RequestCall::commit_generation {
            c: CommitGeneration {
                generation: generation_row(),
                extents: vec![extent_row()],
                now: UnixMs(1_000),
            },
            condition: Some(Precondition::Absent),
            record: record(),
        },
        RequestCall::commit_sliced {
            c: CommitGeneration {
                generation: generation_row(),
                extents: vec![extent_row()],
                now: UnixMs(1_000),
            },
            write: write_id(),
            condition: None,
            record: record(),
        },
        RequestCall::copy_generation {
            c: CopyGeneration {
                generation: generation_row(),
                source: GenerationId::new("g_0019a00000000e1e1e1e1e1e1e1e1"),
                source_key: "src".into(),
                now: UnixMs(1_000),
            },
            condition: Some(Precondition::Etag("\"e1\"".into())),
            record: record(),
        },
        RequestCall::open_intents {
            write: write_id(),
            extents: vec![x()],
            now: UnixMs(1_000),
        },
        RequestCall::intents_generation {
            write: write_id(),
            generation: gen_id(),
            slices: 2,
        },
        RequestCall::abandon_intents { write: write_id() },
        RequestCall::raise_floor {
            bucket: b(),
            key: k(),
            id: gen_id(),
            generation: true,
        },
        RequestCall::settle_floor {
            bucket: b(),
            key: k(),
            id: gen_id(),
        },
        RequestCall::raise_floors {
            bucket: b(),
            ids: vec![(k(), gen_id())],
        },
        RequestCall::settle_floors {
            bucket: b(),
            ids: vec![(k(), gen_id())],
        },
        RequestCall::delete_object_before {
            bucket: b(),
            key: k(),
            before: gen_id(),
            now: UnixMs(1_000),
        },
        RequestCall::delete_object_if {
            bucket: b(),
            key: k(),
            before: gen_id(),
            condition: Precondition::Exists,
            now: UnixMs(1_000),
        },
        RequestCall::delete_objects_before {
            bucket: b(),
            deletes: vec![(k(), gen_id(), UnixMs(1_000))],
        },
        RequestCall::create_upload {
            u: UploadRow {
                id: upload_id(),
                bucket_id: b(),
                key: k(),
                content_json: "{}".into(),
                user_meta_json: "{}".into(),
                state: UploadState::Open,
                revision: 0,
                completed_generation_id: None,
                complete_digest: None,
                result_etag: None,
                initiated_at: UnixMs(1_000),
            },
        },
        RequestCall::put_upload_part {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            part: part_row(),
            extent: extent_row(),
            now: UnixMs(1_000),
        },
        RequestCall::put_upload_part_sliced {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            part: part_row(),
            extents: vec![extent_row()],
            write: write_id(),
            now: UnixMs(1_000),
        },
        RequestCall::complete_upload {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            revision: 1,
            digest: [9; 32],
            c: CompleteUpload {
                generation: generation_row(),
                placements: vec![ExtentPlacement {
                    extent_id: x(),
                    seq: 0,
                    plain_offset: 0,
                }],
                now: UnixMs(1_000),
            },
            condition: None,
            record: record(),
        },
        RequestCall::abort_upload {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            now: UnixMs(1_000),
        },
        RequestCall::unmark_sent {
            jobs: vec![Job::Extent {
                v: JOB_VERSION,
                extent: x(),
                generation: gen_id(),
                stage: OutboxStage::Post,
            }],
            mark: UnixMs(1_000),
        },
        RequestCall::fence_upload {
            bucket: b(),
            key: k(),
            upload: upload_id(),
            revision: 1,
        },
    ]
}

fn refusals() -> Vec<Refused> {
    vec![
        Refused::Identity(Refusal::WrongName),
        Refused::Provision(ProvisionRefusal::AlreadyBorn),
        Refused::Unauthenticated,
        Refused::WroteWithoutAuthentication,
        Refused::AwaitedInside,
        Refused::StaleSync,
        Refused::KeysNotApplied,
        Refused::AccountProblem,
        Refused::AccessDenied,
        Refused::NotFound,
        Refused::Keys(KeyRefusal::Gap),
        Refused::Import(ImportRefusal::OutOfOrder),
        Refused::Restore(RestoreRefusal::Moved),
        Refused::Gate(GateRefusal::AckMismatch),
        Refused::Export(ExportRefusal::HashOnly),
        Refused::Recount(RecountRefusal::ImportNotSealed),
        Refused::Reserve(ReserveRefusal::GrantLimitsNotServed),
        Refused::Size(SizeRefusal::TooManyExtents),
        Refused::Buckets(BucketRefusal::NotEmpty),
        Refused::Request(RequestRefusal::OutOfBounds),
    ]
}

/// The bodies of the reservation calls' `ok` answers (exhaustive over
/// what an ask and a binding read answer).
fn reservation_bodies() -> Value {
    let principal = PrincipalView {
        id: "p_1".into(),
        status: SubjectStatus::Active,
        held: false,
        grants: vec![],
    };
    let admits = vec![
        Admit::Admitted {
            rid: Rid([0x44; 16]),
            keys_seq: 3,
            again: false,
            scope: Some("p_1".into()),
            bound: None,
            subject: Some("AKGOLDEN000000000002".into()),
            unit: None,
        },
        Admit::Applied {
            status: Some(201),
            body: Some("{}".into()),
            subject: Some("AKGOLDEN000000000002".into()),
            bucket: None,
            grant_seq: None,
        },
        Admit::Reused,
        Admit::Narrowing { keys_seq: 3 },
        Admit::NotOpen { open: None },
        Admit::NotOpen {
            open: Some((Rid([0x44; 16]), 3)),
        },
        Admit::Exists(principal),
        Admit::Refused(ReserveRefusal::CapReached),
        Admit::RefusedDrop(ReserveRefusal::GrantNotHeld, Rid([0x44; 16])),
    ];
    let mut kinds = std::collections::BTreeSet::new();
    for a in &admits {
        kinds.insert(match a {
            Admit::Admitted { .. } => "admitted",
            Admit::Applied { .. } => "applied",
            Admit::Reused => "reused",
            Admit::Narrowing { .. } => "narrowing",
            Admit::NotOpen { .. } => "not_open",
            Admit::Exists(_) => "exists",
            Admit::Refused(_) => "refused",
            Admit::RefusedDrop(..) => "refused_drop",
        });
    }
    assert_eq!(kinds.len(), 8);
    let bindings = [
        Binding::Open {
            rid: Rid([0x47; 16]),
            name: "alpha".into(),
            creator: "p_1".into(),
            unit: 0,
        },
        Binding::Created {
            bucket: "b_00000000000000f1".into(),
        },
        Binding::None,
    ];
    for b in &bindings {
        match b {
            Binding::Open { .. } | Binding::Created { .. } | Binding::None => {}
        }
    }
    json!({
        "admits": admits.iter().map(Admit::body).collect::<Vec<_>>(),
        "bindings": bindings.iter().map(Binding::body).collect::<Vec<_>>(),
    })
}

fn answers() -> Vec<UnitAnswer> {
    let mut out = vec![
        UnitAnswer::Ok {
            seqs: seqs(),
            body: json!({ "synced": 7 }),
        },
        UnitAnswer::SyncNeeded { seqs: seqs() },
        UnitAnswer::Stale { seqs: seqs() },
        UnitAnswer::RenewNeeded {
            seqs: seqs(),
            why: None,
        },
        UnitAnswer::RenewNeeded {
            seqs: seqs(),
            why: Some(LeaseRefusal::ProofTooOld),
        },
        UnitAnswer::KeysBehind { seqs: seqs() },
        UnitAnswer::UndoBookmark {
            seqs: seqs(),
            bookmark: Bookmark("bm-1".into()),
        },
        UnitAnswer::Unborn { listed: true },
        UnitAnswer::Closed {
            seqs: seqs(),
            why: Closed::Restoring,
        },
        UnitAnswer::Failed {
            class: "sql".into(),
        },
    ];
    out.extend(refusals().into_iter().map(|reason| UnitAnswer::Refused {
        reason,
        alarm: false,
    }));
    out
}

/// The answer as it leaves the unit: the answer's object with the
/// lease's time left and, for a unit that holds keys, `revoked`.
fn replies() -> Vec<Value> {
    let samples = [
        UnitReply {
            answer: UnitAnswer::Ok {
                seqs: seqs(),
                body: json!({ "fresh_until": 1_795_000_600_000_i64, "applied": 1 }),
            },
            lease_left_ms: 600_000,
            revoked: Some(2),
        },
        UnitReply {
            answer: UnitAnswer::RenewNeeded {
                seqs: seqs(),
                why: None,
            },
            lease_left_ms: 0,
            revoked: None,
        },
    ];
    samples
        .into_iter()
        .map(|r| {
            let v = serde_json::to_value(&r).unwrap();
            assert_eq!(serde_json::from_value::<UnitReply>(v.clone()).unwrap(), r);
            v
        })
        .collect()
}

fn document() -> Value {
    let calls: Vec<Value> = ops()
        .into_iter()
        .map(|op| {
            let kind = match op {
                UnitOp::Job { .. } => CallKind::Job,
                UnitOp::Request { .. } => CallKind::Request,
                _ => CallKind::Worker,
            };
            let c = UnitCall {
                name: name(),
                kind,
                seqs: Some(seqs()),
                authenticated: true,
                listed: true,
                op,
            };
            // Each reads back to itself.
            let v = serde_json::to_value(&c).unwrap();
            assert_eq!(serde_json::from_value::<UnitCall>(v.clone()).unwrap(), c);
            v
        })
        .collect();
    let answers: Vec<Value> = answers()
        .into_iter()
        .map(|a| {
            let v = serde_json::to_value(&a).unwrap();
            assert_eq!(serde_json::from_value::<UnitAnswer>(v.clone()).unwrap(), a);
            v
        })
        .collect();
    let requests: Vec<Value> = requests()
        .into_iter()
        .map(|call| {
            let c = UnitCall {
                name: name(),
                kind: CallKind::Request,
                seqs: Some(seqs()),
                authenticated: true,
                listed: true,
                op: UnitOp::Request {
                    call: Box::new(call),
                },
            };
            let v = serde_json::to_value(&c).unwrap();
            assert_eq!(serde_json::from_value::<UnitCall>(v.clone()).unwrap(), c);
            v
        })
        .collect();
    json!({
        "calls": calls,
        "answers": answers,
        "replies": replies(),
        "nested": nested(),
        "import_progress": import_progress_bodies(),
        "requests": requests,
    })
}

#[test]
fn every_variant_has_a_sample() {
    let ops: std::collections::BTreeSet<_> = ops().iter().map(op_kind).collect();
    assert_eq!(ops.len(), 30, "{ops:?}");
    let requests: std::collections::BTreeSet<_> = requests().iter().map(request_kind).collect();
    assert_eq!(requests.len(), 53, "{requests:?}");
    let readers: std::collections::BTreeSet<_> = ops_readers().into_iter().collect();
    assert_eq!(readers.len(), 2, "both readers have a sample");
    // The variants that carry data, each with a sample (exhaustive).
    let mut targets = std::collections::BTreeSet::new();
    let mut values = std::collections::BTreeSet::new();
    for op in self::ops() {
        match op {
            UnitOp::Restore { target, .. } => {
                targets.insert(match target {
                    RestoreTarget::Time { .. } => "time",
                    RestoreTarget::Bookmark { .. } => "bookmark",
                });
            }
            UnitOp::Import { batch, .. } => {
                for v in batch.rows.iter().flatten() {
                    values.insert(match v {
                        ImportValue::Null => "n",
                        ImportValue::Int(_) => "i",
                        ImportValue::Text(_) => "t",
                        ImportValue::Blob(_) => "b",
                    });
                }
            }
            _ => {}
        }
    }
    assert_eq!(targets.len(), 2, "{targets:?}");
    assert_eq!(values.len(), 4, "{values:?}");
    let answers: std::collections::BTreeSet<_> = answers().iter().map(answer_kind).collect();
    assert_eq!(answers.len(), 10, "{answers:?}");
    let reasons: std::collections::BTreeSet<_> = refusals().iter().map(refused_kind).collect();
    assert_eq!(reasons.len(), 20, "{reasons:?}");
}

#[test]
fn the_wire_format_is_the_golden_file() {
    let text = serde_json::to_string_pretty(&document()).unwrap() + "\n";
    if std::env::var("UNIT_WIRE_GOLDEN").as_deref() == Ok("write") {
        std::fs::write(GOLDEN, &text).unwrap();
    }
    let golden = std::fs::read_to_string(GOLDEN).expect("tests/golden/unit-wire.json");
    assert_eq!(
        text, golden,
        "the unit wire format changed: see the module doc"
    );
}

fn ops_readers() -> Vec<&'static str> {
    ops()
        .iter()
        .filter_map(|op| match op {
            UnitOp::ReadPlan {
                reader: Some(r), ..
            } => Some(match r {
                Reader::Key { .. } => "key",
                Reader::Public => "public",
            }),
            _ => None,
        })
        .collect()
}
