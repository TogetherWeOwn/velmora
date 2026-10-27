// Independent acceptance: S §§4-8, R §3, P2 §§5,8-10, M2 §§3.5,8.
// NON-AUTHORITATIVE / NOT INSTALLED. No producer, crypto, DB, clock or IO.
use super::{adapter, contract::*};

pub const WRITERS: &[&str] = &[
    "library_remove",
    "playback_session_revoke",
    "session_logout",
    "session_expire",
    "user_disable",
    "user_delete_tombstone",
    "security_epoch_reset",
    "playback_entitlement_remove",
    "import_entitlement_remove",
    "permission_remove",
    "source_withdraw",
    "source_replace",
    "target_source_delete",
    "target_source_replace",
    "track_selection_change",
    "material_replace",
    "material_revoke",
    "provider_update",
    "provider_delete",
    "owner_disable",
    "policy_change",
    "plan_decrease",
    "issuer_key_revoke",
    "caller_key_revoke",
    "import_cancel",
    "import_expire",
    "job_generation_change",
    "probe_attempt_replace",
    "probe_dispatch_invalidate",
    "probe_plan_change",
    "probe_target_change",
    "admitting_session_expire",
];
pub fn id(n: u32) -> Id {
    format!("00000000-0000-4000-8000-{n:012x}")
}
pub fn seed() -> Seed {
    Seed {
        origin: Origin {
            env: "staging".into(),
            play_intent_id: id(1),
            authorization_id: id(2),
            playback_request_id: id(3),
            owner: "synthetic_owner_é".into(),
            pool_owner: "synthetic_owner_é".into(),
            track_id: "synthetic_track".into(),
            session_id: "synthetic_session".into(),
            session_epoch: 1,
            user_epoch: 1,
            library_epoch: 1,
            track_epoch: 1,
            material_epoch: 1,
            grant_digest: "1".repeat(64),
            grant_expires_at: 1900,
            metadata_contract: "nntune.playback-manifest/2".into(),
            admission_id: id(4),
            publication_id: id(5),
            manifest_id: id(6),
            manifest_revision: 1,
            manifest_digest: "2".repeat(64),
            source: Source {
                job_id: "job_0123456789abcdef".into(),
                job_generation: 1,
                source_selection_id: id(7),
                selection_version: 1,
                plan_digest: "3".repeat(64),
                audio_ordinal: 1,
            },
            material_ref: Material {
                material_id: id(8),
                material_version: 1,
                algorithm: "XSalsa20-Poly1305".into(),
            },
            selection: Selection::All,
            issued_at: 1000,
            hard_deadline: 1900,
            plan_digest: "4".repeat(64),
        },
        actions: (0..2)
            .map(|n| Action {
                ordinal: n,
                manifest_ordinal: n,
                message_id_sha256: (5 + n).to_string().repeat(64),
                decoded_offset: u64::from(n) * 32768,
                decoded_length: if n == 0 { 32768 } else { 32833 },
                decoded_sha256: "8".repeat(64),
                wire_max_bytes: 65536,
            })
            .collect(),
        content_steps: (0..2)
            .map(|n| ContentStep {
                step_id: id(20 + n),
                action_ordinal: n as u16,
            })
            .collect(),
        connection_steps: (0..50)
            .flat_map(|n| {
                [
                    ConnectionStep {
                        step_id: id(100 + n * 2),
                        pair: n as u8,
                        operation: "connect".into(),
                    },
                    ConnectionStep {
                        step_id: id(101 + n * 2),
                        pair: n as u8,
                        operation: "checkout".into(),
                    },
                ]
            })
            .collect(),
        scope_id: id(9),
        jti: id(10),
        issuer: "nntune-provider-authority".into(),
        cnf_kid: "synthetic_stream_key_ref".into(),
        cnf_kv: 1,
        provider_version: 1,
        owner_epoch: 1,
        permission_epoch: 1,
        policy_version: 1,
        cap_expires_at: 1030,
        material_lease_until: 1015,
        replacement_used: true,
    }
}
pub fn call() -> Call {
    Call {
        resolver_role: "nntune-vault-provider".into(),
        stream_role: "nntune-stream".into(),
        env: "staging".into(),
        owner: "synthetic_owner_é".into(),
        actual_pool_owner: "synthetic_owner_é".into(),
        purpose: "provider".into(),
        operation: "provider.resolve.play".into(),
        evidence: Evidence::SyntheticVerified,
        authoritative: true,
        rollback_detected: false,
        now: 1000,
    }
}
pub fn nonce(n: u32) -> Nonce {
    Nonce {
        env: "staging".into(),
        caller: "nntune-stream".into(),
        kid: "synthetic_stream_key_ref".into(),
        kv: 1,
        nonce: id(500 + n),
    }
}
fn frozen() -> impl Model {
    let mut m = adapter::new("staging");
    assert_eq!(m.freeze(seed()), Ok(()), "missing inert freeze behavior");
    m
}
fn reserved(m: &mut impl Model) -> Reservation {
    let r = m
        .reserve(&id(1), &id(10), call(), nonce(1))
        .expect("first synthetic reserve");
    assert_eq!(r.until, 1002);
    r
}
fn finalize(r: &Reservation) -> Finalize {
    Finalize {
        reservation_id: r.reservation_id.clone(),
        call: Call {
            now: 1001,
            ..call()
        },
        intent_ack: true,
        terminal_ack: true,
        interleave: None,
    }
}
#[test]
fn freeze_is_immutable_and_mapping_is_one_to_one_in_environment() {
    let mut m = frozen();
    for field in 0..6 {
        let mut s = seed();
        match field {
            0 => s.origin.play_intent_id = id(30),
            1 => s.origin.authorization_id = id(30),
            2 => s.origin.playback_request_id = id(30),
            3 => s.origin.source.job_generation += 1,
            4 => s.origin.material_ref.material_version += 1,
            _ => s.actions[0].decoded_length += 1,
        }
        assert_eq!(m.freeze(s), Err(Denial::Conflict), "field {field}");
    }
    let v = m.inspect(&id(1)).unwrap();
    assert!(v.origin == seed().origin && v.actions == seed().actions);
    // Same owner may have independently authorized later responses, not a user->one-intent map.
    let mut s = seed();
    s.origin.play_intent_id = id(31);
    s.origin.authorization_id = id(32);
    s.origin.playback_request_id = id(33);
    s.scope_id = id(34);
    assert_eq!(
        m.freeze(s.clone()),
        Err(Denial::Conflict),
        "same env/issuer/JTI"
    );
    s.jti = id(35);
    assert_eq!(m.freeze(s), Ok(()));
    let mut prod = adapter::new("production");
    let mut s = seed();
    s.origin.env = "production".into();
    assert_eq!(prod.freeze(s), Ok(()));
    let mut cross = seed();
    cross.origin.env = "production".into();
    assert_eq!(m.freeze(cross), Err(Denial::Denied));
}
#[test]
fn mutual_distinct_ids_and_stable_steps_reject_corruption() {
    for field in 0..7 {
        let mut s = seed();
        match field {
            0 => s.origin.authorization_id = s.origin.play_intent_id.clone(),
            1 => s.origin.playback_request_id = s.origin.authorization_id.clone(),
            2 => s.origin.playback_request_id = s.origin.play_intent_id.clone(),
            3 => s.content_steps[1].step_id = s.content_steps[0].step_id.clone(),
            4 => s.content_steps[1].action_ordinal = 0,
            5 => s.connection_steps[1].step_id = s.connection_steps[0].step_id.clone(),
            _ => s.connection_steps.pop().map(|_| ()).unwrap(),
        }
        assert!(adapter::new("staging").freeze(s).is_err(), "field {field}");
    }
    let m = frozen();
    let v = m.inspect(&id(1)).unwrap();
    assert_eq!(v.content_steps, seed().content_steps);
    assert_eq!(v.connection_steps, seed().connection_steps);
    assert!(v.replacement_used);
}
#[test]
fn replay_key_is_env_caller_kid_kv_nonce_not_a_global_nonce() {
    let mut m = adapter::new("staging");
    let n = nonce(2);
    assert_eq!(m.record_nonce(n.clone(), 1000), Ok(()));
    assert_eq!(m.record_nonce(n.clone(), 1000), Err(Denial::Replay));
    for field in 0..3 {
        let mut other = n.clone();
        match field {
            0 => other.caller = "nntune-vault-provider".into(),
            1 => other.kid = "synthetic_other_key_ref".into(),
            _ => other.kv = 2,
        }
        assert_eq!(m.record_nonce(other, 1000), Ok(()));
    }
    let mut cross = n;
    cross.env = "production".into();
    assert_eq!(m.record_nonce(cross.clone(), 1000), Err(Denial::Denied));
    assert_eq!(adapter::new("production").record_nonce(cross, 1000), Ok(()));
}
#[test]
fn reserve_consumes_replay_nonce_and_jti_at_most_once() {
    let mut m = frozen();
    let r = reserved(&mut m);
    assert!(m.reserve(&id(1), &id(10), call(), nonce(1)).is_err());
    assert!(m.reserve(&id(1), &id(10), call(), nonce(3)).is_err());
    assert_eq!(m.record_nonce(nonce(1), 1001), Err(Denial::Replay));
    assert_eq!(
        m.first_finalize(finalize(&r)),
        Ok(Delivery {
            lease_id: id(10),
            until: 1015
        })
    );
    assert!(m.first_finalize(finalize(&r)).is_err());
    assert!(m.reserve(&id(1), &id(10), call(), nonce(4)).is_err());
    let v = m.inspect(&id(1)).unwrap();
    assert_eq!(v.deliveries, 1);
    assert_eq!(v.state, State::Consumed);
    assert_eq!(v.lease_until, Some(1015));
}
#[test]
fn wrong_authority_never_reserves_even_with_known_ids() {
    for field in 0..11 {
        let mut m = frozen();
        let mut c = call();
        match field {
            0 => c.resolver_role = "nntune-ingest".into(),
            1 => c.stream_role = "nntune-ingest".into(),
            2 => c.owner = "synthetic_other_owner".into(),
            3 => c.actual_pool_owner = "synthetic_other_owner".into(),
            4 => c.env = "production".into(),
            5 => c.purpose = "indexer".into(),
            6 => c.operation = "provider.resolve.probe".into(),
            7 => c.evidence = Evidence::RawUserSelector,
            8 => c.evidence = Evidence::ReusedPlayGrant,
            9 => c.authoritative = false,
            _ => c.rollback_detected = true,
        }
        assert!(
            m.reserve(&id(1), &id(10), c.clone(), nonce(10 + field))
                .is_err(),
            "field {field}"
        );
        assert_eq!(m.inspect(&id(1)).unwrap().deliveries, 0);
        let mut m = frozen();
        let r = reserved(&mut m);
        let mut f = finalize(&r);
        f.call = Call { now: 1001, ..c };
        assert!(m.first_finalize(f).is_err(), "finalize field {field}");
        assert_eq!(m.inspect(&id(1)).unwrap().deliveries, 0);
    }
    let mut m = frozen();
    assert!(m.reserve(&id(999), &id(10), call(), nonce(1)).is_err());
    assert!(m.reserve(&id(1), &id(999), call(), nonce(2)).is_err());
}
#[test]
fn proof_nonce_must_bind_the_frozen_cnf_key_and_stream_caller() {
    for field in 0..4 {
        let mut m = frozen();
        let mut n = nonce(1);
        match field {
            0 => n.kid = "synthetic_other_key_ref".into(),
            1 => n.kv = 2,
            2 => n.caller = "nntune-vault-provider".into(),
            _ => n.env = "production".into(),
        }
        assert!(
            m.reserve(&id(1), &id(10), call(), n).is_err(),
            "field {field}"
        );
        assert_eq!(m.inspect(&id(1)).unwrap().state, State::Frozen);
    }
}
#[test]
fn native_owner_equality_does_not_normalize_or_trim() {
    for owner in [
        "synthetic_owner_e\u{301}",
        "synthetic_owner_é ",
        "SYNTHETIC_OWNER_É",
    ] {
        let mut m = frozen();
        let mut c = call();
        c.owner = owner.into();
        assert!(m.reserve(&id(1), &id(10), c, nonce(1)).is_err());
    }
}
#[test]
fn every_invalidator_orders_before_reserve_and_finalize_and_after_finalize() {
    for &writer in WRITERS {
        let mut m = frozen();
        assert_eq!(m.invalidate(&id(1), writer, 1000), Ok(()));
        assert!(
            m.reserve(&id(1), &id(10), call(), nonce(1)).is_err(),
            "{writer}"
        );
        let mut m = frozen();
        let r = reserved(&mut m);
        assert_eq!(m.invalidate(&id(1), writer, 1001), Ok(()));
        assert!(m.first_finalize(finalize(&r)).is_err(), "{writer}");
        let mut m = frozen();
        let r = reserved(&mut m);
        let d = m.first_finalize(finalize(&r)).unwrap();
        assert_eq!(m.invalidate(&id(1), writer, 1001), Ok(()));
        let v = m.inspect(&id(1)).unwrap();
        assert_eq!(v.deliveries, 1);
        assert_eq!(d.until, 1015);
        assert!(v.synchronous_fenced);
        assert!(m.first_finalize(finalize(&r)).is_err(), "{writer}");
        assert!(v.origin == seed().origin && v.actions == seed().actions);
        assert_eq!(v.content_steps, seed().content_steps);
        assert!(v.replacement_used);
        assert!(v.retain_until.unwrap() >= v.closed_at.unwrap() + 86400);
        assert!(
            m.freeze(seed()).is_err(),
            "tombstone must prevent resurrection: {writer}"
        );
    }
}
#[test]
fn post_unwrap_and_both_post_ack_rereads_cannot_release_stale_state() {
    for phase in [Phase::Unwrapped, Phase::IntentAcked, Phase::TerminalAcked] {
        for &writer in WRITERS {
            let mut m = frozen();
            let r = reserved(&mut m);
            let mut f = finalize(&r);
            f.interleave = Some((phase, writer));
            assert!(m.first_finalize(f).is_err(), "{phase:?}/{writer}");
            let v = m.inspect(&id(1)).unwrap();
            assert_eq!(v.deliveries, 0);
            assert!(v.synchronous_fenced);
            assert!(m.first_finalize(finalize(&r)).is_err());
        }
    }
}
#[test]
fn missing_or_failed_audit_ack_has_no_terminal_success_or_redelivery() {
    for (intent, terminal) in [(false, false), (false, true), (true, false)] {
        let mut m = frozen();
        let r = reserved(&mut m);
        let mut f = finalize(&r);
        f.intent_ack = intent;
        f.terminal_ack = terminal;
        assert!(m.first_finalize(f).is_err());
        assert_eq!(m.inspect(&id(1)).unwrap().deliveries, 0);
        assert!(m.first_finalize(finalize(&r)).is_err());
    }
}
#[test]
fn unknown_reservation_stale_or_rolled_back_finalize_never_succeeds() {
    for field in 0..4 {
        let mut m = frozen();
        let r = reserved(&mut m);
        let mut f = finalize(&r);
        match field {
            0 => f.reservation_id = id(999),
            1 => f.call.authoritative = false,
            2 => f.call.rollback_detected = true,
            _ => f.call.actual_pool_owner = "synthetic_other_owner".into(),
        }
        assert!(m.first_finalize(f).is_err());
        assert_eq!(m.inspect(&id(1)).unwrap().deliveries, 0);
    }
}
#[test]
fn strict_deadlines_and_minimum_remaining_lease_do_not_renew_on_receive() {
    for now in [1002, 1030, 1900] {
        let mut m = frozen();
        let r = reserved(&mut m);
        let mut f = finalize(&r);
        f.call.now = now;
        assert!(
            m.first_finalize(f).is_err(),
            "strict reservation expiry at {now}"
        );
    }
    for (material, cap, hard, want) in [
        (1015, 1030, 1900, 1015),
        (1010, 1030, 1900, 1010),
        (1015, 1012, 1900, 1012),
        (1014, 1014, 1014, 1014),
    ] {
        let mut m = adapter::new("staging");
        let mut s = seed();
        s.material_lease_until = material;
        s.cap_expires_at = cap;
        s.origin.hard_deadline = hard;
        assert_eq!(m.freeze(s), Ok(()));
        let r = reserved(&mut m);
        assert_eq!(
            m.first_finalize(finalize(&r)),
            Ok(Delivery {
                lease_id: id(10),
                until: want
            })
        );
        assert_eq!(m.inspect(&id(1)).unwrap().lease_until, Some(want));
    }
    for (cap, hard) in [(1000, 1900), (1030, 1000)] {
        let mut m = adapter::new("staging");
        let mut s = seed();
        s.cap_expires_at = cap;
        s.origin.hard_deadline = hard;
        assert_eq!(m.freeze(s), Ok(()));
        assert!(
            m.reserve(&id(1), &id(10), call(), nonce(1)).is_err(),
            "strict cap/origin expiry at reserve {cap}/{hard}"
        );
    }
    let mut m = adapter::new("staging");
    let mut s = seed();
    s.material_lease_until = 1003;
    assert_eq!(m.freeze(s), Ok(()));
    let r = reserved(&mut m);
    assert!(
        m.first_finalize(finalize(&r)).is_err(),
        "less than three seconds left"
    );
}
#[test]
fn unsupported_catalogue_cannot_reset_steps_credit_deadline_or_recover_delivery() {
    let mut m = frozen();
    for op in [
        "issuance",
        "replacement",
        "advance",
        "step-admission",
        "producer",
        "crypto",
        "probe-producer",
        "discovery",
        "material-renewal",
        "recover-delivery",
        "purge-tombstone",
    ] {
        assert_eq!(m.unsupported(op), Err(Denial::Unsupported), "{op}");
    }
    let v = m.inspect(&id(1)).unwrap();
    assert!(v.replacement_used);
    assert_eq!(v.origin.hard_deadline, 1900);
    assert_eq!(v.deliveries, 0);
    assert_eq!(v.content_steps, seed().content_steps);
    assert_eq!(v.connection_steps, seed().connection_steps);
}
#[test]
fn audit_outbox_is_closed_allowlist_and_debug_is_not_an_identity_or_bearer_dump() {
    let mut m = frozen();
    let r = reserved(&mut m);
    m.first_finalize(finalize(&r)).unwrap();
    let v = m.inspect(&id(1)).unwrap();
    assert!(!v.outbox.is_empty());
    let allowed = [
        "event_id",
        "request_id",
        "authorization_id",
        "attempt_id",
        "publication_id",
        "timestamp",
        "environment",
        "role",
        "purpose",
        "contract_version",
        "outcome",
        "reason",
        "revision",
        "generation",
        "count_bucket",
        "latency_bucket",
    ];
    for event in &v.outbox {
        assert!(!event.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for (key, _) in event {
            assert!(allowed.contains(&key.as_str()), "outbox field {key}");
            assert!(seen.insert(key), "duplicate outbox field");
        }
    }
    let rendered = format!("{m:?} {:?}", v.outbox);
    for forbidden in [
        "synthetic_owner",
        "synthetic_track",
        "synthetic_session",
        "job_0123",
        "synthetic_stream_key_ref",
        &"1".repeat(64),
        &"3".repeat(64),
        &"4".repeat(64),
    ] {
        assert!(
            !rendered.contains(forbidden),
            "sensitive observability: {forbidden}"
        );
    }
}
