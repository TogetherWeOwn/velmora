// NON-AUTHORITATIVE / NOT INSTALLED. Maps the frozen contract types onto the
// detached inert model; it holds no state or rules of its own.
#[path = "../../src/provider_authority_store.rs"]
mod store;

use super::contract as c;

#[derive(Debug)]
pub struct Adapter(store::AuthorityStore);

pub fn new(env: &str) -> Adapter {
    Adapter(store::AuthorityStore::new(env))
}

fn denial(d: store::Denial) -> c::Denial {
    match d {
        store::Denial::Denied => c::Denial::Denied,
        store::Denial::Unavailable => c::Denial::Unavailable,
        store::Denial::Replay => c::Denial::Replay,
        store::Denial::Conflict => c::Denial::Conflict,
        store::Denial::Expired => c::Denial::Expired,
        store::Denial::Unsupported => c::Denial::Unsupported,
    }
}

fn state(s: store::State) -> c::State {
    match s {
        store::State::Frozen => c::State::Frozen,
        store::State::Reserved => c::State::Reserved,
        store::State::Consumed => c::State::Consumed,
        store::State::Failed => c::State::Failed,
        store::State::Revoked => c::State::Revoked,
        store::State::Expired => c::State::Expired,
    }
}

fn selection_in(s: &c::Selection) -> store::Selection {
    match s {
        c::Selection::All => store::Selection::All,
        c::Selection::Range {
            start,
            end_exclusive,
        } => store::Selection::Range {
            start: *start,
            end_exclusive: *end_exclusive,
        },
    }
}

fn selection_out(s: &store::Selection) -> c::Selection {
    match s {
        store::Selection::All => c::Selection::All,
        store::Selection::Range {
            start,
            end_exclusive,
        } => c::Selection::Range {
            start: *start,
            end_exclusive: *end_exclusive,
        },
    }
}

fn origin_in(o: &c::Origin) -> store::Origin {
    store::Origin {
        env: o.env.clone(),
        play_intent_id: o.play_intent_id.clone(),
        authorization_id: o.authorization_id.clone(),
        playback_request_id: o.playback_request_id.clone(),
        owner: o.owner.clone(),
        pool_owner: o.pool_owner.clone(),
        track_id: o.track_id.clone(),
        session_id: o.session_id.clone(),
        session_epoch: o.session_epoch,
        user_epoch: o.user_epoch,
        library_epoch: o.library_epoch,
        track_epoch: o.track_epoch,
        material_epoch: o.material_epoch,
        grant_digest: o.grant_digest.clone(),
        grant_expires_at: o.grant_expires_at,
        metadata_contract: o.metadata_contract.clone(),
        admission_id: o.admission_id.clone(),
        publication_id: o.publication_id.clone(),
        manifest_id: o.manifest_id.clone(),
        manifest_revision: o.manifest_revision,
        manifest_digest: o.manifest_digest.clone(),
        source: store::Source {
            job_id: o.source.job_id.clone(),
            job_generation: o.source.job_generation,
            source_selection_id: o.source.source_selection_id.clone(),
            selection_version: o.source.selection_version,
            plan_digest: o.source.plan_digest.clone(),
            audio_ordinal: o.source.audio_ordinal,
        },
        material_ref: store::Material {
            material_id: o.material_ref.material_id.clone(),
            material_version: o.material_ref.material_version,
            algorithm: o.material_ref.algorithm.clone(),
        },
        selection: selection_in(&o.selection),
        issued_at: o.issued_at,
        hard_deadline: o.hard_deadline,
        plan_digest: o.plan_digest.clone(),
    }
}

fn origin_out(o: &store::Origin) -> c::Origin {
    c::Origin {
        env: o.env.clone(),
        play_intent_id: o.play_intent_id.clone(),
        authorization_id: o.authorization_id.clone(),
        playback_request_id: o.playback_request_id.clone(),
        owner: o.owner.clone(),
        pool_owner: o.pool_owner.clone(),
        track_id: o.track_id.clone(),
        session_id: o.session_id.clone(),
        session_epoch: o.session_epoch,
        user_epoch: o.user_epoch,
        library_epoch: o.library_epoch,
        track_epoch: o.track_epoch,
        material_epoch: o.material_epoch,
        grant_digest: o.grant_digest.clone(),
        grant_expires_at: o.grant_expires_at,
        metadata_contract: o.metadata_contract.clone(),
        admission_id: o.admission_id.clone(),
        publication_id: o.publication_id.clone(),
        manifest_id: o.manifest_id.clone(),
        manifest_revision: o.manifest_revision,
        manifest_digest: o.manifest_digest.clone(),
        source: c::Source {
            job_id: o.source.job_id.clone(),
            job_generation: o.source.job_generation,
            source_selection_id: o.source.source_selection_id.clone(),
            selection_version: o.source.selection_version,
            plan_digest: o.source.plan_digest.clone(),
            audio_ordinal: o.source.audio_ordinal,
        },
        material_ref: c::Material {
            material_id: o.material_ref.material_id.clone(),
            material_version: o.material_ref.material_version,
            algorithm: o.material_ref.algorithm.clone(),
        },
        selection: selection_out(&o.selection),
        issued_at: o.issued_at,
        hard_deadline: o.hard_deadline,
        plan_digest: o.plan_digest.clone(),
    }
}

fn action_in(a: &c::Action) -> store::Action {
    store::Action {
        ordinal: a.ordinal,
        manifest_ordinal: a.manifest_ordinal,
        message_id_sha256: a.message_id_sha256.clone(),
        decoded_offset: a.decoded_offset,
        decoded_length: a.decoded_length,
        decoded_sha256: a.decoded_sha256.clone(),
        wire_max_bytes: a.wire_max_bytes,
    }
}

fn action_out(a: &store::Action) -> c::Action {
    c::Action {
        ordinal: a.ordinal,
        manifest_ordinal: a.manifest_ordinal,
        message_id_sha256: a.message_id_sha256.clone(),
        decoded_offset: a.decoded_offset,
        decoded_length: a.decoded_length,
        decoded_sha256: a.decoded_sha256.clone(),
        wire_max_bytes: a.wire_max_bytes,
    }
}

fn call_in(call: &c::Call) -> store::Call {
    store::Call {
        resolver_role: call.resolver_role.clone(),
        stream_role: call.stream_role.clone(),
        env: call.env.clone(),
        owner: call.owner.clone(),
        actual_pool_owner: call.actual_pool_owner.clone(),
        purpose: call.purpose.clone(),
        operation: call.operation.clone(),
        evidence: match call.evidence {
            c::Evidence::SyntheticVerified => store::Evidence::SyntheticVerified,
            c::Evidence::RawUserSelector => store::Evidence::RawUserSelector,
            c::Evidence::ReusedPlayGrant => store::Evidence::ReusedPlayGrant,
        },
        authoritative: call.authoritative,
        rollback_detected: call.rollback_detected,
        now: call.now,
    }
}

fn nonce_in(n: &c::Nonce) -> store::Nonce {
    store::Nonce {
        env: n.env.clone(),
        caller: n.caller.clone(),
        kid: n.kid.clone(),
        kv: n.kv,
        nonce: n.nonce.clone(),
    }
}

impl c::Model for Adapter {
    fn freeze(&mut self, seed: c::Seed) -> Result<(), c::Denial> {
        self.0
            .freeze(store::Seed {
                origin: origin_in(&seed.origin),
                actions: seed.actions.iter().map(action_in).collect(),
                content_steps: seed
                    .content_steps
                    .iter()
                    .map(|s| store::ContentStep {
                        step_id: s.step_id.clone(),
                        action_ordinal: s.action_ordinal,
                    })
                    .collect(),
                connection_steps: seed
                    .connection_steps
                    .iter()
                    .map(|s| store::ConnectionStep {
                        step_id: s.step_id.clone(),
                        pair: s.pair,
                        operation: s.operation.clone(),
                    })
                    .collect(),
                scope_id: seed.scope_id,
                jti: seed.jti,
                issuer: seed.issuer,
                cnf_kid: seed.cnf_kid,
                cnf_kv: seed.cnf_kv,
                provider_version: seed.provider_version,
                owner_epoch: seed.owner_epoch,
                permission_epoch: seed.permission_epoch,
                policy_version: seed.policy_version,
                cap_expires_at: seed.cap_expires_at,
                material_lease_until: seed.material_lease_until,
                replacement_used: seed.replacement_used,
            })
            .map_err(denial)
    }

    fn record_nonce(&mut self, nonce: c::Nonce, now: c::Time) -> Result<(), c::Denial> {
        self.0.record_nonce(nonce_in(&nonce), now).map_err(denial)
    }

    fn reserve(
        &mut self,
        origin: &c::Id,
        jti: &c::Id,
        call: c::Call,
        nonce: c::Nonce,
    ) -> Result<c::Reservation, c::Denial> {
        self.0
            .reserve(origin, jti, call_in(&call), nonce_in(&nonce))
            .map(|r| c::Reservation {
                reservation_id: r.reservation_id,
                until: r.until,
            })
            .map_err(denial)
    }

    fn first_finalize(&mut self, request: c::Finalize) -> Result<c::Delivery, c::Denial> {
        self.0
            .first_finalize(store::FinalizeRequest {
                reservation_id: request.reservation_id,
                call: call_in(&request.call),
                intent_ack: request.intent_ack,
                terminal_ack: request.terminal_ack,
                interleave: request.interleave.map(|(phase, writer)| {
                    let phase = match phase {
                        c::Phase::Unwrapped => store::Phase::Unwrapped,
                        c::Phase::IntentAcked => store::Phase::IntentAcked,
                        c::Phase::TerminalAcked => store::Phase::TerminalAcked,
                    };
                    (phase, writer)
                }),
            })
            .map(|d| c::Delivery {
                lease_id: d.lease_id,
                until: d.until,
            })
            .map_err(denial)
    }

    fn invalidate(
        &mut self,
        origin: &c::Id,
        writer: &'static str,
        now: c::Time,
    ) -> Result<(), c::Denial> {
        self.0.invalidate(origin, writer, now).map_err(denial)
    }

    fn inspect(&self, origin: &c::Id) -> Option<c::View> {
        let v = self.0.inspect(origin)?;
        Some(c::View {
            origin: origin_out(&v.origin),
            actions: v.actions.iter().map(action_out).collect(),
            content_steps: v
                .content_steps
                .iter()
                .map(|s| c::ContentStep {
                    step_id: s.step_id.clone(),
                    action_ordinal: s.action_ordinal,
                })
                .collect(),
            connection_steps: v
                .connection_steps
                .iter()
                .map(|s| c::ConnectionStep {
                    step_id: s.step_id.clone(),
                    pair: s.pair,
                    operation: s.operation.clone(),
                })
                .collect(),
            state: state(v.state),
            replacement_used: v.replacement_used,
            lease_until: v.lease_until,
            deliveries: v.deliveries,
            outbox: v.outbox,
            closed_at: v.closed_at,
            retain_until: v.retain_until,
            synchronous_fenced: v.synchronous_fenced,
        })
    }

    fn unsupported(&mut self, operation: &str) -> Result<(), c::Denial> {
        self.0.unsupported(operation).map_err(denial)
    }
}
