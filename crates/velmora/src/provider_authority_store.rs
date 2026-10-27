//! NON-AUTHORITATIVE / NOT INSTALLED.
//!
//! Inert, deterministic model of the provider authority-store records and the
//! synchronous invalidation fence. It is deliberately NOT declared in `lib.rs`,
//! has no production caller or re-export, performs no input or output, and is
//! reachable only from the acceptance adapter. It models record shapes and the
//! reserve / first-finalize / invalidate ordering; it is not a database race
//! proof, not an installed schema and not a new authority operation.
//!
//! Scoping (S 4.4, R 3, P2 8-10): one store instance is one environment, so
//! every key below is implicitly `(env, ..)`. Input for another environment is
//! denied, never read. Replay key: `(env, caller, kid, kv, nonce)`. JTI key:
//! `(env, issuer, jti)`. Mapping: `(env, authorization_id)`, `(env, play_intent_id)`
//! and `(env, playback_request_id)` are each unique and mutually distinct.
//!
//! Every real writer of the 32-writer catalogue is unintegrated; the model's
//! `invalidate` stands in for the shared lock domain, and the outbox is only a
//! record of what happened, never the fence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub type Id = String;
pub type Time = u64;

pub const RESOLVER_ROLE: &str = "nntune-vault-provider";
pub const STREAM_ROLE: &str = "nntune-stream";
pub const PURPOSE: &str = "provider";
pub const OPERATION: &str = "provider.resolve.play";
pub const CONTRACT_VERSION: &str = "provider-authority-store/1";
pub const RESERVE_WINDOW: Time = 2;
pub const LEASE_TERM: Time = 15;
pub const MIN_REMAINING: Time = 3;
pub const TOMBSTONE_RETENTION: Time = 86_400;
pub const CONNECTION_PAIRS: usize = 50;

/// Closed catalogue of writers that must share the fence. Unknown names are
/// unsupported, never silently accepted.
pub const WRITERS: [&str; 32] = [
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

/// Closed, secret-free audit projection. No other key may be emitted.
pub const OUTBOX_FIELDS: [&str; 16] = [
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

// Records never print identities, digests or key references.
macro_rules! redacted_debug {
    ($($t:ident),*) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), "(..)"))
            }
        }
    )*};
}

#[derive(Clone, PartialEq, Eq)]
pub struct Source {
    pub job_id: String,
    pub job_generation: u32,
    pub source_selection_id: Id,
    pub selection_version: u32,
    pub plan_digest: String,
    pub audio_ordinal: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Material {
    pub material_id: Id,
    pub material_version: u32,
    pub algorithm: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Selection {
    All,
    Range { start: u64, end_exclusive: u64 },
}

#[derive(Clone, PartialEq, Eq)]
pub struct Origin {
    pub env: String,
    pub play_intent_id: Id,
    pub authorization_id: Id,
    pub playback_request_id: Id,
    pub owner: String,
    pub pool_owner: String,
    pub track_id: String,
    pub session_id: String,
    pub session_epoch: u32,
    pub user_epoch: u32,
    pub library_epoch: u32,
    pub track_epoch: u32,
    pub material_epoch: u32,
    pub grant_digest: String,
    pub grant_expires_at: Time,
    pub metadata_contract: String,
    pub admission_id: Id,
    pub publication_id: Id,
    pub manifest_id: Id,
    pub manifest_revision: u32,
    pub manifest_digest: String,
    pub source: Source,
    pub material_ref: Material,
    pub selection: Selection,
    pub issued_at: Time,
    pub hard_deadline: Time,
    pub plan_digest: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Action {
    pub ordinal: u16,
    pub manifest_ordinal: u16,
    pub message_id_sha256: String,
    pub decoded_offset: u64,
    pub decoded_length: u64,
    pub decoded_sha256: String,
    pub wire_max_bytes: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ContentStep {
    pub step_id: Id,
    pub action_ordinal: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionStep {
    pub step_id: Id,
    pub pair: u8,
    pub operation: String,
}

#[derive(Clone)]
pub struct Seed {
    pub origin: Origin,
    pub actions: Vec<Action>,
    pub content_steps: Vec<ContentStep>,
    pub connection_steps: Vec<ConnectionStep>,
    pub scope_id: Id,
    pub jti: Id,
    pub issuer: String,
    pub cnf_kid: String,
    pub cnf_kv: u64,
    pub provider_version: u64,
    pub owner_epoch: u64,
    pub permission_epoch: u64,
    pub policy_version: u64,
    pub cap_expires_at: Time,
    pub material_lease_until: Time,
    pub replacement_used: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Nonce {
    pub env: String,
    pub caller: String,
    pub kid: String,
    pub kv: u64,
    pub nonce: Id,
}

/// Already-verified synthetic evidence class. Only `SyntheticVerified` can ever
/// establish authority; a caller-supplied user selector or a reused play grant
/// never does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Evidence {
    SyntheticVerified,
    RawUserSelector,
    ReusedPlayGrant,
}

#[derive(Clone)]
pub struct Call {
    pub resolver_role: String,
    pub stream_role: String,
    pub env: String,
    pub owner: String,
    pub actual_pool_owner: String,
    pub purpose: String,
    pub operation: String,
    pub evidence: Evidence,
    pub authoritative: bool,
    pub rollback_detected: bool,
    pub now: Time,
}

/// Where a modeled concurrent writer commits relative to a finalize.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Unwrapped,
    IntentAcked,
    TerminalAcked,
}

#[derive(Clone)]
pub struct FinalizeRequest {
    pub reservation_id: Id,
    pub call: Call,
    pub intent_ack: bool,
    pub terminal_ack: bool,
    pub interleave: Option<(Phase, &'static str)>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reservation {
    pub reservation_id: Id,
    pub until: Time,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delivery {
    pub lease_id: Id,
    pub until: Time,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Denial {
    Denied,
    Unavailable,
    Replay,
    Conflict,
    Expired,
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Frozen,
    Reserved,
    Consumed,
    Failed,
    Revoked,
    Expired,
}

#[derive(Clone)]
pub struct View {
    pub origin: Origin,
    pub actions: Vec<Action>,
    pub content_steps: Vec<ContentStep>,
    pub connection_steps: Vec<ConnectionStep>,
    pub state: State,
    pub replacement_used: bool,
    pub lease_until: Option<Time>,
    pub deliveries: usize,
    pub outbox: Vec<Vec<(String, String)>>,
    pub closed_at: Option<Time>,
    pub retain_until: Option<Time>,
    pub synchronous_fenced: bool,
}

redacted_debug!(
    Source,
    Material,
    Selection,
    Origin,
    Action,
    Seed,
    Nonce,
    Call,
    FinalizeRequest,
    View
);

struct Record {
    seed: Seed,
    state: State,
    reservation: Option<Reservation>,
    lease_until: Option<Time>,
    deliveries: usize,
    outbox: Vec<Vec<(String, String)>>,
    closed_at: Option<Time>,
    retain_until: Option<Time>,
    fenced: bool,
}

impl Record {
    fn event(&mut self, ordinal: usize, role: &str, outcome: &str, reason: &str, now: Time) {
        let o = &self.seed.origin;
        let event = vec![
            (
                "event_id".to_string(),
                format!("evt-{}-{ordinal}", o.play_intent_id),
            ),
            ("request_id".to_string(), o.playback_request_id.clone()),
            ("authorization_id".to_string(), o.authorization_id.clone()),
            ("publication_id".to_string(), o.publication_id.clone()),
            ("timestamp".to_string(), now.to_string()),
            ("environment".to_string(), o.env.clone()),
            ("role".to_string(), role.to_string()),
            ("purpose".to_string(), PURPOSE.to_string()),
            ("contract_version".to_string(), CONTRACT_VERSION.to_string()),
            ("outcome".to_string(), outcome.to_string()),
            ("reason".to_string(), reason.to_string()),
        ];
        debug_assert!(event
            .iter()
            .all(|(k, _)| OUTBOX_FIELDS.contains(&k.as_str())));
        self.outbox.push(event);
    }

    /// Terminal close: tombstone is kept for at least 24 hours past closure and
    /// the replacement credit is never reset.
    fn close(&mut self, now: Time) {
        if self.closed_at.is_none() {
            self.closed_at = Some(now);
            self.retain_until = Some(now.saturating_add(TOMBSTONE_RETENTION));
        }
    }

    fn end(&mut self, state: State, role: &str, reason: &str, now: Time) {
        self.state = state;
        self.close(now);
        let outcome = if state == State::Expired {
            "expired"
        } else {
            "failed"
        };
        let n = self.outbox.len();
        self.event(n, role, outcome, reason, now);
    }

    /// The synchronous fence. Commits before any later reserve/finalize reread.
    fn fence(&mut self, writer: &str, now: Time) {
        self.fenced = true;
        if matches!(
            self.state,
            State::Frozen | State::Reserved | State::Consumed
        ) {
            self.state = State::Revoked;
            self.close(now);
            let n = self.outbox.len();
            self.event(n, RESOLVER_ROLE, "revoked", writer, now);
        }
        self.close(now);
    }

    fn live_reserved(&self) -> bool {
        self.state == State::Reserved && !self.fenced
    }
}

fn authorize(env: &str, o: &Origin, c: &Call) -> Result<(), Denial> {
    if !c.authoritative || c.rollback_detected {
        return Err(Denial::Unavailable);
    }
    // o.owner == o.pool_owner holds for every frozen record: validate_shape
    // rejects a mismatched origin at freeze (schema.sql check), so authorize
    // only rechecks the caller-selected identities.
    let allowed = c.resolver_role == RESOLVER_ROLE
        && c.stream_role == STREAM_ROLE
        && c.env == env
        && o.env == env
        && c.owner == o.owner
        && c.actual_pool_owner == o.pool_owner
        && c.purpose == PURPOSE
        && c.operation == OPERATION
        && c.evidence == Evidence::SyntheticVerified;
    if allowed {
        Ok(())
    } else {
        Err(Denial::Denied)
    }
}

fn validate_shape(seed: &Seed) -> Result<(), Denial> {
    let o = &seed.origin;
    if o.authorization_id == o.play_intent_id
        || o.playback_request_id == o.authorization_id
        || o.playback_request_id == o.play_intent_id
        || o.hard_deadline < o.issued_at
        || o.owner != o.pool_owner
    {
        return Err(Denial::Denied);
    }
    let ordinals: BTreeSet<u16> = seed.actions.iter().map(|a| a.ordinal).collect();
    let steps: BTreeSet<&Id> = seed.content_steps.iter().map(|s| &s.step_id).collect();
    let step_actions: BTreeSet<u16> = seed
        .content_steps
        .iter()
        .map(|s| s.action_ordinal)
        .collect();
    if seed.actions.is_empty()
        || ordinals.len() != seed.actions.len()
        || steps.len() != seed.content_steps.len()
        || step_actions != ordinals
        || step_actions.len() != seed.content_steps.len()
    {
        return Err(Denial::Denied);
    }
    let conn_ids: BTreeSet<&Id> = seed.connection_steps.iter().map(|s| &s.step_id).collect();
    let pairs: BTreeSet<(u8, &str)> = seed
        .connection_steps
        .iter()
        .map(|s| (s.pair, s.operation.as_str()))
        .collect();
    let complete = (0..CONNECTION_PAIRS)
        .all(|p| pairs.contains(&(p as u8, "connect")) && pairs.contains(&(p as u8, "checkout")));
    if seed.connection_steps.len() != CONNECTION_PAIRS * 2
        || conn_ids.len() != seed.connection_steps.len()
        || pairs.len() != seed.connection_steps.len()
        || !complete
    {
        return Err(Denial::Denied);
    }
    Ok(())
}

pub struct AuthorityStore {
    env: String,
    records: BTreeMap<Id, Record>,
    by_authorization: BTreeSet<Id>,
    by_request: BTreeSet<Id>,
    by_jti: BTreeSet<(String, Id)>,
    connection_claims: BTreeSet<(Id, Id)>,
    connection_pairs: BTreeSet<(Id, u8, String)>,
    nonces: BTreeSet<(String, String, u64, Id)>,
    reservations: BTreeMap<Id, Id>,
    next_reservation: u64,
}

impl fmt::Debug for AuthorityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityStore")
            .field("env", &self.env)
            .field("origins", &self.records.len())
            .field("nonces", &self.nonces.len())
            .finish()
    }
}

impl AuthorityStore {
    pub fn new(env: &str) -> Self {
        Self {
            env: env.to_string(),
            records: BTreeMap::new(),
            by_authorization: BTreeSet::new(),
            by_request: BTreeSet::new(),
            by_jti: BTreeSet::new(),
            connection_claims: BTreeSet::new(),
            connection_pairs: BTreeSet::new(),
            nonces: BTreeSet::new(),
            reservations: BTreeMap::new(),
            next_reservation: 0,
        }
    }

    /// Freeze origin, plan and stable step identity once. Every later change is
    /// a conflict; there is no update path. A connection step already claimed
    /// under the same scope also conflicts (schema.sql `connection_step` keys).
    pub fn freeze(&mut self, seed: Seed) -> Result<(), Denial> {
        if seed.origin.env != self.env {
            return Err(Denial::Denied);
        }
        validate_shape(&seed)?;
        let o = &seed.origin;
        if self.records.contains_key(&o.play_intent_id)
            || self.by_authorization.contains(&o.authorization_id)
            || self.by_request.contains(&o.playback_request_id)
            || self
                .by_jti
                .contains(&(seed.issuer.clone(), seed.jti.clone()))
        {
            return Err(Denial::Conflict);
        }
        // validate_shape already rejects duplicates inside this seed, so a
        // disjoint check against every frozen record is the whole key.
        let claims: BTreeSet<(Id, Id)> = seed
            .connection_steps
            .iter()
            .map(|s| (seed.scope_id.clone(), s.step_id.clone()))
            .collect();
        let pairs: BTreeSet<(Id, u8, String)> = seed
            .connection_steps
            .iter()
            .map(|s| (seed.scope_id.clone(), s.pair, s.operation.clone()))
            .collect();
        if !claims.is_disjoint(&self.connection_claims)
            || !pairs.is_disjoint(&self.connection_pairs)
        {
            return Err(Denial::Conflict);
        }
        self.connection_claims.extend(claims);
        self.connection_pairs.extend(pairs);
        self.by_authorization.insert(o.authorization_id.clone());
        self.by_request.insert(o.playback_request_id.clone());
        self.by_jti.insert((seed.issuer.clone(), seed.jti.clone()));
        self.records.insert(
            o.play_intent_id.clone(),
            Record {
                seed,
                state: State::Frozen,
                reservation: None,
                lease_until: None,
                deliveries: 0,
                outbox: Vec::new(),
                closed_at: None,
                retain_until: None,
                fenced: false,
            },
        );
        Ok(())
    }

    fn nonce_key(n: &Nonce) -> (String, String, u64, Id) {
        (n.caller.clone(), n.kid.clone(), n.kv, n.nonce.clone())
    }

    /// Record a replay nonce under `(env, caller, kid, kv, nonce)`.
    pub fn record_nonce(&mut self, nonce: Nonce, _now: Time) -> Result<(), Denial> {
        if nonce.env != self.env {
            return Err(Denial::Denied);
        }
        if self.nonces.insert(Self::nonce_key(&nonce)) {
            Ok(())
        } else {
            Err(Denial::Replay)
        }
    }

    pub fn reserve(
        &mut self,
        origin: &Id,
        jti: &Id,
        call: Call,
        nonce: Nonce,
    ) -> Result<Reservation, Denial> {
        let rec = self.records.get_mut(origin).ok_or(Denial::Denied)?;
        if &rec.seed.jti != jti {
            return Err(Denial::Denied);
        }
        authorize(&self.env, &rec.seed.origin, &call)?;
        if nonce.env != self.env
            || nonce.caller != call.stream_role
            || nonce.kid != rec.seed.cnf_kid
            || nonce.kv != rec.seed.cnf_kv
        {
            return Err(Denial::Denied);
        }
        match rec.state {
            State::Frozen if !rec.fenced => {}
            State::Revoked => return Err(Denial::Denied),
            _ => return Err(Denial::Conflict),
        }
        if self.nonces.contains(&Self::nonce_key(&nonce)) {
            return Err(Denial::Replay);
        }
        let now = call.now;
        let s = &rec.seed;
        if now >= s.cap_expires_at
            || now >= s.origin.hard_deadline
            || now >= s.origin.grant_expires_at
            || now >= s.material_lease_until
        {
            rec.end(State::Expired, &call.resolver_role, "deadline", now);
            return Err(Denial::Expired);
        }
        let until = now
            .saturating_add(RESERVE_WINDOW)
            .min(s.cap_expires_at)
            .min(s.origin.hard_deadline)
            .min(s.origin.grant_expires_at)
            .min(s.material_lease_until);
        self.next_reservation += 1;
        let reservation = Reservation {
            reservation_id: format!("reservation-{:06}", self.next_reservation),
            until,
        };
        self.nonces.insert(Self::nonce_key(&nonce));
        self.reservations
            .insert(reservation.reservation_id.clone(), origin.clone());
        rec.state = State::Reserved;
        rec.reservation = Some(reservation.clone());
        let n = rec.outbox.len();
        rec.event(n, &call.resolver_role, "reserved", "none", now);
        Ok(reservation)
    }

    /// First and only finalize. Authority is rechecked after unwrap and after
    /// each audit acknowledgement; any invalidation that committed first wins.
    pub fn first_finalize(&mut self, request: FinalizeRequest) -> Result<Delivery, Denial> {
        let origin = self
            .reservations
            .get(&request.reservation_id)
            .ok_or(Denial::Denied)?;
        let rec = self.records.get_mut(origin).ok_or(Denial::Denied)?;
        authorize(&self.env, &rec.seed.origin, &request.call)?;
        match rec.state {
            State::Reserved if !rec.fenced => {}
            State::Revoked => return Err(Denial::Denied),
            _ => return Err(Denial::Conflict),
        }
        if rec.reservation.as_ref().map(|r| &r.reservation_id) != Some(&request.reservation_id) {
            return Err(Denial::Denied);
        }
        let now = request.call.now;
        let role = request.call.resolver_role.clone();
        let reserved_until = rec.reservation.as_ref().map_or(0, |r| r.until);
        let s = &rec.seed;
        if now >= reserved_until
            || now >= s.cap_expires_at
            || now >= s.origin.hard_deadline
            || now >= s.origin.grant_expires_at
        {
            rec.end(State::Expired, &role, "reservation_expired", now);
            return Err(Denial::Expired);
        }
        // No renewal: the lease never extends past any bound.
        let lease_until = now
            .saturating_add(LEASE_TERM)
            .min(s.cap_expires_at)
            .min(s.origin.hard_deadline)
            .min(s.origin.grant_expires_at)
            .min(s.material_lease_until);
        if lease_until.saturating_sub(now) < MIN_REMAINING {
            rec.end(State::Failed, &role, "lease_too_short", now);
            return Err(Denial::Expired);
        }
        let reread = |rec: &mut Record, phase: Phase| -> Result<(), Denial> {
            if let Some((at, writer)) = request.interleave {
                if at == phase {
                    if !WRITERS.contains(&writer) {
                        return Err(Denial::Unsupported);
                    }
                    rec.fence(writer, now);
                }
            }
            if rec.live_reserved() {
                Ok(())
            } else {
                Err(Denial::Denied)
            }
        };
        reread(rec, Phase::Unwrapped)?;
        if !request.intent_ack {
            rec.end(State::Failed, &role, "intent_audit_unacknowledged", now);
            return Err(Denial::Unavailable);
        }
        reread(rec, Phase::IntentAcked)?;
        if !request.terminal_ack {
            rec.end(State::Failed, &role, "terminal_audit_unacknowledged", now);
            return Err(Denial::Unavailable);
        }
        reread(rec, Phase::TerminalAcked)?;
        rec.state = State::Consumed;
        rec.lease_until = Some(lease_until);
        rec.deliveries += 1;
        rec.close(now);
        let n = rec.outbox.len();
        rec.event(n, &role, "delivered", "none", now);
        Ok(Delivery {
            lease_id: rec.seed.jti.clone(),
            until: lease_until,
        })
    }

    /// Model of a writer's participation in the shared fence. Idempotent.
    pub fn invalidate(
        &mut self,
        origin: &Id,
        writer: &'static str,
        now: Time,
    ) -> Result<(), Denial> {
        if !WRITERS.contains(&writer) {
            return Err(Denial::Unsupported);
        }
        let rec = self.records.get_mut(origin).ok_or(Denial::Denied)?;
        rec.fence(writer, now);
        Ok(())
    }

    pub fn inspect(&self, origin: &Id) -> Option<View> {
        let r = self.records.get(origin)?;
        Some(View {
            origin: r.seed.origin.clone(),
            actions: r.seed.actions.clone(),
            content_steps: r.seed.content_steps.clone(),
            connection_steps: r.seed.connection_steps.clone(),
            state: r.state,
            replacement_used: r.seed.replacement_used,
            lease_until: r.lease_until,
            deliveries: r.deliveries,
            outbox: r.outbox.clone(),
            closed_at: r.closed_at,
            retain_until: r.retain_until,
            synchronous_fenced: r.fenced,
        })
    }

    /// Issuance, replacement, advance, step admission, producers, crypto,
    /// discovery, renewal, delivery recovery and tombstone purge are OUT of this
    /// foundation. They fail closed and change nothing.
    pub fn unsupported(&mut self, _operation: &str) -> Result<(), Denial> {
        Err(Denial::Unsupported)
    }
}

#[cfg(test)]
mod review_pins {
    //! Builder-owned pins for the model guards the frozen acceptance bank
    //! does not isolate. The frozen bank is never edited; these cases pin the
    //! lease/grant caps, the scope-step key, owner equality, the lease term,
    //! each mapping key and unknown-writer rejection.
    use super::*;

    fn id(n: u32) -> Id {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn seed() -> Seed {
        Seed {
            origin: Origin {
                env: "staging".into(),
                play_intent_id: id(1),
                authorization_id: id(2),
                playback_request_id: id(3),
                owner: "synthetic_owner".into(),
                pool_owner: "synthetic_owner".into(),
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

    fn call_at(now: Time) -> Call {
        Call {
            resolver_role: RESOLVER_ROLE.into(),
            stream_role: STREAM_ROLE.into(),
            env: "staging".into(),
            owner: "synthetic_owner".into(),
            actual_pool_owner: "synthetic_owner".into(),
            purpose: PURPOSE.into(),
            operation: OPERATION.into(),
            evidence: Evidence::SyntheticVerified,
            authoritative: true,
            rollback_detected: false,
            now,
        }
    }

    fn nonce(n: u32) -> Nonce {
        Nonce {
            env: "staging".into(),
            caller: STREAM_ROLE.into(),
            kid: "synthetic_stream_key_ref".into(),
            kv: 1,
            nonce: id(500 + n),
        }
    }

    fn finalize_request(reservation_id: Id, now: Time) -> FinalizeRequest {
        FinalizeRequest {
            reservation_id,
            call: call_at(now),
            intent_ack: true,
            terminal_ack: true,
            interleave: None,
        }
    }

    #[test]
    fn lease_and_reservation_never_outlive_grant_or_material() {
        let mut m = AuthorityStore::new("staging");
        let mut s = seed();
        s.origin.grant_expires_at = 1010;
        s.cap_expires_at = 1030;
        s.origin.hard_deadline = 1900;
        s.material_lease_until = 1015;
        m.freeze(s).unwrap();
        let r = m.reserve(&id(1), &id(10), call_at(1000), nonce(1)).unwrap();
        assert_eq!(r.until, 1002);
        let d = m
            .first_finalize(finalize_request(r.reservation_id.clone(), 1001))
            .unwrap();
        assert_eq!(d.until, 1010);
        assert_eq!(m.inspect(&id(1)).unwrap().lease_until, Some(1010));

        // The reservation window is capped by the grant, the material lease,
        // the capability expiry and the hard deadline independently: each
        // sub-case varies one bound alone.
        for (n, (grant, material, cap, hard)) in [
            (1001, 1900, 1900, 1900),
            (1900, 1001, 1900, 1900),
            (1900, 1900, 1001, 1900),
            (1900, 1900, 1900, 1001),
        ]
        .iter()
        .enumerate()
        {
            let mut m = AuthorityStore::new("staging");
            let mut s = seed();
            s.origin.grant_expires_at = *grant;
            s.material_lease_until = *material;
            s.cap_expires_at = *cap;
            s.origin.hard_deadline = *hard;
            m.freeze(s).unwrap();
            let r = m
                .reserve(&id(1), &id(10), call_at(1000), nonce(20 + n as u32))
                .unwrap();
            assert_eq!(
                r.until, 1001,
                "grant {grant} material {material} cap {cap} hard {hard}"
            );
        }

        for (n, (grant, material)) in [(1000, 1015), (1900, 1000)].iter().enumerate() {
            let mut m = AuthorityStore::new("staging");
            let mut s = seed();
            s.origin.grant_expires_at = *grant;
            s.material_lease_until = *material;
            m.freeze(s).unwrap();
            assert_eq!(
                m.reserve(&id(1), &id(10), call_at(1000), nonce(10 + n as u32)),
                Err(Denial::Expired),
                "grant {grant} material {material}"
            );
        }
    }

    #[test]
    fn lease_term_fifteen_seconds_is_the_binding_cap() {
        let mut m = AuthorityStore::new("staging");
        let mut s = seed();
        s.origin.grant_expires_at = 1900;
        s.cap_expires_at = 1900;
        s.origin.hard_deadline = 1900;
        s.material_lease_until = 1900;
        m.freeze(s).unwrap();
        let r = m.reserve(&id(1), &id(10), call_at(1000), nonce(1)).unwrap();
        assert_eq!(r.until, 1002);
        let d = m
            .first_finalize(finalize_request(r.reservation_id.clone(), 1001))
            .unwrap();
        assert_eq!(d.until, 1001 + LEASE_TERM);
        assert_eq!(d.until, 1016);
    }

    #[test]
    fn lease_never_outlives_hard_deadline_alone() {
        // The hard deadline is the sole binding bound: every other bound is
        // 1900, so only the finalize `.min(hard_deadline)` operand can cap
        // the lease at 1012.
        let mut m = AuthorityStore::new("staging");
        let mut s = seed();
        s.origin.grant_expires_at = 1900;
        s.cap_expires_at = 1900;
        s.origin.hard_deadline = 1012;
        s.material_lease_until = 1900;
        m.freeze(s).unwrap();
        let r = m.reserve(&id(1), &id(10), call_at(1000), nonce(1)).unwrap();
        assert_eq!(r.until, 1002);
        let d = m
            .first_finalize(finalize_request(r.reservation_id.clone(), 1001))
            .unwrap();
        assert_eq!(d.until, 1012);
    }

    #[test]
    fn freeze_enforces_scope_step_key_across_records() {
        let mut m = AuthorityStore::new("staging");
        m.freeze(seed()).unwrap();
        let mut same_scope = seed();
        same_scope.origin.play_intent_id = id(31);
        same_scope.origin.authorization_id = id(32);
        same_scope.origin.playback_request_id = id(33);
        same_scope.jti = id(35);
        assert_eq!(m.freeze(same_scope), Err(Denial::Conflict));
        // Same scope with fresh step ids: the (scope_id, step_id) claims are
        // disjoint but the (scope_id, pair, operation) keys clash, so only
        // the pairs operand can fire.
        let mut same_scope_fresh_steps = seed();
        same_scope_fresh_steps.origin.play_intent_id = id(51);
        same_scope_fresh_steps.origin.authorization_id = id(52);
        same_scope_fresh_steps.origin.playback_request_id = id(53);
        same_scope_fresh_steps.jti = id(55);
        for (i, step) in same_scope_fresh_steps
            .connection_steps
            .iter_mut()
            .enumerate()
        {
            step.step_id = id(1000 + i as u32);
        }
        assert_eq!(m.freeze(same_scope_fresh_steps), Err(Denial::Conflict));
        // A fresh scope may reuse the same step shape.
        let mut fresh_scope = seed();
        fresh_scope.origin.play_intent_id = id(41);
        fresh_scope.origin.authorization_id = id(42);
        fresh_scope.origin.playback_request_id = id(43);
        fresh_scope.scope_id = id(44);
        fresh_scope.jti = id(45);
        assert_eq!(m.freeze(fresh_scope), Ok(()));
    }

    #[test]
    fn freeze_rejects_owner_pool_owner_mismatch() {
        let mut m = AuthorityStore::new("staging");
        let mut s = seed();
        s.origin.owner = "synthetic_owner_a".into();
        s.origin.pool_owner = "synthetic_owner_b".into();
        assert_eq!(m.freeze(s), Err(Denial::Denied));
    }

    #[test]
    fn freeze_rejects_each_duplicated_mapping_key_alone() {
        // Duplicate exactly one mapping key; every other identity is fresh so
        // only that key's check can fire.
        for (field, intent, auth, req) in [
            ("play_intent", id(1), id(32), id(33)),
            ("authorization", id(31), id(2), id(33)),
            ("request", id(31), id(32), id(3)),
        ] {
            let mut m = AuthorityStore::new("staging");
            m.freeze(seed()).unwrap();
            let mut s = seed();
            s.origin.play_intent_id = intent;
            s.origin.authorization_id = auth;
            s.origin.playback_request_id = req;
            s.scope_id = id(34);
            s.jti = id(35);
            assert_eq!(m.freeze(s), Err(Denial::Conflict), "{field}");
        }
    }

    #[test]
    fn unknown_writer_is_unsupported_at_invalidate_and_reread() {
        let mut m = AuthorityStore::new("staging");
        m.freeze(seed()).unwrap();
        assert_eq!(
            m.invalidate(&id(1), "not_a_writer", 1000),
            Err(Denial::Unsupported)
        );
        assert!(!m.inspect(&id(1)).unwrap().synchronous_fenced);
        let r = m.reserve(&id(1), &id(10), call_at(1000), nonce(1)).unwrap();
        let mut req = finalize_request(r.reservation_id.clone(), 1001);
        req.interleave = Some((Phase::Unwrapped, "not_a_writer"));
        assert_eq!(m.first_finalize(req), Err(Denial::Unsupported));
        assert_eq!(m.inspect(&id(1)).unwrap().deliveries, 0);
    }
}
