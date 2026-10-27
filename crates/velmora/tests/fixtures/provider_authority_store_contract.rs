// NON-AUTHORITATIVE / NOT INSTALLED. Frozen test boundary, not an authority API.
// S §§4-8 + R §3; metadata remains M2, provider profile v3. No signed fixtures.
use std::fmt::Debug;

pub type Id = String;
pub type Time = u64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub job_id: String,
    pub job_generation: u32,
    pub source_selection_id: Id,
    pub selection_version: u32,
    pub plan_digest: String,
    pub audio_ordinal: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Material {
    pub material_id: Id,
    pub material_version: u32,
    pub algorithm: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub ordinal: u16,
    pub manifest_ordinal: u16,
    pub message_id_sha256: String,
    pub decoded_offset: u64,
    pub decoded_length: u64,
    pub decoded_sha256: String,
    pub wire_max_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentStep {
    pub step_id: Id,
    pub action_ordinal: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug)]
pub struct Call {
    pub resolver_role: String,
    pub stream_role: String,
    pub env: String,
    pub owner: String,
    pub actual_pool_owner: String,
    pub purpose: String,
    pub operation: String,
    // Only an already-verified SYNTHETIC opaque reference. Never a grant/proof/key.
    pub evidence: Evidence,
    pub authoritative: bool,
    pub rollback_detected: bool,
    pub now: Time,
}
#[derive(Clone, Debug)]
pub enum Evidence {
    SyntheticVerified,
    RawUserSelector,
    ReusedPlayGrant,
}
#[derive(Clone, Debug)]
pub struct Nonce {
    pub env: String,
    pub caller: String,
    pub kid: String,
    pub kv: u64,
    pub nonce: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Unwrapped,
    IntentAcked,
    TerminalAcked,
}
#[derive(Clone, Debug)]
pub struct Finalize {
    pub reservation_id: Id,
    pub call: Call,
    pub intent_ack: bool,
    pub terminal_ack: bool,
    pub interleave: Option<(Phase, &'static str)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub reservation_id: Id,
    pub until: Time,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub lease_id: Id,
    pub until: Time,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    Denied,
    Unavailable,
    Replay,
    Conflict,
    Expired,
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
// Adapter is Builder-owned at tests/support/provider_authority_store_adapter.rs.
// It must delegate to the detached inert Rust implementation, never emulate it.
// Input records are fixture projections, NOT replacement wire schemas or producers.
pub trait Model: Debug {
    fn freeze(&mut self, seed: Seed) -> Result<(), Denial>;
    fn record_nonce(&mut self, nonce: Nonce, now: Time) -> Result<(), Denial>;
    fn reserve(
        &mut self,
        origin: &Id,
        jti: &Id,
        call: Call,
        nonce: Nonce,
    ) -> Result<Reservation, Denial>;
    fn first_finalize(&mut self, request: Finalize) -> Result<Delivery, Denial>;
    fn invalidate(&mut self, origin: &Id, writer: &'static str, now: Time) -> Result<(), Denial>;
    fn inspect(&self, origin: &Id) -> Option<View>;
    fn unsupported(&mut self, operation: &str) -> Result<(), Denial>;
}
