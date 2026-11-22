//! The unit clients of the composition root (lane L6, package L6-5b;
//! AM-71): L2's `UnitClient` for one unit, built per call over the
//! isolate's client state, for the request router, the management plane
//! and the queue consumer.
//!
//! - **One client state per isolate.** The renewals in flight, the
//!   spacing and the backoff of rule 11 are [`RootCache::flights`], kept
//!   beside the route and head caches and bounded at 4,096 units
//!   (`unit_lease::client::InFlight`; an evicted unit loses only its
//!   backoff). [`Root::unit_client`] builds a client over it every time.
//!   A client with fresh state per invocation would let every
//!   unauthenticated request start a renewal.
//! - **One retry layer.** `UnitClient::call` makes the rule-5 retry
//!   (renew, sync or the unit's numbers, then once more). Nothing here or
//!   in the router adds one.
//! - **`KeyFinisher`** ([`RootFinisher`]) enqueues `apply_control(tenant,
//!   keys)` through [`ControlSend`] and never runs the finisher inline: a
//!   renewal runs on the request path, which has a CPU bound, and the
//!   queue is the finisher's durable path anyway (ADR §2.5).
//!
//! [`RootCache::flights`]: super::RootCache::flights

use crate::config::Maintenance;
use crate::directory::chain::TenantChain;
use crate::directory::seal::DoorSeal;
use crate::jobmsg::{ControlIntent, IntentChain};
use crate::ports::{BlobEntry, BlobMeta, BlobStore, Clock};
use crate::recovery::Unpublished;
use crate::types::{BridgeError, ByteSpan, Result, UnixMs};
use crate::unit::{TenantId, UnitName};
use crate::unit_lease::client::{KeyFinisher, RecordNames, UnitClient, UnitReplies};
use crate::unit_lease::lease::LeaseRules;
use crate::unit_router::{RequestClients, Routed, Router};
use velmora::rng::FillRandom;

use super::feed::RootKeyFeed;
use super::{Root, RootPorts};

/// A key-chain finisher message could not be named (not a managed
/// tenant).
const ERR_CONTROL_TENANT: BridgeError = BridgeError::Invalid("apply_control: not a managed tenant");

/// What the root needs beyond [`RootPorts`] to call a unit: the unit
/// objects, the safety bucket as a blob store (the lease proof's reads
/// and the stamp objects), and the queue for control intents.
pub trait UnitPorts: RootPorts {
    /// One unit object (L2's port: the whole reply).
    type Object: UnitReplies;
    type Safety: BlobStore;
    type Control: ControlSend;
    /// The object named `name`. `Err`: the namespace is not bound or
    /// cannot name it.
    fn object(&self, name: &UnitName) -> Result<Self::Object>;
    fn safety(&self) -> &Self::Safety;
    fn control(&self) -> &Self::Control;
    /// The lease dials (T).
    fn lease(&self) -> LeaseRules {
        LeaseRules::DEFAULT
    }
}

/// Sends a control intent (`apply_control`, ADR §2.5 step 1) with its
/// delay (`jobmsg::APPLY_CONTROL_DELAY_SECS`).
#[allow(async_fn_in_trait)]
pub trait ControlSend {
    async fn send_control(&self, intent: &ControlIntent) -> Result<()>;
}

impl<T: ControlSend> ControlSend for &T {
    async fn send_control(&self, intent: &ControlIntent) -> Result<()> {
        (**self).send_control(intent).await
    }
}

/// The key chain's finisher as a renewal tells it of revocations the unit
/// did not hold (rule 12): one `apply_control(tenant, keys, 0)`. The
/// finisher reads the chain's head and lists `m/rk/<t>/`, never the
/// message's seq, so seq 0 names no record and asks for exactly that.
pub struct RootFinisher<'a, C> {
    pub control: &'a C,
}

impl<C: ControlSend> KeyFinisher for RootFinisher<'_, C> {
    async fn revocations_unrecorded(&self, tenant: &TenantId) -> Result<()> {
        let intent =
            ControlIntent::new(tenant.as_str(), IntentChain::Keys, 0).ok_or(ERR_CONTROL_TENANT)?;
        self.control.send_control(&intent).await
    }
}

/// A port the root holds by reference, as the unit client takes it by
/// value.
pub struct Shared<'a, T>(pub &'a T);

impl<T: Clock> Clock for Shared<'_, T> {
    fn now(&self) -> UnixMs {
        self.0.now()
    }
}

impl<T: BlobStore> BlobStore for Shared<'_, T> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.0.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }
    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, start_after, limit).await
    }
    async fn list_entries(
        &self,
        prefix: &str,
        start_after: &str,
        limit: u32,
    ) -> Result<Vec<BlobEntry>> {
        self.0.list_entries(prefix, start_after, limit).await
    }
}

/// The unit client the root builds: L2's `UnitClient` over the root's
/// ports.
pub type RootUnitClient<'r, 'a, P, R> = UnitClient<
    <P as UnitPorts>::Object,
    Shared<'a, <P as UnitPorts>::Safety>,
    Shared<'a, <P as RootPorts>::Clock>,
    RecordNames,
    RootHeads<'r, 'a, P>,
    RootKeyFeed<'r, 'a, P, R>,
    RootFinisher<'a, <P as UnitPorts>::Control>,
>;

/// The tenant heads the root reads (door parts only).
pub type RootHeads<'r, 'a, P> =
    TenantChain<'r, <P as RootPorts>::Records, DoorSeal<'a, <P as RootPorts>::Kek>>;

/// The router over the root's clients and heads.
pub type RootRouter<'r, 'a, P, R> =
    Router<'r, RootClients<'r, 'a, P, R>, RootHeads<'r, 'a, P>, <P as RootPorts>::Clock>;

impl<'a, P: UnitPorts, R: FillRandom> Root<'a, P, R> {
    /// The client of unit `name`, over the isolate's client state.
    /// `listed`: the request path takes it from the head (rule 7); job
    /// and Worker calls send `false` (AM-50). `Err`: the unit object
    /// cannot be named.
    pub fn unit_client(
        &self,
        name: &UnitName,
        listed: bool,
    ) -> Result<RootUnitClient<'_, 'a, P, R>> {
        Ok(UnitClient {
            unit: self.ports.object(name)?,
            safety: Shared(self.ports.safety()),
            clock: Shared(self.ports.clock()),
            names: RecordNames,
            heads: self.heads(),
            keys: self.key_feed(),
            finisher: RootFinisher {
                control: self.ports.control(),
            },
            name: name.clone(),
            listed,
            lease: self.ports.lease(),
            flights: self.cache.flights.clone(),
        })
    }

    /// The request clients for the router.
    pub fn clients(&self) -> RootClients<'_, 'a, P, R> {
        RootClients { root: self }
    }

    /// The router of one request or one management call, over the
    /// isolate's head cache and this root's clients and heads. The S3 path
    /// and the management plane both call units through it.
    pub fn router<'r>(
        &'r self,
        maintenance: Maintenance,
        clients: &'r RootClients<'r, 'a, P, R>,
        heads: &'r RootHeads<'r, 'a, P>,
    ) -> RootRouter<'r, 'a, P, R> {
        Router {
            maintenance,
            clients,
            heads,
            cache: self.head_cache(),
            clock: self.ports.clock(),
        }
    }
}

impl<'a, P: RootPorts, R: FillRandom> Root<'a, P, R> {
    /// The key chain as a unit takes it.
    pub fn key_feed(&self) -> RootKeyFeed<'_, 'a, P, R> {
        RootKeyFeed { root: self }
    }
}

/// The router's [`RequestClients`]: one unit client per routed unit, with
/// `listed` as routed.
pub struct RootClients<'r, 'a, P: RootPorts, R> {
    root: &'r Root<'a, P, R>,
}

impl<'r, 'a, P: UnitPorts, R: FillRandom> RequestClients for RootClients<'r, 'a, P, R> {
    type Client = RootUnitClient<'r, 'a, P, R>;
    fn client(&self, routed: &Routed) -> Result<Self::Client> {
        self.root.unit_client(&routed.unit, routed.listed)
    }
}
