//! The key chain of a managed tenant: its access keys, app passwords,
//! principals and internal key, recorded before any database holds them.
//!
//! Nothing here is wired into the Worker yet. The unit and the directory
//! that will hold copies of the key table are ports ([`ports`]), so the
//! order of the writes can be proven against fakes first.
//!
//! # Stores and names
//!
//! | Name | What | Written |
//! |---|---|---|
//! | `m/k/<t>/<seq>` | the key chain: one change to one subject per record, with the subject's whole state after it | put once, exactly the next seq ([`chain`], [`record`]) |
//! | `m/kc/<t>/<seq>` | a checkpoint: every subject as of chain record `seq` | by the finisher, beside the chain ([`checkpoint`]) |
//! | `m/rk/<t>/<akid>` | a revocation; overrides every chain status | put once, after the intent, before the chain record ([`revocations`]) |
//! | `m/kr/<akid>` | the route of an access key id to its tenant | put once, before the key's first chain record ([`routes`]) |
//! | `m/tk/<t>/<n>.<v>` | tenant key version `n` under KEK version `v`, in the key buckets only | created in the arbiter, then copied ([`tk`]) |
//! | `m/kl/<seq>` | the closed set of key locations | put once, exactly the next seq ([`locations`]) |
//!
//! A bucket create writes its creator grant to the key chain first, and
//! the bucket's id is derived from that record's seq ([`buckets`]).
//!
//! # Why the chain decides
//!
//! The databases are copies. A unit or a directory restored to an older
//! point, or rebuilt, takes its key table from the chain again, so it can
//! never bring back a revoked key or a narrowed grant. That only holds if
//! every change is in the chain **before** any copy has it, which is what
//! [`writer`] does, and if a change whose record is written always
//! reaches every copy, which is what [`writer::finish_keys`] does.

pub mod apply;
pub mod audit;
pub mod buckets;
pub mod chain;
pub mod checkpoint;
pub mod escrow;
pub mod frozen;
pub mod gate;
pub mod locations;
pub mod moving;
pub mod ports;
pub mod record;
pub mod revocations;
pub mod routes;
pub mod tk;
pub mod writer;
