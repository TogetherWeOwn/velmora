//! The lease side of a unit (ADR-TENANCY §2.4 rules 8 and 12, §8.5,
//! §8.6): the freshness lease, the Worker's renewal proof, the unit's
//! stamp id, the write mark, and the alarm dispatcher.
//!
//! Everything here is pure or generic over the ports, so the unit object
//! (a SQLite Durable Object) and native tests run the same code. The unit
//! object itself, its tables and its calls are built beside this module;
//! it calls into it:
//!
//! - every call: [`lease::FreshLease::admit`]; `renew`:
//!   [`lease::FreshLease::renew`];
//! - the Worker, before `renew`: [`renewal::prove`];
//! - the stamp of a unit: [`crate::stamp::Stamp`] keyed by
//!   [`stamp_id::UnitStampId`];
//! - the unit's database: [`mark::MarkedSql`] over its `Sql`, and
//!   [`mark::Mark`] on every page of a dump;
//! - the alarm: [`alarm::on_alarm`], [`alarm::after_renew`],
//!   [`alarm::rearm`], and the two jobs it sends ([`job`]);
//! - the unit's rows of all this: [`store`] (`unit_lease`,
//!   `unit_revoked_ids`; migration `u0002`).

pub mod alarm;
pub mod job;
pub mod lease;
pub mod mark;
pub mod renewal;
pub mod stamp_id;
pub mod store;

pub use stamp_id::UnitStampId;
