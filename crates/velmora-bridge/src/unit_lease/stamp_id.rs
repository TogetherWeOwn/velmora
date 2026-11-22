//! The rollback stamp id of a unit (ADR-TENANCY §8.5, RL-5).
//!
//! A unit's stamp objects live under `rs/<tenant>.<unit>/`, and its
//! `rollback_stamp` row carries exactly that id. Tenant 0's D1 keeps the
//! id `main` (`CATALOGUE_ID`), with its objects under `rs/main/`.
//!
//! **The written form, chosen here:** the tenant id as a record name
//! takes it ([`crate::recovery::valid_tenant_id`]: `t_` and 1 to 64
//! lowercase letters and digits), a `.`, and the unit number in
//! decimal without leading zeros. The longest is 66 + 1 + 10 = 77
//! bytes ([`MAX_UNIT_STAMP_ID_LEN`]).
//!
//! Why a dot: a catalogue id is `[a-z0-9_-]{1,32}` (`config.rs`), which
//! has no dot, so no unit id is ever a catalogue id and the two never
//! share a stamp prefix. The configuration's validator is left as it is:
//! a unit id never goes through the configuration. It is made here, from
//! the tenant and the unit the unit object is named by.
//!
//! Tenant 0 has no unit in this design (it keeps D1 until it is moved
//! and retired), so no unit id is made for it.

use crate::recovery::{valid_tenant_id, DEFAULT_TENANT};
use crate::types::{BridgeError, Result};

/// Between the tenant and the unit number.
pub const UNIT_SEPARATOR: char = '.';

/// The longest unit stamp id: `t_` + 64, the dot, and `u32::MAX` in
/// decimal.
pub const MAX_UNIT_STAMP_ID_LEN: usize = 2 + 64 + 1 + 10;

const ERR_UNIT_STAMP_ID: BridgeError =
    BridgeError::Invalid("a unit's stamp id needs a managed tenant id and a unit number");

/// The stamp id of one unit: `<tenant>.<unit>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnitStampId {
    id: String,
    dot: usize,
    unit: u32,
}

impl UnitStampId {
    /// The id of unit `unit` of `tenant`. Refuses an id that is not a
    /// tenant id, and tenant 0.
    pub fn new(tenant: &str, unit: u32) -> Result<UnitStampId> {
        if !valid_tenant_id(tenant) || tenant == DEFAULT_TENANT {
            return Err(ERR_UNIT_STAMP_ID);
        }
        let id = format!("{tenant}{UNIT_SEPARATOR}{unit}");
        Ok(UnitStampId {
            dot: tenant.len(),
            id,
            unit,
        })
    }

    /// Reads an id back, as a stamp row or a stamp key holds it. `None`
    /// for anything [`UnitStampId::new`] would not have made, so an id
    /// has exactly one written form.
    pub fn parse(id: &str) -> Option<UnitStampId> {
        let (tenant, unit) = id.rsplit_once(UNIT_SEPARATOR)?;
        let canonical = !unit.is_empty()
            && unit.bytes().all(|b| b.is_ascii_digit())
            && (unit == "0" || !unit.starts_with('0'));
        if !canonical {
            return None;
        }
        let unit: u32 = unit.parse().ok()?;
        UnitStampId::new(tenant, unit).ok()
    }

    /// The id as the stamp row and the stamp keys carry it.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The tenant part.
    pub fn tenant(&self) -> &str {
        &self.id[..self.dot]
    }

    /// The unit number.
    pub fn unit(&self) -> u32 {
        self.unit
    }
}

impl std::fmt::Display for UnitStampId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}
