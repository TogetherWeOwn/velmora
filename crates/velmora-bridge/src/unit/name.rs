//! The name of a unit: `<tenant>/<unit number>` (tenancy ADR §2.1).
//!
//! A tenant id is `t_` and 16 lowercase hex digits; tenant 0 is
//! [`crate::recovery::DEFAULT_TENANT`]. A unit number is a decimal
//! `u32` without leading zeros. The object's name in its namespace is
//! exactly [`UnitName::object_name`], so the name a Durable Object was
//! made under, the names in a call and the names in a birth certificate
//! can be compared as strings.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A tenant id: `t_` and 16 lowercase hex digits.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    pub fn parse(s: &str) -> Option<TenantId> {
        let hex = s.strip_prefix("t_")?;
        let ok = hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        ok.then(|| TenantId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tenant 0, the one tenant of today's catalogue.
    pub fn zero() -> TenantId {
        TenantId(crate::recovery::DEFAULT_TENANT.to_string())
    }

    pub fn is_zero(&self) -> bool {
        self.0 == crate::recovery::DEFAULT_TENANT
    }
}

impl TryFrom<String> for TenantId {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        TenantId::parse(&s).ok_or("not a tenant id")
    }
}

impl From<TenantId> for String {
    fn from(t: TenantId) -> String {
        t.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One unit of one tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitName {
    pub tenant: TenantId,
    pub unit: u32,
}

impl UnitName {
    pub fn new(tenant: TenantId, unit: u32) -> UnitName {
        UnitName { tenant, unit }
    }

    /// The name the object is made under: `<tenant>/<unit>`.
    pub fn object_name(&self) -> String {
        format!("{}/{}", self.tenant, self.unit)
    }

    /// Reads [`Self::object_name`] back. Anything else (another
    /// separator, a leading zero, a sign, a bad tenant) is `None`.
    pub fn parse(name: &str) -> Option<UnitName> {
        let (tenant, unit) = name.split_once('/')?;
        let canonical = !unit.is_empty()
            && unit.bytes().all(|b| b.is_ascii_digit())
            && (unit == "0" || !unit.starts_with('0'));
        if !canonical {
            return None;
        }
        Some(UnitName {
            tenant: TenantId::parse(tenant)?,
            unit: unit.parse().ok()?,
        })
    }
}

impl fmt::Display for UnitName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.tenant, self.unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_reads_back_as_itself() {
        let n = UnitName::new(TenantId::parse("t_0123456789abcdef").unwrap(), 7);
        assert_eq!(n.object_name(), "t_0123456789abcdef/7");
        assert_eq!(UnitName::parse(&n.object_name()), Some(n));
        let zero = UnitName::new(TenantId::zero(), 0);
        assert_eq!(UnitName::parse("t_0000000000000000/0"), Some(zero));
    }

    #[test]
    fn only_the_canonical_form_is_a_name() {
        for bad in [
            "t_0123456789abcdef/07",
            "t_0123456789abcdef/+7",
            "t_0123456789abcdef/",
            "t_0123456789abcdef/4294967296",
            "t_0123456789ABCDEF/1",
            "t_0123456789abcde/1",
            "t_0123456789abcdef0/1",
            "u_0123456789abcdef/1",
            "t_0123456789abcdef.1",
            "t_0123456789abcdef/1/2",
        ] {
            assert_eq!(UnitName::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_tenant_id_refuses_anything_else_when_read() {
        assert!(serde_json::from_str::<TenantId>("\"t_0000000000000001\"").is_ok());
        assert!(serde_json::from_str::<TenantId>("\"t_000000000000000G\"").is_err());
        assert!(serde_json::from_str::<TenantId>("\"main\"").is_err());
    }
}
