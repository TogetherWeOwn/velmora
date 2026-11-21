//! The `plan_rev` contract, part 2: the value (`docs/units.md`,
//! "Restore gate").
//!
//! The stored plan of an extent never changes, so `plan_rev` is 0 (no
//! plan yet) or 1 (the plan its articles were posted under), and nothing
//! raises it. Every statement that binds a `plan_rev` takes it from
//! [`bound`], which refuses a value above 1 before any statement runs; a
//! record that carries one is not [`readable`] and is reported, never
//! written from. Part 1, the statements by name, is the test
//! `tests/plan_rev_contract.rs`.
//!
//! The first change that writes a `plan_rev` above 1 needs the
//! plan-change design first and lifts this on purpose.

use crate::ports::SqlValue;
use crate::types::{BridgeError, Result};

/// The highest `plan_rev` this code knows.
pub const HIGHEST: u32 = 1;

/// The class of the refusal.
pub const ERR_PLAN_REV: &str = "plan_rev above 1: no plan ever changes";

/// `rev` as a bound value; above [`HIGHEST`] is an error.
pub fn bound(rev: u32) -> Result<SqlValue> {
    if rev > HIGHEST {
        return Err(BridgeError::Invalid(ERR_PLAN_REV));
    }
    Ok(SqlValue::Int(i64::from(rev)))
}

/// Whether a record's `plan_rev` is one this code may write from.
pub fn readable(rev: u32) -> bool {
    rev <= HIGHEST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_zero_and_one_are_bound() {
        assert_eq!(bound(0).unwrap(), SqlValue::Int(0));
        assert_eq!(bound(1).unwrap(), SqlValue::Int(1));
        for rev in [2, 3, u32::MAX] {
            assert!(matches!(
                bound(rev),
                Err(BridgeError::Invalid(ERR_PLAN_REV))
            ));
            assert!(!readable(rev));
        }
        assert!(readable(0) && readable(1));
    }
}
