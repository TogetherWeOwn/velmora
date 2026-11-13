//! Request ingress (integration lane): `origin_form`, declared length,
//! `read_capped` and the per-isolate [`ByteBudget`] (DESIGN §A.2, §A.10).
//!
//! Walking-skeleton stub: only the `ByteBudget` type exists, because
//! [`crate::ports::Bridge`] names it.

/// Per-isolate in-flight byte budget (`INFLIGHT_BUDGET_BYTES`). Charging
/// and release land with the integration lane.
#[derive(Debug)]
pub struct ByteBudget {
    capacity: u64,
}

impl ByteBudget {
    pub fn new(capacity: u64) -> Self {
        ByteBudget { capacity }
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}
