//! What a managed tenant's key writer reads of the move before it writes
//! (DS1 §3.4, §3.7, §3.8; ADR §2.8 with AM-28, AM-31 and AM-54).
//!
//! The owner move puts tenant 0's keys into a managed tenant `<t>`, and
//! an undo or a give-up takes them back to D1. While that runs, a key
//! change of `<t>` must not land where no store will apply it. The writer
//! decides from two heads, read and verified for every call:
//!
//! - **`<t>`'s key-chain head**, which may carry the undo's freeze
//!   (`frozen_at = K_u`, a key-chain record: [`super::frozen`]). Every D1
//!   build reads `<t>`'s chain up to `K_u` and never further, so nothing
//!   may be recorded above it but the exit's own grant removals and the
//!   thaw.
//! - **tenant 0's head** ([`ZeroHead`]), through the [`MoveGate`] port.
//!
//! In this order (see [`decide`]):
//!
//! | Tenant 0 | `<t>`'s chain | Change | Answer |
//! |---|---|---|---|
//! | `d1`, undone to `<t>` | any | revoke of a key `<t>` holds | tenant 0's path: flat `m/rk/<akid>`, then D1; `200` once D1 refuses it (AM-54 LOW 3) |
//! | `d1`, undone to `<t>` | any | anything else | `409 key_moved`, nothing put |
//! | `d1`, no move | any | status or grant change of a key whose `m/kr/` is not `<t>`'s | an existing `m/rk/<t>/<akid>` applied to D1, then `409 key_moved` (AM-31; first, also when frozen: AM-54 LOW 2) |
//! | any | frozen | revoke | `m/rk/<t>/<akid>`, no record; tenant 0 read again: undone to `<t>` → applied to D1, `200`; else `503` |
//! | any | frozen | anything else | `503` |
//! | `moving` to `<t>` | not frozen | anything but a revoke | `503` (AM-31: only the move tool's records and revokes) |
//!
//! Otherwise the change goes on as before. A revocation always wins (ADR
//! §8.5): every path that refuses a revoke's chain record has put its
//! `m/rk/` first.

use std::collections::BTreeSet;

use crate::crypto::scheme2::TenantId;
use crate::types::Result;

/// Tenant 0's verified head, as the key writer of a managed tenant needs
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZeroHead {
    /// Selector `d1` with `move` absent: before any move, or after a
    /// give-up.
    D1,
    /// Selector `d1` after an undo: `undo_stamp` set, `move.to` = `to`.
    Undone { to: TenantId },
    /// The move's window into `to`.
    Moving { to: TenantId },
    /// The flip is done: tenant 0's data is `to`'s.
    Moved { to: TenantId },
    /// Day 30 is done.
    Retired,
}

/// What `<t>`'s verified tenant head says that the frozen writer and the
/// exit's grant removals need.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TenantDoor {
    /// `keys_frozen = {at}`: copied from the key chain's `frozen_at` by
    /// the record that sets `restoring` on the root unit (AM-28).
    pub keys_frozen: Option<u64>,
    /// `moved_in` is set: a move placed tenant 0's buckets here.
    pub moved_in: bool,
    /// The bucket ids placed on the root unit.
    pub root_placed: BTreeSet<String>,
}

/// The move's heads and tenant 0's key path, for a managed tenant's key
/// writer. Every answer is the verified head as of the call: no cache.
/// An `Err` makes the writer answer `503`.
#[allow(async_fn_in_trait)]
pub trait MoveGate {
    /// Tenant 0's head. A shape [`ZeroHead`] cannot state is an `Err`.
    async fn zero_head(&self) -> Result<ZeroHead>;
    /// `tenant`'s head.
    async fn tenant_door(&self, tenant: &TenantId) -> Result<TenantDoor>;
    /// Tenant 0's revoke of `akid`: the flat `m/rk/<akid>` first, then
    /// D1 (`disabled`, grants deleted). `Ok` only once D1 refuses the
    /// key (DUR-7); a key D1 does not hold is refused already.
    async fn zero_revoke(&self, akid: &str) -> Result<()>;
    /// Applies an existing `m/rk/<t>/<akid>` to D1 (`disabled`, grants
    /// deleted), as `forget_revoked_keys` does for flat ones. `Ok` only
    /// once D1 refuses the key; idempotent.
    async fn refuse_in_d1(&self, akid: &str) -> Result<()>;
}

/// The kind of a key change, as the gate classes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// A new subject.
    Create,
    /// A revoke of an existing subject.
    Revoke,
    /// Any other status or grant change of an existing subject.
    Other,
}

/// What the gate decided for one change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No move rule applies: the change goes on.
    Go,
    /// `409 key_moved`, nothing put. With `pre_apply`, an existing
    /// `m/rk/<t>/<akid>` of the key is applied to D1 first (AM-31).
    KeyMoved { pre_apply: bool },
    /// The revoke goes to tenant 0's path (AM-54 LOW 3).
    ZeroRevoke,
    /// The chain is frozen and this is a revoke: `m/rk/<t>/<akid>`, no
    /// record, then tenant 0 is read again (AM-28).
    FrozenRevoke,
    /// `503`, nothing put.
    Unavailable,
}

/// The facts [`decide`] reads.
#[derive(Clone, Copy, Debug)]
pub struct Facts<'a> {
    pub tenant: &'a TenantId,
    pub zero: &'a ZeroHead,
    /// `<t>`'s key-chain head carries `frozen_at`.
    pub frozen: bool,
    pub kind: ChangeKind,
    /// The subject is a key with a secret (an S3 key, an app password or
    /// the internal key) that `<t>`'s chain holds.
    pub key_held: bool,
    /// The key's `m/kr/` names `<t>`. `None` when not read (not a key);
    /// an unreadable or missing route is `Some(false)`.
    pub routed_here: Option<bool>,
}

/// The move rules, in the order of the table in this module's docs.
pub fn decide(f: &Facts<'_>) -> Gate {
    let to_us = |to: &TenantId| to == f.tenant;
    match f.zero {
        ZeroHead::Undone { to } if to_us(to) => {
            return match (f.kind, f.key_held) {
                (ChangeKind::Revoke, true) => Gate::ZeroRevoke,
                _ => Gate::KeyMoved { pre_apply: false },
            }
        }
        ZeroHead::D1 => {
            let changes_key = matches!(f.kind, ChangeKind::Revoke | ChangeKind::Other);
            if changes_key && f.key_held && f.routed_here == Some(false) {
                return Gate::KeyMoved { pre_apply: true };
            }
        }
        _ => {}
    }
    if f.frozen {
        return match f.kind {
            ChangeKind::Revoke => Gate::FrozenRevoke,
            _ => Gate::Unavailable,
        };
    }
    match f.zero {
        ZeroHead::Moving { to } if to_us(to) && f.kind != ChangeKind::Revoke => Gate::Unavailable,
        _ => Gate::Go,
    }
}

/// Whether the D1 rule of AM-31 needs the key's route: only with tenant
/// 0 at `d1` and no move, for a change of an existing key.
pub fn needs_route(zero: &ZeroHead, kind: ChangeKind, key_held: bool) -> bool {
    *zero == ZeroHead::D1 && kind != ChangeKind::Create && key_held
}

#[cfg(feature = "testkit")]
pub mod testkit {
    //! A [`MoveGate`] whose heads a test sets, and which records the calls
    //! on tenant 0's path.
    use super::*;
    use std::cell::RefCell;

    use crate::types::BridgeError;

    pub struct FakeGate {
        pub zero: RefCell<Option<ZeroHead>>,
        pub door: RefCell<Option<TenantDoor>>,
        /// Every `zero_revoke` and `refuse_in_d1`, in order.
        pub calls: RefCell<Vec<String>>,
        /// `zero_revoke` and `refuse_in_d1` fail while set.
        pub d1_down: RefCell<bool>,
        /// After this many `zero_head` reads, the head becomes the second
        /// one (a head that moves during a call).
        pub then: RefCell<Option<(u32, ZeroHead)>>,
    }

    impl FakeGate {
        /// Tenant 0 at `d1` with no move, the tenant head empty.
        pub fn before_move() -> FakeGate {
            FakeGate {
                zero: RefCell::new(Some(ZeroHead::D1)),
                door: RefCell::new(Some(TenantDoor::default())),
                calls: RefCell::new(Vec::new()),
                d1_down: RefCell::new(false),
                then: RefCell::new(None),
            }
        }

        pub fn set_zero(&self, z: ZeroHead) {
            *self.zero.borrow_mut() = Some(z);
        }

        pub fn set_door(&self, d: TenantDoor) {
            *self.door.borrow_mut() = Some(d);
        }
    }

    impl MoveGate for FakeGate {
        async fn zero_head(&self) -> Result<ZeroHead> {
            let mut then = self.then.borrow_mut();
            if let Some((n, next)) = then.take() {
                match n {
                    0 => *self.zero.borrow_mut() = Some(next),
                    n => *then = Some((n - 1, next)),
                }
            }
            self.zero
                .borrow()
                .clone()
                .ok_or(BridgeError::Blob("tenant 0 head unreadable".into()))
        }
        async fn tenant_door(&self, _tenant: &TenantId) -> Result<TenantDoor> {
            self.door
                .borrow()
                .clone()
                .ok_or(BridgeError::Blob("tenant head unreadable".into()))
        }
        async fn zero_revoke(&self, akid: &str) -> Result<()> {
            if *self.d1_down.borrow() {
                return Err(BridgeError::Sql("d1 down".into()));
            }
            self.calls.borrow_mut().push(format!("zero_revoke {akid}"));
            Ok(())
        }
        async fn refuse_in_d1(&self, akid: &str) -> Result<()> {
            if *self.d1_down.borrow() {
                return Err(BridgeError::Sql("d1 down".into()));
            }
            self.calls.borrow_mut().push(format!("refuse_in_d1 {akid}"));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: &str) -> TenantId {
        TenantId::parse(n).unwrap()
    }

    fn facts<'a>(
        tenant: &'a TenantId,
        zero: &'a ZeroHead,
        frozen: bool,
        kind: ChangeKind,
        routed_here: Option<bool>,
    ) -> Facts<'a> {
        Facts {
            tenant,
            zero,
            frozen,
            kind,
            key_held: true,
            routed_here,
        }
    }

    #[test]
    fn the_table_in_order() {
        let us = t("t_00000000000000a1");
        let other = t("t_00000000000000b2");
        use ChangeKind::*;
        let undone = ZeroHead::Undone { to: us.clone() };
        // Undone to us: a held key's revoke goes to tenant 0's path, the
        // rest is key_moved, frozen or not.
        for frozen in [false, true] {
            assert_eq!(
                decide(&facts(&us, &undone, frozen, Revoke, None)),
                Gate::ZeroRevoke
            );
            assert_eq!(
                decide(&facts(&us, &undone, frozen, Other, None)),
                Gate::KeyMoved { pre_apply: false }
            );
            assert_eq!(
                decide(&facts(&us, &undone, frozen, Create, None)),
                Gate::KeyMoved { pre_apply: false }
            );
        }
        // A revoke of a subject the chain does not hold as a key.
        let mut f = facts(&us, &undone, true, Revoke, None);
        f.key_held = false;
        assert_eq!(decide(&f), Gate::KeyMoved { pre_apply: false });
        // d1, no move: a key routed elsewhere is key_moved first, also
        // frozen (AM-54 LOW 2).
        for frozen in [false, true] {
            for kind in [Revoke, Other] {
                assert_eq!(
                    decide(&facts(&us, &ZeroHead::D1, frozen, kind, Some(false))),
                    Gate::KeyMoved { pre_apply: true }
                );
            }
        }
        assert_eq!(
            decide(&facts(&us, &ZeroHead::D1, false, Other, Some(true))),
            Gate::Go
        );
        assert_eq!(
            decide(&facts(&us, &ZeroHead::D1, false, Create, None)),
            Gate::Go
        );
        // Frozen: a revoke keeps its m/rk/, the rest is 503.
        for zero in [
            ZeroHead::D1,
            ZeroHead::Moved { to: us.clone() },
            ZeroHead::Moving { to: us.clone() },
            ZeroHead::Retired,
        ] {
            assert_eq!(
                decide(&facts(&us, &zero, true, Revoke, Some(true))),
                Gate::FrozenRevoke
            );
            assert_eq!(
                decide(&facts(&us, &zero, true, Other, Some(true))),
                Gate::Unavailable
            );
            assert_eq!(
                decide(&facts(&us, &zero, true, Create, None)),
                Gate::Unavailable
            );
        }
        // Moving to us, not frozen: only revokes.
        let moving = ZeroHead::Moving { to: us.clone() };
        assert_eq!(decide(&facts(&us, &moving, false, Revoke, None)), Gate::Go);
        assert_eq!(
            decide(&facts(&us, &moving, false, Other, None)),
            Gate::Unavailable
        );
        assert_eq!(
            decide(&facts(&us, &moving, false, Create, None)),
            Gate::Unavailable
        );
        // A move into another tenant changes nothing here.
        for zero in [
            ZeroHead::Moving { to: other.clone() },
            ZeroHead::Moved { to: other.clone() },
            ZeroHead::Undone { to: other.clone() },
            ZeroHead::Moved { to: us.clone() },
        ] {
            for kind in [Create, Revoke, Other] {
                assert_eq!(decide(&facts(&us, &zero, false, kind, None)), Gate::Go);
            }
        }
    }

    #[test]
    fn the_route_is_read_only_for_the_d1_rule() {
        assert!(needs_route(&ZeroHead::D1, ChangeKind::Revoke, true));
        assert!(needs_route(&ZeroHead::D1, ChangeKind::Other, true));
        assert!(!needs_route(&ZeroHead::D1, ChangeKind::Create, true));
        assert!(!needs_route(&ZeroHead::D1, ChangeKind::Other, false));
        assert!(!needs_route(&ZeroHead::Retired, ChangeKind::Other, true));
    }
}
