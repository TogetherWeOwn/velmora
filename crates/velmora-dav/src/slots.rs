//! Part buffers of an isolate: a count shared by every upload in it.
//!
//! A part that goes up is held whole: its bytes in the gateway, plus the
//! runtime's copy while the request carries them. At 16 MiB a part that
//! is 32 MiB, and a Worker isolate has 128 MB for everything it runs. So
//! the parts held at once are counted for the whole isolate, not per
//! upload: two uploads in parallel share the slots instead of doubling
//! the memory.

use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::task::{Poll, Waker};

thread_local! {
    static USED: Cell<usize> = const { Cell::new(0) };
    static WAITERS: RefCell<Vec<Waker>> = const { RefCell::new(Vec::new()) };
}

/// One part buffer, held until dropped.
#[derive(Debug)]
pub struct Slot(());

impl Slot {
    /// A slot now, if fewer than `max` are held.
    pub fn try_acquire(max: usize) -> Option<Slot> {
        USED.with(|used| {
            (used.get() < max.max(1)).then(|| {
                used.set(used.get() + 1);
                Slot(())
            })
        })
    }

    /// Waits for a slot.
    pub async fn acquire(max: usize) -> Slot {
        poll_fn(|cx| match Slot::try_acquire(max) {
            Some(slot) => Poll::Ready(slot),
            None => {
                WAITERS.with(|w| w.borrow_mut().push(cx.waker().clone()));
                Poll::Pending
            }
        })
        .await
    }

    /// Slots held now in this isolate.
    pub fn held() -> usize {
        USED.with(Cell::get)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        USED.with(|used| used.set(used.get().saturating_sub(1)));
        let waiters = WAITERS.with(|w| std::mem::take(&mut *w.borrow_mut()));
        for w in waiters {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_across_holders() {
        let a = Slot::try_acquire(2).unwrap();
        let b = Slot::try_acquire(2).unwrap();
        assert!(Slot::try_acquire(2).is_none());
        assert_eq!(Slot::held(), 2);
        drop(a);
        let c = Slot::try_acquire(2).unwrap();
        drop((b, c));
        assert_eq!(Slot::held(), 0);
    }
}
