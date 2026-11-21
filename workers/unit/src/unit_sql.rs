//! [`UnitSql`] for [`DoSql`]: a whole unit call inside one
//! `storage.transactionSync` (`docs/units.md`, rule 2).
//!
//! The call runs as a Rust closure that the shim calls back from inside
//! the transaction. A batch inside it is a nested `transactionSync`,
//! which the runtime keeps as a savepoint: a refused batch rolls back
//! only itself, and an error of the call rolls back everything.

use std::cell::RefCell;
use std::rc::Rc;

use velmora_bridge::unit::UnitSql;
use velmora_bridge::{BridgeError, Result};
use worker::js_sys::Function;
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::{self, prelude::wasm_bindgen, JsCast, JsValue};
use worker::worker_sys::DurableObjectStorage;

use crate::DoSql;

#[wasm_bindgen(module = "/src/shim.js")]
extern "C" {
    #[wasm_bindgen(js_name = doAtomically, catch)]
    fn do_atomically(
        storage: &DurableObjectStorage,
        run: &Function,
    ) -> std::result::Result<(), JsValue>;
}

impl UnitSql for DoSql {
    fn atomically(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let failure: Rc<RefCell<Option<BridgeError>>> = Rc::new(RefCell::new(None));
        let f: *mut (dyn FnMut() -> Result<()> + '_) = f;
        // SAFETY: the closure below is called only by `doAtomically`,
        // synchronously, before this function returns: `transactionSync`
        // runs its callback at once and keeps no reference to it, and the
        // closure is dropped right after the call. So `f` outlives every
        // use of the pointer, and nothing else borrows it meanwhile.
        // A Rust panic inside `f` traps the instance: the transaction
        // rolls back, the error reaches this frame as the runtime's, and
        // the caller only turns it into a `failed` answer, with no SQL.
        let f: *mut (dyn FnMut() -> Result<()> + 'static) = unsafe { std::mem::transmute(f) };
        let fail = failure.clone();
        let run = Closure::<dyn FnMut() -> std::result::Result<(), JsValue>>::new(move || {
            // SAFETY: see above.
            let f = unsafe { &mut *f };
            f().map_err(|e| {
                *fail.borrow_mut() = Some(e);
                JsValue::from_str("unit: roll back")
            })
        });
        let out = do_atomically(self.raw(), run.as_ref().unchecked_ref());
        drop(run);
        match out {
            Ok(()) => Ok(()),
            // The call's own error, if it made one; else the runtime's.
            Err(js) => Err(failure
                .borrow_mut()
                .take()
                .unwrap_or_else(|| crate::do_sql::runtime_error(js))),
        }
    }

    fn apply_script(&self, script: &str) -> Result<()> {
        self.apply(script)
    }
}
