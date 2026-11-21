// The JavaScript side of `DoSql` (do_sql.rs) and of the point-in-time
// bridge (pitr.rs). workers-rs 0.8.7 binds neither
// `storage.transactionSync` nor the point-in-time calls, so they are
// reached from here. Every function takes the object's storage
// (`ctx.storage`) and nothing else from the runtime.
//
// Rows changed: the difference of SQLite's `total_changes()` around the
// statement, read in the same synchronous turn. It counts the rows that
// triggers change, as D1's `meta.changes` does.

function totalChanges(sql) {
  return sql.exec("SELECT total_changes()").raw().next().value[0];
}

// One statement run to completion; its rows (null = not kept) and the
// rows it changed.
function step(sql, text, params, keepRows) {
  const before = totalChanges(sql);
  const cursor = sql.exec(text, ...params);
  let rows = null;
  if (keepRows) {
    rows = cursor.raw().toArray();
  } else {
    for (const _ of cursor.raw()) {
      // Runs the statement to its end; `RETURNING` and `SELECT` rows are
      // dropped.
    }
  }
  return [rows, totalChanges(sql) - before];
}

export function doQuery(storage, text, params) {
  return step(storage.sql, text, params, true)[0];
}

export function doExec(storage, text, params) {
  return step(storage.sql, text, params, false)[1];
}

// All or nothing: a throw inside `transactionSync` rolls every statement
// of the batch back, and the throw reaches the caller.
export function doBatch(storage, stmts) {
  const sql = storage.sql;
  return storage.transactionSync(() =>
    stmts.map(([text, params]) => step(sql, text, params, false)[1]),
  );
}

// A script of several statements (a migration), in one transaction.
export function doApply(storage, script) {
  const sql = storage.sql;
  storage.transactionSync(() => {
    for (const _ of sql.exec(script).raw()) {
      // Runs the last statement to its end.
    }
  });
}

export function doDatabaseSize(storage) {
  return storage.sql.databaseSize;
}

export function pitrCurrent(storage) {
  return storage.getCurrentBookmark();
}

export function pitrAt(storage, unixMs) {
  return storage.getBookmarkForTime(unixMs);
}

// Arms the restore and ends the object's session in one step, so that a
// restore is never armed without the restart that applies it. The
// request that asks for it does not get an answer: `abort()` resets the
// object, and the next request starts it from `bookmark`. The caller
// takes `getCurrentBookmark()` first and keeps it outside the object:
// that bookmark undoes the restore.
export async function pitrRestoreNow(state, storage, bookmark) {
  await storage.onNextSessionRestoreBookmark(bookmark);
  state.abort("point-in-time restore");
}

// One unit call as one transaction: `run` is the Rust side of the call.
// A throw from it rolls every write of the call back and reaches the
// caller.
export function doAtomically(storage, run) {
  storage.transactionSync(() => {
    run();
  });
}
