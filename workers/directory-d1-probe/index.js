// A test-only Worker: it runs the directory's statements on D1 for the
// native test suite, so that a statement D1 refuses fails a test before it
// fails in production. Never deployed with a route; run with `wrangler dev`
// (local D1) or `wrangler dev --remote` (a throwaway D1). See README.md.
//
// It binds values as `workers/s3-bridge/src/d1.rs` does: an integer as a
// JS number, refused outside ±(2^53 - 1); text as a string; a blob as an
// ArrayBuffer; null as null. `query` reads `.raw()` rows, `exec` and every
// statement of `batch` read `meta.changes`, and `batch` is `D1Database.batch`
// (one transaction). Each request names its database (`DB0` or `DB1`).

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function bindValue(v) {
  if (v === null) return null;
  switch (v.t) {
    case "i": {
      const n = Number(v.v);
      if (!Number.isSafeInteger(n) || String(n) !== v.v) {
        throw new Error("d1: integer outside JS safe range");
      }
      return n;
    }
    case "s":
      return v.v;
    case "b":
      return Uint8Array.from(atob(v.v), (c) => c.charCodeAt(0)).buffer;
    default:
      throw new Error("probe: unknown value tag");
  }
}

function readValue(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > MAX_SAFE) {
      throw new Error("d1: unexpected result shape");
    }
    return { t: "i", v: String(v) };
  }
  if (typeof v === "string") return { t: "s", v };
  let bytes;
  if (v instanceof ArrayBuffer) bytes = new Uint8Array(v);
  else if (v instanceof Uint8Array) bytes = v;
  else if (Array.isArray(v)) bytes = Uint8Array.from(v);
  else throw new Error("d1: unexpected result shape");
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return { t: "b", v: btoa(s) };
}

function changes(result) {
  if (result.success === false || !result.meta) {
    throw new Error("d1: unexpected result shape");
  }
  const n = result.meta.changes;
  if (typeof n !== "number") throw new Error("d1: unexpected result shape");
  return n;
}

function statement(db, s) {
  return db.prepare(s.sql).bind(...s.params.map(bindValue));
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("POST only", { status: 405 });
    const url = new URL(request.url);
    const db = env[url.searchParams.get("db")];
    if (!db || !/^DB[01]$/.test(url.searchParams.get("db"))) {
      return Response.json({ error: "probe: unknown database" }, { status: 400 });
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return Response.json({ error: "probe: body is not JSON" }, { status: 400 });
    }
    try {
      switch (url.pathname) {
        // Drops every object of the database but SQLite's and the
        // platform's own (triggers and views first, then tables, newest
        // first so a child goes before its parent), then runs each schema
        // statement on its own.
        case "/wipe": {
          const objects = await db
            .prepare(
              "SELECT type, name FROM sqlite_master WHERE type IN ('trigger', 'view', 'table') " +
                "AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' " +
                "ORDER BY CASE type WHEN 'table' THEN 1 ELSE 0 END, rowid DESC",
            )
            .raw();
          for (const [type, name] of objects) {
            if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error("probe: bad object name");
            const kind = type === "trigger" ? "TRIGGER" : type === "view" ? "VIEW" : "TABLE";
            await db.prepare(`DROP ${kind} IF EXISTS ${name}`).run();
          }
          for (const sql of body.schema) await db.prepare(sql).run();
          return Response.json({ ok: true });
        }
        case "/query": {
          const rows = await statement(db, body).raw();
          return Response.json({ rows: rows.map((r) => r.map(readValue)) });
        }
        case "/exec": {
          return Response.json({ changed: changes(await statement(db, body).run()) });
        }
        case "/batch": {
          const results = await db.batch(body.stmts.map((s) => statement(db, s)));
          if (results.length !== body.stmts.length) throw new Error("d1: unexpected result shape");
          return Response.json({ changed: results.map(changes) });
        }
        default:
          return Response.json({ error: "probe: unknown call" }, { status: 404 });
      }
    } catch (e) {
      // The database's own message: this Worker serves tests only, and
      // the statements and values are the tests' own.
      return Response.json({ error: String(e && e.message ? e.message : e) }, { status: 200 });
    }
  },
};
