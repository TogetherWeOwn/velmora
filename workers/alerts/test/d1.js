// A D1-shaped adapter over node:sqlite, so tests run the real SQL.
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export class FakeD1 {
  constructor() {
    this.db = new DatabaseSync(":memory:");
    this.log = [];
  }
  exec(sql) {
    this.db.exec(sql);
  }
  applyDir(dir) {
    for (const f of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
      this.db.exec(readFileSync(join(dir, f), "utf8"));
    }
    return this;
  }
  prepare(sql) {
    const self = this;
    let params = [];
    const stmt = {
      bind(...p) {
        params = p;
        return stmt;
      },
      async first() {
        self.log.push(sql);
        return self.db.prepare(sql).get(...params) ?? null;
      },
      async all() {
        self.log.push(sql);
        return { results: self.db.prepare(sql).all(...params), success: true };
      },
      async run() {
        self.log.push(sql);
        const r = self.db.prepare(sql).run(...params);
        return { success: true, meta: { changes: Number(r.changes) } };
      },
    };
    return stmt;
  }
}

/** An R2-shaped bucket holding only keys. */
export class FakeBucket {
  constructor(keys = []) {
    this.keys = [...keys].sort();
    this.lists = 0;
  }
  async list({ prefix = "", startAfter = "", limit = 1000, cursor } = {}) {
    this.lists++;
    const all = this.keys.filter((k) => k.startsWith(prefix) && k > startAfter);
    const start = cursor ? Number(cursor) : 0;
    const page = all.slice(start, start + limit);
    const truncated = start + limit < all.length;
    return { objects: page.map((key) => ({ key })), truncated, cursor: truncated ? String(start + limit) : undefined };
  }
}

export class FakeEmail {
  constructor() {
    this.sent = [];
    this.fail = null;
  }
  async send(m) {
    if (this.fail) {
      const e = new Error(this.fail);
      e.code = this.fail;
      throw e;
    }
    this.sent.push(m);
    return { messageId: `m${this.sent.length}` };
  }
}
