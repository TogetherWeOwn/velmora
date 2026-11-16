// velmora console UI. Plain DOM, no framework. User data only ever goes
// into the page through textContent / properties, never innerHTML.

const PART = 16 * 1024 * 1024;
const PART_CONCURRENCY = 2;
const RETRIES = 4;

const $ = (id) => document.getElementById(id);
const state = { bucket: "", prefix: "", folders: [], files: [], next: null, selected: new Set(), filter: "" };

function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (k === "class") n.className = v;
    else if (k in n) n[k] = v;
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) n.append(c instanceof Node ? c : String(c));
  return n;
}

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove("show"), 4000);
}

class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
  }
}

async function api(path, { method = "GET", body, query } = {}) {
  const qs = query ? "?" + new URLSearchParams(query) : "";
  const init = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers["content-type"] = "application/json";
  }
  const res = await fetch(`/api${path}${qs}`, init);
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* not JSON (an Access redirect or a 403 page) */
  }
  if (!res.ok) throw new ApiError(res.status, data?.error, data?.message || data?.error);
  return data;
}

function fmtSize(n) {
  if (n === undefined || n === null) return "";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i ? v.toFixed(v < 10 ? 1 : 0) : v} ${u[i]}`;
}

function fmtDate(s) {
  if (!s) return "";
  const d = new Date(s);
  return isNaN(d) ? s : d.toLocaleString();
}

const baseName = (k) => k.replace(/\/$/, "").split("/").pop();

// ---------------------------------------------------------------------------
// Navigation (hash: #/<bucket>/<prefix>)

function go(bucket, prefix = "") {
  location.hash = "#/" + encodeURIComponent(bucket) + (prefix ? "/" + encodeURIComponent(prefix) : "");
}

function readHash() {
  const m = location.hash.match(/^#\/([^/]*)(?:\/(.*))?$/);
  if (!m) return { bucket: "", prefix: "" };
  try {
    return { bucket: decodeURIComponent(m[1]), prefix: m[2] ? decodeURIComponent(m[2]) : "" };
  } catch {
    return { bucket: "", prefix: "" };
  }
}

window.addEventListener("hashchange", () => {
  const { bucket, prefix } = readHash();
  open(bucket, prefix);
});

// ---------------------------------------------------------------------------
// Buckets

async function loadBuckets() {
  const ul = $("buckets");
  try {
    const { buckets } = await api("/buckets");
    ul.replaceChildren(
      ...buckets.map((b) =>
        el("li", {}, el("button", { type: "button", on: { click: () => go(b.name) }, "aria-current": String(b.name === state.bucket) }, b.name)),
      ),
    );
    if (!buckets.length) ul.replaceChildren(el("li", { class: "empty" }, "No buckets yet"));
    return buckets;
  } catch (e) {
    ul.replaceChildren(el("li", { class: "empty" }, `Could not list buckets: ${e.message}`));
    return [];
  }
}

$("refresh-buckets").addEventListener("click", loadBuckets);
$("new-bucket").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const name = $("new-bucket-name").value.trim();
  try {
    await api("/buckets", { method: "POST", body: { name } });
    $("new-bucket-name").value = "";
    toast(`Bucket ${name} created`);
    await loadBuckets();
    go(name);
  } catch (e) {
    toast(`Create failed: ${e.message}`);
  }
});

// ---------------------------------------------------------------------------
// Listing

async function open(bucket, prefix) {
  state.bucket = bucket;
  state.prefix = prefix;
  state.selected.clear();
  state.filter = "";
  $("search").value = "";
  for (const b of $("buckets").querySelectorAll("button")) b.setAttribute("aria-current", String(b.textContent === bucket));
  renderCrumbs();
  if (!bucket) {
    state.folders = [];
    state.files = [];
    state.next = null;
    render();
    return;
  }
  await loadPage(false);
}

let listSeq = 0;

async function loadPage(more) {
  // Only the newest listing may change the view: a slow answer for a
  // folder or bucket left meanwhile is dropped, success or failure.
  const seq = ++listSeq;
  const { bucket, prefix } = state;
  const token = more ? state.next : null;
  let out = null;
  let failure = null;
  try {
    out = await api("/list", { query: { bucket, prefix, ...(token ? { token } : {}) } });
  } catch (e) {
    failure = e;
  }
  if (seq !== listSeq || bucket !== state.bucket || prefix !== state.prefix) return;
  if (!more) {
    state.folders = [];
    state.files = [];
    state.next = null;
  }
  if (failure) {
    toast(`Listing failed: ${failure.message}`);
  } else {
    state.folders.push(...out.folders);
    // The folder's own marker object is not listed as a file in it.
    state.files.push(...out.files.filter((f) => f.key !== prefix));
    state.next = out.truncated ? out.next : null;
  }
  render();
}

$("more").addEventListener("click", () => loadPage(true));

function renderCrumbs() {
  const items = [];
  if (state.bucket) {
    items.push(el("li", {}, el("button", { type: "button", on: { click: () => go(state.bucket) } }, state.bucket)));
    let acc = "";
    for (const part of state.prefix.split("/").filter(Boolean)) {
      acc += part + "/";
      const p = acc;
      items.push(el("li", {}, el("button", { type: "button", on: { click: () => go(state.bucket, p) } }, part)));
    }
  } else {
    items.push(el("li", {}, "Pick a bucket"));
  }
  $("crumbs").replaceChildren(...items);
}

function render() {
  const f = state.filter.toLowerCase();
  const match = (k) => !f || baseName(k).toLowerCase().includes(f);
  const rows = [];
  for (const p of state.folders.filter(match)) {
    rows.push(
      el(
        "tr",
        {},
        el("td", { class: "c-check" }, checkbox(p)),
        el("td", {}, el("button", { type: "button", class: "link folder", on: { click: () => go(state.bucket, p) } }, baseName(p) + "/")),
        el("td", { class: "c-size" }),
        el("td", { class: "c-date" }),
        el(
          "td",
          { class: "c-act" },
          el("button", { type: "button", on: { click: () => renameFolder(p) } }, "Rename/move"),
          el("button", { type: "button", class: "del", on: { click: () => deleteKeys([], [p]) } }, "Delete"),
        ),
      ),
    );
  }
  for (const o of state.files.filter((x) => match(x.key))) {
    rows.push(
      el(
        "tr",
        {},
        el("td", { class: "c-check" }, checkbox(o.key)),
        el("td", {}, el("button", { type: "button", class: "link", on: { click: () => info(o.key) } }, baseName(o.key))),
        el("td", { class: "c-size" }, fmtSize(o.size)),
        el("td", { class: "c-date" }, fmtDate(o.modified)),
        el(
          "td",
          { class: "c-act" },
          el("a", { href: downloadUrl(o.key), download: baseName(o.key), class: "dl" }, "Download"),
          el("button", { type: "button", on: { click: () => info(o.key) } }, "Info"),
          el("button", { type: "button", on: { click: () => renameFile(o.key) } }, "Rename/move"),
          el("button", { type: "button", class: "del", on: { click: () => deleteKeys([o.key], []) } }, "Delete"),
        ),
      ),
    );
  }
  $("rows").replaceChildren(...rows);
  $("empty").hidden = rows.length > 0 || !state.bucket;
  $("more").hidden = !state.next;
  $("select-all").checked = false;
  updateSelection();
}

function checkbox(key) {
  return el("input", {
    type: "checkbox",
    checked: state.selected.has(key),
    "aria-label": `Select ${baseName(key)}`,
    on: {
      change: (e) => {
        if (e.target.checked) state.selected.add(key);
        else state.selected.delete(key);
        updateSelection();
      },
    },
  });
}

function updateSelection() {
  $("delete-selected").disabled = state.selected.size === 0;
  $("delete-selected").textContent = state.selected.size ? `Delete selected (${state.selected.size})` : "Delete selected";
}

$("select-all").addEventListener("change", (e) => {
  for (const cb of $("rows").querySelectorAll("input[type=checkbox]")) {
    cb.checked = e.target.checked;
    cb.dispatchEvent(new Event("change"));
  }
});

$("search").addEventListener("input", (e) => {
  state.filter = e.target.value;
  render();
});

function downloadUrl(key) {
  return "/api/download?" + new URLSearchParams({ bucket: state.bucket, key });
}

// ---------------------------------------------------------------------------
// Dialogs

// One shared <dialog>: dialogs (some opened by background uploads) wait
// their turn, so an answer never belongs to another question.
let dialogChain = Promise.resolve();

function dialog(title, content, buttons) {
  const run = () =>
    new Promise((resolve) => {
      const d = $("dialog");
      $("dialog-title").textContent = title;
      $("dialog-content").replaceChildren(content);
      $("dialog-buttons").replaceChildren(
        ...buttons.map(([label, value, cls]) => el("button", { value, class: cls || "", type: "submit" }, label)),
      );
      d.addEventListener("close", () => resolve(d.returnValue), { once: true });
      d.returnValue = "";
      d.showModal();
      content.querySelector?.("input")?.focus();
    });
  const p = dialogChain.then(run);
  dialogChain = p.catch(() => {});
  return p;
}

async function ask(title, label, value) {
  const input = el("input", { type: "text", value, "aria-label": label });
  const p = dialog(title, el("div", {}, el("p", {}, label), input), [["Cancel", "cancel", "ghost"], ["OK", "ok"]]);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      $("dialog").close("ok");
    }
  });
  return (await p) === "ok" ? input.value : null;
}

async function confirmBox(title, text) {
  return (await dialog(title, el("p", {}, text), [["Cancel", "cancel", "ghost"], ["Delete", "ok", "danger"]])) === "ok";
}

function kv(pairs) {
  return el("dl", { class: "kv" }, ...pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v ?? "")]));
}

// ---------------------------------------------------------------------------
// Info

/** A one-word summary of velmora's per-extent state. */
function lifecycle(st) {
  if (!st || st.unavailable || !Array.isArray(st.extents)) return ["unknown", ""];
  const xs = st.extents;
  if (!xs.length) return ["empty", "good"];
  // Stages: post → verify → release → done (or dead / cancelled).
  if (xs.some((x) => x.stage === "dead")) return ["failed: a job is dead", "warn"];
  if (xs.every((x) => x.safety_state === "released" || x.safety_state === "deleted")) {
    return ["released (Usenet + cache)", "good"];
  }
  if (xs.some((x) => x.stage === "post")) return ["posting", "warn"];
  if (xs.some((x) => x.stage === "verify")) return ["posted, verifying", "warn"];
  if (xs.some((x) => x.stage === "release" || x.safety_state === "releasing")) return ["verified, releasing", "good"];
  return ["verified, safety copy held", "good"];
}

async function info(key) {
  let data;
  try {
    data = await api("/info", { query: { bucket: state.bucket, key } });
  } catch (e) {
    toast(`Info failed: ${e.message}`);
    return;
  }
  const { head, state: st } = data;
  const [label, cls] = lifecycle(st);
  const content = el(
    "div",
    {},
    kv([
      ["Key", key],
      ["Size", `${fmtSize(head.size)} (${head.size} bytes)`],
      ["ETag", head.etag],
      ["Content type", head.contentType],
      ["Modified", fmtDate(head.modified)],
      ["velmora state", el("span", { class: `badge ${cls}` }, label)],
      ["Generation", st?.generation ? `${st.generation} (${st.state})` : st?.unavailable || ""],
    ]),
  );
  if (Array.isArray(st?.extents) && st.extents.length) {
    content.append(
      el(
        "table",
        { class: "mini" },
        el("thead", {}, el("tr", {}, ...["#", "stage", "safety copy", "cache", "verified on"].map((h) => el("th", {}, h)))),
        el(
          "tbody",
          {},
          ...st.extents.map((x) =>
            el(
              "tr",
              {},
              el("td", {}, x.seq),
              el("td", {}, x.stage ?? "done"),
              el("td", {}, x.safety_state),
              el("td", {}, x.cache),
              el(
                "td",
                {},
                (x.backbones || [])
                  .filter((b) => b.total > 0)
                  .map((b) => `${b.backbone} ${b.ok}/${b.total}${b.counts ? "" : " (not counted)"}`)
                  .join(", ") || "-",
              ),
            ),
          ),
        ),
      ),
    );
  }
  await dialog(baseName(key), content, [["Close", "close"]]);
}

// ---------------------------------------------------------------------------
// Rename, move, folders, delete

async function listAll(bucket, prefix) {
  const keys = [];
  let token;
  do {
    const out = await api("/list", { query: { bucket, prefix, recursive: "1", ...(token ? { token } : {}) } });
    keys.push(...out.files.map((f) => f.key));
    token = out.truncated ? out.next : null;
  } while (token);
  return keys;
}

async function renameFile(key) {
  const bucket = state.bucket;
  let to = await ask("Rename or move", "New path in this bucket (end with / to move into a folder)", key);
  if (to === null || !to) return;
  if (to.endsWith("/")) to += baseName(key);
  if (to === key) return;
  try {
    await api("/move", { method: "POST", body: { bucket, from: key, to } });
    toast("Moved");
  } catch (e) {
    toast(`Move failed: ${e.message}`);
  }
  loadPage(false);
}

async function renameFolder(prefix) {
  // The bucket is fixed when the operation starts, whatever is browsed meanwhile.
  const bucket = state.bucket;
  let to = await ask("Rename or move folder", "New folder path in this bucket", prefix);
  if (to === null || !to) return;
  if (!to.endsWith("/")) to += "/";
  if (to === prefix) return;
  if (to.startsWith(prefix)) {
    toast("A folder cannot move into itself");
    return;
  }
  const keys = await listAll(bucket, prefix);
  const t = transfer(`Move ${prefix} → ${to}`, keys.length);
  let done = 0;
  let failed = 0;
  for (const k of keys) {
    if (t.cancelled) break;
    try {
      await api("/move", { method: "POST", body: { bucket, from: k, to: to + k.slice(prefix.length) } });
    } catch {
      failed++;
    }
    t.progress(++done, `${done}/${keys.length}`);
  }
  t.finish(failed ? `${failed} failed` : t.cancelled ? "stopped" : "done");
  loadPage(false);
}

$("new-folder").addEventListener("click", async () => {
  if (!state.bucket) return toast("Pick a bucket first");
  const { bucket, prefix } = state;
  const name = await ask("New folder", "Folder name", "");
  if (!name) return;
  try {
    await api("/folder", { method: "POST", body: { bucket, prefix: prefix + name.replace(/^\/+/, "") } });
  } catch (e) {
    toast(`Failed: ${e.message}`);
  }
  loadPage(false);
});

async function deleteKeys(keys, folders) {
  let all = [...keys];
  const bucket = state.bucket;
  for (const p of folders) all.push(...(await listAll(bucket, p)));
  all = [...new Set(all)];
  if (!all.length) return toast("Nothing to delete");
  const what = folders.length ? `${all.length} object(s), including everything in ${folders.length} folder(s)` : `${all.length} object(s)`;
  if (!(await confirmBox("Delete", `Delete ${what}? This cannot be undone.`))) return;
  let failed = 0;
  for (let i = 0; i < all.length; i += 1000) {
    try {
      const out = await api("/delete", { method: "POST", body: { bucket, keys: all.slice(i, i + 1000) } });
      failed += out.errors.length;
    } catch (e) {
      failed += Math.min(1000, all.length - i);
      toast(`Delete failed: ${e.message}`);
    }
  }
  if (failed) toast(`${failed} could not be deleted`);
  else toast(`Deleted ${all.length}`);
  state.selected.clear();
  loadPage(false);
}

$("delete-selected").addEventListener("click", () => {
  const sel = [...state.selected];
  deleteKeys(
    sel.filter((k) => !k.endsWith("/") || state.files.some((f) => f.key === k)),
    sel.filter((k) => k.endsWith("/") && state.folders.includes(k)),
  );
});

// ---------------------------------------------------------------------------
// Transfers

function transfer(name, total) {
  $("transfers").hidden = false;
  const bar = el("progress", { max: total || 1, value: 0 });
  const st = el("span", { class: "t-state" }, "waiting");
  const t = { cancelled: false, onCancel: null };
  const cancel = el("button", {
    type: "button",
    class: "ghost",
    on: {
      click: () => {
        t.cancelled = true;
        cancel.disabled = true;
        t.onCancel?.();
      },
    },
  }, "Cancel");
  const li = el("li", {}, el("span", { class: "t-name", title: name }, name), el("div", {}, bar, st), cancel);
  $("transfer-list").prepend(li);
  t.progress = (v, label) => {
    bar.value = v;
    st.textContent = label;
  };
  t.finish = (label) => {
    st.textContent = label;
    cancel.disabled = true;
    bar.value = bar.max;
  };
  return t;
}

/** PUT with upload progress (fetch has none). */
function xhrPut(url, blob, onProgress, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new ApiError(0, "Aborted", "cancelled"));
    const x = new XMLHttpRequest();
    x.open("PUT", url);
    x.responseType = "json";
    x.upload.onprogress = (e) => onProgress(e.loaded);
    x.onload = () => {
      if (x.status >= 200 && x.status < 300) resolve(x.response);
      else reject(new ApiError(x.status, x.response?.error, x.response?.message));
    };
    x.onerror = () => reject(new ApiError(0, "Network", "network error"));
    x.onabort = () => reject(new ApiError(0, "Aborted", "cancelled"));
    signal.addEventListener("abort", () => x.abort(), { once: true });
    x.send(blob);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function withRetry(fn, signal) {
  for (let i = 0; ; i++) {
    if (signal.aborted) throw new ApiError(0, "Aborted", "cancelled");
    try {
      return await fn();
    } catch (e) {
      const transient = e.status === 0 || e.status === 429 || e.status >= 500;
      if (signal.aborted || !transient || e.code === "Aborted" || i >= RETRIES) throw e;
      await sleep(1000 * 2 ** i);
    }
  }
}

const resumeKey = (bucket, key, file) => `velmora-upload:${bucket}:${key}:${file.size}:${file.lastModified}`;

async function uploadFile(bucket, key, file) {
  const t = transfer(key, file.size);
  const ctl = new AbortController();
  t.onCancel = () => ctl.abort();
  const type = file.type || "application/octet-stream";
  const label = (n) => `${fmtSize(n)} / ${fmtSize(file.size)}`;
  try {
    if (file.size <= PART) {
      const put = (overwrite) => {
        const url = "/api/object?" + new URLSearchParams({ bucket, key, type, ...(overwrite ? { overwrite: "1" } : {}) });
        return withRetry(() => xhrPut(url, file, (n) => t.progress(n, label(n)), ctl.signal), ctl.signal);
      };
      try {
        await put(false);
      } catch (e) {
        if (e.code !== "DestinationExists" || !(await replaceOk(key))) throw e;
        await put(true);
      }
      t.finish("done");
      return true;
    }
    const count = Math.ceil(file.size / PART);
    if (count > 10000) throw new ApiError(400, "TooLarge", "larger than 10000 parts of 16 MiB");
    // Ask before sending gigabytes; the conditional complete still guards a race.
    let overwrite = false;
    const { exists } = await api("/head", { query: { bucket, key } });
    if (exists) {
      if (!(await replaceOk(key))) throw new ApiError(0, "Aborted", "kept the existing object");
      overwrite = true;
    }
    // Multipart, resumable: the upload id is kept until the upload ends.
    const rk = resumeKey(bucket, key, file);
    let uploadId = localStorage.getItem(rk);
    const done = new Map();
    if (uploadId) {
      try {
        const { parts } = await api("/mpu/parts", { query: { bucket, key, uploadId } });
        for (const p of parts) done.set(p.partNumber, p);
        t.progress(0, `resuming (${done.size} parts already there)`);
      } catch (e) {
        // Only a gone upload starts over; anything else keeps the id for next time.
        if (e.status !== 404) throw e;
        uploadId = null;
      }
    }
    if (!uploadId) {
      uploadId = (await api("/mpu/create", { method: "POST", body: { bucket, key, contentType: type } })).uploadId;
      localStorage.setItem(rk, uploadId);
    }
    t.onCancel = async () => {
      ctl.abort();
      localStorage.removeItem(rk);
      try {
        await api("/mpu/abort", { method: "POST", body: { bucket, key, uploadId } });
      } catch {
        /* listed under unfinished uploads */
      }
    };
    const sent = new Map();
    const report = () => {
      let n = 0;
      for (const v of sent.values()) n += v;
      t.progress(n, label(n));
    };
    const etags = new Array(count + 1);
    const queue = [];
    for (let n = 1; n <= count; n++) {
      const size = Math.min(PART, file.size - (n - 1) * PART);
      const have = done.get(n);
      if (have && have.size === size) {
        etags[n] = have.etag;
        sent.set(n, size);
      } else queue.push(n);
    }
    report();
    const worker = async () => {
      while (queue.length && !ctl.signal.aborted) {
        const n = queue.shift();
        const blob = file.slice((n - 1) * PART, Math.min(n * PART, file.size));
        const url = "/api/mpu/part?" + new URLSearchParams({ bucket, key, uploadId, partNumber: String(n) });
        const out = await withRetry(
          () =>
            xhrPut(url, blob, (b) => {
              sent.set(n, b);
              report();
            }, ctl.signal),
          ctl.signal,
        );
        etags[n] = out.etag;
        sent.set(n, blob.size);
        report();
      }
    };
    try {
      await Promise.all(Array.from({ length: PART_CONCURRENCY }, worker));
    } catch (e) {
      // One part failed for good: stop the other uploader too. The upload
      // stays open, so dropping the file again resumes it.
      ctl.abort();
      throw e;
    }
    if (ctl.signal.aborted) throw new ApiError(0, "Aborted", "cancelled");
    t.progress(file.size, "finishing");
    const parts = [];
    for (let n = 1; n <= count; n++) parts.push({ partNumber: n, etag: etags[n] });
    const complete = (overwrite) =>
      withRetry(() => api("/mpu/complete", { method: "POST", body: { bucket, key, uploadId, parts, overwrite } }), ctl.signal);
    try {
      await complete(overwrite);
    } catch (e) {
      // A refused complete leaves the upload open: it can still be finished.
      if (e.code !== "DestinationExists" || !(await replaceOk(key))) throw e;
      await complete(true);
    }
    localStorage.removeItem(rk);
    t.finish("done");
    return true;
  } catch (e) {
    t.finish(e.code === "Aborted" ? "cancelled" : `failed: ${e.message} (drop the file again to resume)`);
    return false;
  }
}

async function replaceOk(key) {
  const answer = await dialog("Replace?", el("p", {}, `${key} already exists. Replace it? The old version is not kept.`), [
    ["Keep the old one", "cancel", "ghost"],
    ["Replace", "ok", "danger"],
  ]);
  return answer === "ok";
}

// Batches run one after another, so two drops never race each other.
let uploadChain = Promise.resolve();
function uploadAll(items, bucket = state.bucket, base = state.prefix) {
  // The destination is where the files were dropped, not where the user
  // is by the time an earlier batch has finished.
  if (!bucket) return toast("Pick a bucket first");
  const run = uploadChain.then(() => uploadBatch(items, bucket, base));
  uploadChain = run.catch(() => {});
  return run;
}

async function uploadBatch(items, bucket, base) {
  let ok = 0;
  for (const { file, path } of items) {
    if (await uploadFile(bucket, base + path, file)) ok++;
  }
  toast(`Uploaded ${ok} of ${items.length}`);
  if (state.bucket === bucket) loadPage(false);
}

$("pick-files").addEventListener("change", (e) => {
  uploadAll([...e.target.files].map((f) => ({ file: f, path: f.name })));
  e.target.value = "";
});
$("pick-folder").addEventListener("change", (e) => {
  uploadAll([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
  e.target.value = "";
});

async function walk(entry, path, out) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, path: path + file.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const child of batch) await walk(child, `${path}${entry.name}/`, out);
    }
  }
}

const drop = $("drop");
drop.addEventListener("dragover", (e) => {
  e.preventDefault();
  drop.classList.add("over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", async (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  // Pinned before the (possibly long) walk of a dropped folder tree.
  const { bucket, prefix } = state;
  if (!bucket) return toast("Pick a bucket first");
  const entries = [...e.dataTransfer.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  const out = [];
  if (entries.length) for (const en of entries) await walk(en, "", out);
  else for (const f of e.dataTransfer.files) out.push({ file: f, path: f.name });
  uploadAll(out, bucket, prefix);
});

// ---------------------------------------------------------------------------
// Unfinished uploads and status

$("pending-btn").addEventListener("click", async () => {
  if (!state.bucket) return toast("Pick a bucket first");
  let uploads;
  try {
    ({ uploads } = await api("/mpu/list", { query: { bucket: state.bucket } }));
  } catch (e) {
    return toast(`Failed: ${e.message}`);
  }
  const list = el("ul", {});
  for (const u of uploads) {
    const b = el("button", {
      type: "button",
      class: "danger",
      on: {
        click: async () => {
          b.disabled = true;
          try {
            await api("/mpu/abort", { method: "POST", body: { bucket: state.bucket, key: u.key, uploadId: u.uploadId } });
            li.remove();
          } catch (e) {
            toast(`Abort failed: ${e.message}`);
            b.disabled = false;
          }
        },
      },
    }, "Abort");
    const li = el("li", {}, `${u.key} (started ${fmtDate(u.initiated)}) `, b);
    list.append(li);
  }
  const content = uploads.length
    ? el("div", {}, el("p", {}, "Drop the same file into the same folder to resume one."), list)
    : el("p", {}, "None.");
  await dialog(`Unfinished uploads in ${state.bucket}`, content, [["Close", "close"]]);
});

$("status-btn").addEventListener("click", async () => {
  let s;
  try {
    s = await api("/status");
  } catch (e) {
    return toast(`Status failed: ${e.message}`);
  }
  const outbox = Object.entries(s.outbox || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || "empty";
  const content = el(
    "div",
    {},
    kv([
      ["Environment", s.environment],
      ["Maintenance", s.maintenance],
      ["Real data ready", String(s.real_data_ready)],
      ["Outbox", outbox],
      ["Dead jobs", String(s.dead)],
      ["Pinned (safety) bytes", `${fmtSize(s.hot?.pinned_bytes)} in ${s.hot?.pinned_extents} extents`],
      ["Evictable cache", `${fmtSize(s.hot?.evictable_bytes)} of ${fmtSize(s.hot?.cap_bytes)}`],
      ["Replay unfinished", String(s.replay_unfinished)],
      ["Warnings", (s.config_warnings || []).join("; ") || "none"],
    ]),
    el(
      "table",
      { class: "mini" },
      el("thead", {}, el("tr", {}, ...["provider", "backbone", "enabled", "healthy", "connections", "cooling"].map((h) => el("th", {}, h)))),
      el(
        "tbody",
        {},
        ...(s.providers || []).map((p) =>
          el(
            "tr",
            {},
            el("td", {}, p.id),
            el("td", {}, p.backbone),
            el("td", {}, String(p.enabled)),
            el("td", {}, p.healthy ? "yes" : `no${p.reason ? ` (${p.reason})` : ""}`),
            el("td", {}, `${p.held}/${p.max_conns}`),
            el("td", {}, p.cooling ? "yes" : "no"),
          ),
        ),
      ),
    ),
  );
  await dialog("velmora status (refreshed on demand)", content, [["Close", "close"]]);
});

// ---------------------------------------------------------------------------

(async () => {
  try {
    const { email } = await api("/session");
    $("who").textContent = email;
  } catch {
    /* shown by the failing calls below */
  }
  const buckets = await loadBuckets();
  const h = readHash();
  if (h.bucket) open(h.bucket, h.prefix);
  else if (buckets.length) go(buckets[0].name);
  else open("", "");
})();
