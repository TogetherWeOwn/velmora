//! DeleteObjects takes its keys a chunk at a time, with one catalogue
//! call a step for the whole chunk, and several chunks together. What a
//! request leaves must not depend on that: the catalogue and the
//! recovery records are those of one DeleteObject per key, also beside
//! writes on the same keys, and a replay of the records agrees.

mod intent_support;
mod service_support;

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use base64::Engine as _;
use intent_support::{column, number, restore, rollback, snapshot};
use service_support::*;
use velmora_bridge::crypto::open_manifest;
use velmora_bridge::recovery::Tombstone;
use velmora_bridge::*;

const BUCKET: &str = "bkt-chunks";

/// xorshift64: the same key sets for the same seed.
struct Rand(u64);

impl Rand {
    fn new(seed: u64) -> Self {
        Rand(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 >> 16
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn delete_xml(keys: &[String]) -> String {
    let mut xml = String::from("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for key in keys {
        let key = key
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        xml.push_str(&format!("<Object><Key>{key}</Key></Object>"));
    }
    xml.push_str("</Delete>");
    xml
}

async fn delete_objects(rig: &Rig, signer: &Signer, keys: &[String]) -> Resp {
    let xml = delete_xml(keys);
    let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(xml.as_bytes()).0);
    rig.call(
        signer,
        Method::Post,
        &format!("/{BUCKET}"),
        &[("delete", "")],
        &[("content-md5", &md5)],
        xml.as_bytes(),
    )
    .await
}

async fn delete_object(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Delete, &path(BUCKET, key), &[], &[], b"")
        .await
}

/// `key generation_id` of every live object.
fn live_ids(rig: &Rig) -> Vec<String> {
    column(
        rig,
        "SELECT key || ' ' || generation_id FROM objects ORDER BY key",
    )
}

fn live_keys(rig: &Rig) -> Vec<String> {
    column(rig, "SELECT key FROM objects ORDER BY key")
}

/// Every tombstone record of the safety store, opened: `(key, deleted_at)`.
async fn tombstones(rig: &Rig) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for name in rig.bridge.safety.keys() {
        if !name.starts_with("m/del/") {
            continue;
        }
        let sealed = rig.bridge.safety.inner.get(&name, None).await.unwrap();
        let plain = open_manifest(&rig.bridge.kek, &name, &sealed.unwrap()).unwrap();
        let record: Tombstone = serde_json::from_slice(&plain).unwrap();
        assert_eq!(format!("m/del/{}", record.id), name);
        out.push((record.key, record.deleted_at));
    }
    out.sort();
    out
}

/// What the catalogue says about the keys, without the ids (they carry
/// random bits): every generation and its state, the live objects, the
/// floors and their marks, the work queued for the extents.
fn catalogue_state(rig: &Rig) -> Vec<String> {
    let mut out = Vec::new();
    for query in [
        "SELECT 'generation ' || key || ' ' || state || ' ' || etag || ' ' || \
           COALESCE(retired_at, '-') FROM generations ORDER BY key, id",
        "SELECT 'live ' || o.key || ' ' || g.etag FROM objects o \
           JOIN generations g ON g.id = o.generation_id ORDER BY o.key",
        "SELECT 'floor ' || key || ' ' || unpublished FROM key_floors ORDER BY key",
        "SELECT 'gc ' || g.key || ' ' || gc.action || ' ' || gc.due_at FROM gc \
           JOIN extents e ON e.id = gc.extent_id JOIN generations g ON g.id = e.generation_id \
           ORDER BY g.key, g.id, gc.action",
        "SELECT 'outbox ' || g.key || ' ' || o.stage FROM outbox o \
           JOIN extents e ON e.id = o.extent_id JOIN generations g ON g.id = e.generation_id \
           ORDER BY g.key, g.id",
    ] {
        out.extend(column(rig, query));
    }
    out
}

/// The pool of keys a scene draws from: plain ones, and some that need
/// care on the way through XML, JSON and SQL.
fn pool() -> Vec<String> {
    let mut keys: Vec<String> = (0..150).map(|i| format!("dir/k{i:03}")).collect();
    keys.extend(
        [
            "sp ace",
            "quo\"te",
            "back\\slash",
            "amp&lt<gt>",
            "ümläut/ß",
            "emoji-\u{1F600}",
            "per%cent",
            "'single'",
            "[\"json\",1]",
            "tab-less\u{7f}",
            "nul-like\\u0000",
        ]
        .map(String::from),
    );
    keys.push("L".repeat(1024));
    keys
}

/// A rig with a snapshot of its empty catalogue, and keys of the pool in
/// every state a delete can find one in, as `seed` decides.
async fn scene(seed: u64) -> (Rig, Signer) {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    snapshot(&rig);
    let mut rand = Rand::new(seed);
    let put = |key: String, n: u64| {
        let (rig, signer) = (&rig, &signer);
        async move {
            rig.bridge.clock.advance_ms(7);
            rig.put(signer, BUCKET, &key, format!("{key} {n}").as_bytes())
                .await
        }
    };
    for key in pool() {
        match rand.below(8) {
            // Never written.
            0 => {}
            // Written, written twice.
            1 | 2 => {
                put(key, 1).await.expect(200);
            }
            3 => {
                put(key.clone(), 1).await.expect(200);
                put(key, 2).await.expect(200);
            }
            // Deleted before.
            4 => {
                put(key.clone(), 1).await.expect(200);
                rig.bridge.clock.advance_ms(7);
                delete_object(&rig, &signer, &key).await.expect(204);
            }
            // A write that was not published and kept its record, on a
            // key without an object and on one with.
            5 => {
                rig.bridge.catalog.sql.fail_batches.set(1);
                put(key, 1).await.expect_error(500, "InternalError");
            }
            6 => {
                put(key.clone(), 1).await.expect(200);
                rig.bridge.catalog.sql.fail_batches.set(1);
                put(key, 2).await.expect_error(500, "InternalError");
            }
            // The same after a delete.
            _ => {
                put(key.clone(), 1).await.expect(200);
                rig.bridge.clock.advance_ms(7);
                delete_object(&rig, &signer, &key).await.expect(204);
                rig.bridge.catalog.sql.fail_batches.set(1);
                put(key, 2).await.expect_error(500, "InternalError");
            }
        }
    }
    rig.bridge.clock.advance_ms(1000);
    (rig, signer)
}

/// The keys of one request: most of the pool in a random order, some
/// named again, and now and then a key that cannot be stored.
fn request(rand: &mut Rand) -> Vec<String> {
    let mut all = pool();
    let mut keys = Vec::new();
    let take = all.len() - rand.below(40);
    for _ in 0..take {
        keys.push(all.swap_remove(rand.below(all.len())));
    }
    for _ in 0..rand.below(12) {
        let again = keys[rand.below(keys.len())].clone();
        keys.insert(rand.below(keys.len() + 1), again);
    }
    if rand.below(2) == 0 {
        keys.insert(rand.below(keys.len() + 1), "K".repeat(1025));
    }
    keys
}

/// `key -> error code` of a DeleteObjects answer (`None` = `Deleted`),
/// checked to name exactly the keys of the request, in its order.
fn answers(resp: &Resp, keys: &[String]) -> BTreeMap<String, Option<String>> {
    resp.expect(200);
    let text = resp.text();
    let mut named = Vec::new();
    let mut out = BTreeMap::new();
    // `<Deleted>` and `<Error>` entries, as they come.
    let mut rest = text.as_str();
    while let Some(at) = rest.find("<Key>") {
        let failed = rest[..at].rfind("<Error>") > rest[..at].rfind("<Deleted>");
        rest = &rest[at + 5..];
        let end = rest.find("</Key>").unwrap();
        let key = rest[..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&");
        let code = failed.then(|| {
            let from = rest.find("<Code>").unwrap() + 6;
            let to = rest.find("</Code>").unwrap();
            rest[from..to].to_string()
        });
        if let Some(before) = out.insert(key.clone(), code.clone()) {
            assert_eq!(before, code, "{key}: one answer for a key named twice");
        }
        named.push(key);
    }
    assert_eq!(named, keys, "an entry per key, in request order");
    out
}

/// One DeleteObjects request leaves what a DeleteObject per key leaves,
/// one after the other: the same tombstones, the same catalogue, and
/// the same catalogue again after a replay of the records. Over random
/// sets of keys in every state, named in random order and some twice,
/// with the calls of the chunks of the request interleaved at random.
#[tokio::test(flavor = "current_thread")]
async fn chunks_leave_what_a_delete_per_key_leaves() {
    for seed in 0..12 {
        let (mut batch, batch_signer) = scene(seed).await;
        let (mut single, single_signer) = scene(seed).await;
        assert_eq!(catalogue_state(&batch), catalogue_state(&single));
        let keys = request(&mut Rand::new(seed ^ 0xD1CE));
        let distinct: Vec<&String> = {
            let mut seen = BTreeSet::new();
            keys.iter().filter(|k| seen.insert(*k)).collect()
        };

        batch.trip().jitter(seed);
        let resp = delete_objects(&batch, &batch_signer, &keys).await;
        for (key, code) in answers(&resp, &keys) {
            let expected = (key.len() > 1024).then(|| "InvalidArgument".to_string());
            assert_eq!(code, expected, "seed {seed}: {key}");
        }
        for key in distinct {
            if key.len() <= 1024 {
                delete_object(&single, &single_signer, key)
                    .await
                    .expect(204);
            }
        }

        let records = tombstones(&batch).await;
        assert_eq!(records, tombstones(&single).await, "seed {seed}");
        assert_eq!(
            batch.bridge.safety.keys().len(),
            single.bridge.safety.keys().len(),
            "seed {seed}: nothing else stored"
        );
        let state = catalogue_state(&batch);
        assert_eq!(state, catalogue_state(&single), "seed {seed}");
        let left = live_keys(&batch);
        assert!(left.iter().all(|k| !keys.contains(k)), "seed {seed}");

        // The catalogue is lost and rebuilt from the records. No key of
        // the request comes back. (A key the request did not name can:
        // the record of a write that was not published is published by
        // a replay, until a delete covers it.)
        for rig in [&mut batch, &mut single] {
            rollback(rig);
            restore(rig).await;
            let live = live_keys(rig);
            assert!(left.iter().all(|k| live.contains(k)), "seed {seed}");
            assert!(live.iter().all(|k| !keys.contains(k)), "seed {seed}");
        }
        assert_eq!(
            catalogue_state(&batch),
            catalogue_state(&single),
            "seed {seed}: after the replay"
        );
    }
}

/// Two DeleteObjects requests that share keys, beside writes on some of
/// those keys, with all their calls interleaved at random. Every key is
/// answered; a key no write touched is gone; a key a write touched
/// holds that write or nothing; no key outside the requests changed;
/// and a replay of the records gives the live objects there are, under
/// their ids.
#[tokio::test(flavor = "current_thread")]
async fn chunks_beside_writes_and_another_request_replay_to_the_same() {
    let mut retried = 0;
    // Writes that were published, and writes that were not.
    let mut outcomes = [0, 0];
    for seed in 0..40 {
        let (mut rig, signer) = scene(seed).await;
        let mut rand = Rand::new(seed ^ 0xBEEF);
        let first = request(&mut rand);
        let second = request(&mut rand);
        let named: BTreeSet<&String> = first.iter().chain(&second).collect();
        // Writes on keys both requests name, on one only, on none.
        let all = pool();
        let written: Vec<String> = (0..6)
            .map(|_| all[rand.below(all.len())].clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let before: BTreeMap<String, String> = live_ids(&rig)
            .into_iter()
            .map(|line| {
                let (key, id) = line.rsplit_once(' ').unwrap();
                (key.to_string(), id.to_string())
            })
            .collect();

        rig.trip().jitter(seed);
        let puts = futures_util::future::join_all(written.iter().map(|key| {
            let (rig, signer) = (&rig, &signer);
            // Every other write is held to an object of the key.
            let held = key.len() % 2 == 0;
            async move {
                let headers: &[(&str, &str)] = if held { &[("if-match", "*")] } else { &[] };
                let body = format!("{key} raced");
                let answer = rig
                    .call(
                        signer,
                        Method::Put,
                        &path(BUCKET, key),
                        &[],
                        headers,
                        body.as_bytes(),
                    )
                    .await;
                (held, answer)
            }
        }));
        let (a, b, puts) = tokio::join!(
            delete_objects(&rig, &signer, &first),
            delete_objects(&rig, &signer, &second),
            puts
        );
        let mut deleted = BTreeSet::new();
        for (resp, keys) in [(&a, &first), (&b, &second)] {
            for (key, code) in answers(resp, keys) {
                match code.as_deref() {
                    None => {
                        deleted.insert(key);
                    }
                    Some("InvalidArgument") => assert!(key.len() > 1024),
                    // Only a key with a write beside the delete.
                    Some("SlowDown") => {
                        assert!(written.contains(&key), "seed {seed}: {key}");
                        retried += 1;
                    }
                    Some(other) => panic!("seed {seed}: {key} answered {other}"),
                }
            }
        }
        for (held, put) in &puts {
            let refused = matches!(put.status, 404 | 412);
            assert!(
                put.status == 200 || put.code() == "SlowDown" || (*held && refused),
                "seed {seed}: a PUT answered {} {}",
                put.status,
                put.text()
            );
            outcomes[usize::from(put.status != 200)] += 1;
        }

        let after: BTreeMap<String, String> = live_ids(&rig)
            .into_iter()
            .map(|line| {
                let (key, id) = line.rsplit_once(' ').unwrap();
                (key.to_string(), id.to_string())
            })
            .collect();
        for key in &all {
            let raced = written.contains(key);
            match (named.contains(key), raced) {
                // Untouched.
                (false, false) => assert_eq!(after.get(key), before.get(key), "seed {seed}: {key}"),
                // Deleted, and nothing wrote it.
                (true, false) => {
                    assert!(deleted.contains(key), "seed {seed}: {key}");
                    assert!(!after.contains_key(key), "seed {seed}: {key}");
                }
                // The write, or nothing: never what was there before.
                (named, true) => {
                    // A write that is held to an object of the key is
                    // not published beside a delete of the key: the
                    // delete took the object it was held to, or the
                    // object it wrote.
                    if named && deleted.contains(key) && key.len() % 2 == 0 {
                        assert!(!after.contains_key(key), "seed {seed}: {key}");
                    }
                    if let Some(id) = after.get(key) {
                        assert_ne!(Some(id), before.get(key), "seed {seed}: {key}");
                        let got = rig
                            .call(&signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
                            .await;
                        assert_eq!(got.expect(200).body, format!("{key} raced").as_bytes());
                    }
                }
            }
        }
        assert_eq!(rig.bridge.budget.in_use(), 0, "seed {seed}");

        // The replay: every key a request named or a write touched is
        // as it was, under the id it had. (A key that none of them
        // touched can come back from the record of a write that was
        // not published; no delete covered it.)
        let touched = |line: &String| {
            let key = line.rsplit_once(' ').unwrap().0;
            named.iter().any(|k| *k == key) || written.iter().any(|k| k == key)
        };
        let live: Vec<String> = live_ids(&rig).into_iter().filter(touched).collect();
        rollback(&rig);
        restore(&mut rig).await;
        let replayed: Vec<String> = live_ids(&rig).into_iter().filter(touched).collect();
        assert_eq!(replayed, live, "seed {seed}: after the replay");
    }
    // Informative only: how many keys lost every round to a write.
    println!("keys answered SlowDown over all seeds: {retried}; writes {outcomes:?}");
    assert!(outcomes[0] > 20 && outcomes[1] > 20, "{outcomes:?}");
}

/// `key_heads` answers for every key what the calls of a DeleteObject
/// read for it, whatever the text of the key.
#[tokio::test(flavor = "current_thread")]
async fn the_ids_of_a_chunk_are_those_read_key_by_key() {
    let (rig, _) = scene(3).await;
    let catalog = &rig.bridge.catalog;
    let bucket = catalog.bucket_by_name(BUCKET).await.unwrap().unwrap();
    let pool = pool();
    let keys: Vec<&str> = pool.iter().map(String::as_str).collect();
    let heads = catalog.key_heads(&bucket.id, &keys).await.unwrap();
    assert_eq!(heads.len(), keys.len());
    let (mut live, mut unpublished) = (0, 0);
    for (key, head) in keys.iter().zip(&heads) {
        let object = catalog.live_object(&bucket.id, key).await.unwrap();
        assert_eq!(head.live, object.map(|(g, _)| g.id), "{key}");
        let floor = catalog.unpublished_floor(&bucket.id, key).await.unwrap();
        assert_eq!(head.unpublished, floor.is_some(), "{key}");
        if head.unpublished {
            assert_eq!(head.floor, floor, "{key}");
        }
        let newest = catalog.newest_id(&bucket.id, key).await.unwrap();
        assert_eq!(head.live.clone().max(head.floor.clone()), newest, "{key}");
        live += usize::from(head.live.is_some());
        unpublished += usize::from(head.unpublished);
    }
    assert!(live > 20 && unpublished > 20, "{live} {unpublished}");
    // A key of another bucket and no key at all.
    let other = rig.bucket("bkt-chunks-other", true).await;
    let heads = catalog.key_heads(&other.id, &keys).await.unwrap();
    assert!(heads.iter().all(|h| *h == KeyHead::default()));
    assert!(catalog.key_heads(&bucket.id, &[]).await.unwrap().is_empty());
}

/// The calls one request makes: to the database, and to the store.
struct Calls {
    database: u64,
    store: u64,
}

/// Runs `request` and counts its calls.
async fn counted(rig: &Rig, request: impl std::future::Future<Output = Resp>) -> (Resp, Calls) {
    let (calls, puts) = (rig.trip().calls(), rig.bridge.safety.puts.borrow().len());
    let resp = request.await;
    let store = (rig.bridge.safety.puts.borrow().len() - puts) as u64;
    let calls = Calls {
        database: rig.trip().calls() - calls - store,
        store,
    };
    (resp, calls)
}

/// A request of 1,000 live keys makes about a twelfth of the calls that
/// 1,000 deletes of one key make, and its database calls do not grow
/// with the keys of a chunk: one tombstone a key, and a handful of
/// database calls for every fifty keys.
#[tokio::test(flavor = "current_thread")]
async fn a_thousand_keys_take_a_handful_of_database_calls_per_chunk() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = (0..1001).map(|i| format!("bulk/{i:04}")).collect();
    for key in &keys {
        rig.put(&signer, BUCKET, key, b"x").await.expect(200);
    }
    rig.bridge.clock.advance_ms(1000);

    // One key, as a DeleteObjects request of its own: what every key
    // cost when each took its calls alone.
    let (resp, one) = counted(&rig, delete_objects(&rig, &signer, &keys[1000..])).await;
    assert!(!resp.expect(200).text().contains("<Error>"));
    // No key: the calls of the request itself.
    let (_, none) = counted(&rig, delete_objects(&rig, &signer, &["no/such".into()])).await;
    assert_eq!(none.store, 0);
    let fixed = none.database - 2;
    let per_key = one.database - fixed;
    assert_eq!(
        (one.store, per_key),
        (1, 5),
        "the gate, the ids, three batches"
    );

    let (resp, bulk) = counted(&rig, delete_objects(&rig, &signer, &keys[..1000])).await;
    assert!(!resp.expect(200).text().contains("<Error>"));
    assert!(live_keys(&rig).is_empty());
    assert_eq!(tombstones(&rig).await.len(), 1001);
    println!(
        "1,000 keys: {} database calls, {} store calls ({} fixed)",
        bulk.database, bulk.store, fixed
    );
    assert_eq!(bulk.store, 1000);
    // Twenty chunks of fifty keys, five calls each.
    assert_eq!(bulk.database - fixed, 20 * 5);
    // Against the 10,000 calls one request may make.
    assert!(bulk.database + bulk.store < 1200);
}

/// The batch of a chunk deletes nothing when one of its keys took a
/// newer id meanwhile. Every key then goes on alone: the others are
/// deleted under the tombstones they have, and the one with the newer
/// id starts again above it, as the key of a DeleteObject does.
#[tokio::test(flavor = "current_thread")]
async fn a_chunk_whose_batch_is_refused_finishes_key_by_key() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    snapshot(&rig);
    let keys: Vec<String> = (0..60).map(|i| format!("k{i:02}")).collect();
    for key in &keys {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    rig.bridge.clock.advance_ms(1000);

    // While the first tombstone is on its way, a write on `k07` begins:
    // the floor of the key goes above the tombstone chosen for it.
    let bridge = Rc::clone(&rig.bridge);
    let newer = GenerationId::mint(UnixMs(rig.now().0 + 5000), [7; 8]);
    *rig.bridge.safety.before_put.borrow_mut() = Some(Box::new(move |_| {
        let script = format!(
            "UPDATE key_floors SET floor_id = '{}', unpublished = 1 WHERE key = 'k07';",
            newer.as_str()
        );
        bridge
            .catalog
            .sql
            .with_conn(|c| c.execute_batch(&script).unwrap());
    }));
    let (resp, calls) = counted(&rig, delete_objects(&rig, &signer, &keys)).await;
    assert!(answers(&resp, &keys).values().all(Option::is_none));
    assert!(live_keys(&rig).is_empty());
    // A tombstone a key, and a second one for the key that started again.
    let records = tombstones(&rig).await;
    assert_eq!(records.len(), 61);
    assert_eq!(records.iter().filter(|(key, _)| key == "k07").count(), 2);
    // The first chunk took its batch key by key; the second did not.
    assert!(
        calls.database > 50 && calls.database < 100,
        "{}",
        calls.database
    );
    assert_eq!(
        number(
            &rig,
            "SELECT COUNT(*) FROM key_floors WHERE unpublished <> 0"
        ),
        0
    );

    let mut rig = rig;
    rollback(&rig);
    restore(&mut rig).await;
    assert!(live_keys(&rig).is_empty());
}

/// A step of a chunk that fails before the batch, fails for the keys
/// that take it and for no other; a batch that fails leaves each key its
/// own try; nothing is deleted without its tombstone, and the request
/// can be sent again.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_step_of_a_chunk_fails_its_keys_only() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = (0..70).map(|i| format!("k{i:02}")).collect();
    for key in &keys[..60] {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    rig.bridge.clock.advance_ms(1000);
    let codes = |resp: &Resp| -> Vec<Option<String>> {
        let by_key = answers(resp, &keys);
        keys.iter().map(|k| by_key[k].clone()).collect()
    };
    let internal = Some("InternalError".to_string());

    // The ids of one of the two chunks cannot be read: its keys fail,
    // the keys of the other chunk are deleted.
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("json_each", 1));
    let resp = delete_objects(&rig, &signer, &keys).await;
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
    let got = codes(&resp);
    let failed = got.iter().filter(|c| **c == internal).count();
    assert!(got.iter().all(|c| c.is_none() || *c == internal));
    assert!(failed == 50 || failed == 20, "{failed}");
    assert_eq!(live_keys(&rig).len(), if failed == 50 { 50 } else { 10 });
    let stored = tombstones(&rig).await.len();
    assert_eq!(stored + live_keys(&rig).len(), 60);

    // The store takes no tombstone: the live keys fail one by one, the
    // keys with nothing to delete are answered as deleted.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/del/".into());
    let live = live_keys(&rig);
    let got = codes(&delete_objects(&rig, &signer, &keys).await);
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    for (key, code) in keys.iter().zip(&got) {
        let expected = live.contains(key).then(|| "InternalError".to_string());
        assert_eq!(*code, expected, "{key}");
    }
    assert_eq!(live_keys(&rig), live);
    // The floors were raised for records that were not stored: the mark
    // of an unpublished generation is not set by a tombstone.
    assert_eq!(
        number(
            &rig,
            "SELECT COUNT(*) FROM key_floors WHERE unpublished <> 0"
        ),
        0
    );

    // The batch that deletes fails after every tombstone was stored, or
    // is carried out and not answered: each key goes on alone under the
    // tombstone it has, and is deleted. No second tombstone is stored.
    // Calls of a request of one chunk: the gate, the ids, the floors,
    // the tombstones, the marks, then the batch.
    let signed_calls = {
        let (_, none) = counted(&rig, delete_objects(&rig, &signer, &["no/such".into()])).await;
        none.database - 2
    };
    for (trip, chunk) in [(Trip::Fail, &live[..5]), (Trip::Lost, &live[5..10])] {
        let before = tombstones(&rig).await.len();
        rig.trip().arm(signed_calls + 3 + 5 + 1, trip);
        let resp = delete_objects(&rig, &signer, chunk).await;
        assert!(rig.trip().tripped());
        let by_key = answers(&resp, chunk);
        assert!(by_key.values().all(Option::is_none), "{by_key:?}");
        assert!(chunk.iter().all(|key| !live_keys(&rig).contains(key)));
        assert_eq!(tombstones(&rig).await.len(), before + 5);
    }
    assert_eq!(live_keys(&rig).len(), live.len() - 10);

    // Sent again, everything goes.
    let got = codes(&delete_objects(&rig, &signer, &keys).await);
    assert!(got.iter().all(Option::is_none));
    assert!(live_keys(&rig).is_empty());
}

/// A replay that starts while a chunk is at work: the batch of the
/// chunk changes nothing, and every key says that writes are refused.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_that_starts_under_a_chunk_refuses_its_keys() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
    for key in &keys {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    rig.bridge.clock.advance_ms(1000);
    let bridge = Rc::clone(&rig.bridge);
    *rig.bridge.safety.before_put.borrow_mut() = Some(Box::new(move |_| {
        bridge.catalog.sql.with_conn(|c| {
            c.execute_batch(
                "INSERT OR REPLACE INTO rollback_stamp(id, counter, catalogue_id, rolled_back_at) \
                 VALUES (1, 0, 'c', 1);",
            )
            .unwrap()
        });
    }));
    let resp = delete_objects(&rig, &signer, &keys).await;
    let by_key = answers(&resp, &keys);
    assert!(
        by_key
            .values()
            .all(|c| c.as_deref() == Some("ServiceUnavailable")),
        "{by_key:?}"
    );
    assert_eq!(live_keys(&rig), keys);
}

/// Each key of a chunk is deleted under the clock reading of its own
/// tombstone, however long the tombstones of the chunk took to store:
/// the time the generation was retired at is the time on the record,
/// and the floor the delete leaves is in the millisecond of the
/// tombstone, as after a DeleteObject.
#[tokio::test(flavor = "current_thread")]
async fn a_key_of_a_chunk_is_retired_at_the_time_of_its_tombstone() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = (0..5).map(|i| format!("k{i}")).collect();
    for key in &keys {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    rig.bridge.clock.advance_ms(1000);
    // Every tombstone takes 300 ms to store.
    let bridge = Rc::clone(&rig.bridge);
    *rig.bridge.safety.before_put.borrow_mut() =
        Some(Box::new(move |_| bridge.clock.advance_ms(300)));
    let resp = delete_objects(&rig, &signer, &keys).await;
    *rig.bridge.safety.before_put.borrow_mut() = None;
    assert!(answers(&resp, &keys).values().all(Option::is_none));

    let records = tombstones(&rig).await;
    assert_eq!(records.len(), keys.len());
    for (key, deleted_at) in records {
        let retired = number(
            &rig,
            &format!("SELECT retired_at FROM generations WHERE key = '{key}'"),
        );
        assert_eq!(retired, deleted_at, "{key}");
        let floor = column(
            &rig,
            &format!("SELECT floor_id FROM key_floors WHERE key = '{key}'"),
        );
        let ms = GenerationId::mint(UnixMs(deleted_at), [0; 8]);
        assert!(floor[0].starts_with(&ms.as_str()[..15]), "{key} {floor:?}");
    }
}

/// A tombstone that was not stored leaves the mark of an unpublished
/// write on its key: the next delete still has a record to cover.
#[tokio::test(flavor = "current_thread")]
async fn a_tombstone_that_was_not_stored_leaves_the_mark_of_its_key() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    snapshot(&rig);
    // A write that kept its record, on a key without an object and on
    // one with; and a plain object.
    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "bare", b"1")
        .await
        .expect_error(500, "InternalError");
    rig.put(&signer, BUCKET, "over", b"1").await.expect(200);
    rig.bridge.clock.advance_ms(7);
    rig.bridge.catalog.sql.fail_batches.set(1);
    rig.put(&signer, BUCKET, "over", b"2")
        .await
        .expect_error(500, "InternalError");
    rig.put(&signer, BUCKET, "plain", b"1").await.expect(200);
    rig.bridge.clock.advance_ms(1000);
    let marks = || {
        column(
            &rig,
            "SELECT key FROM key_floors WHERE unpublished <> 0 ORDER BY key",
        )
    };
    assert_eq!(marks(), ["bare", "over"]);

    let keys: Vec<String> = ["bare", "over", "plain"].map(String::from).to_vec();
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/del/".into());
    let resp = delete_objects(&rig, &signer, &keys).await;
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    let internal = Some("InternalError".to_string());
    assert!(answers(&resp, &keys).values().all(|c| *c == internal));
    assert_eq!(marks(), ["bare", "over"]);
    assert_eq!(live_keys(&rig), ["over", "plain"]);

    // Sent again, the keys go and stay gone in a replay.
    let resp = delete_objects(&rig, &signer, &keys).await;
    assert!(answers(&resp, &keys).values().all(Option::is_none));
    assert!(marks().is_empty());
    assert_eq!(tombstones(&rig).await.len(), 3);
    let mut rig = rig;
    rollback(&rig);
    restore(&mut rig).await;
    assert!(live_keys(&rig).is_empty());
}

/// The tombstone of a key sorts above its floor also when the floor is
/// ahead of the clock (a write that began under a later clock reading).
#[tokio::test(flavor = "current_thread")]
async fn a_tombstone_of_a_chunk_sorts_above_a_floor_ahead_of_the_clock() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = ["a", "b"].map(String::from).to_vec();
    for key in &keys {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    let ahead = GenerationId::mint(UnixMs(rig.now().0 + 60_000), [9; 8]);
    let script = format!(
        "INSERT OR REPLACE INTO key_floors(bucket_id, key, floor_id) \
         SELECT bucket_id, key, '{}' FROM objects WHERE key = 'a';",
        ahead.as_str()
    );
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(&script).unwrap());
    rig.bridge.clock.advance_ms(1000);
    let resp = delete_objects(&rig, &signer, &keys).await;
    assert!(answers(&resp, &keys).values().all(Option::is_none));
    assert!(live_keys(&rig).is_empty());
    let above: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|name| name.starts_with("m/del/") && &name[6..] > ahead.as_str())
        .collect();
    assert_eq!(above.len(), 1, "{above:?}");
}
