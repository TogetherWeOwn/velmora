//! Conditional writes: `If-None-Match: *` and `If-Match` on PutObject,
//! CopyObject, CompleteMultipartUpload and DeleteObject.
//!
//! - what each header answers on each operation, and what it leaves;
//! - a condition that is not understood is `501`, never ignored;
//! - two writers on one key, their store and database calls interleaved
//!   by a seed: one wins, the other is told so and leaves nothing;
//! - a key that changes between the look at it and the batch: the batch
//!   refuses;
//! - a replay of the recovery records gives the catalogue the requests
//!   left, also where a refused write could not remove its record.

mod intent_support;
mod service_support;

use base64::Engine as _;
use intent_support::*;
use service_support::*;
use velmora_bridge::replay::{ReplayCursor, ReplayLimits};
use velmora_bridge::*;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// A body of one extent, and one that is stored in three slices.
fn small(seed: u8) -> Vec<u8> {
    pattern(seed, 700)
}

fn sliced(seed: u8) -> Vec<u8> {
    pattern(seed, 2 * SLICE + 100)
}

fn put_req(rig: &Rig, signer: &Signer, key: &str, body: &[u8], headers: &[(&str, &str)]) -> Req {
    signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, key),
        &[],
        headers,
        body.to_vec(),
    )
}

async fn put_if(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Resp {
    rig.send(put_req(rig, signer, key, body, headers)).await
}

fn delete_req(rig: &Rig, signer: &Signer, key: &str, headers: &[(&str, &str)]) -> Req {
    signer.sign(
        rig.now(),
        Method::Delete,
        &path(BUCKET, key),
        &[],
        headers,
        Vec::new(),
    )
}

async fn delete_if(rig: &Rig, signer: &Signer, key: &str, headers: &[(&str, &str)]) -> Resp {
    rig.send(delete_req(rig, signer, key, headers)).await
}

fn copy_req(rig: &Rig, signer: &Signer, from: &str, to: &str, extra: &[(&str, &str)]) -> Req {
    let source = format!("/{BUCKET}/{}", uri_encode(from, true));
    let mut headers = vec![("x-amz-copy-source", source.as_str())];
    headers.extend_from_slice(extra);
    signer.sign(
        rig.now(),
        Method::Put,
        &path(BUCKET, to),
        &[],
        &headers,
        Vec::new(),
    )
}

/// An open upload of one part under `key`: its id and the ETag of the part.
async fn upload(rig: &Rig, signer: &Signer, key: &str, part: &[u8]) -> (String, String) {
    let r = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    r.expect(200);
    let id = r.values("UploadId").remove(0);
    let r = rig
        .call(
            signer,
            Method::Put,
            &path(BUCKET, key),
            &[("partNumber", "1"), ("uploadId", &id)],
            &[],
            part,
        )
        .await;
    r.expect(200);
    let etag = r.header("etag").unwrap().to_string();
    (id, etag)
}

fn complete_req(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    (id, etag): &(String, String),
    headers: &[(&str, &str)],
) -> Req {
    let xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>\
         </CompleteMultipartUpload>",
        etag.replace('"', "&quot;")
    );
    signer.sign(
        rig.now(),
        Method::Post,
        &path(BUCKET, key),
        &[("uploadId", id)],
        headers,
        xml.into_bytes(),
    )
}

async fn abort(rig: &Rig, signer: &Signer, key: &str, id: &str) -> Resp {
    rig.call(
        signer,
        Method::Delete,
        &path(BUCKET, key),
        &[("uploadId", id)],
        &[],
        b"",
    )
    .await
}

fn upload_state(rig: &Rig, id: &str) -> String {
    rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT state FROM uploads WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    })
}

fn tick(rig: &Rig) {
    rig.bridge.clock.advance_ms(1000);
}

// ---------------------------------------------------------------------------
// What the stores hold
// ---------------------------------------------------------------------------

/// Tombstone records.
fn tombstones(rig: &Rig) -> usize {
    let keys = rig.bridge.safety.keys();
    keys.iter().filter(|k| k.starts_with("m/del/")).count()
}

/// The ids of the tombstones, in the shape of [`records`].
fn tombstone_ids(rig: &Rig) -> Vec<String> {
    let keys = rig.bridge.safety.keys();
    keys.iter()
        .filter_map(|k| k.strip_prefix("m/del/"))
        .map(str::to_owned)
        .collect()
}

/// Everything a request can leave: every catalogue row that says
/// something about an object, and every key of the safety store.
fn footprint(rig: &Rig) -> (Vec<i64>, Vec<String>) {
    let tables = [
        "generations",
        "objects",
        "extents",
        "generation_extents",
        "outbox",
        "gc",
        "write_intents",
    ];
    let mut keys = rig.bridge.safety.keys();
    keys.sort();
    (tables.iter().map(|t| rig.count(t)).collect(), keys)
}

/// The live generation of every key.
fn live_ids(rig: &Rig) -> Vec<String> {
    column(
        rig,
        "SELECT key || '=' || generation_id FROM objects ORDER BY key",
    )
}

/// The tables a replay rebuilds, children first.
const TABLES: [&str; 14] = [
    "generation_extents",
    "outbox",
    "key_floors",
    "verifications",
    "articles",
    "upload_parts",
    "uploads",
    "gc",
    "objects",
    "extents",
    "generations",
    "grants",
    "access_keys",
    "buckets",
];

/// Loses the catalogue and rebuilds it from the recovery records. The
/// access key is not in them: it is issued again.
async fn lose_and_replay(rig: &Rig) -> Signer {
    for t in TABLES {
        sql(rig, &format!("DELETE FROM {t};"));
    }
    assert_eq!(rig.count("objects") + rig.count("generations"), 0);
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    let mut calls = 0;
    while let Some(at) = cursor {
        calls += 1;
        assert!(calls < 10_000, "the replay does not end");
        let mut step = rig
            .bridge
            .replay_step_within(at, ReplayLimits::default())
            .await
            .unwrap();
        assert!(
            step.unpublishable.is_empty() && step.unreadable.is_empty(),
            "{step:?}"
        );
        cursor = step.next.take();
    }
    let bucket = rig
        .bridge
        .catalog
        .bucket_by_name(BUCKET)
        .await
        .unwrap()
        .expect("the replay restored the bucket");
    let signer = rig.key(AKID, secret(), KeyStatus::Active).await;
    rig.grant(AKID, &bucket, Perm::Rw).await;
    signer
}

/// A replay of the records publishes the generations that are live now,
/// under the ids they have, and nothing else: no write that was refused.
async fn replay_gives_the_same(rig: &Rig, what: &str) {
    let before = live_ids(rig);
    lose_and_replay(rig).await;
    assert_eq!(live_ids(rig), before, "{what}: after the replay");
}

// ---------------------------------------------------------------------------
// The headers
// ---------------------------------------------------------------------------

/// Conditions no write evaluates. The last ones are `If-Match` and
/// `If-None-Match` in shapes that are not one strong ETag or `*`.
const NOT_UNDERSTOOD: [&[(&str, &str)]; 9] = [
    &[("if-modified-since", "Fri, 15 Jan 2027 08:00:00 GMT")],
    &[("if-unmodified-since", "Fri, 15 Jan 2027 08:00:00 GMT")],
    &[("if-none-match", "\"0123456789abcdef0123456789abcdef\"")],
    &[("if-none-match", "*"), ("if-match", "*")],
    &[
        ("if-none-match", "*"),
        ("if-unmodified-since", "Fri, 15 Jan 2027 08:00:00 GMT"),
    ],
    &[("if-match", "\"aa\", \"bb\"")],
    &[("if-match", "W/\"0123456789abcdef0123456789abcdef\"")],
    &[("if-match", "\"unbalanced")],
    &[("if-match", "\"\"")],
];

#[tokio::test(flavor = "current_thread")]
async fn a_condition_that_is_not_understood_is_501_on_every_write() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "k", &small(1), &[]).await.expect(200);
    put_if(&rig, &signer, "src", &small(2), &[])
        .await
        .expect(200);
    let open = upload(&rig, &signer, "mp", &small(3)).await;
    let before = footprint(&rig);

    for headers in NOT_UNDERSTOOD {
        // PutObject, of one extent and sliced: refused before the body.
        for body in [small(4), sliced(4)] {
            for key in ["k", "new"] {
                let (resp, polled) = rig
                    .send_watched(put_req(&rig, &signer, key, &body, headers))
                    .await;
                resp.expect_error(501, "NotImplemented");
                assert!(!polled, "{headers:?}: the body was read");
            }
        }
        for to in ["k", "new"] {
            rig.send(copy_req(&rig, &signer, "src", to, headers))
                .await
                .expect_error(501, "NotImplemented");
        }
        rig.send(complete_req(&rig, &signer, "mp", &open, headers))
            .await
            .expect_error(501, "NotImplemented");
        delete_if(&rig, &signer, "k", headers)
            .await
            .expect_error(501, "NotImplemented");
        assert_eq!(footprint(&rig), before, "{headers:?}");
    }
    // A delete can only be held to the object it deletes.
    delete_if(&rig, &signer, "k", &[("if-none-match", "*")])
        .await
        .expect_error(501, "NotImplemented");
    assert_eq!(footprint(&rig), before);
    assert_eq!(upload_state(&rig, &open.0), "open");
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, small(1));
}

#[tokio::test(flavor = "current_thread")]
async fn the_other_multipart_calls_and_delete_objects_take_no_condition() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "k", &small(1), &[]).await.expect(200);
    let etag = md5_etag(&small(1));
    let open = upload(&rig, &signer, "mp", &small(3)).await;
    let before = footprint(&rig);
    let delete_objects = |xml: String, extra: Vec<(&'static str, String)>| {
        let (rig, signer) = (&rig, &signer);
        async move {
            let md5 =
                base64::engine::general_purpose::STANDARD.encode(md5::compute(xml.as_bytes()).0);
            let mut headers = vec![("content-md5", md5.as_str())];
            headers.extend(extra.iter().map(|(n, v)| (*n, v.as_str())));
            rig.call(
                signer,
                Method::Post,
                &format!("/{BUCKET}"),
                &[("delete", "")],
                &headers,
                xml.as_bytes(),
            )
            .await
        }
    };

    for (name, value) in [("if-none-match", "*"), ("if-match", etag.as_str())] {
        // CreateMultipartUpload, UploadPart, AbortMultipartUpload.
        rig.call(
            &signer,
            Method::Post,
            &path(BUCKET, "mp2"),
            &[("uploads", "")],
            &[(name, value)],
            b"",
        )
        .await
        .expect_error(501, "NotImplemented");
        rig.call(
            &signer,
            Method::Put,
            &path(BUCKET, "mp"),
            &[("partNumber", "2"), ("uploadId", &open.0)],
            &[(name, value)],
            &small(5),
        )
        .await
        .expect_error(501, "NotImplemented");
        rig.call(
            &signer,
            Method::Delete,
            &path(BUCKET, "mp"),
            &[("uploadId", &open.0)],
            &[(name, value)],
            b"",
        )
        .await
        .expect_error(501, "NotImplemented");
        // DeleteObjects with a conditional header.
        let plain = "<Delete><Object><Key>k</Key></Object></Delete>".to_string();
        delete_objects(plain, vec![(name, value.to_string())])
            .await
            .expect_error(501, "NotImplemented");
    }
    // DeleteObjects with a condition on one of its keys.
    for condition in [
        format!("<ETag>{}</ETag>", etag.replace('"', "&quot;")),
        "<LastModifiedTime>Fri, 15 Jan 2027 08:00:00 GMT</LastModifiedTime>".to_string(),
        "<Size>700</Size>".to_string(),
    ] {
        let xml = format!(
            "<Delete><Object><Key>other</Key></Object>\
             <Object><Key>k</Key>{condition}</Object></Delete>"
        );
        delete_objects(xml, Vec::new())
            .await
            .expect_error(501, "NotImplemented");
    }
    assert_eq!(footprint(&rig), before);
    assert_eq!(upload_state(&rig, &open.0), "open");
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, small(1));
    // Without one, the same document deletes.
    let plain = "<Delete><Object><Key>k</Key></Object></Delete>".to_string();
    delete_objects(plain, Vec::new()).await.expect(200);
    get(&rig, &signer, "k").await.expect(404);
}

// ---------------------------------------------------------------------------
// PutObject
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn put_if_none_match_creates_a_key_once() {
    for body in [small, sliced] {
        let rig = small_rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let first = put_if(&rig, &signer, "k", &body(1), &[("if-none-match", "*")]).await;
        first.expect(200);
        assert_eq!(first.header("etag"), Some(md5_etag(&body(1)).as_str()));
        tick(&rig);

        // The second is refused before its body is read, and leaves
        // nothing: no blob, no row, no record.
        let before = footprint(&rig);
        let floors = rig.count("key_floors");
        for again in [body(2), body(1)] {
            let req = put_req(&rig, &signer, "k", &again, &[("if-none-match", "*")]);
            let (resp, polled) = rig.send_watched(req).await;
            resp.expect_error(412, "PreconditionFailed");
            assert!(!polled, "the body was read");
            assert_eq!(resp.header("etag"), None);
        }
        assert_eq!(footprint(&rig), before);
        assert_eq!(rig.count("key_floors"), floors);
        assert_eq!(rig.bridge.budget.in_use(), 0);
        assert_eq!(get(&rig, &signer, "k").await.expect(200).body, body(1));

        // Another key is free, and so is this one once it is deleted.
        put_if(&rig, &signer, "k2", &body(3), &[("if-none-match", "*")])
            .await
            .expect(200);
        delete_if(&rig, &signer, "k", &[]).await.expect(204);
        tick(&rig);
        put_if(&rig, &signer, "k", &body(4), &[("if-none-match", " * ")])
            .await
            .expect(200);
        assert_eq!(get(&rig, &signer, "k").await.expect(200).body, body(4));
        replay_gives_the_same(&rig, "if-none-match").await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn put_if_match_replaces_the_object_it_names() {
    for body in [small, sliced] {
        let rig = small_rig();
        let (_, signer) = rig.standard(BUCKET).await;
        let etag = |seed: u8| md5_etag(&body(seed));

        // No object: `404 NoSuchKey`, whatever is named.
        let before = footprint(&rig);
        for value in [etag(1), "*".to_string()] {
            let req = put_req(&rig, &signer, "k", &body(1), &[("if-match", &value)]);
            let (resp, polled) = rig.send_watched(req).await;
            resp.expect_error(404, "NoSuchKey");
            assert!(!polled, "the body was read");
        }
        assert_eq!(footprint(&rig), before);
        assert_eq!(rig.count("key_floors"), 0);

        put_if(&rig, &signer, "k", &body(1), &[]).await.expect(200);
        tick(&rig);
        // Another ETag: `412`, and the object stays.
        let before = footprint(&rig);
        for wrong in [etag(2), "\"0123456789abcdef0123456789abcdef\"".to_string()] {
            let req = put_req(&rig, &signer, "k", &body(2), &[("if-match", &wrong)]);
            let (resp, polled) = rig.send_watched(req).await;
            resp.expect_error(412, "PreconditionFailed");
            assert!(!polled, "the body was read");
        }
        assert_eq!(footprint(&rig), before);
        assert_eq!(get(&rig, &signer, "k").await.expect(200).body, body(1));

        // The ETag of the live object, as the service gave it (quoted)...
        let quoted = etag(1);
        let r = put_if(&rig, &signer, "k", &body(2), &[("if-match", &quoted)]).await;
        r.expect(200);
        assert_eq!(r.header("etag"), Some(etag(2).as_str()));
        tick(&rig);
        // ...which now names nothing live...
        put_if(&rig, &signer, "k", &body(3), &[("if-match", &quoted)])
            .await
            .expect_error(412, "PreconditionFailed");
        // ...bare...
        let bare = etag(2).trim_matches('"').to_string();
        put_if(&rig, &signer, "k", &body(3), &[("if-match", &bare)])
            .await
            .expect(200);
        tick(&rig);
        // ...and `*`: whatever is live.
        put_if(&rig, &signer, "k", &body(4), &[("if-match", "*")])
            .await
            .expect(200);
        assert_eq!(get(&rig, &signer, "k").await.expect(200).body, body(4));
        assert_eq!(rig.count("objects"), 1);
        replay_gives_the_same(&rig, "if-match").await;
    }
}

// ---------------------------------------------------------------------------
// CopyObject
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_copy_is_held_to_the_condition_on_its_destination() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "src", &small(1), &[])
        .await
        .expect(200);
    put_if(&rig, &signer, "dst", &small(2), &[])
        .await
        .expect(200);
    tick(&rig);
    let (src_etag, dst_etag) = (md5_etag(&small(1)), md5_etag(&small(2)));

    let before = footprint(&rig);
    let floors = rig.count("key_floors");
    // A live destination is not absent, and the ETag of the source is
    // not the ETag of the destination.
    for headers in [("if-none-match", "*"), ("if-match", src_etag.as_str())] {
        rig.send(copy_req(&rig, &signer, "src", "dst", &[headers]))
            .await
            .expect_error(412, "PreconditionFailed");
    }
    // No destination: nothing to match.
    for headers in [("if-match", "*"), ("if-match", src_etag.as_str())] {
        rig.send(copy_req(&rig, &signer, "src", "new", &[headers]))
            .await
            .expect_error(404, "NoSuchKey");
    }
    assert_eq!(footprint(&rig), before);
    assert_eq!(get(&rig, &signer, "dst").await.expect(200).body, small(2));
    // Refused before anything was written: no floor on the key either,
    // which would keep an otherwise empty bucket in use.
    assert_eq!(rig.count("key_floors"), floors);

    rig.send(copy_req(
        &rig,
        &signer,
        "src",
        "dst",
        &[("if-match", &dst_etag)],
    ))
    .await
    .expect(200);
    rig.send(copy_req(
        &rig,
        &signer,
        "src",
        "new",
        &[("if-none-match", "*")],
    ))
    .await
    .expect(200);
    for key in ["dst", "new"] {
        assert_eq!(get(&rig, &signer, key).await.expect(200).body, small(1));
    }
    // A condition on the source is another header, and still judged.
    rig.send(copy_req(
        &rig,
        &signer,
        "src",
        "third",
        &[
            ("if-none-match", "*"),
            ("x-amz-copy-source-if-match", &dst_etag),
        ],
    ))
    .await
    .expect_error(412, "PreconditionFailed");
    get(&rig, &signer, "third").await.expect(404);
    replay_gives_the_same(&rig, "copy").await;
}

// ---------------------------------------------------------------------------
// CompleteMultipartUpload
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_refused_complete_leaves_the_upload_open() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let part = small(7);

    // `If-Match` without an object: `404`. The upload can be completed
    // all the same, here on the condition that the key is still free.
    let open = upload(&rig, &signer, "k", &part).await;
    let before = footprint(&rig);
    for value in ["*", "\"0123456789abcdef0123456789abcdef\""] {
        rig.send(complete_req(
            &rig,
            &signer,
            "k",
            &open,
            &[("if-match", value)],
        ))
        .await
        .expect_error(404, "NoSuchKey");
    }
    assert_eq!(footprint(&rig), before);
    assert_eq!(rig.count("key_floors"), 0);
    assert_eq!(upload_state(&rig, &open.0), "open");
    let done = rig
        .send(complete_req(
            &rig,
            &signer,
            "k",
            &open,
            &[("if-none-match", "*")],
        ))
        .await;
    done.expect(200);
    let got = get(&rig, &signer, "k").await;
    assert_eq!(got.expect(200).body, part);
    // The ETag of a multipart object, as a GET gives it.
    let etag = got.header("etag").unwrap().to_string();
    assert!(etag.ends_with("-1\""), "{etag}");
    assert!(done.values("ETag")[0].contains(etag.trim_matches('"')));
    // The same Complete again is answered from its receipt: it is the
    // request that created the object, not a second one.
    rig.send(complete_req(
        &rig,
        &signer,
        "k",
        &open,
        &[("if-none-match", "*")],
    ))
    .await
    .expect(200);
    tick(&rig);

    // An object under the key: `412` for `If-None-Match: *` and for
    // another ETag. Refused, the upload is open, with its part.
    let second = upload(&rig, &signer, "k", &small(8)).await;
    let before = footprint(&rig);
    for headers in [
        ("if-none-match", "*"),
        ("if-match", "\"0123456789abcdef0123456789abcdef\""),
    ] {
        rig.send(complete_req(&rig, &signer, "k", &second, &[headers]))
            .await
            .expect_error(412, "PreconditionFailed");
    }
    assert_eq!(footprint(&rig), before);
    assert_eq!(upload_state(&rig, &second.0), "open");
    let parts = number(
        &rig,
        &format!(
            "SELECT COUNT(*) FROM upload_parts WHERE upload_id = '{}'",
            second.0
        ),
    );
    assert_eq!(parts, 1, "the part of the open upload");
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, part);
    // It completes against the ETag that is live...
    rig.send(complete_req(
        &rig,
        &signer,
        "k",
        &second,
        &[("if-match", &etag)],
    ))
    .await
    .expect(200);
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, small(8));
    tick(&rig);

    // ...and one that was refused can be aborted instead.
    let third = upload(&rig, &signer, "k", &small(9)).await;
    rig.send(complete_req(
        &rig,
        &signer,
        "k",
        &third,
        &[("if-none-match", "*")],
    ))
    .await
    .expect_error(412, "PreconditionFailed");
    abort(&rig, &signer, "k", &third.0).await.expect(204);
    assert_eq!(upload_state(&rig, &third.0), "aborted");
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, small(8));
    replay_gives_the_same(&rig, "complete").await;
}

// ---------------------------------------------------------------------------
// DeleteObject
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn delete_if_match_deletes_the_object_it_names() {
    let rig = small_rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "k", &small(1), &[]).await.expect(200);
    tick(&rig);
    put_if(&rig, &signer, "k", &small(2), &[]).await.expect(200);
    put_if(&rig, &signer, "star", &sliced(3), &[])
        .await
        .expect(200);
    tick(&rig);
    let (old, live) = (md5_etag(&small(1)), md5_etag(&small(2)));

    // Another ETag (the one the key had before): `412`, the object
    // stays, and no tombstone is written that a replay would apply.
    let before = footprint(&rig);
    for wrong in [old.as_str(), "\"0123456789abcdef0123456789abcdef\""] {
        delete_if(&rig, &signer, "k", &[("if-match", wrong)])
            .await
            .expect_error(412, "PreconditionFailed");
    }
    // No object: `404`, unlike a delete without a condition.
    for value in ["*", live.as_str()] {
        delete_if(&rig, &signer, "none", &[("if-match", value)])
            .await
            .expect_error(404, "NoSuchKey");
    }
    assert_eq!(footprint(&rig), before);
    assert_eq!(tombstones(&rig), 0);
    assert_eq!(get(&rig, &signer, "k").await.expect(200).body, small(2));
    delete_if(&rig, &signer, "none", &[]).await.expect(204);

    // The live ETag: deleted, as by any delete.
    delete_if(&rig, &signer, "k", &[("if-match", &live)])
        .await
        .expect(204);
    assert!(rig.live(&bucket, "k").await.is_none());
    get(&rig, &signer, "k").await.expect(404);
    assert_eq!(tombstones(&rig), 1);
    // Again: there is nothing to match any more.
    delete_if(&rig, &signer, "k", &[("if-match", &live)])
        .await
        .expect_error(404, "NoSuchKey");
    assert_eq!(tombstones(&rig), 1);

    // `If-Match: *` deletes whatever is live.
    delete_if(&rig, &signer, "star", &[("if-match", "*")])
        .await
        .expect(204);
    get(&rig, &signer, "star").await.expect(404);
    replay_gives_the_same(&rig, "delete").await;
    get(&rig, &lose_and_replay(&rig).await, "k")
        .await
        .expect(404);
}

#[tokio::test(flavor = "current_thread")]
async fn a_conditional_write_is_refused_while_a_replay_is_under_way() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "k", &small(1), &[]).await.expect(200);
    let etag = md5_etag(&small(1));
    let before = footprint(&rig);
    sql(
        &rig,
        "INSERT INTO restore_state (id, state, since_ms, started_at) \
         VALUES (1, 'replaying', 0, 1);",
    );
    assert!(rig.bridge.catalog.restore_pending().await.unwrap());
    put_if(&rig, &signer, "k", &small(2), &[("if-match", &etag)])
        .await
        .expect_writes_refused();
    put_if(&rig, &signer, "new", &small(2), &[("if-none-match", "*")])
        .await
        .expect_writes_refused();
    delete_if(&rig, &signer, "k", &[("if-match", &etag)])
        .await
        .expect_writes_refused();
    assert_eq!(footprint(&rig), before);
    assert_eq!(tombstones(&rig), 0);
}

// ---------------------------------------------------------------------------
// A key that changes between the look at it and the batch
// ---------------------------------------------------------------------------

/// The conditional writes of the tests below, each `If-Match` on the
/// object `seed 1` under `k`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Writer {
    Put,
    SlicedPut,
    Copy,
    Complete,
}

const WRITERS: [Writer; 4] = [
    Writer::Put,
    Writer::SlicedPut,
    Writer::Copy,
    Writer::Complete,
];

struct Scene {
    rig: Rig,
    signer: Signer,
    /// The open upload of [`Writer::Complete`].
    open: (String, String),
}

/// `k` and `src` live, an open upload for `k`.
async fn scene() -> Scene {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    put_if(&rig, &signer, "k", &small(1), &[]).await.expect(200);
    put_if(&rig, &signer, "src", &small(5), &[])
        .await
        .expect(200);
    let open = upload(&rig, &signer, "k", &small(6)).await;
    tick(&rig);
    Scene { rig, signer, open }
}

impl Scene {
    fn write(&self, writer: Writer, headers: &[(&str, &str)]) -> Req {
        let (rig, signer) = (&self.rig, &self.signer);
        match writer {
            Writer::Put => put_req(rig, signer, "k", &small(2), headers),
            Writer::SlicedPut => put_req(rig, signer, "k", &sliced(2), headers),
            Writer::Copy => copy_req(rig, signer, "src", "k", headers),
            Writer::Complete => complete_req(rig, signer, "k", &self.open, headers),
        }
    }

    /// What `k` reads as once `writer` has written it.
    fn written(&self, writer: Writer) -> Vec<u8> {
        match writer {
            Writer::Put => small(2),
            Writer::SlicedPut => sliced(2),
            Writer::Copy => small(5),
            Writer::Complete => small(6),
        }
    }
}

/// A delete that chose its tombstone before the conditional write raised
/// the floor of the key deletes the object without leaving a newer id
/// on the key. The floor then lets the write pass; the condition in its
/// batch does not. The delete is stopped at every one of its calls in
/// turn, the write is taken to the point where its record is stored
/// (its look at the key lies behind it), the delete ends, and the write
/// goes on into its batch.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_under_a_conditional_write_is_seen_by_its_batch() {
    for writer in WRITERS {
        let mut stops = 0;
        for n in 0.. {
            let s = scene().await;
            let rig = &s.rig;
            let etag = md5_etag(&small(1));
            let kept = records(rig);

            let delete = start(rig, delete_req(rig, &s.signer, "k", &[]));
            let Ran::Stalled(delete) = run_until(rig, delete, n, Trip::Stall).await else {
                // The delete made fewer than `n` calls.
                rig.trip().disarm();
                break;
            };
            stops += 1;
            // The write comes later: its id sorts after the tombstone.
            tick(rig);
            let write = start(rig, s.write(writer, &[("if-match", &etag)]));
            let write = step_to(rig, write, |rig| records(rig).len() > kept.len())
                .await
                .stalled();
            rig.trip().disarm();
            delete.await.expect(204);
            let answer = write.await;

            let what = format!("{writer:?}, delete stopped at call {n}");
            assert_eq!(answer.status, 404, "{what}: {}", answer.text());
            assert_eq!(answer.code(), "NoSuchKey", "{what}");
            get(rig, &s.signer, "k").await.expect(404);
            // Refused, the write left no record of itself.
            assert_eq!(records(rig), kept, "{what}");
            assert!(orphaned_rows(rig).is_empty(), "{what}");
            assert_eq!(upload_state(rig, &s.open.0), "open", "{what}");
            replay_gives_the_same(rig, &what).await;
        }
        assert!(stops > 5, "{writer:?}: the delete made {stops} calls");
    }
}

/// The same schedule, and the write cannot remove its record once it
/// is refused: the record stays in the store, with an id above the
/// tombstone the delete chose first. A tombstone covers what is older
/// than itself, so that one would leave the record to a replay, which
/// would publish the write over the delete that was answered `204`. The
/// delete therefore does not finish under a newer id on the key: it
/// starts again with a tombstone above it. The delete is plain or held
/// to the object itself.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_is_not_undone_by_the_record_of_a_write_it_refused() {
    for writer in WRITERS {
        for held in [false, true] {
            let mut stops = 0;
            for n in 0.. {
                let s = scene().await;
                let rig = &s.rig;
                let etag = md5_etag(&small(1));
                let kept = records(rig);

                let condition = [("if-match", etag.as_str())];
                let headers: &[(&str, &str)] = if held { &condition } else { &[] };
                let delete = start(rig, delete_req(rig, &s.signer, "k", headers));
                let Ran::Stalled(delete) = run_until(rig, delete, n, Trip::Stall).await else {
                    rig.trip().disarm();
                    break;
                };
                stops += 1;
                tick(rig);
                let write = start(rig, s.write(writer, &condition));
                let write = step_to(rig, write, |rig| records(rig).len() > kept.len())
                    .await
                    .stalled();
                rig.trip().disarm();
                rig.bridge.safety.fail_record_deletes.set(u32::MAX);
                delete.await.expect(204);
                let answer = write.await;
                rig.bridge.safety.fail_record_deletes.set(0);

                let what = format!("{writer:?}, held {held}, delete stopped at call {n}");
                // The write was not done, and could not say that
                // nothing of it is left.
                assert_eq!(answer.status, 500, "{what}: {}", answer.text());
                get(rig, &s.signer, "k").await.expect(404);
                assert_eq!(upload_state(rig, &s.open.0), "open", "{what}");
                let left: Vec<String> = records(rig)
                    .into_iter()
                    .filter(|r| !kept.contains(r))
                    .collect();
                assert!(!left.is_empty(), "{what}: its record");
                let newest = tombstone_ids(rig).into_iter().max().unwrap();
                for record in &left {
                    let id = record.split('/').next().unwrap();
                    assert!(newest.as_str() > id, "{what}: {newest} covers {record}");
                }
                let signer = lose_and_replay(rig).await;
                assert!(live_ids(rig).iter().all(|l| !l.starts_with("k=")), "{what}");
                get(rig, &signer, "k").await.expect(404);
            }
            assert!(stops > 5, "{writer:?}: the delete made {stops} calls");
        }
    }
}

/// The other order: the write is done and answered while the delete
/// waits. It was held to the object the delete came for, so it ran
/// before the delete, and the delete, answered `204` after it, removes
/// what it wrote. A delete that kept the tombstone it chose before the
/// write would delete nothing and still say `204`. Stopped before it
/// has read the key, the delete has not begun; stopped after its batch,
/// it is done and the write finds no object.
#[tokio::test(flavor = "current_thread")]
async fn a_delete_answered_after_a_write_deletes_what_it_wrote() {
    for writer in WRITERS {
        for held in [false, true] {
            let (mut stops, mut written) = (0, 0);
            for n in 0.. {
                let s = scene().await;
                let rig = &s.rig;
                let etag = md5_etag(&small(1));
                let condition = [("if-match", etag.as_str())];

                let delete = start(rig, delete_req(rig, &s.signer, "k", &[]));
                let Ran::Stalled(delete) = run_until(rig, delete, n, Trip::Stall).await else {
                    rig.trip().disarm();
                    break;
                };
                stops += 1;
                tick(rig);
                rig.trip().disarm();
                let headers: &[(&str, &str)] = if held { &condition } else { &[] };
                let answer = rig.send(s.write(writer, headers)).await;
                let what = format!("{writer:?}, held {held}, delete stopped at call {n}");
                assert_eq!(answer.status, 200, "{what}: {}", answer.text());
                written += 1;
                delete.await.expect(204);

                get(rig, &s.signer, "k").await.expect(404);
                assert!(orphaned_rows(rig).is_empty(), "{what}");
                let signer = lose_and_replay(rig).await;
                assert!(live_ids(rig).iter().all(|l| !l.starts_with("k=")), "{what}");
                get(rig, &signer, "k").await.expect(404);
            }
            assert!(stops > 5, "{writer:?}: the delete made {stops} calls");
            assert_eq!(written, stops, "{writer:?}");
        }
    }
}

/// Both wait. The delete is stopped at every one of its calls in turn
/// (or has not begun), the write, which comes later, at every one of
/// its own; then the delete runs to its end and is answered, and the
/// write goes on, unable to remove a record. Wherever the two stood,
/// the write was held to the object the delete removed and cannot be
/// published after it: the key is empty, and stays empty when the
/// catalogue is rebuilt from the records.
///
/// This holds the order of [`hold_precondition`]'s two steps: the id of
/// the write is on the key before the write looks at it. A write that
/// looked first could pass, lose the object to a delete that saw no id
/// above its tombstone, and then store a record above that tombstone.
#[tokio::test(flavor = "current_thread")]
async fn a_write_stopped_anywhere_is_not_published_over_a_delete() {
    for writer in WRITERS {
        let (mut most, mut refused) = (0, 0);
        // `None`: the delete begins when the write has been stopped.
        let mut at = None;
        loop {
            let mut stops = 0;
            let mut delete_ended = false;
            for n in 0.. {
                let s = scene().await;
                let rig = &s.rig;
                let etag = md5_etag(&small(1));

                let mut delete = Some(start(rig, delete_req(rig, &s.signer, "k", &[])));
                if let Some(d) = at {
                    match run_until(rig, delete.take().unwrap(), d, Trip::Stall).await {
                        Ran::Stalled(stalled) => delete = Some(stalled),
                        Ran::Done(_) => {
                            rig.trip().disarm();
                            delete_ended = true;
                            break;
                        }
                    }
                    tick(rig);
                }
                let write = start(rig, s.write(writer, &[("if-match", &etag)]));
                let Ran::Stalled(write) = run_until(rig, write, n, Trip::Stall).await else {
                    rig.trip().disarm();
                    break;
                };
                stops += 1;
                rig.trip().disarm();
                tick(rig);
                delete.unwrap().await.expect(204);
                rig.bridge.safety.fail_record_deletes.set(u32::MAX);
                let answer = write.await;
                rig.bridge.safety.fail_record_deletes.set(0);

                let what = format!(
                    "{writer:?} stopped at call {n}, delete at {at:?}: {}",
                    answer.status
                );
                // Published before the delete (and deleted by it), or
                // not at all.
                assert!(
                    matches!(answer.status, 200 | 404 | 500),
                    "{what}: {}",
                    answer.text()
                );
                refused += usize::from(answer.status != 200);
                get(rig, &s.signer, "k").await.expect(404);
                assert!(orphaned_rows(rig).is_empty(), "{what}");
                let signer = lose_and_replay(rig).await;
                assert!(live_ids(rig).iter().all(|l| !l.starts_with("k=")), "{what}");
                get(rig, &signer, "k").await.expect(404);
            }
            if delete_ended {
                break;
            }
            most = most.max(stops);
            at = Some(at.map_or(0, |d| d + 1));
        }
        assert!(at > Some(5), "{writer:?}: the delete made {at:?} calls");
        assert!(most > 5, "{writer:?}: the write made {most} calls");
        assert!(refused > 2, "{writer:?}: refused at {refused} stops");
    }
}

/// Extent rows of a generation that was never published.
fn orphaned_rows(rig: &Rig) -> Vec<String> {
    column(
        rig,
        "SELECT id FROM extents WHERE generation_id IS NOT NULL \
         AND generation_id NOT IN (SELECT id FROM generations)",
    )
}

/// One Complete sent twice at once (a client that retries early), on the
/// condition that the key is free. One of the two creates the object.
/// The other meets that object, of its own upload: it is answered from
/// the receipt like any retry of a Complete that won, not with `412`.
#[tokio::test(flavor = "current_thread")]
async fn a_complete_sent_twice_at_once_is_answered_twice() {
    let mut overlapped = 0;
    for seed in 0..SEEDS {
        let ran = race(seed, true, |s| {
            [
                s.write(Writer::Complete, &[("if-none-match", "*")]),
                s.write(Writer::Complete, &[("if-none-match", "*")]),
            ]
        })
        .await;
        let rig = &ran.s.rig;
        for answer in &ran.answers {
            assert!(
                answer.status == 200
                    || (answer.status, answer.code().as_str()) == (503, "SlowDown"),
                "seed {seed}: {} {}",
                answer.status,
                answer.text()
            );
        }
        assert!(ran.answers.iter().any(|a| a.status == 200), "seed {seed}");
        overlapped += usize::from(ran.answers.iter().all(|a| a.status == 200));
        let published = number(
            rig,
            "SELECT COUNT(*) FROM generations WHERE key = 'k' AND state = 'live'",
        );
        assert_eq!(published, 1, "seed {seed}");
        assert_eq!(upload_state(rig, &ran.s.open.0), "completed");
        replay_gives_the_same(rig, &format!("seed {seed}")).await;
        assert_eq!(ran.body().await, Some(small(6)), "seed {seed}");
    }
    assert!(overlapped as u64 > SEEDS / 2, "{overlapped} of {SEEDS}");
}

/// A refused write whose record a replay has published in the meantime
/// (a row exists under its id): the write does not say `412`, and does
/// not publish a second time. It says `500`, and the record stays.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_write_that_is_published_after_all_does_not_answer_412() {
    for writer in WRITERS {
        let s = scene().await;
        let rig = &s.rig;
        delete_if(rig, &s.signer, "k", &[]).await.expect(204);
        tick(rig);
        let kept = records(rig);
        let write = start(rig, s.write(writer, &[("if-none-match", "*")]));
        let write = step_to(rig, write, |rig| records(rig).len() > kept.len())
            .await
            .stalled();
        rig.trip().disarm();
        let mine: Vec<String> = records(rig)
            .into_iter()
            .filter(|id| !kept.contains(id))
            .collect();
        assert_eq!(mine.len(), 1, "{writer:?}");
        put_if(rig, &s.signer, "k", &small(9), &[])
            .await
            .expect(200);
        // What a replay of the record leaves under its id.
        sql(
            rig,
            &format!(
                "INSERT INTO generations SELECT '{}', bucket_id, key, 'superseded', size, etag, \
                 checksum_json, content_json, user_meta_json, extent_count, created_at, \
                 created_at FROM generations WHERE key = 'k' AND state = 'live';",
                mine[0]
            ),
        );
        let generations = rig.count("generations");
        let answer = write.await;
        assert_eq!(answer.status, 500, "{writer:?}: {}", answer.text());
        assert!(records(rig).contains(&mine[0]), "{writer:?}: the record");
        assert_eq!(rig.count("generations"), generations, "{writer:?}");
        assert_eq!(get(rig, &s.signer, "k").await.expect(200).body, small(9));
    }
}

/// The other way round: the key is written while a conditional write
/// stands between its look at the key and its batch.
#[tokio::test(flavor = "current_thread")]
async fn an_overwrite_under_a_conditional_write_is_seen_by_its_batch() {
    for writer in WRITERS {
        for (condition, absent) in [("if-match", false), ("if-none-match", true)] {
            let s = scene().await;
            let rig = &s.rig;
            if absent {
                delete_if(rig, &s.signer, "k", &[]).await.expect(204);
                tick(rig);
            }
            let etag = md5_etag(&small(1));
            let value = if absent { "*" } else { etag.as_str() };
            let kept = records(rig);

            let write = start(rig, s.write(writer, &[(condition, value)]));
            let write = step_to(rig, write, |rig| records(rig).len() > kept.len())
                .await
                .stalled();
            rig.trip().disarm();
            put_if(rig, &s.signer, "k", &small(9), &[])
                .await
                .expect(200);
            let answer = write.await;

            let what = format!("{writer:?} {condition}");
            assert_eq!(answer.status, 412, "{what}: {}", answer.text());
            assert_eq!(answer.code(), "PreconditionFailed", "{what}");
            assert_eq!(get(rig, &s.signer, "k").await.expect(200).body, small(9));
            assert_eq!(records(rig).len(), kept.len() + 1, "{what}: the overwrite");
            assert!(orphaned_rows(rig).is_empty(), "{what}");
            assert_eq!(upload_state(rig, &s.open.0), "open", "{what}");
            replay_gives_the_same(rig, &what).await;
        }
    }
}

/// A conditional delete whose object is replaced after its look at it.
#[tokio::test(flavor = "current_thread")]
async fn an_overwrite_under_a_conditional_delete_is_seen_by_its_batch() {
    let mut stops = 0;
    for n in 0.. {
        let s = scene().await;
        let rig = &s.rig;
        let etag = md5_etag(&small(1));

        let delete = start(rig, delete_req(rig, &s.signer, "k", &[("if-match", &etag)]));
        let Ran::Stalled(delete) = run_until(rig, delete, n, Trip::Stall).await else {
            rig.trip().disarm();
            break;
        };
        stops += 1;
        rig.trip().disarm();
        put_if(rig, &s.signer, "k", &small(9), &[])
            .await
            .expect(200);
        let answer = delete.await;

        // Wherever the delete stood, it does not delete the new object.
        assert_eq!(answer.status, 412, "call {n}: {}", answer.text());
        assert_eq!(get(rig, &s.signer, "k").await.expect(200).body, small(9));
        replay_gives_the_same(rig, &format!("delete stopped at call {n}")).await;
    }
    assert!(stops > 5, "the delete made {stops} calls");
}

// ---------------------------------------------------------------------------
// A refused write whose record cannot be removed
// ---------------------------------------------------------------------------

/// The record of a refused write is removed before the write is tried
/// again or answered. When the store refuses that, the write does not
/// say `412`: with its record left, what a replay makes of it is not
/// known to be nothing. It says `500`. And the record that stays sorts
/// under the write that took the key, so the replay keeps that one.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_write_that_keeps_its_record_does_not_answer_412() {
    for writer in WRITERS {
        for (condition, absent) in [("if-match", false), ("if-none-match", true)] {
            let s = scene().await;
            let rig = &s.rig;
            if absent {
                delete_if(rig, &s.signer, "k", &[]).await.expect(204);
                tick(rig);
            }
            let etag = md5_etag(&small(1));
            let value = if absent { "*" } else { etag.as_str() };
            let kept = records(rig);

            let write = start(rig, s.write(writer, &[(condition, value)]));
            let write = step_to(rig, write, |rig| records(rig).len() > kept.len())
                .await
                .stalled();
            rig.trip().disarm();
            put_if(rig, &s.signer, "k", &small(9), &[])
                .await
                .expect(200);
            rig.bridge.safety.fail_record_deletes.set(u32::MAX);
            let answer = write.await;
            rig.bridge.safety.fail_record_deletes.set(0);

            let what = format!("{writer:?} {condition}");
            assert_eq!(answer.status, 500, "{what}: {}", answer.text());
            assert_eq!(records(rig).len(), kept.len() + 2, "{what}: both records");
            assert_eq!(get(rig, &s.signer, "k").await.expect(200).body, small(9));
            assert_eq!(upload_state(rig, &s.open.0), "open", "{what}");
            // The replay reads the record of the refused write, and
            // leaves the key to the write that sorts after it.
            let live = live_ids(rig);
            let signer = lose_and_replay(rig).await;
            assert_eq!(live_ids(rig), live, "{what}: after the replay");
            assert_eq!(get(rig, &signer, "k").await.expect(200).body, small(9));
        }
    }
}

// ---------------------------------------------------------------------------
// Two writers, one key
// ---------------------------------------------------------------------------

const SEEDS: u64 = 150;

/// What two requests on `k` answered, and what `k` is afterwards.
struct Raced {
    s: Scene,
    answers: [Resp; 2],
    seed: u64,
}

/// Runs the two requests of `pair` together, their store and database
/// calls interleaved as `seed` decides, then checks what holds for any
/// two writers: nothing is half-written, and a replay of the records
/// gives the same catalogue.
async fn race(seed: u64, absent: bool, pair: impl FnOnce(&Scene) -> [Req; 2]) -> Raced {
    let s = scene().await;
    if absent {
        delete_if(&s.rig, &s.signer, "k", &[]).await.expect(204);
        tick(&s.rig);
    }
    let [a, b] = pair(&s);
    s.rig.trip().jitter(seed);
    let (a, b) = tokio::join!(s.rig.send(a), s.rig.send(b));
    Raced {
        s,
        answers: [a, b],
        seed,
    }
}

impl Raced {
    /// Exactly one of the two won; the other was refused with `refusal`
    /// (or, having lost the key too often, told to come back). Returns
    /// the index of the winner.
    async fn one_won(&self, what: &str, refusal: [(u16, &str); 2]) -> usize {
        let what = format!("{what}, seed {}", self.seed);
        let won = |r: &Resp| matches!(r.status, 200 | 204);
        let winners: Vec<usize> = (0..2).filter(|i| won(&self.answers[*i])).collect();
        assert_eq!(
            winners.len(),
            1,
            "{what}: {} / {}",
            self.answers[0].text(),
            self.answers[1].text()
        );
        let loser = 1 - winners[0];
        let lost = &self.answers[loser];
        let (status, code) = refusal[loser];
        assert!(
            (lost.status, lost.code().as_str()) == (status, code)
                || (lost.status, lost.code().as_str()) == (503, "SlowDown"),
            "{what}: the loser answered {} {}",
            lost.status,
            lost.text()
        );
        let rig = &self.s.rig;
        assert!(orphaned_rows(rig).is_empty(), "{what}");
        assert!(rig.count("objects") <= 2, "{what}: `k` and `src`");
        assert_eq!(rig.bridge.budget.in_use(), 0, "{what}");
        replay_gives_the_same(rig, &what).await;
        winners[0]
    }

    async fn body(&self) -> Option<Vec<u8>> {
        // The replay issued the same access key again.
        let got = get(&self.s.rig, &self.s.signer, "k").await;
        match got.status {
            200 => Some(got.body),
            404 => None,
            other => panic!("GET answered {other}"),
        }
    }
}

/// Two creations of one key (`If-None-Match: *`), by every pair of
/// writers: one creates it, the other is told it exists.
#[tokio::test(flavor = "current_thread")]
async fn two_creations_of_one_key_have_one_winner() {
    let mut refused = 0;
    for seed in 0..SEEDS {
        let (first, second) = (
            WRITERS[(seed % 4) as usize],
            WRITERS[((seed / 4) % 4) as usize],
        );
        // An upload completes once, so two Completes are not two writers.
        let second = match (first, second) {
            (Writer::Complete, Writer::Complete) => Writer::Put,
            _ => second,
        };
        let ran = race(seed, true, |s| {
            [
                s.write(first, &[("if-none-match", "*")]),
                s.write(second, &[("if-none-match", "*")]),
            ]
        })
        .await;
        let what = format!("{first:?} and {second:?}");
        let winner = ran.one_won(&what, [(412, "PreconditionFailed"); 2]).await;
        refused += usize::from(ran.answers[1 - winner].status == 412);
        let by = [first, second][winner];
        // Two PUTs of the same bytes cannot be told apart by them.
        if first != second {
            assert_eq!(ran.body().await, Some(ran.s.written(by)), "{what}");
        } else {
            assert!(ran.body().await.is_some(), "{what}");
        }
        // One generation was published under the key, and one record
        // says so: the loser's is gone.
        let rig = &ran.s.rig;
        let published = number(
            rig,
            "SELECT COUNT(*) FROM generations WHERE key = 'k' AND state = 'live'",
        );
        assert_eq!(published, 1, "{what}, seed {seed}");
        let on_record = records(rig);
        let live = column(rig, "SELECT generation_id FROM objects WHERE key = 'k'");
        assert!(on_record.contains(&live[0]), "{what}, seed {seed}");
    }
    // Losing the key five times in a row to one other writer is not what
    // these runs are about: nearly every loser is told `412`.
    assert!(refused as u64 > SEEDS * 9 / 10, "{refused} of {SEEDS}");
}

/// Two replacements of the same object (`If-Match` on its ETag): one
/// replaces it, and the other, which named an object that is no longer
/// there, is refused. No update is lost.
#[tokio::test(flavor = "current_thread")]
async fn two_replacements_of_one_object_have_one_winner() {
    for seed in 0..SEEDS {
        let (first, second) = (
            WRITERS[(seed % 4) as usize],
            WRITERS[((seed / 4) % 4) as usize],
        );
        let second = match (first, second) {
            (Writer::Complete, Writer::Complete) => Writer::Copy,
            _ => second,
        };
        let etag = md5_etag(&small(1));
        let ran = race(seed, false, |s| {
            [
                s.write(first, &[("if-match", &etag)]),
                s.write(second, &[("if-match", &etag)]),
            ]
        })
        .await;
        let what = format!("{first:?} and {second:?}");
        let winner = ran.one_won(&what, [(412, "PreconditionFailed"); 2]).await;
        if first != second {
            let by = [first, second][winner];
            assert_eq!(ran.body().await, Some(ran.s.written(by)), "{what}");
        }
    }
}

/// A replacement and a delete of the same object, both `If-Match` on
/// its ETag: the object is replaced or deleted, never both.
#[tokio::test(flavor = "current_thread")]
async fn a_replacement_and_a_delete_of_one_object_have_one_winner() {
    let mut deleted = 0;
    for seed in 0..SEEDS {
        let writer = WRITERS[(seed % 4) as usize];
        let etag = md5_etag(&small(1));
        let ran = race(seed, false, |s| {
            [
                s.write(writer, &[("if-match", &etag)]),
                delete_req(&s.rig, &s.signer, "k", &[("if-match", &etag)]),
            ]
        })
        .await;
        let what = format!("{writer:?} and a delete");
        // The write lost to the delete: no object. The delete lost to
        // the write: another object.
        let winner = ran
            .one_won(&what, [(404, "NoSuchKey"), (412, "PreconditionFailed")])
            .await;
        let expected = (winner == 0).then(|| ran.s.written(writer));
        assert_eq!(ran.body().await, expected, "{what}, seed {seed}");
        deleted += winner;
    }
    assert!(
        deleted > 0 && (deleted as u64) < SEEDS,
        "{deleted} deletes won"
    );
}

/// A creation against a write without a condition. The write always
/// goes through. The creation does only if it came first, and then the
/// other write is what the key holds.
#[tokio::test(flavor = "current_thread")]
async fn a_creation_never_lands_on_a_key_another_write_took() {
    let mut created = 0;
    for seed in 0..SEEDS {
        let writer = WRITERS[(seed % 4) as usize];
        let ran = race(seed, true, |s| {
            [
                s.write(writer, &[("if-none-match", "*")]),
                put_req(&s.rig, &s.signer, "k", &small(9), &[]),
            ]
        })
        .await;
        let what = format!("{writer:?} against a PUT, seed {seed}");
        let [conditional, plain] = &ran.answers;
        plain.expect(200);
        match conditional.status {
            200 => created += 1,
            503 => assert_eq!(conditional.code(), "SlowDown", "{what}"),
            _ => {
                conditional.expect_error(412, "PreconditionFailed");
            }
        }
        replay_gives_the_same(&ran.s.rig, &what).await;
        assert_eq!(ran.body().await, Some(small(9)), "{what}");
    }
    assert!(created > 0 && (created as u64) < SEEDS, "{created} created");
}
