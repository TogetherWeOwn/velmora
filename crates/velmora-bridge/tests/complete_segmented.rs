//! CompleteMultipartUpload of an object with more extents than one
//! recovery record in one document names: the record is written as
//! segments and then a head, the answer is a `200` whose document
//! follows, and at no point is there a head without its segments, or a
//! generation without its record. An object within one document is
//! recorded and answered as before.
//!
//! The rig cuts records far below the production figures: a record in
//! segments above 8 extents, 4 extents a segment.

mod intent_support;
mod service_support;

use std::rc::Rc;

use futures_util::StreamExt;
use intent_support::*;
use service_support::*;
use velmora_bridge::config::COMPLETE_CHARGE_BYTES;
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::keepalive::{Deferred, KEEPALIVE_BYTE, XML_DECLARATION};
use velmora_bridge::recovery::{
    read_segment, read_stored_generation, set_id, write_generation, Cut, GenerationHead,
    GenerationManifest, SegmentWriter, StoredGeneration, MAX_SEGMENTS, SINGLE_RECORD_EXTENTS,
};
use velmora_bridge::*;

const KEY: &str = "large";
/// Extents of half a MiB: a part of 5 MiB, the smallest that is not the
/// last, is stored in 10.
const SLICE_HALF: usize = MIB / 2;
const PART: usize = 5 * MIB;
const CUT: Cut = Cut { after: 8, per: 4 };

fn seg_config() -> BridgeConfig {
    let mut cfg = config(Vec::new());
    cfg.max_extent_bytes = MIB as u64;
    cfg.slice_bytes = SLICE_HALF as u64;
    cfg.max_put_bytes = 8 * MIB as u64;
    cfg.max_object_extents = 200;
    cfg.record_cut = CUT;
    cfg.intent_sweep = true;
    cfg
}

fn body(seed: u8, len: usize) -> Vec<u8> {
    pattern(4 * seed + 3, len)
}

struct Scene {
    rig: Rig,
    bucket: Bucket,
    signer: Signer,
    id: String,
}

async fn scene_with(cfg: BridgeConfig) -> Scene {
    let rig = rig_with(NoNntp, cfg);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let created = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, KEY),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    let id = created.values("UploadId").remove(0);
    Scene {
        rig,
        bucket,
        signer,
        id,
    }
}

async fn scene() -> Scene {
    scene_with(seg_config()).await
}

fn complete_xml(parts: &[(u16, String)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (n, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

impl Scene {
    async fn send_part(&self, n: u16, bytes: &[u8]) -> Resp {
        let number = n.to_string();
        self.rig
            .send(mode_req_at(
                &self.rig,
                &self.signer,
                KEY,
                &[("partNumber", &number), ("uploadId", &self.id)],
                bytes,
                Mode::Literal,
            ))
            .await
    }

    async fn part(&self, n: u16, bytes: &[u8]) -> (u16, String) {
        let sent = self.send_part(n, bytes).await;
        assert_eq!(sent.status, 200, "part {n}: {}", sent.text());
        (n, sent.header("etag").unwrap().to_owned())
    }

    fn complete_req(&self, parts: &[(u16, String)]) -> Req {
        self.signer.sign(
            self.rig.now(),
            Method::Post,
            &path(BUCKET, KEY),
            &[("uploadId", &self.id)],
            &[("content-type", "application/xml")],
            complete_xml(parts).into_bytes(),
        )
    }

    /// The answer of a Complete as the handler returns it, not yet read.
    async fn complete_raw(&self, parts: &[(u16, String)]) -> S3Response {
        Rc::clone(&self.rig.bridge)
            .handle(self.complete_req(parts).into_request())
            .await
    }

    async fn complete(&self, parts: &[(u16, String)]) -> Resp {
        self.rig.send(self.complete_req(parts)).await
    }

    async fn abort(&self) -> Resp {
        self.rig
            .call(
                &self.signer,
                Method::Delete,
                &path(BUCKET, KEY),
                &[("uploadId", &self.id)],
                &[],
                b"",
            )
            .await
    }

    async fn read(&self) -> Resp {
        get(&self.rig, &self.signer, KEY).await
    }

    /// The names of the segments in the safety store.
    fn segments(&self) -> Vec<String> {
        keys_under(&self.rig, "m/seg/")
    }

    /// The heads in the safety store, each read in full by the readers
    /// of a restore: every segment it names is there and is the one it
    /// names. Returns the extents each record names.
    async fn heads(&self) -> Vec<(GenerationHead, usize)> {
        let b = &self.rig.bridge;
        let mut heads = Vec::new();
        for id in records(&self.rig) {
            let name = format!("m/{id}");
            match read_stored_generation(&b.safety, &b.kek, &name)
                .await
                .unwrap()
            {
                Some(StoredGeneration::Segmented(head)) => {
                    let mut extents = 0;
                    for index in 0..head.segments.len() {
                        extents += read_segment(&b.safety, &b.kek, &b.cfg.records, &head, index)
                            .await
                            .expect("a head names segments that are stored")
                            .len();
                    }
                    heads.push((head, extents));
                }
                Some(StoredGeneration::Single(_)) => panic!("{name} is in one document"),
                None => panic!("{name} is gone"),
            }
        }
        heads
    }
}

/// Whether a Complete was answered with a failure: by its status, or by
/// an `<Error>` document in a `200`.
fn failed(r: &Resp) -> bool {
    r.status != 200 || r.text().contains("<Error>")
}

/// A Complete that was answered with `code` in a `200`: the document
/// after the XML declaration is one `<Error>`.
fn expect_error_document(r: &Resp, code: &str) {
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.code(), code, "{}", r.text());
    let text = r.text();
    assert!(
        text.starts_with("<Error>") && text.ends_with("</Error>"),
        "{text}"
    );
    assert!(!text.contains("CompleteMultipartUploadResult"), "{text}");
}

/// A tick is a few turns of the executor.
fn quick_ticks() -> Sleeper {
    Rc::new(|_ms| {
        Box::pin(async {
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        })
    })
}

fn deferred(resp: S3Response) -> Deferred {
    assert_eq!(resp.status, 200);
    match resp.body {
        RespBody::Deferred(d) => d,
        _ => panic!("the answer is not deferred"),
    }
}

/// Reads a streamed body to its end. Returns the document after the
/// declaration and the whitespace, and how many keepalive bytes came.
async fn read_stream(mut body: ByteStream) -> (String, usize) {
    assert_eq!(body.next().await.unwrap().unwrap(), XML_DECLARATION);
    let (mut out, mut keepalives) = (Vec::new(), 0);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.expect("a keepalive body never fails");
        if chunk == KEEPALIVE_BYTE {
            assert!(out.is_empty(), "whitespace only before the root");
            keepalives += 1;
        } else {
            out.extend(chunk);
        }
    }
    (String::from_utf8(out).unwrap(), keepalives)
}

// ---------------------------------------------------------------------------
// Within one document: as before
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn an_object_within_one_document_is_recorded_and_answered_as_before() {
    // 8 extents is the most one document names here.
    for extents in [1usize, 7, 8] {
        let s = scene().await;
        let bytes = body(1, extents * SLICE_HALF + usize::from(extents == 1));
        let listed = [s.part(1, &bytes).await];
        let resp = s.complete_raw(&listed).await;
        // The answer is whole, with its status: nothing is deferred.
        assert!(matches!(resp.body, RespBody::Bytes(_)), "{extents}");
        let resp = Resp::collect(resp).await;
        resp.expect(200);
        assert!(resp.text().contains("CompleteMultipartUploadResult"));

        // One record in one document, the one a build before this one
        // wrote for the same rows, and no segment.
        assert!(s.segments().is_empty(), "{extents}");
        let b = &s.rig.bridge;
        let (generation, rows) = s.rig.live(&s.bucket, KEY).await.unwrap();
        assert_eq!(rows.len(), extents);
        let name = format!("m/{}", generation.id);
        let Some(StoredGeneration::Single(record)) =
            read_stored_generation(&b.safety, &b.kek, &name)
                .await
                .unwrap()
        else {
            panic!("{extents}: not a record in one document");
        };
        assert!(record == GenerationManifest::new(&s.bucket, &generation, &rows).unwrap());
        assert!(s.read().await.body == bytes);
        // One message for each extent, in one batch.
        assert_eq!(b.jobs.inner.calls(), 1);
        assert_eq!(b.jobs.inner.sent().len(), rows.len());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_production_cut_asks_nothing_more_of_the_catalogue() {
    // With the limit one document holds, a Complete makes the calls it
    // made before segments existed: the upload is not counted first.
    // The figures are those of the build before the writer of
    // segments, counted there for the same two requests: a part of one
    // extent, and one stored in three slices (with its stamp).
    const BEFORE: [(usize, u64); 2] = [(100, 11), (3 * SLICE_HALF, 15)];
    let mut plain = seg_config();
    plain.record_cut = Cut::BUILT_IN;
    plain.max_object_extents = 10_000;
    let mut counted = plain.clone();
    counted.max_object_extents = 131_072;
    for (len, calls_before) in BEFORE {
        // A limit above one document costs one count, and nothing else.
        for (cfg, more) in [(plain.clone(), 0), (counted.clone(), 1)] {
            let s = scene_with(cfg).await;
            let listed = [s.part(1, &body(1, len)).await];
            let before = s.rig.trip().calls();
            let resp = s.complete_raw(&listed).await;
            assert!(matches!(resp.body, RespBody::Bytes(_)));
            assert_eq!(resp.status, 200);
            let calls = s.rig.trip().calls() - before;
            assert_eq!(calls, calls_before + more, "{len} bytes");
            assert!(s.segments().is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Above it: segments, then the head
// ---------------------------------------------------------------------------

/// Three parts whose numbers are in three runs of the paged read: 10,
/// 10 and 1 extents.
async fn three_parts(s: &Scene) -> (Vec<(u16, String)>, Vec<u8>) {
    let bodies = [body(1, PART), body(2, PART), body(3, SLICE_HALF + 9)];
    let mut listed = Vec::new();
    for (n, bytes) in [1u16, 300, 700].into_iter().zip(&bodies) {
        listed.push(s.part(n, bytes).await);
    }
    (listed, bodies.concat())
}

#[tokio::test(flavor = "current_thread")]
async fn a_larger_object_is_recorded_in_segments_then_a_head() {
    let mut s = scene().await;
    let (listed, whole) = three_parts(&s).await;
    // A part that is not listed is read by no run and is in no record.
    s.part(500, &body(9, 3 * SLICE_HALF)).await;
    s.rig.bridge.safety.puts.borrow_mut().clear();

    let resp = s.complete_raw(&listed).await;
    assert_eq!(resp.status, 200);
    assert!(
        matches!(resp.body, RespBody::Deferred(_)),
        "the document follows the headers"
    );
    let resp = Resp::collect(resp).await;
    let text = resp.text();
    assert!(text.starts_with("<CompleteMultipartUploadResult"), "{text}");
    assert!(!failed(&resp));
    assert_eq!(resp.values("ETag").len(), 1);

    // 21 extents: five segments of 4 and one of 1, stored in order, and
    // the head after the last of them.
    let (generation, rows) = s.rig.live(&s.bucket, KEY).await.unwrap();
    assert_eq!((rows.len(), generation.extent_count), (21, 21));
    let puts: Vec<String> = s
        .rig
        .bridge
        .safety
        .puts
        .borrow()
        .iter()
        .map(|(key, _)| key.clone())
        .filter(|key| key.starts_with("m/"))
        .collect();
    let heads = s.heads().await;
    assert_eq!(heads.len(), 1);
    let (head, named) = &heads[0];
    assert_eq!(*named, 21);
    assert_eq!(head.generation.id, generation.id.as_str());
    assert_eq!(head.segments.len(), 6);
    assert_eq!(CUT.segments(21), 6);
    let mut expected: Vec<String> = (0..6)
        .map(|i| head.segment_key(&s.rig.bridge.cfg.records, i))
        .collect();
    assert_eq!(s.segments(), expected);
    expected.push(format!("m/{}", generation.id));
    assert_eq!(puts, expected, "segments first, the head last");
    // The segments name the rows of the catalogue, in order.
    let b = &s.rig.bridge;
    let mut seq = 0;
    for index in 0..6 {
        for e in read_segment(&b.safety, &b.kek, &b.cfg.records, head, index)
            .await
            .unwrap()
        {
            let row = &rows[seq as usize];
            assert_eq!(
                (e.id.as_str(), e.seq, Some(e.plain_offset)),
                (row.id.as_str(), seq, row.plain_offset)
            );
            seq += 1;
        }
    }

    // The batch left one obligation for each extent, and one batch of
    // messages was sent.
    assert_eq!(s.rig.count("outbox"), 21);
    assert_eq!(b.jobs.inner.calls(), 1);
    assert_eq!(b.jobs.inner.sent().len(), 21);
    assert!(s.read().await.body == whole);
    assert_eq!(s.rig.bridge.budget.in_use(), 0);
    assert_eq!(s.rig.bridge.budget.peak(), COMPLETE_CHARGE_BYTES);

    // The same request again is answered from the receipt, whole.
    let again = s.complete_raw(&listed).await;
    assert!(matches!(again.body, RespBody::Bytes(_)));
    assert_eq!(
        Resp::collect(again).await.values("ETag"),
        resp.values("ETag")
    );
    assert_eq!(s.heads().await.len(), 1);

    // And the record is one a restore publishes the object from.
    restore(&mut s.rig).await;
    let (restored, rows) = s.rig.live(&s.bucket, KEY).await.unwrap();
    assert_eq!((restored.id, rows.len()), (generation.id, 21));
    assert!(s.read().await.body == whole);
}

#[tokio::test(flavor = "current_thread")]
async fn one_batch_of_at_most_a_hundred_messages_is_sent() {
    let s = scene().await;
    // 11 parts of the same 5 MiB: 110 extents.
    let bytes = body(1, PART);
    let mut listed = Vec::new();
    for n in 1..=11 {
        listed.push(s.part(n, &bytes).await);
    }
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    let b = &s.rig.bridge;
    assert_eq!(s.rig.count("outbox"), 110, "the obligations are the rows");
    assert_eq!(b.jobs.inner.calls(), 1);
    let sent = b.jobs.inner.sent();
    assert_eq!(sent.len(), 100);
    // The first hundred of the object, in its order.
    let (_, rows) = s.rig.live(&s.bucket, KEY).await.unwrap();
    for (job, row) in sent.iter().zip(&rows) {
        assert!(matches!(&job.job, Job::Extent { extent, .. } if *extent == row.id));
    }
    assert_eq!(s.heads().await[0].1, 110);
    assert_eq!(s.segments().len(), 28);
}

// ---------------------------------------------------------------------------
// Refused before anything is stored
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn an_upload_above_the_limit_is_refused_with_its_status() {
    let mut cfg = seg_config();
    cfg.max_object_extents = 15;
    let s = scene_with(cfg).await;
    let first = s.part(1, &body(1, PART)).await;
    // The early refusal of a part in slices holds to the same limit.
    let refused = s.send_part(2, &body(2, 3 * MIB)).await;
    refused.expect_error(400, "EntityTooLarge");
    assert!(refused.message().contains("more than 15 stored extents"));
    // Parts of one extent are counted by Complete, listed or not.
    let mut listed = vec![first];
    for n in 2..=7 {
        listed.push(s.part(n, &body(n as u8, 100)).await);
    }
    let resp = s.complete_raw(&listed[..2]).await;
    assert!(matches!(resp.body, RespBody::Bytes(_)));
    let resp = Resp::collect(resp).await;
    resp.expect_error(400, "EntityTooLarge");
    assert!(resp.message().contains("more than 15 stored extents"));
    assert!(s.segments().is_empty() && records(&s.rig).is_empty());
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(s.rig.bridge.budget.peak(), 2 * SLICE_HALF as u64);
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_of_more_segments_than_a_head_names_is_never_begun() {
    // A configuration that was checked never allows this: 192 segments
    // of one extent are fewer than the limit.
    let mut cfg = seg_config();
    cfg.record_cut = Cut { after: 8, per: 1 };
    cfg.max_object_extents = 300;
    assert!(!cfg.record_cut.fits(193) && cfg.record_cut.fits(192));
    let s = scene_with(cfg).await;
    let bytes = body(1, PART);
    let mut listed = Vec::new();
    for n in 1..=20 {
        listed.push(s.part(n, &bytes).await);
    }
    // 200 extents: refused whole, with a status, before a segment.
    let resp = s.complete_raw(&listed).await;
    assert!(matches!(resp.body, RespBody::Bytes(_)));
    let resp = Resp::collect(resp).await;
    resp.expect_error(400, "EntityTooLarge");
    assert!(resp.message().contains("more than 192 stored extents"));
    assert!(s.segments().is_empty() && records(&s.rig).is_empty());
    assert_eq!(s.rig.count("generations"), 0);

    // Also when the listed parts alone would fit: what the upload
    // holds is what counts, as for the limit.
    let resp = s.complete(&listed[..19]).await;
    resp.expect_error(400, "EntityTooLarge");
    assert!(s.segments().is_empty());

    // The writer holds to the bound itself: extent 193 begins no
    // segment, and the 192 before it leave no head.
    let (_, rows) = {
        let small = scene().await;
        let one = [small.part(1, &body(1, PART)).await];
        assert!(!failed(&small.complete(&one).await));
        small.rig.live(&small.bucket, KEY).await.unwrap()
    };
    let b = &s.rig.bridge;
    let mut writer = SegmentWriter::new(
        &b.safety,
        &b.kek,
        &b.cfg.records,
        &s.bucket,
        set_id(s.rig.now(), [7; 8]),
        1,
    )
    .unwrap();
    let mut row = rows[0].clone();
    row.bucket_id = s.bucket.id.clone();
    for seq in 0..MAX_SEGMENTS as u32 {
        row.seq = Some(seq);
        row.plain_offset = Some(u64::from(seq) * row.plain_size);
        writer.push(&row).await.unwrap();
    }
    assert_eq!(s.segments().len(), MAX_SEGMENTS);
    row.seq = Some(MAX_SEGMENTS as u32);
    row.plain_offset = Some(MAX_SEGMENTS as u64 * row.plain_size);
    assert!(writer.push(&row).await.is_err());
    assert_eq!(writer.extents(), MAX_SEGMENTS as u32);
    assert_eq!(s.segments().len(), MAX_SEGMENTS, "nothing more was stored");
    assert!(records(&s.rig).is_empty());
}

/// A generation and one of its extent rows, made for `s`'s bucket by a
/// Complete elsewhere: what the writers are handed.
async fn a_generation_for(s: &Scene) -> (GenerationRow, ExtentRow) {
    let small = scene().await;
    let one = [small.part(1, &body(1, PART)).await];
    assert!(!failed(&small.complete(&one).await));
    let (mut generation, rows) = small.rig.live(&small.bucket, KEY).await.unwrap();
    generation.bucket_id = s.bucket.id.clone();
    let mut row = rows[0].clone();
    row.bucket_id = s.bucket.id.clone();
    (generation, row)
}

/// `row` as extent `seq` of a generation of such rows.
fn nth(row: &ExtentRow, seq: u32) -> ExtentRow {
    let mut row = row.clone();
    row.seq = Some(seq);
    row.plain_offset = Some(u64::from(seq) * row.plain_size);
    row
}

#[tokio::test(flavor = "current_thread")]
async fn the_writer_stores_a_head_only_for_the_extents_the_generation_counts() {
    let s = scene().await;
    let (generation, row) = a_generation_for(&s).await;
    let b = &s.rig.bridge;
    let writer = |tag: u8| {
        SegmentWriter::new(
            &b.safety,
            &b.kek,
            &b.cfg.records,
            &s.bucket,
            set_id(s.rig.now(), [tag; 8]),
            4,
        )
        .unwrap()
    };
    const PUSHED: u32 = 5;
    let exact = |g: &mut GenerationRow| {
        g.extent_count = PUSHED;
        g.size = u64::from(PUSHED) * row.plain_size;
    };

    // One extent more or fewer than were pushed, another size, or
    // another bucket.
    type Change = fn(&mut GenerationRow);
    let wrong: [Change; 5] = [
        |g| g.extent_count += 1,
        |g| g.extent_count -= 1,
        |g| g.size += 1,
        |g| g.size -= 1,
        |g| g.bucket_id = BucketId::mint([0; 8]),
    ];
    for (tag, change) in wrong.into_iter().enumerate() {
        let mut w = writer(tag as u8);
        for seq in 0..PUSHED {
            w.push(&nth(&row, seq)).await.unwrap();
        }
        let mut g = generation.clone();
        exact(&mut g);
        change(&mut g);
        let puts = b.safety.puts.borrow().len();
        assert!(w.finish(&b.catalog, &g).await.is_err(), "{tag}");
        assert!(records(&s.rig).is_empty(), "{tag}: no head");
        // Refused before the last segment is stored.
        assert_eq!(b.safety.puts.borrow().len(), puts, "{tag}");
    }

    // An extent that leaves a gap, in `seq` or in the bytes, is not
    // taken, and neither is one pushed twice.
    let mut w = writer(9);
    w.push(&nth(&row, 0)).await.unwrap();
    assert!(w.push(&nth(&row, 2)).await.is_err());
    assert!(w.push(&nth(&row, 0)).await.is_err());
    let mut shifted = nth(&row, 1);
    shifted.plain_offset = Some(row.plain_size + 1);
    assert!(w.push(&shifted).await.is_err());
    let mut skipped = nth(&row, 1);
    skipped.seq = Some(2);
    assert!(w.push(&skipped).await.is_err());
    assert_eq!(w.extents(), 1);

    // A writer whose segment was not stored takes no more and stores
    // no head: the extents of that segment are gone from it.
    let mut w = writer(10);
    for seq in 0..3 {
        w.push(&nth(&row, seq)).await.unwrap();
    }
    *b.safety.fail_put_prefix.borrow_mut() = Some("m/seg/".into());
    assert!(w.push(&nth(&row, 3)).await.is_err());
    *b.safety.fail_put_prefix.borrow_mut() = None;
    assert!(w.push(&nth(&row, 4)).await.is_err());
    let mut g = generation.clone();
    g.extent_count = 4;
    g.size = 4 * row.plain_size;
    assert!(w.finish(&b.catalog, &g).await.is_err());
    assert!(records(&s.rig).is_empty());

    // Also when the segment that was lost held no byte, and the size
    // of the rest is the size of the generation.
    let mut w = SegmentWriter::new(
        &b.safety,
        &b.kek,
        &b.cfg.records,
        &s.bucket,
        set_id(s.rig.now(), [12; 8]),
        1,
    )
    .unwrap();
    w.push(&nth(&row, 0)).await.unwrap();
    let mut empty = nth(&row, 1);
    empty.plain_size = 0;
    *b.safety.fail_put_prefix.borrow_mut() = Some("m/seg/".into());
    assert!(w.push(&empty).await.is_err());
    *b.safety.fail_put_prefix.borrow_mut() = None;
    let mut g = generation.clone();
    g.extent_count = 2;
    g.size = row.plain_size;
    assert!(w.finish(&b.catalog, &g).await.is_err());
    assert!(records(&s.rig).is_empty());

    // The same extents, counted as they are, get their head.
    let mut w = writer(11);
    for seq in 0..PUSHED {
        w.push(&nth(&row, seq)).await.unwrap();
    }
    let mut g = generation.clone();
    exact(&mut g);
    w.finish(&b.catalog, &g).await.unwrap();
    let heads = s.heads().await;
    assert_eq!((heads.len(), heads[0].1), (1, PUSHED as usize));
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_in_one_document_is_refused_above_what_it_holds() {
    let s = scene().await;
    let (mut generation, row) = a_generation_for(&s).await;
    let b = &s.rig.bridge;
    let most = SINGLE_RECORD_EXTENTS;
    let rows: Vec<ExtentRow> = (0..=most).map(|seq| nth(&row, seq)).collect();
    generation.extent_count = most + 1;
    generation.size = u64::from(most + 1) * row.plain_size;
    let before = b.safety.puts.borrow().len();
    let refused = write_generation(
        &b.catalog,
        &b.safety,
        &b.kek,
        &b.cfg.records,
        &s.bucket,
        &generation,
        &rows,
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(b.safety.puts.borrow().len(), before, "nothing was stored");
    assert!(records(&s.rig).is_empty());

    // What one document holds is taken.
    generation.extent_count = most;
    generation.size = u64::from(most) * row.plain_size;
    let recorded = write_generation(
        &b.catalog,
        &b.safety,
        &b.kek,
        &b.cfg.records,
        &s.bucket,
        &generation,
        &rows[..most as usize],
    )
    .await;
    assert!(recorded.is_ok());
    assert_eq!(records(&s.rig).len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn sliced_parts_without_their_stamp_get_no_head() {
    let s = scene().await;
    // Parts that were stored and answered `503`: the stamp was not
    // raised. The client takes them from ListParts.
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
    let mut listed = Vec::new();
    let mut whole = Vec::new();
    for n in 1..=2u16 {
        let bytes = body(n as u8, PART);
        s.send_part(n, &bytes).await.expect_error(503, "SlowDown");
        listed.push((n, md5_etag(&bytes)));
        whole.extend(bytes);
    }
    assert!(stamps(&s.rig).is_empty());

    // 20 extents: a record in segments. Without the stamp there is no
    // head and nothing is published; the client is told to come back.
    let resp = s.complete(&listed).await;
    expect_error_document(&resp, "SlowDown");
    assert!(records(&s.rig).is_empty(), "no head before the stamp");
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(s.rig.bridge.budget.in_use(), 0);

    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert_eq!(stamps(&s.rig).len(), 1);
    assert!(s.read().await.body == whole);
    let heads = s.heads().await;
    assert_eq!((heads.len(), heads[0].1), (1, 20));
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_that_outgrows_one_document_during_a_complete_is_published_in_one() {
    // 8 extents: counted as one document. A part that comes in at any
    // call of the Complete makes the upload 9. The request lists the
    // 8 it began with, so its record is one document whatever the
    // upload holds by then: it is not refused as too large and it
    // writes no segment.
    let bytes = body(1, 8 * SLICE_HALF);
    let total = {
        let s = scene().await;
        let listed = [s.part(1, &bytes).await];
        let before = s.rig.trip().calls();
        s.complete(&listed).await.expect(200);
        s.rig.trip().calls() - before
    };
    for skip in 0..total {
        let s = scene().await;
        let listed = [s.part(1, &bytes).await];
        let ran = run_until(&s.rig, s.complete(&listed), skip, Trip::Stall).await;
        let running = ran.stalled();
        s.rig.trip().disarm();
        s.part(2, &body(2, 100)).await;
        let resp = resume(&s.rig, running).await;
        let what = format!("call {skip}: {} {}", resp.status, resp.text());
        assert!(!failed(&resp), "{what}");
        assert!(s.segments().is_empty(), "{what}");
        assert_eq!(records(&s.rig).len(), 1, "{what}");
        assert!(s.read().await.body == bytes, "{what}");
        assert_eq!(s.rig.bridge.budget.in_use(), 0, "{what}");
    }
}

/// Stores part 1 again as a later version would: the same bytes and
/// ETag, in new extents, one more of them (the last is in two). The
/// new ones are named outside what an id is minted as.
fn store_again_in_one_more_extent(rig: &Rig) {
    sql(
        rig,
        "CREATE TEMP TABLE again AS SELECT * FROM extents WHERE id IN
           (SELECT extent_id FROM upload_parts UNION SELECT extent_id FROM upload_part_extents);
         UPDATE again SET id = 'x_zz' || substr(id, 5);
         INSERT INTO extents SELECT * FROM again;
         UPDATE upload_parts SET extent_id = 'x_zz' || substr(extent_id, 5);
         UPDATE upload_part_extents SET extent_id = 'x_zz' || substr(extent_id, 5);
         DELETE FROM again WHERE id NOT IN
           (SELECT extent_id FROM upload_part_extents WHERE piece = 7);
         UPDATE again SET id = 'x_yy' || substr(id, 5), plain_size = plain_size / 2;
         UPDATE extents SET plain_size = plain_size / 2 WHERE id IN
           (SELECT extent_id FROM upload_part_extents WHERE piece = 7);
         INSERT INTO extents SELECT * FROM again;
         INSERT INTO upload_part_extents (upload_id, part_number, piece, extent_id)
           SELECT upload_id, part_number, 8, 'x_yy' || substr(extent_id, 5)
             FROM upload_part_extents WHERE piece = 7;
         UPDATE uploads SET revision = revision + 1;
         DROP TABLE again;",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn only_a_charged_complete_stores_segments() {
    // 8 extents: counted as one document, so the request holds no
    // charge. At any call of it the listed part is stored again with
    // the same ETag in 9 extents (a version with a smaller slice took
    // the client's retry), and the next attempt of the Complete accepts
    // it by its ETag. Its record would be segments: the request is told
    // to come back, and the one sent again is charged for them.
    let bytes = body(1, 8 * SLICE_HALF);
    let total = {
        let s = scene().await;
        let listed = [s.part(1, &bytes).await];
        let before = s.rig.trip().calls();
        s.complete(&listed).await.expect(200);
        s.rig.trip().calls() - before
    };
    let charge = velmora_bridge::config::COMPLETE_CHARGE_BYTES;
    let mut sent_back = 0;
    for skip in 0..total {
        let s = scene().await;
        let listed = [s.part(1, &bytes).await];
        assert!(s.rig.bridge.budget.peak() < charge);
        let ran = run_until(&s.rig, s.complete(&listed), skip, Trip::Stall).await;
        let running = ran.stalled();
        s.rig.trip().disarm();
        store_again_in_one_more_extent(&s.rig);
        let resp = resume(&s.rig, running).await;
        let what = format!("call {skip}: {} {}", resp.status, resp.text());
        if s.rig.bridge.budget.peak() < charge {
            // Not charged: nothing of a segmented record is stored.
            assert!(s.segments().is_empty(), "{what}");
            if records(&s.rig).is_empty() {
                assert_eq!(resp.status, 503, "{what}");
                assert!(resp.text().contains("SlowDown"), "{what}");
                assert_eq!(s.rig.count("generations"), 0, "{what}");
                sent_back += 1;
                let resp = s.complete(&listed).await;
                assert!(!failed(&resp), "{what}: {}", resp.text());
                assert!(s.rig.bridge.budget.peak() >= charge, "{what}");
            } else {
                // The part came after the record of the 8 was stored.
                assert!(!failed(&resp), "{what}");
                continue;
            }
        } else {
            assert!(!failed(&resp), "{what}");
        }
        let heads = s.heads().await;
        assert_eq!((heads.len(), heads[0].1), (1, 9), "{what}");
        assert_eq!(s.rig.bridge.budget.in_use(), 0, "{what}");
    }
    assert!(sent_back > 0, "no attempt met the part stored again");
}

#[tokio::test(flavor = "current_thread")]
async fn without_room_for_its_charge_a_complete_is_told_to_come_back() {
    let cfg = seg_config();
    let rig_budget = ByteBudget::new(COMPLETE_CHARGE_BYTES - 1);
    let rig = rig_with_budget(NoNntp, cfg, rig_budget);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let created = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, KEY),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    let id = created.values("UploadId").remove(0);
    let s = Scene {
        rig,
        bucket,
        signer,
        id,
    };
    let bytes = body(1, PART);
    let listed = [s.part(1, &bytes).await];
    let resp = s.complete_raw(&listed).await;
    assert!(matches!(resp.body, RespBody::Bytes(_)));
    let resp = Resp::collect(resp).await;
    resp.expect_error(503, "SlowDown");
    assert!(s.segments().is_empty() && records(&s.rig).is_empty());
    assert_eq!(s.rig.count("generations"), 0);
    // An object within one document is not charged, and is published.
    let small = body(2, 4 * MIB);
    let listed = [s.part(1, &small).await];
    s.complete(&listed).await.expect(200);
    assert!(s.read().await.body == small);
}

#[tokio::test(flavor = "current_thread")]
async fn the_host_gets_a_turn_for_its_timers_after_each_run_of_parts() {
    // The window after which the answer is streamed, and the keepalive
    // of the stream, are timers of the host. The read gives it a turn
    // after every run of part numbers.
    let slept = Rc::new(std::cell::RefCell::new(Vec::new()));
    let log = Rc::clone(&slept);
    let sleeper: Sleeper = Rc::new(move |ms| {
        log.borrow_mut().push(ms);
        Box::pin(tokio::task::yield_now())
    });
    let budget = ByteBudget::new(2 * COMPLETE_CHARGE_BYTES).with_sleeper(sleeper);
    let rig = rig_with_budget(NoNntp, seg_config(), budget);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let created = rig
        .call(
            &signer,
            Method::Post,
            &path(BUCKET, KEY),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    let id = created.values("UploadId").remove(0);
    let s = Scene {
        rig,
        bucket,
        signer,
        id,
    };
    // Parts 1, 300 and 700: three runs of 256 part numbers.
    let (listed, whole) = three_parts(&s).await;
    slept.borrow_mut().clear();
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert_eq!(*slept.borrow(), [0, 0, 0]);
    assert!(s.read().await.body == whole);
}

// ---------------------------------------------------------------------------
// A failure once the answer has begun
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_failure_after_the_headers_is_an_error_document() {
    let s = scene().await;
    let bytes = body(1, PART);
    let listed = [s.part(1, &bytes).await];
    // The head cannot be stored: 10 extents are two segments of 4 that
    // are, and one of 2.
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/g_".into());
    let resp = s.complete(&listed).await;
    expect_error_document(&resp, "InternalError");
    assert_eq!(s.segments().len(), 3);
    assert!(records(&s.rig).is_empty(), "no head");
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(s.rig.bridge.jobs.inner.calls(), 0);
    assert_eq!(s.read().await.status, 404);
    assert_eq!(s.rig.bridge.budget.in_use(), 0);

    // The upload is open: the same request publishes it, under segments
    // of its own.
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert_eq!(s.segments().len(), 6);
    let heads = s.heads().await;
    assert_eq!((heads.len(), heads[0].1), (1, 10));
    assert!(s.read().await.body == bytes);
}

#[tokio::test(flavor = "current_thread")]
async fn a_slow_complete_is_kept_alive_and_then_answered() {
    // Once with the document of a publication, once with the error of
    // a head that is not stored.
    for fails in [false, true] {
        let s = scene().await;
        let bytes = body(1, PART);
        let listed = [s.part(1, &bytes).await];
        *s.rig.bridge.safety.hold_put_prefix.borrow_mut() = Some("m/seg/".into());
        if fails {
            *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("m/g_".into());
        }
        let mut body = deferred(s.complete_raw(&listed).await).into_stream(quick_ticks(), 5_000);
        assert_eq!(body.next().await.unwrap().unwrap(), XML_DECLARATION);
        for _ in 0..3 {
            assert_eq!(body.next().await.unwrap().unwrap(), KEEPALIVE_BYTE);
        }
        assert!(s.rig.bridge.safety.held.get());
        assert!(s.segments().is_empty());
        assert_eq!(s.rig.bridge.budget.in_use(), COMPLETE_CHARGE_BYTES);
        *s.rig.bridge.safety.hold_put_prefix.borrow_mut() = None;

        let mut rest = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.unwrap();
            if chunk != KEEPALIVE_BYTE {
                rest.extend(chunk);
            }
        }
        let text = String::from_utf8(rest).unwrap();
        assert_eq!(s.rig.bridge.budget.in_use(), 0);
        if fails {
            assert!(
                text.starts_with("<Error><Code>InternalError</Code>"),
                "{text}"
            );
            assert!(text.ends_with("</Error>"), "{text}");
            assert!(records(&s.rig).is_empty());
            assert_eq!(s.read().await.status, 404);
        } else {
            assert!(text.starts_with("<CompleteMultipartUploadResult"), "{text}");
            assert!(text.ends_with("</CompleteMultipartUploadResult>"), "{text}");
            assert!(s.read().await.body == bytes);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_client_that_goes_away_does_not_stop_the_publication() {
    let s = scene().await;
    let bytes = body(1, PART);
    let listed = [s.part(1, &bytes).await];
    // The work runs apart from the body, as the Worker runs it.
    let mut answer = deferred(s.complete_raw(&listed).await);
    let work = answer.take_work().expect("the work is there once");
    drop(answer);
    assert_eq!(s.rig.count("generations"), 0);
    work.await;
    assert_eq!(s.rig.count("generations"), 1);
    assert_eq!(s.rig.bridge.budget.in_use(), 0);
    assert!(s.read().await.body == bytes);
    // The client asks again and is answered from the receipt.
    let again = s.complete_raw(&listed).await;
    assert!(matches!(again.body, RespBody::Bytes(_)));
    assert_eq!(again.status, 200);

    // Work that is dropped (the isolate ended): the body ends with an
    // error document, and the upload is as the work left it.
    let s = scene().await;
    let listed = [s.part(1, &bytes).await];
    let mut answer = deferred(s.complete_raw(&listed).await);
    drop(answer.take_work());
    let (text, _) = read_stream(answer.into_stream(quick_ticks(), 5_000)).await;
    assert!(
        text.starts_with("<Error><Code>InternalError</Code>"),
        "{text}"
    );
    assert_eq!(s.rig.bridge.budget.in_use(), 0);
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert!(s.read().await.body == bytes);
}

#[tokio::test(flavor = "current_thread")]
async fn a_segment_that_is_not_stored_leaves_no_head() {
    // Each segment in turn, and then the head.
    for k in 0..=3usize {
        let s = scene().await;
        let bytes = body(1, PART);
        let listed = [s.part(1, &bytes).await];
        // Which call of the Complete put `k` of the record is: the
        // request is stopped at it.
        let before = s.rig.trip().calls();
        let stopped = step_to(&s.rig, s.complete(&listed), |rig| {
            let puts = rig.bridge.safety.puts.borrow();
            puts.iter().filter(|(key, _)| key.starts_with("m/")).count() == k + 1
        })
        .await;
        let skip = s.rig.trip().calls() - before - 1;
        drop(stopped.stalled());

        for trip in [Trip::Fail, Trip::Lost] {
            let mut s = scene().await;
            let listed = [s.part(1, &bytes).await];
            s.rig.bridge.safety.puts.borrow_mut().clear();
            s.rig.trip().arm(skip, trip);
            let resp = s.complete(&listed).await;
            assert!(s.rig.trip().tripped(), "{k} {trip:?}");
            // The call that failed was that put, the last one sent.
            let sent = (s.rig.bridge.safety.puts.borrow().iter())
                .filter(|(key, _)| key.starts_with("m/"))
                .count();
            assert_eq!(sent, k + 1, "{k} {trip:?}");
            let what = format!("put {k} {trip:?}: {}", resp.text());
            if k < 3 || trip == Trip::Fail {
                // A segment that may not be stored: no head is written
                // over it. A head that was not stored: none.
                expect_error_document(&resp, "InternalError");
                assert!(records(&s.rig).is_empty(), "{what}");
            } else {
                // The head was stored and the store did not say so:
                // the request fails, and the record is whole.
                expect_error_document(&resp, "InternalError");
                assert_eq!(s.heads().await.len(), 1, "{what}");
            }
            assert_eq!(s.rig.count("generations"), 0, "{what}");
            assert_eq!(s.read().await.status, 404, "{what}");

            // The request again publishes the upload.
            let resp = s.complete(&listed).await;
            assert!(!failed(&resp), "{what}");
            assert!(s.read().await.body == bytes, "{what}");
            for (_, named) in s.heads().await {
                assert_eq!(named, 10, "{what}");
            }
            // A restore ends with the object, whichever records it met.
            restore(&mut s.rig).await;
            assert!(s.read().await.body == bytes, "{what}");
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_fault_at_any_call_leaves_a_head_only_over_its_segments() {
    let bytes = body(1, PART);
    // How many calls a Complete makes.
    let total = {
        let s = scene().await;
        let listed = [s.part(1, &bytes).await];
        let before = s.rig.trip().calls();
        assert!(!failed(&s.complete(&listed).await));
        s.rig.trip().calls() - before
    };
    assert!(total > 12, "{total}");
    let mut failures = 0;
    for skip in 0..total {
        for trip in [Trip::Fail, Trip::Lost] {
            let mut s = scene().await;
            let listed = [s.part(1, &bytes).await];
            s.rig.trip().arm(skip, trip);
            let resp = s.complete(&listed).await;
            let what = format!("call {skip} {trip:?}: {} {}", resp.status, resp.text());
            assert!(s.rig.trip().tripped(), "{what}");
            // Every head there is names segments that are stored, all
            // of them: `heads` reads them.
            let heads = s.heads().await;
            let live = s.rig.live(&s.bucket, KEY).await;
            if failed(&resp) {
                failures += 1;
                if trip == Trip::Fail {
                    // The call did nothing: nothing is published, and
                    // no record says otherwise.
                    assert!(live.is_none(), "{what}");
                    assert!(heads.is_empty(), "{what}");
                }
            } else {
                assert!(live.is_some(), "{what}");
            }
            if let Some((generation, rows)) = &live {
                // A generation has its record.
                assert!(
                    heads
                        .iter()
                        .any(|(h, n)| h.generation.id == generation.id.as_str()
                            && *n == rows.len()),
                    "{what}"
                );
            }
            assert_eq!(s.rig.bridge.budget.in_use(), 0, "{what}");

            // The client sends the request again, and reads the object.
            let again = s.complete(&listed).await;
            assert!(!failed(&again), "{what}: then {}", again.text());
            assert!(s.read().await.body == bytes, "{what}");
            let (generation, _) = s.rig.live(&s.bucket, KEY).await.unwrap();
            for (_, named) in s.heads().await {
                assert_eq!(named, 10, "{what}");
            }
            // A restore publishes the object the client was told of,
            // or a later copy of the same bytes; never less.
            restore(&mut s.rig).await;
            assert!(s.read().await.body == bytes, "{what}");
            let (restored, _) = s.rig.live(&s.bucket, KEY).await.unwrap();
            assert!(restored.id >= generation.id, "{what}");
        }
    }
    assert!(failures > 12, "{failures}");
}

// ---------------------------------------------------------------------------
// The upload moves while its extents are read
// ---------------------------------------------------------------------------

/// A Complete of [`three_parts`], stopped when `n` segments are stored.
async fn stopped_at<'a>(s: &'a Scene, listed: &'a [(u16, String)], n: usize) -> Running<'a, Resp> {
    step_to(&s.rig, s.complete(listed), |rig| {
        keys_under(rig, "m/seg/").len() == n
    })
    .await
    .stalled()
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_replaced_during_the_read_is_not_published() {
    // After the first segment (the read has two more runs to go), and
    // after the last full one (every run is read; the head is next).
    for at in [1usize, 5] {
        let s = scene().await;
        let (mut listed, whole) = three_parts(&s).await;
        let running = stopped_at(&s, &listed, at).await;

        s.rig.trip().disarm();
        let other = body(8, SLICE_HALF + 9);
        let replaced = s.part(700, &other).await;

        let resp = resume(&s.rig, running).await;
        // The upload no longer holds the parts as they were listed.
        expect_error_document(&resp, "InvalidPart");
        assert!(records(&s.rig).is_empty(), "{at}: no head");
        assert_eq!(s.rig.count("generations"), 0, "{at}");
        assert_eq!(s.read().await.status, 404, "{at}");
        assert_eq!(s.rig.bridge.jobs.inner.calls(), 0, "{at}");

        // The upload is open, with the part the client sent last.
        listed[2] = replaced;
        let resp = s.complete(&listed).await;
        assert!(!failed(&resp), "{at}: {}", resp.text());
        let mut expected = whole[..2 * PART].to_vec();
        expected.extend_from_slice(&other);
        assert!(s.read().await.body == expected, "{at}");
        let heads = s.heads().await;
        assert_eq!((heads.len(), heads[0].1), (1, 21), "{at}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_added_during_the_read_gets_a_new_attempt() {
    let s = scene().await;
    let (listed, whole) = three_parts(&s).await;
    let running = stopped_at(&s, &listed, 5).await;

    // A part the request does not list: the upload moved, so no head
    // is stored for what was read, and the next attempt reads again.
    s.rig.trip().disarm();
    s.part(400, &body(8, 100)).await;
    assert!(records(&s.rig).is_empty());

    let resp = resume(&s.rig, running).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert!(s.read().await.body == whole);
    let heads = s.heads().await;
    assert_eq!((heads.len(), heads[0].1), (1, 21));
    // The head names the segments of the second attempt; the five of
    // the first are under another set and are named by nothing.
    let set = &heads[0].0.set;
    let (own, other): (Vec<String>, Vec<String>) = s
        .segments()
        .into_iter()
        .partition(|key| key.contains(set.as_str()));
    assert_eq!((own.len(), other.len()), (6, 5));
    assert_eq!(s.rig.bridge.jobs.inner.calls(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_abort_during_the_read_wins() {
    for at in [1usize, 5] {
        let s = scene().await;
        let (listed, _) = three_parts(&s).await;
        let running = stopped_at(&s, &listed, at).await;

        s.rig.trip().disarm();
        s.abort().await.expect(204);

        let resp = resume(&s.rig, running).await;
        expect_error_document(&resp, "NoSuchUpload");
        assert!(records(&s.rig).is_empty(), "{at}: no head");
        assert_eq!(s.rig.count("generations"), 0, "{at}");
        assert_eq!(s.read().await.status, 404, "{at}");
        assert_eq!(s.rig.bridge.jobs.inner.calls(), 0, "{at}");
        assert_eq!(s.rig.bridge.budget.in_use(), 0, "{at}");
        // Nothing reads the segments that were stored: a restore finds
        // no object.
        let mut s = s;
        restore(&mut s.rig).await;
        assert_eq!(s.read().await.status, 404, "{at}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_client_that_stops_reading_leaves_a_whole_answer_for_the_next() {
    // The handler is dropped after the head is stored and before the
    // batch: the record is there, the generation is not.
    let s = scene().await;
    let bytes = body(1, PART);
    let listed = [s.part(1, &bytes).await];
    let stopped = step_to(&s.rig, s.complete(&listed), |rig| !records(rig).is_empty()).await;
    drop(stopped.stalled());
    s.rig.trip().disarm();
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(s.heads().await.len(), 1);

    // The request again publishes the upload under a later id.
    let resp = s.complete(&listed).await;
    assert!(!failed(&resp), "{}", resp.text());
    assert!(s.read().await.body == bytes);
    let (generation, _) = s.rig.live(&s.bucket, KEY).await.unwrap();
    let heads = s.heads().await;
    assert_eq!(heads.len(), 2);
    assert!(heads
        .iter()
        .all(|(h, n)| *n == 10 && h.generation.id.as_str() <= generation.id.as_str()));
    let mut s = s;
    restore(&mut s.rig).await;
    assert!(s.read().await.body == bytes);
    assert_eq!(
        s.rig.live(&s.bucket, KEY).await.unwrap().0.id,
        generation.id
    );
}
