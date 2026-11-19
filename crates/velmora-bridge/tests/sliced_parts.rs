//! UploadPart above one extent: the part is stored in slices, the object
//! reads back whole, and nothing of a part that was refused, replaced,
//! aborted or lost is left behind.

mod intent_support;
mod service_support;

use intent_support::*;
use service_support::*;
use velmora_bridge::*;

const SLICE_8M: usize = 8 * MIB;
const KEY: &str = "big";
const DAY_MS: i64 = 25 * HOUR_MS;

/// Production limits: one extent up to 16 MiB, slices of 8 MiB, bodies
/// up to 99 MiB.
fn big_rig() -> Rig {
    let mut cfg = config(Vec::new());
    cfg.max_put_bytes = 99 * MIB as u64;
    cfg.intent_sweep = true;
    rig_with(NoNntp, cfg)
}

/// A body whose slices all differ: the seed picks the byte of the
/// pattern with the longest period.
fn body(seed: u8, len: usize) -> Vec<u8> {
    pattern(4 * seed + 3, len)
}

async fn create(rig: &Rig, signer: &Signer, key: &str) -> String {
    let created = rig
        .call(
            signer,
            Method::Post,
            &path(BUCKET, key),
            &[("uploads", "")],
            &[],
            b"",
        )
        .await;
    created.expect(200);
    created.values("UploadId").remove(0)
}

fn part_req(rig: &Rig, signer: &Signer, id: &str, n: u16, bytes: &[u8], mode: Mode) -> Req {
    let n = n.to_string();
    mode_req_at(
        rig,
        signer,
        KEY,
        &[("partNumber", &n), ("uploadId", id)],
        bytes,
        mode,
    )
}

async fn send_part(rig: &Rig, signer: &Signer, id: &str, n: u16, bytes: &[u8]) -> Resp {
    rig.send(part_req(rig, signer, id, n, bytes, Mode::Literal))
        .await
}

/// Uploads a part and returns its ETag, which is the MD5 of its body.
async fn part(rig: &Rig, signer: &Signer, id: &str, n: u16, bytes: &[u8]) -> String {
    let sent = send_part(rig, signer, id, n, bytes).await;
    assert_eq!(sent.status, 200, "part {n}: {}", sent.text());
    let etag = sent.header("etag").unwrap().to_owned();
    assert_eq!(etag, md5_etag(bytes), "part {n}");
    etag
}

async fn complete(rig: &Rig, signer: &Signer, id: &str, etags: &[String]) -> Resp {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        signer,
        Method::Post,
        &path(BUCKET, KEY),
        &[("uploadId", id)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
}

async fn abort(rig: &Rig, signer: &Signer, id: &str) -> Resp {
    rig.call(
        signer,
        Method::Delete,
        &path(BUCKET, KEY),
        &[("uploadId", id)],
        &[],
        b"",
    )
    .await
}

async fn range(rig: &Rig, signer: &Signer, key: &str, first: usize, last: usize) -> Resp {
    let value = format!("bytes={first}-{last}");
    rig.call(
        signer,
        Method::Get,
        &path(BUCKET, key),
        &[],
        &[("range", &value)],
        b"",
    )
    .await
}

/// The ETag S3 gives a multipart object: the MD5 of the MD5s of its
/// parts, and their number.
fn multipart_etag(parts: &[Vec<u8>]) -> String {
    let md5s: Vec<u8> = parts
        .iter()
        .flat_map(|p| md5::compute(p).0.to_vec())
        .collect();
    format!("\"{:x}-{}\"", md5::compute(&md5s), parts.len())
}

/// How many extents a part of `len` bytes is stored in.
fn pieces(len: usize, extent: usize, slice: usize) -> usize {
    if len <= extent {
        1
    } else {
        len.div_ceil(slice)
    }
}

/// Extents of parts of open uploads, in part and body order.
fn staged(rig: &Rig) -> Vec<String> {
    column(
        rig,
        "SELECT extent_id FROM (SELECT part_number, 0 AS piece, extent_id FROM upload_parts \
         UNION ALL SELECT part_number, piece, extent_id FROM upload_part_extents) \
         ORDER BY part_number, piece",
    )
}

/// Extents with garbage-collection rows.
fn in_gc(rig: &Rig) -> Vec<String> {
    column(rig, "SELECT DISTINCT extent_id FROM gc ORDER BY extent_id")
}

/// Runs garbage collection with everything in it due.
async fn collect(rig: &Rig) {
    rig.bridge.clock.advance_secs(7 * 86_400);
    assert_eq!(
        rig.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// Production sizes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn parts_of_64_and_95_mib_among_small_ones_read_back() {
    let rig = big_rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;

    // 95 MiB first, and what the request was charged: two slices,
    // whatever the length of the part.
    let lens = [
        95 * MIB,
        5 * MIB,
        64 * MIB,
        16 * MIB,
        16 * MIB + 1,
        6 * MIB + 3,
        1000,
    ];
    let modes = [
        Mode::Literal,
        Mode::Unsigned,
        Mode::SignedChunks,
        Mode::Literal,
        Mode::UnsignedTrailer,
        Mode::SignedTrailer,
        Mode::Literal,
    ];
    let mut parts = Vec::new();
    let mut etags = Vec::new();
    for (i, (len, mode)) in lens.into_iter().zip(modes).enumerate() {
        let bytes = body(i as u8, len);
        let n = i as u16 + 1;
        let sent = rig
            .send(part_req(&rig, &signer, &id, n, &bytes, mode))
            .await;
        assert_eq!(sent.status, 200, "part {n} {mode:?}: {}", sent.text());
        assert_eq!(sent.header("etag"), Some(md5_etag(&bytes).as_str()));
        if i == 0 {
            assert_eq!(rig.bridge.budget.peak(), 2 * SLICE_8M as u64);
        }
        assert_eq!(rig.bridge.budget.in_use(), 0);
        etags.push(md5_etag(&bytes));
        parts.push(bytes);
    }
    assert!(intents(&rig).is_empty(), "every part took its intents");
    assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
    assert!(records(&rig).is_empty(), "no record before Complete");
    // One stamp per part above one extent.
    assert_eq!(stamps(&rig).len(), 3);
    assert!(rig.bridge.jobs.inner.take().is_empty(), "nothing is posted");

    // ListParts gives the size and the ETag of the whole part.
    let listed = rig
        .call(
            &signer,
            Method::Get,
            &path(BUCKET, KEY),
            &[("uploadId", &id)],
            &[],
            b"",
        )
        .await;
    listed.expect(200);
    let sizes: Vec<String> = lens.iter().map(|l| l.to_string()).collect();
    assert_eq!(listed.values("Size"), sizes);
    let quoted: Vec<String> = etags.iter().map(|e| e.replace('"', "&quot;")).collect();
    assert_eq!(listed.values("ETag"), quoted);

    let done = complete(&rig, &signer, &id, &etags).await;
    done.expect(200);
    let etag = multipart_etag(&parts);
    assert_eq!(
        done.values("ETag"),
        [etag.replace('"', "&quot;")],
        "the ETag is that of the parts, not of the extents"
    );

    let whole = parts.concat();
    let (generation, extents) = rig.live(&bucket, KEY).await.unwrap();
    assert_eq!(generation.size, whole.len() as u64);
    assert_eq!(generation.etag, etag);
    let mut expected = Vec::new();
    for len in lens {
        if len <= 16 * MIB {
            expected.push(len as u64);
        } else {
            expected.extend(vec![SLICE_8M as u64; len / SLICE_8M]);
            if len % SLICE_8M != 0 {
                expected.push((len % SLICE_8M) as u64);
            }
        }
    }
    let got: Vec<u64> = extents.iter().map(|e| e.plain_size).collect();
    assert_eq!(got, expected);
    assert_eq!(extents.len(), 12 + 1 + 8 + 1 + 3 + 1 + 1);
    assert_eq!(records(&rig), [generation.id.as_str().to_string()]);
    assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
    assert!(in_gc(&rig).is_empty());
    // One posting job per extent.
    assert_eq!(rig.bridge.jobs.inner.take().len(), extents.len());

    let head = rig.head(&signer, BUCKET, KEY).await;
    head.expect(200);
    assert_eq!(
        head.header("content-length"),
        Some(whole.len().to_string().as_str())
    );
    assert_eq!(head.header("etag"), Some(etag.as_str()));
    let read = get(&rig, &signer, KEY).await;
    read.expect(200);
    assert_eq!(sha256(&read.body), sha256(&whole));
    drop(read);

    // Ranges over the boundary of two slices, of two parts, of a large
    // part and a small one, and to the end.
    let p1 = lens[0];
    let p3 = lens[0] + lens[1];
    let p5 = p3 + lens[2] + lens[3];
    let spans = [
        (SLICE_8M - 10, SLICE_8M + 10),
        (11 * SLICE_8M - 1, p1 + 1),
        (p1 - 1, p1),
        (p3 - 3, p3 + 2 * SLICE_8M + 3),
        (p5 + SLICE_8M - 2, p5 + 2 * SLICE_8M + 2),
        (whole.len() - 1001, whole.len() - 1),
        (p1 - SLICE_8M - 7, p5 + 5),
    ];
    for (first, last) in spans {
        let got = range(&rig, &signer, KEY, first, last).await;
        got.expect(206);
        assert!(got.body == whole[first..=last], "bytes {first}-{last}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_limit_of_a_part_is_that_of_a_put_and_one_extent_is_stored_as_before() {
    let rig = big_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;

    // One byte above the limit is refused from the headers alone.
    for mode in MODES {
        let req = declared_req_at(
            &rig,
            &signer,
            KEY,
            &[("partNumber", "1"), ("uploadId", &id)],
            99 * MIB as u64 + 1,
            mode,
        );
        let (r, polled) = rig.send_watched(req).await;
        r.expect_error(400, "EntityTooLarge");
        assert!(!polled, "{mode:?}: the body was read");
    }
    assert_eq!(rig.count("write_intents"), 0);
    assert!(blobs(&rig).is_empty() && staged(&rig).is_empty());

    // A part of exactly one extent takes the path it always took: no
    // statement of the request names `write_intents`, and no stamp is
    // raised.
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("write_intents", 0));
    let one = body(1, 16 * MIB);
    part(&rig, &signer, &id, 1, &one).await;
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
    assert_eq!(staged(&rig).len(), 1);
    assert_eq!(rig.count("upload_part_extents"), 0);
    assert!(stamps(&rig).is_empty());
    assert_eq!(rig.bridge.budget.peak(), 2 * 16 * MIB as u64);

    // Where no body is sliced, a part stays at one extent.
    let mut cfg = config(Vec::new());
    cfg.intent_sweep = true;
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;
    let req = declared_req_at(
        &rig,
        &signer,
        KEY,
        &[("partNumber", "1"), ("uploadId", &id)],
        16 * MIB as u64 + 1,
        Mode::Literal,
    );
    let (r, polled) = rig.send_watched(req).await;
    r.expect_error(400, "EntityTooLarge");
    assert!(!polled);
}

#[tokio::test(flavor = "current_thread")]
async fn an_object_of_sliced_parts_comes_back_after_the_catalogue_is_lost() {
    let mut rig = big_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;
    let parts = [
        body(1, 17 * MIB),
        body(2, 5 * MIB),
        body(3, 3 * SLICE_8M + 5),
        body(4, 77),
    ];
    let mut etags = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        etags.push(part(&rig, &signer, &id, i as u16 + 1, p).await);
    }
    complete(&rig, &signer, &id, &etags).await.expect(200);
    let whole = parts.concat();
    let digest = sha256(&whole);
    let etag = multipart_etag(&parts);

    // A second upload is still open, with a sliced part.
    let open = create(&rig, &signer, KEY).await;
    part(&rig, &signer, &open, 1, &body(5, 17 * MIB)).await;
    let all = blobs(&rig);

    // The catalogue is lost and replayed from the recovery records.
    sql(
        &rig,
        "PRAGMA foreign_keys = OFF; \
         DELETE FROM upload_part_extents; DELETE FROM upload_parts; DELETE FROM uploads; \
         DELETE FROM outbox; DELETE FROM generation_extents; DELETE FROM extents; \
         DELETE FROM objects; DELETE FROM generations; DELETE FROM key_floors; \
         PRAGMA foreign_keys = ON;",
    );
    get(&rig, &signer, KEY).await.expect_error(404, "NoSuchKey");
    restore(&mut rig).await;

    let head = rig.head(&signer, BUCKET, KEY).await;
    head.expect(200);
    assert_eq!(head.header("etag"), Some(etag.as_str()));
    let read = get(&rig, &signer, KEY).await;
    read.expect(200);
    assert_eq!(read.body.len(), whole.len());
    assert_eq!(sha256(&read.body), digest);
    let first = 17 * MIB + 5 * MIB + SLICE_8M - 9;
    let got = range(&rig, &signer, KEY, first, first + 20).await;
    got.expect(206);
    assert!(got.body == whole[first..=first + 20]);
    assert!(broken(&rig).is_empty());
    // The open upload is not in any record: it is gone, and its part
    // has to be sent again. Its blobs stay where they are.
    send_part(&rig, &signer, &open, 2, b"x")
        .await
        .expect_error(404, "NoSuchUpload");
    assert_eq!(blobs(&rig), all);
}

#[tokio::test(flavor = "current_thread")]
async fn a_range_of_an_object_of_sliced_parts_is_copied_into_a_part() {
    let rig = big_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;
    let parts = [body(1, 20 * MIB), body(2, 18 * MIB), body(3, 9)];
    let mut etags = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        etags.push(part(&rig, &signer, &id, i as u16 + 1, p).await);
    }
    complete(&rig, &signer, &id, &etags).await.expect(200);
    let whole = parts.concat();

    // Over two slices of the first part, over the boundary of the two
    // parts, and the tail.
    let spans = [
        (SLICE_8M - 3 * MIB, SLICE_8M + 3 * MIB - 1),
        (20 * MIB - 4 * MIB, 20 * MIB + 9 * MIB),
        (38 * MIB - 6, 38 * MIB + 8),
    ];
    let source = format!("/{BUCKET}/{KEY}");
    let copy = create(&rig, &signer, "copy").await;
    let mut copied = Vec::new();
    for (i, (first, last)) in spans.into_iter().enumerate() {
        let n = (i + 1).to_string();
        let value = format!("bytes={first}-{last}");
        let r = rig
            .call(
                &signer,
                Method::Put,
                &path(BUCKET, "copy"),
                &[("partNumber", &n), ("uploadId", &copy)],
                &[
                    ("x-amz-copy-source", &source),
                    ("x-amz-copy-source-range", &value),
                ],
                b"",
            )
            .await;
        r.expect(200);
        let etag = r.values("ETag").remove(0).replace("&quot;", "\"");
        assert_eq!(etag, md5_etag(&whole[first..=last]));
        copied.push(etag);
    }
    // A copied part stays at one extent.
    let r = rig
        .call(
            &signer,
            Method::Put,
            &path(BUCKET, "copy"),
            &[("partNumber", "4"), ("uploadId", &copy)],
            &[
                ("x-amz-copy-source", &source),
                ("x-amz-copy-source-range", "bytes=0-16777216"),
            ],
            b"",
        )
        .await;
    r.expect_error(400, "EntityTooLarge");

    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in copied.iter().enumerate() {
        xml.push_str(&format!(
            "<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
            i + 1
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    rig.call(
        &signer,
        Method::Post,
        &path(BUCKET, "copy"),
        &[("uploadId", &copy)],
        &[("content-type", "application/xml")],
        xml.as_bytes(),
    )
    .await
    .expect(200);
    let expected: Vec<u8> = spans
        .iter()
        .flat_map(|(first, last)| whole[*first..=*last].to_vec())
        .collect();
    let read = get(&rig, &signer, "copy").await;
    read.expect(200);
    assert_eq!(sha256(&read.body), sha256(&expected));
    assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
}

// ---------------------------------------------------------------------------
// The same path with small limits
// ---------------------------------------------------------------------------

/// A small rig with one open upload.
struct Setup {
    rig: Rig,
    signer: Signer,
    id: String,
}

async fn setup_with(cfg: config::BridgeConfig) -> Setup {
    let rig = rig_with(NoNntp, cfg);
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;
    rig.bridge.clock.advance_ms(1000);
    Setup { rig, signer, id }
}

async fn setup() -> Setup {
    setup_with(small_config()).await
}

impl Setup {
    async fn part(&self, n: u16, bytes: &[u8]) -> String {
        part(&self.rig, &self.signer, &self.id, n, bytes).await
    }

    /// An UploadPart of part 1, not yet started.
    fn start(&self, bytes: &[u8]) -> Running<'static, Resp> {
        let req = part_req(&self.rig, &self.signer, &self.id, 1, bytes, Mode::Literal);
        start(&self.rig, req)
    }

    async fn complete(&self, etags: &[String]) -> Resp {
        complete(&self.rig, &self.signer, &self.id, etags).await
    }

    async fn read(&self) -> Vec<u8> {
        get(&self.rig, &self.signer, KEY)
            .await
            .expect(200)
            .body
            .clone()
    }

    /// Runs the sweep until a tick finds nothing to do.
    async fn sweep_out(&self) {
        for _ in 0..4 {
            if sweep_tick(&self.rig).await == 0 {
                return;
            }
        }
        panic!("the sweep does not come to an end");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_mode_and_every_cut_of_a_part_reads_back() {
    let lens = [EXTENT + 1, 3 * SLICE - 1, 3 * SLICE, 3 * SLICE + 1, MAX_PUT];
    let mut seed = 0;
    for mode in MODES {
        for len in lens {
            seed += 1;
            let s = setup().await;
            let bytes = body(seed, len);
            let req = part_req(&s.rig, &s.signer, &s.id, 1, &bytes, mode);
            let sent = send_in_pieces(&s.rig, req, 1000).await;
            assert_eq!(sent.status, 200, "{mode:?} {len}: {}", sent.text());
            let etag = md5_etag(&bytes);
            assert_eq!(sent.header("etag"), Some(etag.as_str()));
            assert_eq!(s.rig.bridge.budget.peak(), 2 * SLICE as u64);
            assert_eq!(staged(&s.rig).len(), len.div_ceil(SLICE), "{mode:?} {len}");
            assert!(intents(&s.rig).is_empty());

            s.complete(&[etag]).await.expect(200);
            assert!(s.read().await == bytes, "{mode:?} {len}");
            assert!(orphans(&s.rig).is_empty() && broken(&s.rig).is_empty());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_sent_again_replaces_every_slice_of_the_earlier_one() {
    let s = setup().await;
    // Five slices, two, one extent, three: each replaces the one before.
    let lens = [5 * SLICE, 2 * SLICE - 1, EXTENT, 3 * SLICE];
    let mut replaced: Vec<String> = Vec::new();
    let mut last = Vec::new();
    for (i, len) in lens.into_iter().enumerate() {
        let before = staged(&s.rig);
        let bytes = body(i as u8, len);
        s.part(1, &bytes).await;
        replaced.extend(before);
        let now = staged(&s.rig);
        assert_eq!(now.len(), pieces(len, EXTENT, SLICE), "{len}");
        assert_eq!(
            s.rig.count("upload_part_extents") as usize,
            now.len() - 1,
            "{len}"
        );
        // What was replaced is in garbage collection, and nothing else.
        assert_eq!(in_gc(&s.rig), sorted(replaced.clone()), "{len}");
        assert_eq!(s.rig.count("upload_parts"), 1);
        last = bytes;
    }
    // A second part, so that the first is checked against its size.
    let tail = body(9, 2 * SLICE + 1);
    let etags = [md5_etag(&last), s.part(2, &tail).await];
    // Part 1 is below the smallest part S3 allows before the last.
    s.complete(&etags).await.expect_error(400, "EntityTooSmall");
    s.complete(&etags[..1]).await.expect(200);
    assert!(s.read().await == last);
    // The part that was not listed went to garbage collection too.
    assert_eq!(in_gc(&s.rig).len(), replaced.len() + 3);
    assert!(broken(&s.rig).is_empty() && intents(&s.rig).is_empty());

    // Garbage collection deletes what was replaced and nothing of the
    // object.
    collect(&s.rig).await;
    assert_eq!(blobs(&s.rig).len(), 3);
    assert!(s.read().await == last);
}

#[tokio::test(flavor = "current_thread")]
async fn abort_sends_every_slice_to_garbage_collection() {
    let s = setup().await;
    s.part(1, &body(1, 4 * SLICE + 1)).await;
    s.part(2, &body(2, 100)).await;
    s.part(3, &body(3, 3 * SLICE)).await;
    let all = sorted(staged(&s.rig));
    assert_eq!(all.len(), 5 + 1 + 3);
    assert_eq!(blobs(&s.rig).len(), 9);
    assert!(in_gc(&s.rig).is_empty());

    assert_eq!(s.rig.count("upload_part_extents"), 4 + 2);
    abort(&s.rig, &s.signer, &s.id).await.expect(204);
    assert_eq!(in_gc(&s.rig), all);
    assert_eq!(
        s.rig.count("upload_part_extents"),
        0,
        "closed: no rows left"
    );
    assert_eq!(s.rig.count("gc"), 18, "two rows per extent");
    s.part_refused().await;

    collect(&s.rig).await;
    assert!(blobs(&s.rig).is_empty(), "every slice is deleted");
    assert_eq!(
        number(
            &s.rig,
            "SELECT COUNT(*) FROM extents WHERE wrapped_file_key IS NOT NULL"
        ),
        0,
        "every key is shredded"
    );
}

impl Setup {
    /// A part sent to the upload after it was closed.
    async fn part_refused(&self) {
        let before = (blobs(&self.rig), staged(&self.rig));
        send_part(&self.rig, &self.signer, &self.id, 1, &body(8, 3 * SLICE))
            .await
            .expect_error(404, "NoSuchUpload");
        assert_eq!((blobs(&self.rig), staged(&self.rig)), before);
        assert!(intents(&self.rig).is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn slices_in_service_are_kept_while_the_upload_is_open() {
    let s = setup().await;
    s.part(1, &body(1, 3 * SLICE)).await;
    let ids = staged(&s.rig);
    // Rows as a wrong collection would leave them: due, for extents of
    // an open upload. Neither the blob nor the key goes.
    for id in &ids {
        sql(
            &s.rig,
            &format!(
                "INSERT INTO gc(extent_id, action, due_at) VALUES ('{id}', 'delete_safety', 0), \
                 ('{id}', 'shred_key', 0)"
            ),
        );
    }
    collect(&s.rig).await;
    assert_eq!(blobs(&s.rig).len(), 3);
    // The triggers refuse a shred of a slice after the first as well;
    // the same for the article rows of a slice whose plan is not
    // packed, and for the plan of one whose plan is.
    let run = |q: String| {
        let db = &s.rig.bridge.catalog.sql;
        db.with_conn(|c| c.execute_batch(&q))
    };
    let refused = |q: &str| {
        let e = run(q.to_owned()).unwrap_err().to_string();
        assert!(e.contains("extent is in service"), "{q}: {e}");
    };
    for id in &ids {
        refused(&format!(
            "UPDATE extents SET wrapped_file_key = NULL WHERE id = '{id}'"
        ));
        run(format!(
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
             cipher_offset, cipher_len, payload_sha256, state) \
             VALUES ('{id}', 0, 'm-{id}', 'g', x'00', 0, 1, x'00', 'planned')"
        ))
        .unwrap();
        let rows = format!("DELETE FROM articles WHERE extent_id = '{id}'");
        refused(&rows);
        run(format!("UPDATE extents SET plan = x'00' WHERE id = '{id}'")).unwrap();
        // Packed: the rows are a copy and may go; the plan stays.
        run(rows).unwrap();
        refused(&format!("UPDATE extents SET plan = NULL WHERE id = '{id}'"));
    }
    sql(&s.rig, "DROP TRIGGER extents_keep_plan_in_service");
    sql(&s.rig, "DROP TRIGGER extents_keep_plan_of_slices");
    sql(&s.rig, "UPDATE extents SET plan = NULL");
    let bytes = body(1, 3 * SLICE);
    s.complete(&[md5_etag(&bytes)]).await.expect(200);
    assert!(s.read().await == bytes);
}

#[tokio::test(flavor = "current_thread")]
async fn an_upload_never_holds_more_extents_than_one_object_may_have() {
    let mut cfg = small_config();
    cfg.max_object_extents = 5;
    let s = setup_with(cfg).await;

    // A part of several extents that would take the upload past the
    // limit is refused before anything of it is stored.
    let refused = |r: Resp| {
        r.expect_error(400, "EntityTooLarge");
        assert!(r.message().contains("more than 5 stored extents"));
    };
    refused(send_part(&s.rig, &s.signer, &s.id, 1, &body(1, 6 * SLICE)).await);
    assert!(blobs(&s.rig).is_empty() && staged(&s.rig).is_empty());
    assert!(intents(&s.rig).is_empty());
    let three = body(2, 3 * SLICE);
    let first = s.part(1, &three).await;
    refused(send_part(&s.rig, &s.signer, &s.id, 2, &body(3, 3 * SLICE)).await);
    assert_eq!((blobs(&s.rig).len(), staged(&s.rig).len()), (3, 3));
    // The part being replaced does not count against its replacement.
    let five = body(4, 5 * SLICE);
    let first_of_five = s.part(1, &five).await;
    assert_ne!(first, first_of_five);

    // A part of one extent is not counted when it arrives. Complete
    // counts everything the upload holds, listed or not.
    let small = body(5, 100);
    s.part(2, &small).await;
    refused(s.complete(std::slice::from_ref(&first_of_five)).await);
    // Nothing was published and the upload is still open.
    assert!(records(&s.rig).is_empty());
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(staged(&s.rig).len(), 6);

    // With the first part in four slices the upload is published.
    let four = body(6, 4 * SLICE);
    let etag = s.part(1, &four).await;
    s.complete(&[etag]).await.expect(200);
    assert!(s.read().await == four);
    assert_eq!(
        s.rig.count("upload_part_extents"),
        0,
        "closed: no rows left"
    );
}

// ---------------------------------------------------------------------------
// A part of 96 MiB as aws-cli frames it
// ---------------------------------------------------------------------------

/// CRC-64/NVME of `data`, base64: the value of
/// `x-amz-checksum-crc64nvme`.
fn crc64nvme_b64(data: &[u8]) -> String {
    use base64::Engine as _;
    let mut table = [0u64; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u64;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0x9A6C_9329_AC4B_C9B5
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut c = !0u64;
    for b in data {
        c = table[((c ^ u64::from(*b)) & 0xff) as usize] ^ (c >> 8);
    }
    base64::engine::general_purpose::STANDARD.encode((!c).to_be_bytes())
}

/// What the edge of the account's plan lets through: it refuses a
/// request body of 100 MiB or more before the Worker runs.
const EDGE_LIMIT: usize = 100 * MIB;
/// `multipart_chunksize = 96MB` of aws-cli and boto3.
const PART_96M: usize = 96 * MIB;
/// The body aws-cli 2.31 sends for such a part with its default
/// settings, measured on the wire: 96 chunks of 1 MiB with a size line
/// of 8 bytes and a line end each (960 bytes), the last chunk (3), the
/// trailer `x-amz-checksum-crc64nvme` with its 12 characters (39), and
/// the empty line (2). 1,004 bytes more than the part.
const AWS_CLI_BODY_96M: usize = 100_664_300;

#[tokio::test(flavor = "current_thread")]
async fn a_part_of_96_mib_as_aws_cli_frames_it_is_under_the_edge_limit() {
    use velmora_bridge::config::{edge_put_bytes, EDGE_FRAMING_BYTES};

    // The deployed limits: bodies up to 99 MiB decoded.
    let rig = big_rig();
    assert_eq!(
        rig.bridge.cfg.max_put_bytes,
        edge_put_bytes(EDGE_LIMIT as u64)
    );
    let (bucket, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer, KEY).await;

    // The request of aws-cli: unsigned chunks of 1 MiB and a CRC-64
    // trailer, sent with `Transfer-Encoding: chunked` and no
    // `Content-Length`.
    let bytes = body(5, PART_96M);
    let checksum = crc64nvme_b64(&bytes);
    assert_eq!(checksum.len(), 12);
    let decoded = PART_96M.to_string();
    let (mut req, _) = signer.sign_as(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[("partNumber", "1"), ("uploadId", &id)],
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &decoded),
            ("x-amz-trailer", "x-amz-checksum-crc64nvme"),
            ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
        ],
        Vec::new(),
        Some(UNSIGNED_TRAILER),
    );
    req.set_header("transfer-encoding", "chunked");
    req.body = unsigned_chunks(&bytes, MIB, &format!("x-amz-checksum-crc64nvme:{checksum}"));

    // The framing is what was measured, and the whole body is under the
    // edge limit with 4,193,300 bytes to spare.
    let framed = req.body.len();
    assert_eq!(framed, AWS_CLI_BODY_96M);
    assert_eq!(framed - PART_96M, 1_004);
    assert!(framed < EDGE_LIMIT);
    assert_eq!(EDGE_LIMIT - framed, 4_193_300);
    // HTTP/1.1 chunked transfer adds 971 bytes on the wire in the
    // capture; twice that is still far inside what the limit of the
    // setting leaves for framing.
    assert!(((framed - PART_96M) as u64) * 2 + 971 < EDGE_FRAMING_BYTES);

    // The Worker takes it, as it arrives: in pieces, without a length.
    let sent = send_in_pieces(&rig, req, 256 * 1024 + 7).await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    assert_eq!(sent.header("etag"), Some(md5_etag(&bytes).as_str()));
    // Twelve slices of 8 MiB, two of them in memory at a time.
    assert_eq!(staged(&rig).len(), 12);
    assert_eq!(rig.bridge.budget.peak(), 2 * SLICE_8M as u64);
    assert_eq!(rig.bridge.budget.in_use(), 0);

    // A trailer that is not the checksum of the body is refused, and
    // nothing of that part is kept.
    let (mut bad, _) = signer.sign_as(
        rig.now(),
        Method::Put,
        &path(BUCKET, KEY),
        &[("partNumber", "2"), ("uploadId", &id)],
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &decoded),
            ("x-amz-trailer", "x-amz-checksum-crc64nvme"),
            ("x-amz-sdk-checksum-algorithm", "CRC64NVME"),
        ],
        Vec::new(),
        Some(UNSIGNED_TRAILER),
    );
    bad.set_header("transfer-encoding", "chunked");
    bad.body = unsigned_chunks(&bytes, MIB, "x-amz-checksum-crc64nvme:AAAAAAAAAAA=");
    assert_eq!(bad.body.len(), AWS_CLI_BODY_96M);
    let refused = send_in_pieces(&rig, bad, MIB).await;
    assert_eq!(refused.status, 400, "{}", refused.text());
    assert_eq!(staged(&rig).len(), 12);

    // And the object is the part.
    complete(&rig, &signer, &id, &[md5_etag(&bytes)])
        .await
        .expect(200);
    let (generation, rows) = rig.live(&bucket, KEY).await.unwrap();
    assert_eq!((generation.size, rows.len()), (PART_96M as u64, 12));
    assert!(get(&rig, &signer, KEY).await.body == bytes);
}

// ---------------------------------------------------------------------------
// Requests that fail, stop, or lose their upload
// ---------------------------------------------------------------------------

const SLICES: usize = 4;

fn four() -> Vec<u8> {
    body(1, SLICES * SLICE)
}

/// After a part that did not come through: one sweep, nothing is left
/// of it, and the upload takes the part again.
async fn settles(s: &Setup, what: &str) {
    s.rig.trip().disarm();
    s.rig.bridge.clock.advance_ms(DAY_MS);
    s.sweep_out().await;
    assert!(intents(&s.rig).is_empty(), "{what}");
    assert!(broken(&s.rig).is_empty(), "{what}");
    // Whatever is stored is named by a part or by garbage collection.
    let named = sorted([staged(&s.rig), in_gc(&s.rig)].concat());
    assert_eq!(orphans(&s.rig).len(), 0, "{what}");
    assert_eq!(blobs(&s.rig).len(), named.len(), "{what}");

    let again = body(7, 3 * SLICE);
    let etag = s.part(1, &again).await;
    s.complete(&[etag]).await.expect(200);
    assert!(s.read().await == again, "{what}");
    assert!(broken(&s.rig).is_empty(), "{what}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_that_stops_at_any_call_leaves_nothing_broken() {
    for trip in [Trip::Stall, Trip::Fail, Trip::Lost] {
        let mut n = 0;
        loop {
            let s = setup().await;
            let ran = run_until(&s.rig, s.start(&four()), n, trip).await;
            let reached = s.rig.trip().tripped();
            s.rig.trip().disarm();
            // A stalled request is dropped here: its handler was killed.
            let answered = ran.done().map(|r| r.status);
            if !reached {
                assert_eq!(answered, Some(200));
                assert!(n > 8, "the request made {n} calls");
                break;
            }
            let what = format!("{trip:?} at call {n}");
            if answered == Some(200) {
                // Acknowledged: the part is whole.
                assert_eq!(staged(&s.rig).len(), SLICES, "{what}");
                assert!(intents(&s.rig).is_empty(), "{what}");
            }
            settles(&s, &what).await;
            n += 1;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_killed_after_slice_k_is_swept_after_the_grace_period() {
    for k in 0..=SLICES {
        let s = setup().await;
        let fut = step_to(&s.rig, s.start(&four()), |rig| {
            intents(rig).len() == SLICES && blobs(rig).len() == k
        })
        .await
        .stalled();
        drop(fut);
        s.rig.trip().disarm();
        assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
        assert_eq!(orphans(&s.rig).len(), k);
        assert!(staged(&s.rig).is_empty());

        // Not before the grace period is over.
        s.rig.bridge.clock.advance_ms(24 * HOUR_MS);
        assert_eq!(sweep_tick(&s.rig).await, 0);
        assert_eq!(orphans(&s.rig).len(), k);
        s.rig.bridge.clock.advance_ms(1);
        assert_eq!(sweep_tick(&s.rig).await, 1);
        assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
        assert!(blobs(&s.rig).is_empty());
        assert_eq!(intent_status(&s.rig).await["anomalies"], 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_whose_upload_closes_under_it_is_refused_and_swept() {
    for completed in [false, true] {
        let s = setup().await;
        let small = body(5, 10);
        let etag = s.part(2, &small).await;
        // All four slices are stored; the part is not yet committed.
        let fut = step_to(&s.rig, s.start(&four()), |rig| {
            blobs(rig).len() == 1 + SLICES
        })
        .await
        .stalled();
        s.rig.trip().disarm();
        if completed {
            let mut xml = String::from("<CompleteMultipartUpload>");
            xml.push_str(&format!(
                "<Part><PartNumber>2</PartNumber><ETag>{etag}</ETag></Part>"
            ));
            xml.push_str("</CompleteMultipartUpload>");
            s.rig
                .call(
                    &s.signer,
                    Method::Post,
                    &path(BUCKET, KEY),
                    &[("uploadId", &s.id)],
                    &[],
                    xml.as_bytes(),
                )
                .await
                .expect(200);
        } else {
            abort(&s.rig, &s.signer, &s.id).await.expect(204);
        }
        resume(&s.rig, fut).await.expect_error(404, "NoSuchUpload");
        // The rows are given up: the sweep need not wait a day.
        assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
        assert_eq!(orphans(&s.rig).len(), SLICES);
        assert_eq!(sweep_tick(&s.rig).await, 1);
        assert!(orphans(&s.rig).is_empty() && intents(&s.rig).is_empty());
        assert!(broken(&s.rig).is_empty());
        if completed {
            assert!(s.read().await == small);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_refused_in_its_last_slice_leaves_nothing_after_one_sweep() {
    let s = setup().await;
    // The declared digest is that of another body.
    let bytes = four();
    let mut req = part_req(
        &s.rig,
        &s.signer,
        &s.id,
        1,
        &body(2, SLICES * SLICE),
        Mode::Literal,
    );
    req.body = bytes;
    let r = send_in_pieces(&s.rig, req, 1000).await;
    r.expect_error(400, "BadDigest");
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert!(staged(&s.rig).is_empty());
    assert!(stamps(&s.rig).is_empty(), "no part, no stamp");
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(blobs(&s.rig).is_empty() && intents(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_whose_commit_fails_is_swept_and_can_be_sent_again() {
    let s = setup().await;
    // Two slices are stored; the next batch of the request is the one
    // that stores the part.
    let fut = step_to(&s.rig, s.start(&four()), |rig| blobs(rig).len() == 2)
        .await
        .stalled();
    s.rig.trip().disarm();
    s.rig.bridge.catalog.sql.fail_batches.set(1);
    resume(&s.rig, fut).await.expect_error(500, "InternalError");
    assert_eq!(s.rig.bridge.catalog.sql.fail_batches.get(), 0);
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert!(staged(&s.rig).is_empty());
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(blobs(&s.rig).is_empty());

    let bytes = four();
    let etag = s.part(1, &bytes).await;
    s.complete(&[etag]).await.expect(200);
    assert!(s.read().await == bytes);
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_without_its_stamp_is_not_acknowledged_and_is_replaced_by_the_retry() {
    let s = setup().await;
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
    let bytes = four();
    send_part(&s.rig, &s.signer, &s.id, 1, &bytes)
        .await
        .expect_error(503, "SlowDown");
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    // The part is committed all the same; its rows are gone.
    let first = staged(&s.rig);
    assert_eq!(first.len(), SLICES);
    assert!(intents(&s.rig).is_empty() && stamps(&s.rig).is_empty());

    // The client sends it again.
    let etag = s.part(1, &bytes).await;
    assert_eq!(stamps(&s.rig).len(), 1);
    assert_eq!(in_gc(&s.rig), sorted(first));
    s.complete(&[etag]).await.expect(200);
    assert!(s.read().await == bytes);
    assert!(broken(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn complete_publishes_a_sliced_part_only_with_a_raised_stamp() {
    let s = setup().await;
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
    let bytes = four();
    send_part(&s.rig, &s.signer, &s.id, 1, &bytes)
        .await
        .expect_error(503, "SlowDown");
    // The client does not send the part again: it is in ListParts.
    let etag = md5_etag(&bytes);
    s.complete(std::slice::from_ref(&etag))
        .await
        .expect_error(503, "SlowDown");
    assert!(records(&s.rig).is_empty() && stamps(&s.rig).is_empty());
    assert_eq!(s.rig.count("generations"), 0);
    assert_eq!(staged(&s.rig).len(), SLICES);

    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    s.complete(&[etag]).await.expect(200);
    assert_eq!(stamps(&s.rig).len(), 1);
    assert!(s.read().await == bytes);
    assert!(broken(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn complete_of_parts_of_one_extent_raises_no_stamp() {
    let s = setup().await;
    let bytes = body(3, 100);
    let etag = s.part(1, &bytes).await;
    *s.rig.bridge.safety.fail_put_prefix.borrow_mut() = Some("rs/".into());
    s.complete(&[etag]).await.expect(200);
    assert!(stamps(&s.rig).is_empty());
    assert!(s.read().await == bytes);
}

#[tokio::test(flavor = "current_thread")]
async fn a_part_older_than_twelve_hours_is_not_committed() {
    let s = setup().await;
    let fut = step_to(&s.rig, s.start(&four()), |rig| blobs(rig).len() == 2)
        .await
        .stalled();
    s.rig.trip().disarm();
    s.rig.bridge.clock.advance_ms(12 * HOUR_MS + 1);
    resume(&s.rig, fut).await.expect_error(503, "SlowDown");
    assert_eq!(states(&s.rig), [("abandoned".to_string(), SLICES)]);
    assert!(staged(&s.rig).is_empty());
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(blobs(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn the_sweep_first_then_the_commit_stores_no_part() {
    let s = setup().await;
    let fut = step_to(&s.rig, s.start(&four()), |rig| blobs(rig).len() == SLICES)
        .await
        .stalled();
    s.rig.trip().disarm();
    // The request hangs for more than a day and the sweep takes its
    // rows and its slices.
    let write = intents(&s.rig)[0].write.clone();
    sql(
        &s.rig,
        &format!(
            "UPDATE write_intents SET created_at = created_at - {} WHERE write_id = '{write}'",
            DAY_MS
        ),
    );
    assert_eq!(sweep_tick(&s.rig).await, 1);
    assert!(blobs(&s.rig).is_empty() && intents(&s.rig).is_empty());

    // Its commit then finds no row of its own, and names no blob.
    let r = resume(&s.rig, fut).await;
    r.expect_error(503, "SlowDown");
    assert!(staged(&s.rig).is_empty());
    assert_eq!(s.rig.count("extents"), 0);
    assert!(broken(&s.rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn under_a_replay_no_part_is_stored() {
    let s = setup().await;
    // The replay starts after the request passed the gate, with two
    // slices stored.
    let fut = step_to(&s.rig, s.start(&four()), |rig| blobs(rig).len() == 2)
        .await
        .stalled();
    s.rig.trip().disarm();
    let now = s.rig.now();
    let begun = s.rig.bridge.catalog.restore_begin(UnixMs(0), now).await;
    assert!(begun.unwrap().is_ok());
    assert!(intents(&s.rig).is_empty(), "the begin empties the intents");
    let r = resume(&s.rig, fut).await;
    r.expect_writes_refused();
    assert!(staged(&s.rig).is_empty());
    assert_eq!(s.rig.count("extents"), 0);
}

/// The catalogue is taken back to a point inside an UploadPart that
/// was acknowledged later. The stamp of the part says so: the sweep
/// refuses, the gate closes, and the slices stay.
#[tokio::test(flavor = "current_thread")]
async fn a_catalogue_restored_into_a_part_keeps_its_slices() {
    let s = setup().await;
    let fut = step_to(&s.rig, s.start(&four()), |rig| blobs(rig).len() == 2)
        .await
        .stalled();
    s.rig.trip().disarm();
    snapshot(&s.rig);
    resume(&s.rig, fut).await.expect(200);
    assert_eq!(stamps(&s.rig).len(), 1);
    let all = blobs(&s.rig);
    let part = staged(&s.rig);

    s.rig.bridge.clock.advance_ms(DAY_MS);
    rollback(&s.rig);
    assert_eq!(states(&s.rig), [("open".to_string(), SLICES)]);
    assert!(staged(&s.rig).is_empty());
    let write = intents(&s.rig)[0].write.clone();

    assert_eq!(
        s.rig.bridge.run_job(&sweep_job(&write)).await,
        JobOutcome::Ack
    );
    assert_eq!(blobs(&s.rig), all);
    let report = s.rig.bridge.dispatch().await.unwrap();
    assert!(report.rolled_back);
    assert_eq!(report.sweeps_enqueued, 0);
    send_part(&s.rig, &s.signer, &s.id, 2, &four())
        .await
        .expect_error(503, "SlowDown");
    assert_eq!(blobs(&s.rig), all);
    assert_eq!(part.len(), SLICES);
}
