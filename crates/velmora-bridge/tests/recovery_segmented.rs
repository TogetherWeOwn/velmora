//! Segmented generation records (format 2), read by the replay.
//!
//! No production code writes one: `segmented_support` is the writer.
//! A record is made from the format-1 record of an object that a real
//! request published, so "what a live publish leaves" is at hand.

mod segmented_support;
mod service_support;

use segmented_support::*;
use service_support::*;
use sha2::{Digest, Sha256};
use velmora_bridge::crypto::open_manifest;
use velmora_bridge::recovery::{
    read_generation, read_stored_generation, BucketRecord, ExtentRecord, GenerationHead,
    GenerationManifest, GenerationRecord, Layout, Segment, SegmentEntry, StoredGeneration,
    MAX_SEGMENTS, SEGMENTED_VERSION,
};
use velmora_bridge::replay::{ReplayCursor, ReplayLimits, ReplayReport};
use velmora_bridge::*;

const BUCKET: &str = "vault";
/// Extents of the large object: two full segments of 64 and a part.
const EXTENTS: usize = 161;
const SLICE: usize = 4096;
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sql(rig: &Rig, script: &str) {
    rig.bridge
        .catalog
        .sql
        .with_conn(|c| c.execute_batch(script).unwrap());
}

/// Deletes every catalogue row (the loss).
fn wipe(rig: &Rig) {
    for t in TABLES {
        sql(rig, &format!("DELETE FROM {t};"));
    }
}

/// Everything the catalogue says.
fn dump(rig: &Rig) -> String {
    let mut out = String::new();
    for t in TABLES {
        rig.bridge.catalog.sql.with_conn(|c| {
            let mut stmt = c
                .prepare(&format!("SELECT * FROM {t} ORDER BY 1, 2"))
                .unwrap();
            let n = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                out.push_str(t);
                for i in 0..n {
                    out.push_str(&format!("|{:?}", row.get_ref(i).unwrap()));
                }
                out.push('\n');
            }
        });
    }
    out
}

/// Replays to the end. Returns what was published, which records were
/// unreadable, how many extents were handled, and the number of calls.
async fn replay(rig: &Rig, limits: ReplayLimits) -> (ReplayReport, u32) {
    let mut total = ReplayReport::default();
    let mut cursor = Some(ReplayCursor::start(UnixMs(0)));
    let mut calls = 0;
    while let Some(at) = cursor {
        calls += 1;
        assert!(calls < 10_000, "the replay does not end");
        let mut step = rig.bridge.replay_step_within(at, limits).await.unwrap();
        cursor = step.next.take();
        total.manifests += step.manifests;
        total.published += step.published;
        total.present += step.present;
        total.extents += step.extents;
        total.unreadable.extend(step.unreadable);
        total.unpublishable.extend(step.unpublishable);
    }
    (total, calls)
}

/// A rig that cuts a body into extents of [`SLICE`] bytes and writes
/// its records in `layout`.
fn small_slices(layout: &Layout) -> Rig {
    let mut cfg = config(Vec::new());
    cfg.slice_bytes = SLICE as u64;
    cfg.max_extent_bytes = SLICE as u64;
    cfg.records = layout.clone();
    rig_with(NoNntp, cfg)
}

/// A bucket with a small object, the large one (`big`, [`EXTENTS`]
/// extents) and another small one, written in this order.
async fn world(layout: &Layout) -> (Rig, Bucket, Signer, Vec<u8>) {
    let rig = small_slices(layout);
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "before", b"before")
        .await
        .expect(200);
    rig.bridge.clock.advance_ms(1000);
    let body = pattern(7, (EXTENTS - 1) * SLICE + 100);
    rig.put(&signer, BUCKET, "big", &body).await.expect(200);
    rig.bridge.clock.advance_ms(1000);
    rig.put(&signer, BUCKET, "after", b"after")
        .await
        .expect(200);
    let (_, extents) = rig.live(&bucket, "big").await.unwrap();
    assert_eq!(extents.len(), EXTENTS);
    (rig, bucket, signer, body)
}

/// The format-1 record of the live generation of `key`: its name and
/// what it says.
async fn record_of(
    rig: &Rig,
    bucket: &Bucket,
    key: &str,
    layout: &Layout,
) -> (String, GenerationManifest) {
    let (live, _) = rig.live(bucket, key).await.unwrap();
    let name = layout.generation_key(&live.id);
    let sealed = rig.bridge.safety.inner.stored(&name).unwrap().bytes;
    let plain = open_manifest(&rig.bridge.kek, &name, &sealed).unwrap();
    (name, serde_json::from_slice(&plain).unwrap())
}

async fn store(rig: &Rig, bucket: &Bucket, key: &str, bytes: Vec<u8>) {
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let meta = BlobMeta {
        bucket: &bucket.id,
        extent: &ExtentId::new("x_0"),
        cipher_sha256: &digest,
    };
    rig.bridge
        .safety
        .inner
        .put(key, bytes, &meta)
        .await
        .unwrap();
}

/// Stores `sealed` as a writer would, segments first, in place of the
/// format-1 record at its head's name.
async fn put_segmented(rig: &Rig, bucket: &Bucket, sealed: &Sealed) {
    for (name, bytes) in &sealed.segments {
        rig.bridge.safety.inner.lose(name);
        store(rig, bucket, name, bytes.clone()).await;
    }
    rig.bridge.safety.inner.lose(&sealed.head_key);
    store(rig, bucket, &sealed.head_key, sealed.head_sealed.clone()).await;
}

/// Makes the record of `big` a segmented one with segments of `per`.
async fn segment(rig: &Rig, bucket: &Bucket, layout: &Layout, per: usize) -> Sealed {
    let (name, m) = record_of(rig, bucket, "big", layout).await;
    segment_from(rig, bucket, layout, &name, &m, per).await
}

/// Stores the record `m` of the name `name` as a segmented one with
/// segments of `per`.
async fn segment_from(
    rig: &Rig,
    bucket: &Bucket,
    layout: &Layout,
    name: &str,
    m: &GenerationManifest,
    per: usize,
) -> Sealed {
    let set = set_id(rig.bridge.clock.now().0, per as u64);
    let sealed = seal(&rig.bridge.kek, layout, name, m, &set, per);
    put_segmented(rig, bucket, &sealed).await;
    sealed
}

async fn reissue_key(rig: &Rig) -> Signer {
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

async fn get(rig: &Rig, signer: &Signer, key: &str) -> Resp {
    rig.call(signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
        .await
}

fn invalid(e: BridgeError) -> String {
    match e {
        BridgeError::Invalid(why) => why.to_string(),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The bytes
// ---------------------------------------------------------------------------

fn golden_manifest() -> GenerationManifest {
    let extent = |seq: u32| ExtentRecord {
        id: format!("x_0000018bcfe568{seq:02x}00000000000000aa"),
        seq,
        plain_offset: u64::from(seq) * 8_388_608,
        plain_size: if seq == 4 { 1024 } else { 8_388_608 },
        cipher_size: if seq == 4 { 1064 } else { 8_388_648 },
        media_header: vec![1, 2, 3, seq as u8],
        key_mode: 1,
        wrapped_file_key: vec![0xa0 + seq as u8; 40],
        plain_md5: vec![seq as u8; 16],
        plain_sha256: vec![0x10 + seq as u8; 32],
        cipher_sha256: vec![0x20 + seq as u8; 32],
        created_at: 1_700_000_000_000 + i64::from(seq),
    };
    GenerationManifest {
        v: 1,
        bucket: BucketRecord {
            id: "b_0123456789abcdef".into(),
            name: "vault".into(),
            owner: "o_1".into(),
            bdk_wrapped: vec![0x42; 40],
            kek_version: 1,
            disposable: false,
            created_at: 1_690_000_000_000,
        },
        generation: GenerationRecord {
            id: "g_0000018bcfe5680000000000000000ff".into(),
            key: "dir/a \"large\" file.bin".into(),
            size: 4 * 8_388_608 + 1024,
            etag: "\"0123456789abcdef0123456789abcdef-5\"".into(),
            checksum_json: None,
            content_json: "{\"type\":\"application/octet-stream\"}".into(),
            user_meta_json: "{}".into(),
            created_at: 1_700_000_000_005,
        },
        extents: (0..5).map(extent).collect(),
    }
}

/// Compares with a file of `tests/golden/`. `VELMORA_WRITE_GOLDEN=1`
/// writes the file instead: for a new vector, never to make a changed
/// one pass.
fn golden(name: &str, bytes: &[u8]) {
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("VELMORA_WRITE_GOLDEN").is_some() {
        std::fs::write(&path, bytes).unwrap();
    }
    let stored = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert_eq!(
        String::from_utf8_lossy(bytes),
        String::from_utf8_lossy(&stored),
        "{name}"
    );
}

/// The plaintext of a format-1 record is, byte for byte, what it was
/// before format 2 existed, and the plaintexts of a head and of a
/// segment are the ones checked in. (The sealed bytes have a random
/// nonce; what is sealed is what a format is.)
#[test]
fn the_bytes_of_both_formats_are_the_ones_checked_in() {
    let m = golden_manifest();
    golden("generation-v1.json", &serde_json::to_vec(&m).unwrap());

    let set = "s_0000018bcfe568050123456789abcdef";
    let segments = split(&m, set, 2);
    assert_eq!(segments.len(), 3);
    let digests: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0xd0 + i; 32]).collect();
    let head = head_of(&m, set, &segments, &digests);
    let head_plain = serde_json::to_vec(&head).unwrap();
    golden("generation-v2-head.json", &head_plain);
    golden(
        "generation-v2-segment-1.json",
        &serde_json::to_vec(&segments[1]).unwrap(),
    );

    // What is checked in reads back as the same record.
    let name = format!("m/{}", m.generation.id);
    assert_eq!(GenerationHead::parse(&name, &head_plain).unwrap(), head);
    assert_eq!(head.extent_count(), 5);
    assert_eq!(
        Layout::flat().segment_key(set, 1),
        "m/seg/s_0000018bcfe568050123456789abcdef/00001"
    );
    assert_eq!(
        Layout::default_tenant().segment_key(set, 12),
        "m/x/t_0000000000000000/seg/s_0000018bcfe568050123456789abcdef/00012"
    );
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// A segmented record replays to the catalogue the format-1 record of
/// the same object replays to, row for row, and to the object the live
/// publish left: in both layouts, whatever the size of the segments
/// (the reader takes it from the head: 64, the 4,096 of a production
/// writer, 1, or one that is no divisor of anything), and from every
/// place a call can stop at, each border of a segment among them.
#[tokio::test(flavor = "current_thread")]
async fn a_segmented_record_replays_to_what_the_single_record_replays_to() {
    for layout in Layout::all() {
        let (rig, bucket, _, body) = world(&layout).await;
        let live_before = rig.live(&bucket, "big").await.unwrap();
        let (name, m) = record_of(&rig, &bucket, "big", &layout).await;

        wipe(&rig);
        let (single, _) = replay(&rig, ReplayLimits::default()).await;
        assert_eq!((single.published, single.unreadable.len()), (3, 0));
        let rows = dump(&rig);
        assert_eq!(rig.live(&bucket, "big").await.unwrap(), live_before);

        for (per, records, extents) in [
            (64, 1, 1),
            (64, 1, 63),
            (64, 1, 64),
            (64, 1, 65),
            (64, 2, 7),
            (64, 50, 1000),
            (4096, 1, 50),
            (1, 1, 3),
            (100, 1, 33),
        ] {
            let at = format!("{layout:?} per {per}, {records} records and {extents} extents");
            let sealed = segment_from(&rig, &bucket, &layout, &name, &m, per).await;
            assert_eq!(sealed.segments.len(), EXTENTS.div_ceil(per), "{at}");
            let root = format!("{}seg/", layout.root());
            assert!(sealed.segments.iter().all(|(n, _)| n.starts_with(&root)));

            wipe(&rig);
            let (report, calls) = replay(&rig, ReplayLimits { records, extents }).await;
            assert_eq!(report.unreadable, Vec::<String>::new(), "{at}");
            assert!(report.unpublishable.is_empty(), "{at}");
            assert_eq!(
                (report.manifests, report.published, report.extents),
                (single.manifests, single.published, single.extents),
                "{at}"
            );
            if extents == 1 {
                // A call for each extent: every place was a cursor.
                assert!(calls as usize > EXTENTS, "{at}: {calls} calls");
            }
            assert_eq!(dump(&rig), rows, "{at}");
            assert_eq!(rig.live(&bucket, "big").await.unwrap(), live_before, "{at}");

            // Again: nothing changes.
            let (again, _) = replay(&rig, ReplayLimits { records, extents }).await;
            assert_eq!((again.published, again.present), (0, 3), "{at}");
            assert_eq!(dump(&rig), rows, "{at}");
        }

        let signer = reissue_key(&rig).await;
        assert_eq!(get(&rig, &signer, "big").await.expect(200).body, body);
        assert_eq!(get(&rig, &signer, "after").await.expect(200).body, b"after");
    }
}

/// What every refusal below must leave: the record is named as
/// unreadable, the object it describes is not published, and the
/// objects around it are.
async fn assert_refused(rig: &Rig, head_key: &str, also: Option<&str>, at: &str) {
    for limits in [
        ReplayLimits::default(),
        ReplayLimits {
            records: 1,
            extents: 50,
        },
    ] {
        wipe(rig);
        let (report, _) = replay(rig, limits).await;
        assert!(
            report.unreadable.iter().any(|k| k == head_key),
            "{at}: {report:?}"
        );
        if let Some(also) = also {
            assert!(
                report.unreadable.iter().any(|k| k == also),
                "{at}: {report:?}"
            );
        }
        assert_eq!(report.published, 2, "{at}: {report:?}");
        assert_eq!(rig.count("objects"), 2, "{at}");
        assert_eq!(rig.count("generations"), 2, "{at}");
        assert_eq!(rig.count("generation_extents"), 2, "{at}");
        assert_eq!(rig.count("extents"), 2, "{at}");
        let signer = reissue_key(rig).await;
        get(rig, &signer, "big").await.expect(404);
        assert_eq!(
            get(rig, &signer, "before").await.expect(200).body,
            b"before"
        );
        assert_eq!(get(rig, &signer, "after").await.expect(200).body, b"after");
    }
}

/// The record of `big` in parts, segments of 64, not stored yet.
async fn parts(rig: &Rig, bucket: &Bucket, layout: &Layout) -> (String, GenerationManifest) {
    record_of(rig, bucket, "big", layout).await
}

/// A segment that is not stored: unreadable, nothing published.
#[tokio::test(flavor = "current_thread")]
async fn a_missing_segment_makes_the_record_unreadable() {
    for layout in Layout::all() {
        for lost in [0, 1, 2] {
            let (rig, bucket, _, _) = world(&layout).await;
            let sealed = segment(&rig, &bucket, &layout, 64).await;
            let name = &sealed.segments[lost].0;
            assert!(rig.bridge.safety.inner.lose(name));
            assert_refused(&rig, &sealed.head_key, Some(name), "missing").await;
        }
    }
}

/// A segment whose stored bytes are not the ones the head has the
/// digest of: one changed bit, or a head that names another digest.
#[tokio::test(flavor = "current_thread")]
async fn a_segment_with_another_digest_makes_the_record_unreadable() {
    let layout = Layout::flat();
    // The stored segment changed.
    let (rig, bucket, _, _) = world(&layout).await;
    let sealed = segment(&rig, &bucket, &layout, 64).await;
    let name = &sealed.segments[1].0;
    assert!(rig.bridge.safety.inner.corrupt(name, |b| {
        let last = b.len() - 1;
        b[last] ^= 1;
    }));
    assert_refused(&rig, &sealed.head_key, Some(name), "changed segment").await;

    // The head names another digest for a segment that opens.
    let (rig, bucket, _, _) = world(&layout).await;
    let (name, m) = parts(&rig, &bucket, &layout).await;
    let mut sealed = seal(&rig.bridge.kek, &layout, &name, &m, "s_1", 64);
    sealed.head.segments[2].sha256[0] ^= 1;
    sealed.reseal_head(&rig.bridge.kek);
    put_segmented(&rig, &bucket, &sealed).await;
    assert_refused(
        &rig,
        &sealed.head_key,
        Some(&sealed.segments[2].0),
        "other digest",
    )
    .await;
}

/// Seals `segments` as they are and a head that names them with the
/// digests of what was sealed, so that only what the segments say can
/// be wrong. `entries` then changes the head.
fn forged(
    rig: &Rig,
    layout: &Layout,
    name: &str,
    m: &GenerationManifest,
    segments: Vec<Segment>,
    entries: impl FnOnce(&mut Vec<SegmentEntry>),
) -> Sealed {
    let kek = &rig.bridge.kek;
    let stored: Vec<(String, Vec<u8>)> = segments
        .iter()
        .map(|s| seal_segment(kek, layout, s))
        .collect();
    let digests: Vec<Vec<u8>> = stored
        .iter()
        .map(|(_, sealed)| Sha256::digest(sealed).to_vec())
        .collect();
    // The head a correct writer would write for this object.
    let honest = split(m, &segments[0].set, 64);
    let mut head = head_of(m, &segments[0].set, &honest, &digests);
    entries(&mut head.segments);
    let head_sealed = seal_head(kek, name, &head);
    Sealed {
        head,
        head_key: name.to_string(),
        head_sealed,
        segments: stored,
        plain: segments,
    }
}

/// A segment that opens and has the digest the head names, but does
/// not hold what the head says: another number of extents, another
/// first `seq`, a gap in the offsets, another size.
#[tokio::test(flavor = "current_thread")]
async fn a_segment_that_is_not_what_its_head_says_makes_the_record_unreadable() {
    type InSegments = fn(&mut Vec<Segment>);
    type InHead = fn(&mut Vec<SegmentEntry>);
    let cases: [(&str, InSegments, InHead); 7] = [
        // The head says 65 and 63 where the segments hold 64 and 64.
        (
            "wrong count",
            |_| {},
            |entries| {
                entries[0].count += 1;
                entries[1].seq += 1;
                entries[1].count -= 1;
            },
        ),
        // A segment with one extent less than the head says.
        (
            "short segment",
            |segments| {
                segments[1].extents.pop();
            },
            |_| {},
        ),
        // One extent more than the head says, of no bytes: the seqs,
        // the offsets and the size are the head's, the count is not.
        (
            "an extent more",
            |segments| {
                let mut more = segments[1].extents.last().unwrap().clone();
                more.seq += 1;
                more.plain_offset += more.plain_size;
                more.plain_size = 0;
                segments[1].extents.push(more);
            },
            |_| {},
        ),
        // The extents of segment 1 begin one later than the head says.
        (
            "wrong first seq",
            |segments| {
                for e in &mut segments[1].extents {
                    e.seq += 1;
                }
            },
            |_| {},
        ),
        // Two extents of a segment in the other order.
        (
            "seq out of order",
            |segments| segments[1].extents.swap(3, 4),
            |_| {},
        ),
        // A hole of one byte before the last extent of segment 0.
        (
            "gap in offsets",
            |segments| segments[0].extents[63].plain_offset += 1,
            |_| {},
        ),
        // The last extent is shorter than the head's size for it.
        (
            "wrong size",
            |segments| segments[2].extents.last_mut().unwrap().plain_size -= 1,
            |_| {},
        ),
    ];
    for layout in Layout::all() {
        for (what, in_segments, in_head) in &cases {
            let (rig, bucket, _, _) = world(&layout).await;
            let (name, m) = parts(&rig, &bucket, &layout).await;
            let mut segments = split(&m, "s_1", 64);
            in_segments(&mut segments);
            let sealed = forged(&rig, &layout, &name, &m, segments, in_head);
            // The head is one that reads: only a segment is wrong.
            let plain = serde_json::to_vec(&sealed.head).unwrap();
            GenerationHead::parse(&name, &plain).expect(what);
            put_segmented(&rig, &bucket, &sealed).await;
            assert_refused(&rig, &sealed.head_key, None, what).await;
        }
    }
}

/// A segment of another set at the right name: the bytes of the other
/// record's segment (they do not open under this name), and a segment
/// sealed under this name that says it is of another set.
#[tokio::test(flavor = "current_thread")]
async fn a_segment_of_another_set_makes_the_record_unreadable() {
    for layout in Layout::all() {
        // The bytes of another set's segment, with the digest the head
        // names: only the name they were sealed under is wrong.
        let (rig, bucket, _, _) = world(&layout).await;
        let (name, m) = parts(&rig, &bucket, &layout).await;
        let kek = &rig.bridge.kek;
        let other = seal(kek, &layout, &name, &m, "s_other", 64);
        let mut sealed = seal(kek, &layout, &name, &m, "s_mine", 64);
        sealed.segments[1].1 = other.segments[1].1.clone();
        sealed.head.segments[1].sha256 = Sha256::digest(&other.segments[1].1).to_vec();
        sealed.reseal_head(kek);
        put_segmented(&rig, &bucket, &sealed).await;
        assert_refused(&rig, &sealed.head_key, None, "moved").await;

        // Sealed under the right name, saying another set, or another
        // index of this one.
        for (set, index) in [("s_other", 1), ("s_mine", 2)] {
            let (rig, bucket, _, _) = world(&layout).await;
            let (name, m) = parts(&rig, &bucket, &layout).await;
            let kek = &rig.bridge.kek;
            let mut sealed = seal(kek, &layout, &name, &m, "s_mine", 64);
            let mut segment = sealed.plain[1].clone();
            segment.set = set.into();
            segment.index = index;
            let at = sealed.segments[1].0.clone();
            let bytes = velmora_bridge::crypto::seal_manifest(
                kek,
                &at,
                &serde_json::to_vec(&segment).unwrap(),
                &mut velmora::rng::SystemRng,
            )
            .unwrap();
            sealed.head.segments[1].sha256 = Sha256::digest(&bytes).to_vec();
            sealed.segments[1].1 = bytes;
            sealed.reseal_head(kek);
            put_segmented(&rig, &bucket, &sealed).await;
            assert_refused(&rig, &sealed.head_key, None, "other set").await;
        }
    }
}

/// A head that names one segment more than was stored.
#[tokio::test(flavor = "current_thread")]
async fn a_head_that_names_more_segments_than_exist_is_unreadable() {
    for layout in Layout::all() {
        let (rig, bucket, _, _) = world(&layout).await;
        let (name, m) = parts(&rig, &bucket, &layout).await;
        // Four segments, 64, 64, 32 and 1, of which three are stored.
        let mut segments = split(&m, "s_1", 64);
        let tail = segments[2].extents.split_off(32);
        segments.push(Segment {
            v: SEGMENTED_VERSION,
            set: "s_1".into(),
            index: 3,
            extents: tail,
        });
        let kek = &rig.bridge.kek;
        let stored: Vec<(String, Vec<u8>)> = segments
            .iter()
            .map(|s| seal_segment(kek, &layout, s))
            .collect();
        let digests: Vec<Vec<u8>> = stored
            .iter()
            .map(|(_, b)| Sha256::digest(b).to_vec())
            .collect();
        let head = head_of(&m, "s_1", &segments, &digests);
        assert_eq!(head.segments.len(), 4);
        let mut sealed = Sealed {
            head_sealed: seal_head(kek, &name, &head),
            head,
            head_key: name,
            segments: stored,
            plain: segments,
        };
        let (missing, _) = sealed.segments.pop().unwrap();
        put_segmented(&rig, &bucket, &sealed).await;
        assert_refused(&rig, &sealed.head_key, Some(&missing), "one more").await;
    }
}

/// A head that is cut short: the sealed bytes, or the document inside
/// them. And one that does not tile its object.
#[tokio::test(flavor = "current_thread")]
async fn a_truncated_or_inconsistent_head_is_unreadable() {
    let layout = Layout::flat();
    // The sealed bytes are cut.
    let (rig, bucket, _, _) = world(&layout).await;
    let sealed = segment(&rig, &bucket, &layout, 64).await;
    assert!(rig
        .bridge
        .safety
        .inner
        .corrupt(&sealed.head_key, |b| b.truncate(b.len() / 2)));
    assert_refused(&rig, &sealed.head_key, None, "cut bytes").await;

    // The document is cut, and sealed as it is.
    let (rig, bucket, _, _) = world(&layout).await;
    let mut sealed = segment(&rig, &bucket, &layout, 64).await;
    let plain = serde_json::to_vec(&sealed.head).unwrap();
    sealed.head_sealed = velmora_bridge::crypto::seal_manifest(
        &rig.bridge.kek,
        &sealed.head_key,
        &plain[..plain.len() - 40],
        &mut velmora::rng::SystemRng,
    )
    .unwrap();
    put_segmented(&rig, &bucket, &sealed).await;
    assert_refused(&rig, &sealed.head_key, None, "cut document").await;

    // Heads whose entries do not tile the object, each sealed well.
    type Change = fn(&mut GenerationHead);
    let cases: [(&str, Change); 9] = [
        ("no segment", |h| h.segments.clear()),
        ("last segment dropped", |h| {
            h.segments.pop();
        }),
        ("first seq", |h| h.segments[0].seq = 1),
        ("first offset", |h| h.segments[0].plain_offset = 1),
        ("gap in seq", |h| h.segments[1].seq += 1),
        ("gap in offsets", |h| h.segments[2].plain_offset += 1),
        ("empty segment", |h| h.segments[1].count = 0),
        ("short digest", |h| {
            h.segments[1].sha256.pop();
        }),
        ("bad set id", |h| h.set = "../s_1".into()),
    ];
    for (what, change) in cases {
        let (rig, bucket, _, _) = world(&layout).await;
        let mut sealed = segment(&rig, &bucket, &layout, 64).await;
        change(&mut sealed.head);
        sealed.reseal_head(&rig.bridge.kek);
        put_segmented(&rig, &bucket, &sealed).await;
        assert_refused(&rig, &sealed.head_key, None, what).await;
    }

    // More segments than a head may name.
    let name = format!("m/{}", golden_manifest().generation.id);
    let mut m = golden_manifest();
    let one = m.extents[0].clone();
    m.extents = (0..=MAX_SEGMENTS as u32)
        .map(|seq| ExtentRecord {
            seq,
            plain_offset: u64::from(seq),
            plain_size: 1,
            ..one.clone()
        })
        .collect();
    m.generation.size = MAX_SEGMENTS as u64 + 1;
    let segments = split(&m, "s_1", 1);
    let digests = vec![vec![0u8; 32]; segments.len()];
    let mut head = head_of(&m, "s_1", &segments, &digests);
    let plain = serde_json::to_vec(&head).unwrap();
    assert_eq!(
        invalid(GenerationHead::parse(&name, &plain).unwrap_err()),
        "recovery record is malformed"
    );
    // One less is a head.
    head.segments.pop();
    head.generation.size -= 1;
    let plain = serde_json::to_vec(&head).unwrap();
    assert_eq!(
        GenerationHead::parse(&name, &plain).unwrap().extent_count(),
        MAX_SEGMENTS as u32
    );
}

/// A segment that goes missing while a replay is under way: the calls
/// before it wrote rows of the generation, and still nothing is
/// published.
#[tokio::test(flavor = "current_thread")]
async fn a_segment_lost_during_a_replay_publishes_nothing() {
    let layout = Layout::flat();
    let (rig, bucket, _, _) = world(&layout).await;
    let sealed = segment(&rig, &bucket, &layout, 64).await;
    wipe(&rig);
    let limits = ReplayLimits {
        records: 1,
        extents: 10,
    };
    let mut cursor = ReplayCursor::start(UnixMs(0));
    // Into the first segment of `big`.
    while cursor.extent == 0 {
        let step = rig.bridge.replay_step_within(cursor, limits).await.unwrap();
        cursor = step.next.expect("the replay goes on");
    }
    assert!(cursor.extent > 0 && cursor.extent < 64, "{cursor:?}");
    assert!(rig.bridge.safety.inner.lose(&sealed.segments[2].0));
    let mut unreadable = Vec::new();
    let mut next = Some(cursor);
    while let Some(at) = next {
        let mut step = rig.bridge.replay_step_within(at, limits).await.unwrap();
        next = step.next.take();
        unreadable.extend(step.unreadable);
    }
    assert!(unreadable.contains(&sealed.head_key), "{unreadable:?}");
    assert!(unreadable.contains(&sealed.segments[2].0), "{unreadable:?}");
    assert_eq!(rig.count("objects"), 2);
    let signer = reissue_key(&rig).await;
    get(&rig, &signer, "big").await.expect(404);
    assert_eq!(get(&rig, &signer, "after").await.expect(200).body, b"after");
}

/// A version this build does not know is refused as unknown: 3 by this
/// build, and 2 by the reader of format 1, which is what a build from
/// before format 2 says of a segmented record.
#[tokio::test(flavor = "current_thread")]
async fn a_record_of_an_unknown_version_is_refused() {
    let layout = Layout::flat();
    let (rig, bucket, _, _) = world(&layout).await;
    let mut sealed = segment(&rig, &bucket, &layout, 64).await;
    let (safety, kek) = (&rig.bridge.safety.inner, &rig.bridge.kek);

    let old = read_generation(safety, kek, &sealed.head_key).await;
    assert_eq!(
        invalid(old.err().unwrap()),
        "recovery record version is unknown"
    );
    let now = read_stored_generation(safety, kek, &sealed.head_key).await;
    assert!(matches!(now, Ok(Some(StoredGeneration::Segmented(_)))));

    sealed.head.v = 3;
    sealed.reseal_head(kek);
    put_segmented(&rig, &bucket, &sealed).await;
    let new = read_stored_generation(safety, kek, &sealed.head_key).await;
    assert_eq!(
        invalid(new.err().unwrap()),
        "recovery record version is unknown"
    );
    assert_refused(&rig, &sealed.head_key, None, "v 3").await;

    // A segment of version 3 under a head of version 2.
    let (rig, bucket, _, _) = world(&layout).await;
    let (name, m) = parts(&rig, &bucket, &layout).await;
    let mut segments = split(&m, "s_1", 64);
    segments[0].v = 3;
    let sealed = forged(&rig, &layout, &name, &m, segments, |_| {});
    put_segmented(&rig, &bucket, &sealed).await;
    assert_refused(&rig, &sealed.head_key, None, "segment v 3").await;
}
