//! PutObject above one extent: the body is stored in slices, read back
//! as one object, and nothing of a refused body is left after a sweep.

mod intent_support;
mod service_support;

use intent_support::*;
use service_support::*;
use velmora_bridge::*;

const SLICE_8M: usize = 8 * MIB;

/// Production limits: one extent up to 16 MiB, slices of 8 MiB, bodies
/// up to 99 MiB.
fn big_rig() -> Rig {
    let mut cfg = config(Vec::new());
    cfg.max_put_bytes = 99 * MIB as u64;
    cfg.intent_sweep = true;
    rig_with(NoNntp, cfg)
}

// ---------------------------------------------------------------------------
// Round trips at the sizes that matter, in every body mode
// ---------------------------------------------------------------------------

async fn round_trips(mode: Mode) {
    for (seed, len) in [(1, 16 * MIB + 1), (2, 95 * MIB), (3, 99 * MIB)] {
        let rig = big_rig();
        let (bucket, signer) = rig.standard(BUCKET).await;
        let body = pattern(seed, len);
        let etag = md5_etag(&body);

        let r = rig.send(mode_req(&rig, &signer, "big", &body, mode)).await;
        assert_eq!(r.status, 200, "{mode:?} {len}: {}", r.text());
        assert_eq!(r.header("etag"), Some(etag.as_str()), "{mode:?} {len}");
        // Two slices are charged for the whole request, whatever the
        // length of the body.
        assert_eq!(rig.bridge.budget.peak(), 2 * SLICE_8M as u64);
        assert_eq!(rig.bridge.budget.in_use(), 0);

        let (generation, extents) = rig.live(&bucket, "big").await.unwrap();
        assert_eq!(generation.size, len as u64);
        assert_eq!(generation.etag, etag);
        let sizes: Vec<u64> = extents.iter().map(|e| e.plain_size).collect();
        let mut expected = vec![SLICE_8M as u64; len / SLICE_8M];
        if len % SLICE_8M != 0 {
            expected.push((len % SLICE_8M) as u64);
        }
        assert_eq!(sizes, expected, "{mode:?} {len}");
        assert!(intents(&rig).is_empty(), "the publish took its intents");
        assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
        assert_eq!(records(&rig), [generation.id.as_str().to_string()]);
        // One posting job per slice.
        assert_eq!(rig.bridge.jobs.inner.take().len(), extents.len());

        let head = rig.head(&signer, BUCKET, "big").await;
        head.expect(200);
        assert_eq!(
            head.header("content-length"),
            Some(len.to_string().as_str())
        );
        assert_eq!(head.header("etag"), Some(etag.as_str()));
        let got = get(&rig, &signer, "big").await;
        got.expect(200);
        assert!(got.body == body, "{mode:?} {len}: the body reads back");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_a_payload_hash() {
    round_trips(Mode::Literal).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_an_unsigned_payload() {
    round_trips(Mode::Unsigned).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_signed_chunks() {
    round_trips(Mode::SignedChunks).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_signed_chunks_and_a_trailer() {
    round_trips(Mode::SignedTrailer).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_unsigned_chunks_and_a_trailer() {
    round_trips(Mode::UnsignedTrailer).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_limit_is_99_mib_and_16_mib_is_still_one_extent() {
    let rig = big_rig();
    let (bucket, signer) = rig.standard(BUCKET).await;

    // One byte above the limit is refused from the headers alone.
    for mode in MODES {
        let req = declared_req(&rig, &signer, "over", 99 * MIB as u64 + 1, mode);
        let (r, polled) = rig.send_watched(req).await;
        r.expect_error(400, "EntityTooLarge");
        assert!(!polled, "{mode:?}: the body was read");
    }
    assert_eq!(rig.count("write_intents"), 0);
    assert!(blobs(&rig).is_empty() && records(&rig).is_empty());

    // A body of exactly one extent takes the path it always took: no
    // statement of the request names `write_intents`.
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = Some(("write_intents", 0));
    let body = pattern(4, 16 * MIB);
    rig.put(&signer, BUCKET, "one", &body).await.expect(200);
    *rig.bridge.catalog.sql.fail_matching.borrow_mut() = None;
    let (generation, extents) = rig.live(&bucket, "one").await.unwrap();
    assert_eq!(extents.len(), 1);
    assert_eq!(extents[0].plain_size, 16 * MIB as u64);
    assert_eq!(generation.etag, md5_etag(&body));
    assert!(stamps(&rig).is_empty(), "a single extent raises no stamp");
    assert!(get(&rig, &signer, "one").await.expect(200).body == body);
}

// ---------------------------------------------------------------------------
// The same path with small limits
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn every_mode_and_every_cut_reads_back() {
    let rig = small_rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    // One byte above an extent, a whole number of slices, one byte
    // either side of it, and the limit.
    let lens = [EXTENT + 1, 3 * SLICE - 1, 3 * SLICE, 3 * SLICE + 1, MAX_PUT];
    let mut seed = 0;
    for mode in MODES {
        for len in lens {
            seed += 1;
            let body = pattern(seed, len);
            let key = format!("{mode:?}/{len}");
            let r = rig.send(mode_req(&rig, &signer, &key, &body, mode)).await;
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            assert_eq!(r.header("etag"), Some(md5_etag(&body).as_str()), "{key}");
            let (_, extents) = rig.live(&bucket, &key).await.unwrap();
            assert_eq!(extents.len(), len.div_ceil(SLICE), "{key}");
            assert!(extents.iter().all(|e| e.plain_size <= SLICE as u64));
            let got = get(&rig, &signer, &key).await;
            assert_eq!(got.expect(200).body, body, "{key}");
            // A ranged read over a slice border.
            let range = format!("bytes={}-{}", SLICE - 3, SLICE + 2);
            let part = rig
                .call(
                    &signer,
                    Method::Get,
                    &path(BUCKET, &key),
                    &[],
                    &[("range", &range)],
                    b"",
                )
                .await;
            assert_eq!(part.expect(206).body, body[SLICE - 3..SLICE + 3], "{key}");
        }
    }
    assert!(intents(&rig).is_empty());
    assert!(orphans(&rig).is_empty() && broken(&rig).is_empty());
    // A trailer checksum is stored and answered like that of any object.
    let key = format!("{:?}/{MAX_PUT}", Mode::UnsignedTrailer);
    let head = rig
        .call(
            &signer,
            Method::Head,
            &path(BUCKET, &key),
            &[],
            &[("x-amz-checksum-mode", "ENABLED")],
            b"",
        )
        .await;
    assert!(head.expect(200).header(CRC32C).is_some());

    // The limit holds at these sizes as well.
    for mode in MODES {
        let req = declared_req(&rig, &signer, "over", MAX_PUT as u64 + 1, mode);
        rig.send(req).await.expect_error(400, "EntityTooLarge");
    }
}

/// Requests whose body is refused, with the error S3 answers. Each of
/// them fails at or after the last slice.
fn refused_bodies(
    rig: &Rig,
    signer: &Signer,
    key: &str,
    body: &[u8],
) -> Vec<(&'static str, Req, u16, &'static str)> {
    use base64::Engine as _;
    let now = rig.now();
    let p = path(BUCKET, key);
    let mut other = body.to_vec();
    *other.last_mut().unwrap() ^= 1;
    let mut out = Vec::new();

    let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(&other).0);
    let req = signer.sign(
        now,
        Method::Put,
        &p,
        &[],
        &[("content-md5", &md5)],
        body.to_vec(),
    );
    out.push(("a wrong Content-MD5", req, 400, "BadDigest"));

    let mut req = signer.sign(now, Method::Put, &p, &[], &[], other.clone());
    req.body = body.to_vec();
    out.push(("a wrong payload hash", req, 400, "BadDigest"));

    let sum = base64::engine::general_purpose::STANDARD.encode(sha256(&other));
    let req = signer.sign(
        now,
        Method::Put,
        &p,
        &[],
        &[("x-amz-checksum-sha256", &sum)],
        body.to_vec(),
    );
    out.push(("a wrong checksum header", req, 400, "BadDigest"));

    let mut req = mode_req(rig, signer, key, &other, Mode::UnsignedTrailer);
    let trailer = format!("{CRC32C}:{}", crc32c_b64(&other));
    req.body = unsigned_chunks(body, 64 * 1024, &trailer);
    out.push(("a wrong unsigned trailer checksum", req, 400, "BadDigest"));

    let decoded = body.len().to_string();
    let chunked = [
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", decoded.as_str()),
    ];
    let with_trailer = [chunked[0], chunked[1], ("x-amz-trailer", CRC32C)];
    let sized = |mut req: Req, body: Vec<u8>| {
        req.set_header("content-length", &body.len().to_string());
        req.body = body;
        req
    };

    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        &[],
        &with_trailer,
        Vec::new(),
        Some(SIGNED_TRAILER),
    );
    let wire = signer.signed_chunks(now, &seed, body, CHUNK, Some((CRC32C, crc32c_b64(&other))));
    out.push((
        "a wrong signed trailer checksum",
        sized(req, wire),
        400,
        "BadDigest",
    ));

    // The signature of the last chunk that carries data.
    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        &[],
        &chunked,
        Vec::new(),
        Some(SIGNED),
    );
    let mut wire = signer.signed_chunks(now, &seed, body, CHUNK, None);
    let last_data = body.len() - (body.len() - 1) % CHUNK - 1;
    let good = signer.signed_chunks(now, &seed, &body[..last_data], CHUNK, None);
    // `good` and `wire` agree up to the header of that chunk.
    let header_at = good.len() - "0;chunk-signature=".len() - 64 - 4;
    let sig_at = header_at + wire[header_at..].iter().position(|b| *b == b'=').unwrap() + 1;
    wire[sig_at] = if wire[sig_at] == b'0' { b'1' } else { b'0' };
    out.push((
        "a bad signature on the last data chunk",
        sized(req, wire),
        403,
        "SignatureDoesNotMatch",
    ));

    // The signature of the empty chunk that ends the body.
    let (req, seed) = signer.sign_as(
        now,
        Method::Put,
        &p,
        &[],
        &chunked,
        Vec::new(),
        Some(SIGNED),
    );
    let mut wire = signer.signed_chunks(now, &seed, body, CHUNK, None);
    let sig_at = wire.len() - 64 - 4;
    wire[sig_at] = if wire[sig_at] == b'0' { b'1' } else { b'0' };
    out.push((
        "a bad signature on the final chunk",
        sized(req, wire),
        403,
        "SignatureDoesNotMatch",
    ));

    let mut req = mode_req(rig, signer, key, body, Mode::Unsigned);
    req.body.pop();
    out.push(("a body one byte short", req, 400, "IncompleteBody"));

    let mut req = mode_req(rig, signer, key, body, Mode::Unsigned);
    req.body.push(0);
    out.push(("a body one byte long", req, 400, "EntityTooLarge"));

    out
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_refused_in_its_last_slice_leaves_nothing_after_one_sweep() {
    let count = refused_bodies(
        &small_rig(),
        &Signer::new(AKID, secret()),
        "k",
        &pattern(1, 10 * SLICE),
    )
    .len();
    assert_eq!(count, 9);
    for case in 0..count {
        let rig = small_rig();
        let (bucket, signer) = rig.standard(BUCKET).await;
        // An object under the key, which the refused body must not harm.
        let old = pattern(9, 100);
        rig.put(&signer, BUCKET, "k", &old).await.expect(200);
        let old_id = rig.live(&bucket, "k").await.unwrap().0.id;
        rig.bridge.clock.advance_ms(1000);

        let body = pattern(1, 10 * SLICE);
        let (what, req, http, code) = refused_bodies(&rig, &signer, "k", &body).swap_remove(case);
        let r = send_in_pieces(&rig, req, 1000).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (http, code),
            "{what}: {}",
            r.text()
        );

        // No catalogue row and no recovery record of the refused write.
        assert_eq!(rig.count("generations"), 1, "{what}");
        assert_eq!(rig.count("extents"), 1, "{what}");
        assert_eq!(records(&rig), [old_id.as_str().to_string()], "{what}");
        // Its slices are in the safety bucket, every one with a row, and
        // the request has given them up.
        let left = orphans(&rig);
        assert!(left.len() >= 9, "{what}: {} slices stored", left.len());
        let rows = intents(&rig);
        assert_eq!(rows.len(), 10, "{what}");
        assert!(
            rows.iter()
                .all(|i| i.state == "abandoned" && i.generation.is_none()),
            "{what}: {rows:?}"
        );
        assert!(
            left.iter().all(|id| rows.iter().any(|i| i.extent == *id)),
            "{what}"
        );
        let s = intent_status(&rig).await;
        assert_eq!(
            (s["waiting_writes"].as_u64(), s["kept_writes"].as_u64()),
            (Some(1), Some(0)),
            "{what}: {s}"
        );

        // One sweep, without waiting for the grace period.
        assert_eq!(sweep_tick(&rig).await, 1, "{what}");
        assert!(orphans(&rig).is_empty(), "{what}");
        assert!(intents(&rig).is_empty(), "{what}");
        assert_eq!(records(&rig), [old_id.as_str().to_string()], "{what}");
        assert_eq!(
            get(&rig, &signer, "k").await.expect(200).body,
            old,
            "{what}"
        );
        let s = intent_status(&rig).await;
        assert_eq!(s["waiting_writes"], 0, "{what}: {s}");
        assert_eq!(s["anomalies"], 0, "{what}: {s}");
        assert_eq!(sweep_tick(&rig).await, 0, "{what}");
    }
}

// ---------------------------------------------------------------------------
// Memory: the charge of a sliced body
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn three_large_bodies_fill_the_budget_and_a_fourth_is_refused() {
    // The production ratio: the budget is six slices (48 MiB at 8 MiB).
    let budget = ingress::ByteBudget::new(6 * SLICE as u64);
    let rig = rig_with_budget(NoNntp, small_config(), budget);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(1, MAX_PUT);

    // The call at which the first slice is stored.
    let mut first_put = 0;
    loop {
        let ran = run_until(
            &rig,
            rig.send(mode_req(&rig, &signer, "probe", &body, Mode::Literal)),
            first_put,
            Trip::Stall,
        )
        .await;
        assert!(matches!(ran, Ran::Stalled(_)), "no slice was stored");
        if !intents(&rig).is_empty() && blobs(&rig).is_empty() && rig.bridge.budget.in_use() > 0 {
            // Stalled at the put of the first slice.
            break;
        }
        first_put += 1;
    }
    rig.trip().disarm();
    assert_eq!(
        rig.bridge.budget.in_use(),
        0,
        "a killed request gives its charge back"
    );

    let mut running = Vec::new();
    for key in ["a", "b", "c"] {
        let req = mode_req(&rig, &signer, key, &body, Mode::Literal);
        match run_until(&rig, rig.send(req), first_put, Trip::Stall).await {
            Ran::Stalled(fut) => running.push(fut),
            Ran::Done(r) => panic!("{key} ended: {}", r.text()),
        }
    }
    assert_eq!(rig.bridge.budget.in_use(), 6 * SLICE as u64);
    // No room, and no sleeper to wait with: refused before its body is read.
    let (r, polled) = rig
        .send_watched(mode_req(&rig, &signer, "d", &body, Mode::Literal))
        .await;
    r.expect_error(503, "SlowDown");
    assert!(!polled);
    // A body of one extent charges twice its length: refused as well.
    rig.put(&signer, BUCKET, "small", &pattern(2, SLICE))
        .await
        .expect_error(503, "SlowDown");

    rig.trip().release();
    for fut in running {
        fut.await.expect(200);
    }
    assert_eq!(rig.bridge.budget.in_use(), 0);
    assert_eq!(rig.bridge.budget.peak(), 6 * SLICE as u64);
    for key in ["a", "b", "c"] {
        assert_eq!(get(&rig, &signer, key).await.expect(200).body, body);
    }
}

// ---------------------------------------------------------------------------
// Tenancy
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn intent_rows_hold_the_default_tenant_and_no_extent_is_shared() {
    let rig = small_rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // The same body twice: nothing is adopted from the first write.
    let body = pattern(1, 5 * SLICE);

    let mut seen: Vec<Vec<Intent>> = Vec::new();
    for key in ["a", "b"] {
        // Stop each request once its rows exist, and look at them.
        let mut skip = 0;
        let fut = loop {
            let req = mode_req(&rig, &signer, key, &body, Mode::Literal);
            match run_until(&rig, rig.send(req), skip, Trip::Stall).await {
                Ran::Stalled(fut) if !intents(&rig).is_empty() => break fut,
                Ran::Stalled(_) => skip += 1,
                Ran::Done(r) => panic!("{key} ended: {}", r.text()),
            }
        };
        let rows = intents(&rig);
        assert_eq!(rows.len(), 5);
        assert!(
            blobs(&rig).len() == seen.len() * 5,
            "the rows are there before any slice of the write"
        );
        for row in &rows {
            assert_eq!(row.tenant, DEFAULT_TENANT);
            assert_eq!(row.state, "open");
            assert_eq!(row.generation, None);
            assert_eq!(row.write, rows[0].write);
            assert_eq!(row.created_at, rig.now().0);
        }
        resume(&rig, fut).await.expect(200);
        seen.push(rows);
    }
    assert_ne!(seen[0][0].write, seen[1][0].write);
    let ids = column(&rig, "SELECT id FROM extents ORDER BY id");
    assert_eq!(ids.len(), 10);
    for row in seen.iter().flatten() {
        assert!(ids.contains(&row.extent));
    }
    let mut unique = ids.clone();
    unique.dedup();
    assert_eq!(unique.len(), 10);
    assert_eq!(
        number(&rig, "SELECT COUNT(*) FROM pragma_table_info('write_intents') WHERE name = 'tenant_id' AND \"notnull\" = 1"),
        1
    );
}
