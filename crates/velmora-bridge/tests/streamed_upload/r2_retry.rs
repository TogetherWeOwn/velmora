use super::*;
use velmora_bridge::ingress::settled_log_line;
use velmora_bridge::metrics::RequestObservation;

type Pauses = Rc<RefCell<Vec<u32>>>;
const NETWORK: &str = "r2: put failed: network lost";
const INTERNAL: &str = "r2: put failed: internal (10001)";

fn retry_rig(capacity: u64) -> (Rig, Pauses) {
    let mut rig = rig();
    let pauses = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&pauses);
    let clock = rig.bridge.clock.clone();
    let bridge = Rc::get_mut(&mut rig.bridge).unwrap();
    bridge.cfg.r2_put_retry = true;
    bridge.budget = ByteBudget::new(capacity).with_sleeper(Rc::new(move |ms| {
        seen.borrow_mut().push(ms);
        clock.advance_ms(i64::from(ms));
        Box::pin(async move {
            if ms == velmora_bridge::ingress::CHARGE_POLL_MS {
                tokio::task::yield_now().await;
            }
        })
    }));
    (rig, pauses)
}

fn script(rig: &Rig, failures: impl IntoIterator<Item = (FailMode, &'static str)>) {
    rig.bridge.safety.fail_puts.borrow_mut().extend(failures);
}

async fn send_observed(rig: &Rig, request: S3Request) -> (Resp, String) {
    let mut observation = RequestObservation::default();
    let target = request.raw_target.clone();
    let response = Rc::clone(&rig.bridge)
        .handle_observed(request, &mut observation)
        .await;
    let response = Resp::collect(response).await;
    let (_, log) = settled_log_line(
        "PUT",
        &target,
        "retry-test",
        false,
        response.status,
        response.status,
        &mut observation,
    );
    assert_eq!(rig.bridge.budget.in_use(), 0);
    (response, log)
}

async fn put(rig: &Rig, signer: &Signer, body: &[u8]) -> (Resp, String) {
    let request = in_pieces(mode_req(rig, signer, KEY, body, Mode::Literal), CHUNK_64K);
    send_observed(rig, request).await
}

fn assert_backoff(pauses: &Pauses, count: usize) {
    let pauses = pauses.borrow();
    assert_eq!(pauses.len(), count, "{pauses:?}");
    for (base, &actual) in [1_000, 2_000].into_iter().zip(pauses.iter()) {
        assert!((base..=base + 250).contains(&actual), "delay {actual}");
    }
}

fn assert_identical_replay(rig: &Rig, attempts: usize) {
    let streams = rig.bridge.safety.streams.borrow();
    assert_eq!(streams.len(), attempts);
    let key = &streams[0].key;
    assert_eq!(blobs(rig), [key.strip_prefix("x/").unwrap()]);
    let stored = rig.bridge.safety.stored(key).unwrap();
    assert!(streams
        .iter()
        .all(|s| &s.key == key && s.taken() == s.len && s.len == stored.bytes.len() as u64));
    for failed in rig.bridge.safety.failed_stream_bytes.borrow().iter() {
        assert!(stored.bytes == *failed, "replay changed the sealed bytes");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_retries_a_whole_16_mib_part_and_names_it_once() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    let id = create(&rig, &signer).await;
    let body = pattern(9, 16 * MIB);
    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    let req = mode_req_at(
        &rig,
        &signer,
        KEY,
        &[("partNumber", "1"), ("uploadId", &id)],
        &body,
        Mode::UnsignedTrailer,
    );
    let (r, log) = send_observed(&rig, in_pieces(req, 100_003)).await;
    r.expect(200);
    assert_eq!(r.header("etag"), Some(md5_etag(&body).as_str()));
    assert!(log.ends_with(" retries=1"), "{log}");
    assert_identical_replay(&rig, 2);
    assert_eq!(rows(&rig), (1, 0, 1));
    assert_backoff(&pauses, 1);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_of_a_landed_put_publishes_one_generation_and_one_extent() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (bucket, signer) = rig.standard(BUCKET).await;
    let body = pattern(2, 3 * CHUNK_64K);
    script(&rig, [(FailMode::StoreThenFail, INTERNAL)]);
    let (r, log) = put(&rig, &signer, &body).await;
    r.expect(200);
    assert!(log.ends_with(" retries=1"), "{log}");
    assert_backoff(&pauses, 1);
    assert_identical_replay(&rig, 2);
    assert_eq!(rows(&rig), (1, 1, 0));
    let (_, extents) = rig.live(&bucket, KEY).await.unwrap();
    let stored = rig
        .bridge
        .safety
        .stored(&extents[0].id.safety_key())
        .unwrap();
    assert_eq!(extents[0].cipher_sha256, sha256(&stored.bytes));
    assert!(get(&rig, &signer, KEY).await.body == body);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_can_succeed_on_the_third_attempt() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(3, 2 * CHUNK_64K);
    script(
        &rig,
        [
            (FailMode::ReadAllThenFail, NETWORK),
            (FailMode::StoreThenFail, INTERNAL),
        ],
    );
    let (r, log) = put(&rig, &signer, &body).await;
    r.expect(200);
    assert_identical_replay(&rig, 3);
    assert_backoff(&pauses, 2);
    assert_eq!(rows(&rig), (1, 1, 0));
    assert!(get(&rig, &signer, KEY).await.body == body);
    assert!(log.ends_with(" retries=2"), "{log}");
}

#[tokio::test(flavor = "current_thread")]
async fn replay_disabled_preserves_the_existing_transient_failure_response_and_log() {
    let (mut rig, pauses) = retry_rig(48 * MIB as u64);
    Rc::get_mut(&mut rig.bridge).unwrap().cfg.r2_put_retry = false;
    let (_, signer) = rig.standard(BUCKET).await;
    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    let (r, log) = put(&rig, &signer, b"payload").await;
    r.expect_error(500, "InternalError");
    assert!(
        log.ends_with(" stage=r2 err=Blob code=r2_put_network_lost"),
        "{log}"
    );
    assert_eq!(
        rig.bridge.budget.peak(),
        stream_charge(b"payload".len() as u64)
    );
    only_stream(&rig);
    assert_backoff(&pauses, 0);
    assert_eq!(rows(&rig), (0, 0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn replay_never_retries_an_initial_md5_mismatch() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bridge.safety.false_receipt.set(Some(|mut receipt| {
        receipt.md5[0] ^= 1;
        receipt
    }));
    let (r, log) = put(&rig, &signer, b"payload").await;
    r.expect_error(500, "InternalError");
    assert!(
        log.ends_with(" stage=r2 err=StoredMd5Mismatch code=-"),
        "{log}"
    );
    only_stream(&rig);
    assert_backoff(&pauses, 0);
    assert_eq!(rows(&rig), (0, 0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn replay_stops_at_three_attempts_and_logs_the_last_fault() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    script(
        &rig,
        [
            (FailMode::ReadAllThenFail, INTERNAL),
            (FailMode::ReadAllThenFail, "r2: put failed: timeout"),
            (FailMode::ReadAllThenFail, NETWORK),
        ],
    );
    let (r, log) = put(&rig, &signer, b"payload").await;
    r.expect_error(500, "InternalError");
    assert_eq!(rig.bridge.safety.streams.borrow().len(), 3);
    assert!(
        log.ends_with(" stage=r2 err=Blob code=r2_put_network_lost retries=2"),
        "{log}"
    );
    assert_backoff(&pauses, 2);
    assert_eq!(rows(&rig), (0, 0, 0));
    assert!(blobs(&rig).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn replay_checks_both_receipt_fields_and_does_not_repeat_a_mismatch() {
    let lies: [(ReceiptLie, &str); 2] = [
        (
            |r| PutReceipt {
                size: r.size - 1,
                ..r
            },
            "StoredSizeMismatch",
        ),
        (
            |mut r| {
                r.md5[15] ^= 1;
                r
            },
            "StoredMd5Mismatch",
        ),
    ];
    for (lie, fault) in lies {
        let (rig, pauses) = retry_rig(48 * MIB as u64);
        let (_, signer) = rig.standard(BUCKET).await;
        rig.bridge.safety.false_receipt.set(Some(lie));
        script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
        let (r, log) = put(&rig, &signer, b"payload").await;
        r.expect_error(500, "InternalError");
        assert_eq!(rig.bridge.safety.streams.borrow().len(), 2, "{fault}");
        assert!(
            log.ends_with(&format!(" stage=r2 err={fault} code=- retries=1")),
            "{log}"
        );
        assert_backoff(&pauses, 1);
        assert_eq!(rows(&rig), (0, 0, 0));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_put_classification_accepts_only_allowlisted_failures() {
    let cases = [
        (true, "r2: put failed: network lost"),
        (true, "r2: put failed: timeout"),
        (true, "r2: put failed: internal"),
        (true, "r2: put failed: internal (10001)"),
        (true, "r2: put failed (10001)"),
        (true, "r2: put failed (10043)"),
        (true, "r2: put failed (10058)"),
        (false, "r2: put failed (10014)"),
        (false, "r2: put failed (10054)"),
        (false, "r2: put failed: internal (10054)"),
        (false, "r2: put failed: timeout (10014)"),
        (false, "r2: put failed: stream"),
        (false, "r2: put failed: stream (10001)"),
        (false, "r2: put returned no object"),
        (false, "r2: put returned no md5"),
        (false, "r2: get failed: timeout"),
        (false, "store down"),
    ];
    for (allowed, error) in cases.into_iter().rev() {
        let (rig, pauses) = retry_rig(48 * MIB as u64);
        let (_, signer) = rig.standard(BUCKET).await;
        script(&rig, [(FailMode::ReadAllThenFail, error)]);
        let (r, _) = put(&rig, &signer, b"payload").await;
        r.expect(if allowed { 200 } else { 500 });
        assert_eq!(
            rig.bridge.safety.streams.borrow().len(),
            1 + usize::from(allowed),
            "{error}"
        );
        assert_backoff(&pauses, usize::from(allowed));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_does_not_read_the_rest_of_an_early_stop_or_retry_a_stream_fault() {
    let (rig, pauses) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(4, 3 * CHUNK_64K);
    rig.bridge.safety.stop_stream_after.set(Some(1));
    rig.bridge.safety.stop_stream_error.set(Some(NETWORK));
    put(&rig, &signer, &body)
        .await
        .0
        .expect_error(500, "InternalError");
    assert!(only_stream(&rig).taken() < ciphertext_size(body.len() as u64).unwrap());
    assert_backoff(&pauses, 0);

    rig.bridge.safety.stop_stream_after.set(None);
    rig.bridge.safety.streams.borrow_mut().clear();
    let mut request = in_pieces(mode_req(&rig, &signer, KEY, &body, Mode::Literal), 4099);
    let Body::Stream {
        declared_len,
        stream,
    } = request.body
    else {
        panic!("missing body")
    };
    request.body = Body::Stream {
        declared_len,
        stream: stream
            .take(20)
            .chain(stream::iter([Err(BridgeError::Blob(NETWORK.into()))]))
            .boxed_local(),
    };
    Resp::collect(Rc::clone(&rig.bridge).handle(request).await)
        .await
        .expect_error(400, "IncompleteBody");
    assert!(only_stream(&rig).failed);
    assert_eq!(rows(&rig), (0, 0, 0));
    assert_eq!(rig.bridge.budget.in_use(), 0);
    assert_backoff(&pauses, 0);

    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    put(&rig, &signer, &body).await.0.expect(200);
    assert_backoff(&pauses, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_skips_the_copy_and_wait_when_only_the_stream_window_fits() {
    let capacity = 48 * MIB as u64;
    let (rig, pauses) = retry_rig(capacity);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(4, MIB);
    let occupied = rig
        .bridge
        .budget
        .try_charge(capacity - STREAM_CHARGE_BYTES)
        .unwrap();
    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    send_in_pieces(
        &rig,
        mode_req(&rig, &signer, KEY, &body, Mode::Literal),
        CHUNK_64K,
    )
    .await
    .expect_error(500, "InternalError");
    only_stream(&rig);
    assert_backoff(&pauses, 0);
    assert_eq!(rig.bridge.budget.peak(), capacity);
    assert_eq!(rig.bridge.budget.in_use(), occupied.bytes());
    drop(occupied);
    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    put(&rig, &signer, &body).await.0.expect(200);
    assert_backoff(&pauses, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_never_starts_after_the_twenty_second_cutoff() {
    for (at_first_failure, attempts, sleeps) in [(20_001, 1, 0), (19_500, 1, 0), (18_500, 2, 1)] {
        let (rig, pauses) = retry_rig(48 * MIB as u64);
        let (_, signer) = rig.standard(BUCKET).await;
        let clock = rig.bridge.clock.clone();
        let mut advance = Some(at_first_failure);
        *rig.bridge.safety.at_stream_end.borrow_mut() = Some(Box::new(move |_| {
            if let Some(ms) = advance.take() {
                clock.advance_ms(ms);
            }
        }));
        script(&rig, [(FailMode::ReadAllThenFail, NETWORK); 3]);
        put(&rig, &signer, b"payload")
            .await
            .0
            .expect_error(500, "InternalError");
        assert_eq!(
            rig.bridge.safety.streams.borrow().len(),
            attempts,
            "at {at_first_failure}ms"
        );
        assert_backoff(&pauses, sleeps);
        assert_eq!(rows(&rig), (0, 0, 0));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn replay_does_not_overtake_a_waiter_blocked_only_by_the_stream_window() {
    let capacity = 48 * MIB as u64;
    let (rig, pauses) = retry_rig(capacity);
    let (_, signer) = rig.standard(BUCKET).await;
    let body = pattern(1, MIB);
    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    put(&rig, &signer, &body).await.0.expect(200);
    assert_backoff(&pauses, 1);
    rig.bridge.safety.streams.borrow_mut().clear();
    pauses.borrow_mut().clear();

    // List the waiter with a temporary charge. Leave it waiting while a
    // new upload starts; then only the upload would keep the waiter out.
    let budget = &rig.bridge.budget;
    let blocker = budget.try_charge(STREAM_CHARGE_BYTES).unwrap();
    let mut waiter = Box::pin(budget.charge(capacity - STREAM_CHARGE_BYTES + 1));
    let first_poll = std::future::poll_fn(|cx| {
        std::task::Poll::Ready(std::future::Future::poll(waiter.as_mut(), cx))
    });
    assert!(first_poll.await.is_pending());
    drop(blocker);
    pauses.borrow_mut().clear();

    script(&rig, [(FailMode::ReadAllThenFail, NETWORK)]);
    put(&rig, &signer, &body)
        .await
        .0
        .expect_error(500, "InternalError");
    assert_backoff(&pauses, 0);
    only_stream(&rig);
    let charge = waiter.await.unwrap();
    drop(charge);
    assert_eq!(budget.in_use(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_reservation_is_released_if_the_store_panics() {
    use futures_util::FutureExt as _;
    let (rig, _) = retry_rig(48 * MIB as u64);
    let (_, signer) = rig.standard(BUCKET).await;
    let bridge = Rc::clone(&rig.bridge);
    let bytes = pattern(4, MIB);
    let held = Rc::new(Cell::new(0));
    let capture = Rc::clone(&held);
    *rig.bridge.safety.on_piece.borrow_mut() = Some(Box::new(move |_| {
        capture.set(bridge.budget.in_use());
        panic!("intentional simulated store panic");
    }));
    assert!(std::panic::AssertUnwindSafe(put(&rig, &signer, &bytes))
        .catch_unwind()
        .await
        .is_err());
    rig.bridge.safety.on_piece.borrow_mut().take();
    assert_eq!(rig.bridge.budget.in_use(), 0);
    assert_eq!(
        held.get(),
        STREAM_CHARGE_BYTES + ciphertext_size(bytes.len() as u64).unwrap()
    );
}
