//! DeleteObjects answers `200` once the request can no longer fail with
//! a status code, and its document may follow its headers: the XML
//! declaration at once, a whitespace byte now and then while keys are
//! deleted, then the `DeleteResult`. The streamed document is valid XML
//! and says for each key what the buffered one says; a failure while it
//! streams is the answer for the keys it hit, and the document is whole.
//! The deletes run apart from the body: a client that stops reading
//! leaves what a client that read the answer leaves.

mod service_support;

use std::rc::Rc;

use base64::Engine as _;
use futures_util::StreamExt;
use quick_xml::events::Event;
use service_support::*;
use velmora_bridge::ingress::Sleeper;
use velmora_bridge::keepalive::{self, Deferred, XML_DECLARATION};
use velmora_bridge::recovery::TOMBSTONE_PREFIX;
use velmora_bridge::*;

const BUCKET: &str = "bkt-keepalive";

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

/// A window that never elapses.
fn never() -> Sleeper {
    Rc::new(|_ms| Box::pin(std::future::pending()))
}

fn delete_xml(keys: &[String]) -> String {
    let mut xml = String::from("<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    for key in keys {
        xml.push_str(&format!(
            "<Object><Key>{}</Key></Object>",
            key.replace('&', "&amp;").replace('<', "&lt;")
        ));
    }
    xml.push_str("</Delete>");
    xml
}

fn delete_request(rig: &Rig, signer: &Signer, keys: &[String]) -> S3Request {
    let xml = delete_xml(keys);
    let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(xml.as_bytes()).0);
    signer
        .sign(
            rig.now(),
            Method::Post,
            &format!("/{BUCKET}"),
            &[("delete", "")],
            &[("content-md5", &md5)],
            xml.into_bytes(),
        )
        .into_request()
}

/// A rig with `n` objects, and its keys. Two keys need escaping, one is
/// named twice and one does not exist.
async fn scene(n: usize) -> (Rig, Signer, Vec<String>) {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut keys: Vec<String> = (0..n).map(|i| format!("dir/k{i:03}")).collect();
    keys.push("a&b<c".to_string());
    for key in &keys {
        rig.put(&signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
    keys.push("dir/k000".to_string());
    keys.push("never-written".to_string());
    rig.bridge.clock.advance_ms(1000);
    (rig, signer, keys)
}

/// The response of a DeleteObjects, not yet read.
async fn send(rig: &Rig, signer: &Signer, keys: &[String]) -> S3Response {
    Rc::clone(&rig.bridge)
        .handle(delete_request(rig, signer, keys))
        .await
}

fn deferred(resp: S3Response) -> Deferred {
    assert_eq!(resp.status, 200);
    match resp.body {
        RespBody::Deferred(d) => d,
        _ => panic!("a DeleteObjects answer is deferred"),
    }
}

fn live_keys(rig: &Rig) -> usize {
    rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get::<_, i64>(0))
            .unwrap()
    }) as usize
}

/// Reads `body` with a strict reader: one declaration first, only
/// whitespace before the root, one `DeleteResult` root, every end tag
/// matched. Returns the bytes from the root on.
fn check_document(body: &[u8]) -> &[u8] {
    assert!(body.starts_with(XML_DECLARATION), "declaration first");
    let mut reader = quick_xml::Reader::from_reader(body);
    reader.config_mut().check_end_names = true;
    let (mut decls, mut roots, mut depth) = (0, 0, 0usize);
    loop {
        match reader.read_event().expect("well-formed XML") {
            Event::Decl(_) => {
                assert_eq!((roots, depth), (0, 0));
                decls += 1;
            }
            Event::Text(t) if depth == 0 => {
                let raw: &str = &t.into_inner();
                assert!(
                    raw.bytes().all(|b| b.is_ascii_whitespace()),
                    "only whitespace"
                );
            }
            Event::Start(e) => {
                if depth == 0 {
                    let qname = e.name();
                    let name: &str = qname.as_ref();
                    assert_eq!(name, "DeleteResult");
                    roots += 1;
                }
                depth += 1;
            }
            Event::End(_) => depth -= 1,
            Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!((decls, roots, depth), (1, 1, 0));
    let after_decl = XML_DECLARATION.len();
    let start = after_decl
        + body[after_decl..]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap();
    &body[start..]
}

/// Reads the body to its end; counts the keepalive bytes.
async fn read_all(mut body: ByteStream) -> (Vec<u8>, usize) {
    let (mut out, mut keepalives) = (Vec::new(), 0);
    while let Some(chunk) = body.next().await {
        let chunk = chunk.expect("a keepalive body never fails");
        if chunk == keepalive::KEEPALIVE_BYTE {
            keepalives += 1;
        }
        out.extend(chunk);
    }
    (out, keepalives)
}

/// The buffered answer of the same request on a rig of its own.
async fn buffered(n: usize) -> Vec<u8> {
    let (rig, signer, keys) = scene(n).await;
    let resp = send(&rig, &signer, &keys).await;
    let doc = deferred(resp)
        .settle(Box::pin(std::future::pending()))
        .await
        .unwrap_or_else(|_| panic!("the window never elapses"));
    assert_eq!(live_keys(&rig), 0);
    doc
}

/// While the tombstones are held up, the body sends the declaration and
/// whitespace; then the document, which is valid XML and the bytes of
/// the buffered answer.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_delete_streams_the_buffered_document_after_keepalives() {
    let expected = buffered(120).await;
    assert!(expected.starts_with(b"<DeleteResult"));

    let (rig, signer, keys) = scene(120).await;
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    let resp = send(&rig, &signer, &keys).await;
    let mut body = deferred(resp).into_stream(quick_ticks(), 5_000);
    assert_eq!(body.next().await.unwrap().unwrap(), XML_DECLARATION);
    for _ in 0..3 {
        assert_eq!(
            body.next().await.unwrap().unwrap(),
            keepalive::KEEPALIVE_BYTE
        );
    }
    assert!(rig.bridge.safety.held.get());
    assert_eq!(live_keys(&rig), 121);
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = None;

    let (rest, _) = read_all(body).await;
    let mut whole = XML_DECLARATION.to_vec();
    whole.extend(std::iter::repeat_n(b'\n', 3));
    whole.extend(rest);
    assert_eq!(check_document(&whole), expected.as_slice());
    assert_eq!(live_keys(&rig), 0);
}

/// Tombstone puts that fail once the headers are out are the answer of
/// the keys they hit: `InternalError` for each, in a whole document, and
/// nothing deleted without its tombstone.
#[tokio::test(flavor = "current_thread")]
async fn a_failure_after_the_headers_is_a_per_key_error() {
    let (rig, signer, keys) = scene(60).await;
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    let resp = send(&rig, &signer, &keys).await;
    let mut body = deferred(resp).into_stream(quick_ticks(), 5_000);
    assert_eq!(body.next().await.unwrap().unwrap(), XML_DECLARATION);
    assert_eq!(
        body.next().await.unwrap().unwrap(),
        keepalive::KEEPALIVE_BYTE
    );
    // The store goes down under the request.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = None;
    let (rest, _) = read_all(body).await;
    let mut whole = XML_DECLARATION.to_vec();
    whole.push(b'\n');
    whole.extend(rest);
    let doc = String::from_utf8(check_document(&whole).to_vec()).unwrap();
    // Every key that exists failed; the one never written needs no
    // tombstone and is deleted.
    assert_eq!(doc.matches("<Code>InternalError</Code>").count(), 62);
    assert_eq!(doc.matches("<Deleted>").count(), 1);
    assert!(doc.contains("<Deleted><Key>never-written</Key></Deleted>"));
    assert!(doc.contains("<Error><Key>a&amp;b&lt;c</Key><Code>InternalError</Code>"));
    assert!(doc.ends_with("</DeleteResult>"));
    assert_eq!(live_keys(&rig), 61);

    // Sent again with the store back, the request converges.
    *rig.bridge.safety.fail_put_prefix.borrow_mut() = None;
    let again = Resp::collect(send(&rig, &signer, &keys).await).await;
    again.expect(200);
    assert!(!again.text().contains("<Error>"));
    assert_eq!(live_keys(&rig), 0);
}

/// Work that is dropped before it is done is answered as a failure of
/// every key, in a whole document.
#[tokio::test(flavor = "current_thread")]
async fn work_that_is_dropped_closes_the_document_with_errors() {
    let (rig, signer, keys) = scene(10).await;
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    let mut d = deferred(send(&rig, &signer, &keys).await);
    let mut work = d.take_work().expect("the work, once");
    assert!(d.take_work().is_none());
    // Start the work, then drop it while its tombstones are held up.
    assert!(futures_util::FutureExt::now_or_never(&mut work).is_none());
    drop(work);
    let (whole, _) = read_all(d.into_stream(quick_ticks(), 5_000)).await;
    let doc = String::from_utf8(check_document(&whole).to_vec()).unwrap();
    assert_eq!(
        doc.matches("<Code>InternalError</Code>").count(),
        keys.len()
    );
    assert_eq!(doc.matches("<Error>").count(), keys.len());
    assert_eq!(live_keys(&rig), 11);
}

/// The adapter drives the work apart from the body: a client that goes
/// away after the first bytes leaves every key deleted.
#[tokio::test(flavor = "current_thread")]
async fn a_client_that_goes_away_leaves_the_deletes_done() {
    let (rig, signer, keys) = scene(80).await;
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    let mut d = deferred(send(&rig, &signer, &keys).await);
    let work = d.take_work().unwrap();
    let mut body = d.into_stream(quick_ticks(), 5_000);
    assert_eq!(body.next().await.unwrap().unwrap(), XML_DECLARATION);
    drop(body);
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = None;
    work.await;
    assert_eq!(live_keys(&rig), 0);
}

/// A body whose work was taken waits for it, and has its document once
/// the work is done.
#[tokio::test(flavor = "current_thread")]
async fn a_body_waits_for_work_that_runs_elsewhere() {
    let expected = buffered(30).await;
    let (rig, signer, keys) = scene(30).await;
    let mut d = deferred(send(&rig, &signer, &keys).await);
    let work = d.take_work().unwrap();
    let body = d.into_stream(quick_ticks(), 5_000);
    let ((whole, _), ()) = tokio::join!(read_all(body), work);
    assert_eq!(check_document(&whole), expected.as_slice());
}

/// `settle_response`: a document that is done within the window is sent
/// buffered, as before; one that is not is streamed, without a length,
/// and marked so the edge does not compress it.
#[tokio::test(flavor = "current_thread")]
async fn a_fast_delete_is_buffered_and_a_slow_one_streamed() {
    let expected = buffered(20).await;
    let (rig, signer, keys) = scene(20).await;
    let resp = keepalive::settle_response(send(&rig, &signer, &keys).await, never()).await;
    assert_eq!(resp.status, 200);
    let RespBody::Bytes(doc) = resp.body else {
        panic!("a fast answer is buffered");
    };
    assert_eq!(doc, expected);
    assert!(!resp.headers.iter().any(|(n, _)| n == "cache-control"));

    let (rig, signer, keys) = scene(20).await;
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = Some(TOMBSTONE_PREFIX.to_string());
    let resp = keepalive::settle_response(send(&rig, &signer, &keys).await, quick_ticks()).await;
    assert_eq!(resp.status, 200);
    assert!(resp
        .headers
        .contains(&("cache-control".to_string(), "no-transform".to_string())));
    assert!(resp
        .headers
        .contains(&("content-type".to_string(), "application/xml".to_string())));
    assert!(!resp.headers.iter().any(|(n, _)| n == "content-length"));
    let RespBody::Stream(mut body) = resp.body else {
        panic!("a slow answer is streamed");
    };
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(first, XML_DECLARATION);
    *rig.bridge.safety.hold_put_prefix.borrow_mut() = None;
    let (rest, keepalives) = read_all(body).await;
    let mut whole = first;
    whole.extend(rest);
    assert_eq!(check_document(&whole), expected.as_slice());
    assert!(keepalives <= 1, "{keepalives}");
}

/// What fails before the answer keeps its status code: nothing is
/// deferred.
#[tokio::test(flavor = "current_thread")]
async fn a_request_that_fails_before_the_answer_keeps_its_status() {
    let (rig, signer, keys) = scene(3).await;
    let mut req = delete_request(&rig, &signer, &keys);
    req.headers.retain(|(n, _)| n != "content-md5");
    let resp = Rc::clone(&rig.bridge).handle(req).await;
    assert_ne!(resp.status, 200);
    assert!(!matches!(resp.body, RespBody::Deferred(_)));

    let resp = Rc::clone(&rig.bridge)
        .handle(
            signer
                .sign(
                    rig.now(),
                    Method::Post,
                    &format!("/{BUCKET}"),
                    &[("delete", "")],
                    &[],
                    b"<Delete><Object><Key>k</Key></Object></Delete>".to_vec(),
                )
                .into_request(),
        )
        .await;
    assert_eq!(resp.status, 400);
    assert!(!matches!(resp.body, RespBody::Deferred(_)));
    assert_eq!(live_keys(&rig), 4);
}
