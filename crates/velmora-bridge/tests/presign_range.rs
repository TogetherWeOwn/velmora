mod service_support;

use std::rc::Rc;

use service_support::*;
use velmora_bridge::ingress;

#[tokio::test(flavor = "current_thread")]
async fn one_presigned_get_url_serves_ranges_and_the_whole_object() {
    let rig = rig();
    let bucket = "browser-media";
    let key = "video";
    let (_, signer) = rig.standard(bucket).await;
    let data = pattern(17, 100 * 1024);
    rig.put(&signer, bucket, key, &data).await.expect(200);
    let path = path(bucket, key);
    let len = data.len();

    for (range, start, end) in [
        (Some("bytes=1000-1999"), 1000, 2000),
        (Some("bytes=-500"), len - 500, len),
        (None, 0, len),
    ] {
        let mut req = signer.presign(rig.now(), &path);
        if let Some(range) = range {
            req.set_header("range", range);
        }
        let resp = fetch(&rig, req).await;
        let content_range = range.map(|_| format!("bytes {start}-{}/{len}", end - 1));
        resp.expect(if range.is_some() { 206 } else { 200 });
        assert_eq!(resp.header("content-range"), content_range.as_deref());
        assert_eq!(resp.body, data[start..end]);
    }
}

async fn fetch(rig: &Rig, req: Req) -> Resp {
    Resp::collect(
        ingress::front(req.into_request(), &rig.bridge.cfg, true, |req| {
            Rc::clone(&rig.bridge).handle(req)
        })
        .await,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn presigned_get_applies_unsigned_if_range_to_the_current_generation() {
    let rig = rig();
    let bucket = "browser-media";
    let key = "video";
    let (_, signer) = rig.standard(bucket).await;
    let data = b"0123456789";
    rig.put(&signer, bucket, key, data).await.expect(200);
    let path = path(bucket, key);
    let full = fetch(&rig, signer.presign(rig.now(), &path)).await;
    full.expect(200);
    let etag = full.header("etag").unwrap();
    let modified = full.header("last-modified").unwrap();
    let weak = format!("W/{etag}");

    for (validator, partial) in [
        (None, true),
        (Some(etag), true),
        (Some("\"other\""), false),
        (Some(weak.as_str()), false),
        (Some(modified), true),
        (Some("Fri, 01 Jan 2100 00:00:00 GMT"), false),
        (Some("invalid"), false),
    ] {
        let mut req = signer.presign(rig.now(), &path);
        req.set_header("range", "bytes=2-4");
        if let Some(validator) = validator {
            req.set_header("if-range", validator);
        }
        let resp = fetch(&rig, req).await;
        if partial {
            resp.expect(206);
            assert_eq!(resp.header("content-range"), Some("bytes 2-4/10"));
            assert_eq!(resp.body, &data[2..5]);
        } else {
            resp.expect(200);
            assert_eq!(resp.header("content-range"), None);
            assert_eq!(resp.body, data);
        }
    }
}
