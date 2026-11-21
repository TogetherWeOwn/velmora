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
        let resp = Resp::collect(
            ingress::front(req.into_request(), &rig.bridge.cfg, true, |req| {
                Rc::clone(&rig.bridge).handle(req)
            })
            .await,
        )
        .await;
        let content_range = range.map(|_| format!("bytes {start}-{}/{len}", end - 1));
        resp.expect(if range.is_some() { 206 } else { 200 });
        assert_eq!(resp.header("content-range"), content_range.as_deref());
        assert_eq!(resp.body, data[start..end]);
    }
}
