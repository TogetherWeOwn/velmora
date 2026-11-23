//! Overwrites, deletes and property edits that race another writer, and
//! the bounds of a listing: each test is one review finding's schedule.

mod support;

use support::*;
use velmora_dav::handler::Config;
use velmora_dav::http::{Body, Request};

const LIST_DOCS: &str = "/dav?encoding-type=url&list-type=2&max-keys=1000&prefix=docs%2F";

fn set_prop(name: &str, value: &str) -> Vec<u8> {
    format!(
        r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><Z:{name} xmlns:Z="urn:z">{value}</Z:{name}></D:prop></D:set></D:propertyupdate>"#
    )
    .into_bytes()
}

async fn all_props(w: &World, path: &str) -> String {
    let r = w
        .req(
            "PROPFIND",
            path,
            &[("depth", "0")],
            br#"<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#,
        )
        .await;
    r.expect(207);
    r.text()
}

#[tokio::test]
async fn a_collection_overwrite_keeps_a_same_named_file() {
    let w = World::new().await;
    for (key, body) in [
        ("archive", &b"file bytes"[..]),
        ("archive/old.txt", b"old"),
        ("incoming/new.txt", b"new"),
    ] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    w.req(
        "COPY",
        "/dav/incoming/",
        &[("destination", "/dav/archive/"), ("overwrite", "T")],
        b"",
    )
    .await
    .expect(204);
    assert_eq!(w.s3_get("archive").await.1, b"file bytes");
    assert_eq!(w.s3_get("archive/new.txt").await.1, b"new");
    assert_eq!(w.s3_get("archive/old.txt").await.0, 404);
}

#[tokio::test]
async fn a_folder_delete_keeps_an_upload_that_replaced_a_listed_file() {
    let w = World::new().await;
    for (key, body) in [("docs/report.txt", &b"A"[..]), ("docs/other.txt", b"x")] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    // An S3 sync replaces the file after the DELETE listed it.
    w.storage_fault_target(
        "GET",
        LIST_DOCS,
        StorageFault::Replace {
            key: "docs/report.txt".into(),
            body: b"B".to_vec(),
        },
    );
    let r = w.req("DELETE", "/dav/docs/", &[], b"").await;
    r.expect(207);
    assert!(r.text().contains("/dav/docs/report.txt"), "{}", r.text());
    assert_eq!(w.s3_get("docs/report.txt").await.1, b"B");
    assert_eq!(w.s3_get("docs/other.txt").await.0, 404);
}

#[tokio::test]
async fn a_folder_delete_counts_a_member_deleted_meanwhile_as_deleted() {
    let w = World::new().await;
    for (key, body) in [("docs/report.txt", &b"A"[..]), ("docs/other.txt", b"x")] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault_target("GET", LIST_DOCS, StorageFault::Pause { reached, resume });
    let mut deleting = std::pin::pin!(w.req("DELETE", "/dav/docs/", &[], b""));
    tokio::select! {
        r = deleting.as_mut() => panic!("DELETE finished before its listing paused: {}", r.status),
        r = waiting => r.unwrap(),
    }
    // An S3 client deletes a listed file before the DELETE reaches it.
    assert_eq!(w.s3_delete("docs/report.txt").await, 204);
    release.send(()).unwrap();
    deleting.await.expect(204);
    assert!(w.s3_list("docs/").await.is_empty());
}

#[tokio::test]
async fn a_property_edit_racing_a_save_keeps_both_properties() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"A").await.expect(201);
    w.req(
        "PROPPATCH",
        "/dav/f",
        &[],
        &set_prop("title", "title-value"),
    )
    .await
    .expect(207);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    // The edit has read ETag A when the save of B runs to the end.
    w.storage_fault("HEAD", "f", StorageFault::Pause { reached, resume });
    let rating = set_prop("rating", "rating-value");
    let mut patching = std::pin::pin!(w.req("PROPPATCH", "/dav/f", &[], &rating));
    tokio::select! {
        r = patching.as_mut() => panic!("PROPPATCH finished before the pause: {}", r.status),
        r = waiting => r.unwrap(),
    }
    w.req("PUT", "/dav/f", &[], b"B").await.expect(204);
    release.send(()).unwrap();
    let r = patching.await;
    r.expect(207);
    assert!(r.text().contains("HTTP/1.1 200 OK"), "{}", r.text());
    let props = all_props(&w, "/dav/f").await;
    assert!(props.contains("title-value"), "{props}");
    assert!(props.contains("rating-value"), "{props}");
}

#[tokio::test]
async fn a_property_edit_waits_for_a_save_in_progress() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"A").await.expect(201);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("PUT", "f", StorageFault::Pause { reached, resume });
    let mut saving = std::pin::pin!(w.req("PUT", "/dav/f", &[], b"B"));
    tokio::select! {
        r = saving.as_mut() => panic!("PUT finished before the pause: {}", r.status),
        r = waiting => r.unwrap(),
    }
    let r = w
        .req(
            "PROPPATCH",
            "/dav/f",
            &[],
            &set_prop("rating", "rating-value"),
        )
        .await;
    r.expect(503);
    assert_eq!(r.header("retry-after"), Some("2"));
    release.send(()).unwrap();
    saving.await.expect(204);
    w.req(
        "PROPPATCH",
        "/dav/f",
        &[],
        &set_prop("rating", "rating-value"),
    )
    .await
    .expect(207);
    assert!(all_props(&w, "/dav/f").await.contains("rating-value"));
}

/// A partial MOVE of src/ to dst/: src/a changes while the copies
/// settle, so only src/b goes, and dst/b holds its only copy.
async fn partial_move(w: &World) {
    for (key, body) in [("src/a", &b"old a"[..]), ("src/b", b"old b")] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("PUT", "dst/", StorageFault::Pause { reached, resume });
    let mut moving =
        std::pin::pin!(w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b""));
    tokio::select! {
        r = moving.as_mut() => panic!("MOVE finished before the pause: {}", r.status),
        r = waiting => r.unwrap(),
    }
    assert_eq!(w.s3_put("src/a", b"new a").await, 200);
    release.send(()).unwrap();
    moving.await.expect(207);
    assert_eq!(w.s3_get("src/b").await.0, 404);
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
}

#[tokio::test]
async fn a_folder_overwrite_refuses_to_replace_a_member_kept_after_a_partial_move() {
    let w = World::new().await;
    partial_move(&w).await;
    assert_eq!(w.s3_put("other/b", b"other b").await, 200);
    let before = w.s3_list("").await;
    let r = w
        .req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b"")
        .await;
    r.expect(207);
    assert!(
        r.text().contains("kept after a partial MOVE"),
        "{}",
        r.text()
    );
    assert!(r.text().contains("/dav/dst/b"), "{}", r.text());
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
    assert_eq!(w.s3_list("").await, before);
}

#[tokio::test]
async fn an_identical_copy_keeps_the_partial_move_record() {
    let w = World::new().await;
    partial_move(&w).await;
    // The same bytes from another folder: refused, so the record that
    // keeps dst/b from a prune stays.
    assert_eq!(w.s3_put("other/b", b"old b").await, 200);
    let r = w
        .req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b"")
        .await;
    r.expect(207);
    assert!(r.text().contains("/dav/dst/b"), "{}", r.text());
    // A later overwrite that leaves dst/b out keeps it.
    assert_eq!(w.s3_put("third/c", b"c").await, 200);
    w.req("COPY", "/dav/third/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(207);
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
}

#[tokio::test]
async fn a_property_edit_with_a_stale_if_match_is_refused() {
    let w = World::new().await;
    let first = w.req("PUT", "/dav/f", &[], b"A").await;
    first.expect(201);
    let stale = first.header("etag").unwrap().to_owned();
    w.req("PUT", "/dav/f", &[], b"B").await.expect(204);
    w.req("PROPPATCH", "/dav/f", &[], &set_prop("title", "current"))
        .await
        .expect(207);
    w.req(
        "PROPPATCH",
        "/dav/f",
        &[("if-match", &stale)],
        &set_prop("title", "stale"),
    )
    .await
    .expect(412);
    let props = all_props(&w, "/dav/f").await;
    assert!(props.contains("current"), "{props}");
    assert!(!props.contains("stale"), "{props}");
}

#[tokio::test]
async fn lock_discovery_of_a_large_listing_is_bounded() {
    let w = World::new().await;
    for i in 0..2000 {
        assert_eq!(w.s3_put(&format!("big/{i:04}"), b"x").await, 200);
    }
    // Eight shared depth-infinity locks, each with an owner near the cap:
    // every child inherits all eight.
    let owner = "o".repeat(900);
    let discovery = propfind_body(&["lockdiscovery"]);
    w.req("LOCK", "/dav/big/", &[], &lockinfo("shared", &owner))
        .await
        .expect(200);
    // One such lock over the listing is answered.
    let r = w
        .req("PROPFIND", "/dav/big/", &[("depth", "1")], &discovery)
        .await;
    r.expect(207);
    assert_eq!(r.text().matches("<D:activelock>").count(), 2001);
    for _ in 1..8 {
        w.req("LOCK", "/dav/big/", &[], &lockinfo("shared", &owner))
            .await
            .expect(200);
    }
    w.req("PROPFIND", "/dav/big/", &[("depth", "1")], &discovery)
        .await
        .expect(507);
    // A request that does not show lock discovery is not refused for it.
    let custom =
        br#"<D:propfind xmlns:D="DAV:"><D:prop><Z:title xmlns:Z="urn:z"/></D:prop></D:propfind>"#;
    let propname = br#"<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>"#;
    for body in [&custom[..], &propname[..]] {
        let r = w
            .req("PROPFIND", "/dav/big/", &[("depth", "1")], body)
            .await;
        r.expect(207);
        assert_eq!(r.hrefs().len(), 2001);
    }
    // A single resource still answers.
    let r = w
        .req("PROPFIND", "/dav/big/0001", &[("depth", "0")], &discovery)
        .await;
    r.expect(207);
    assert_eq!(r.text().matches("<D:activelock>").count(), 8);
}

#[tokio::test]
async fn dead_property_quota_counts_bytes_of_stored_values() {
    let w = World::new().await;
    assert_eq!(w.s3_put("f", b"x").await, 200);
    // Four values of 62 KiB of UTF-8 each, but half as many characters.
    let value = "é".repeat(31 * 1024);
    let mut four = String::from(r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>"#);
    for name in ["a", "b", "c", "d"] {
        four.push_str(&format!(r#"<{name} xmlns="urn:test">{value}</{name}>"#));
    }
    four.push_str("</D:prop></D:set></D:propertyupdate>");
    let r = w.req("PROPPATCH", "/dav/f", &[], four.as_bytes()).await;
    r.expect(207);
    assert!(!r.text().contains("HTTP/1.1 507"), "{}", r.text());
    // A fifth takes the resource past 256 KiB.
    let fifth = format!(
        r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><e xmlns="urn:test">{value}</e></D:prop></D:set></D:propertyupdate>"#
    );
    let r = w.req("PROPPATCH", "/dav/f", &[], fifth.as_bytes()).await;
    r.expect(207);
    assert!(r.text().contains("HTTP/1.1 507"), "{}", r.text());
}

#[tokio::test]
async fn a_capped_browser_index_says_that_entries_are_missing() {
    let w = World::with(Config {
        max_listing: 2,
        ..Config::default()
    })
    .await;
    for key in ["docs/a", "docs/b", "docs/c", "small/a"] {
        assert_eq!(w.s3_put(key, b"x").await, 200);
    }
    let r = w.req("GET", "/dav/docs/", &[], b"").await;
    r.expect(200);
    assert!(r.text().contains("Not every item is shown"), "{}", r.text());
    let r = w.req("GET", "/dav/small/", &[], b"").await;
    r.expect(200);
    assert!(
        !r.text().contains("Not every item is shown"),
        "{}",
        r.text()
    );
}

#[tokio::test]
async fn basic_auth_is_refused_over_plain_http() {
    let w = World::new().await;
    assert_eq!(w.s3_put("f", b"x").await, 200);
    let send = |origin: &str| {
        w.dav.handle(Request {
            method: "GET".into(),
            origin: origin.to_owned(),
            path: "/dav/f".into(),
            headers: vec![
                ("host".into(), DAV_HOST.into()),
                ("authorization".into(), basic(APP, APP_SECRET)),
            ],
            body: Body::Empty,
        })
    };
    let r = send(&format!("http://{DAV_HOST}")).await;
    assert_eq!(r.status, 403);
    assert!(!r.headers.iter().any(|(n, _)| n == "www-authenticate"));
    // Loopback (a local test run) and HTTPS are served.
    assert_eq!(send("http://127.0.0.1:8788").await.status, 200);
    assert_eq!(send("http://localhost:8788").await.status, 200);
    assert_eq!(send(&format!("https://{DAV_HOST}")).await.status, 200);
}
