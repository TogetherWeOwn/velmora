//! WebDAV over the storage core: protocol behaviour that litmus does not
//! reach, auth, the safe-download response headers, and the S3 and
//! WebDAV views of one bucket.

mod support;

use support::*;
use velmora_dav::handler::Config;

#[cfg(unix)]
#[test]
fn litmus_gate_requires_success_and_exactly_one_clean_summary_per_group() {
    use std::process::Command;

    let run = |status: &str, log: &str| {
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../workers/webdav/e2e/dav.sh"
        );
        Command::new("bash")
            .args([
                "-c",
                "source \"$1\"; STEP=2-litmus; check_litmus \"$2\" \"$3\"",
                "--",
                script,
                status,
                log,
            ])
            .output()
            .unwrap()
    };
    let summary = |group: &str, passed: u8, failed: u8| {
        format!("<- summary for `{group}': of 2 tests run: {passed} passed, {failed} failed.")
    };
    let clean = ["basic", "copymove", "props", "locks", "http"]
        .map(|group| summary(group, 2, 0))
        .join("\n");
    assert!(run("0", &clean).status.success());
    let duplicate = clean.replace("`locks'", "`props'");
    let failed = clean.replace(&summary("locks", 2, 0), &summary("locks", 1, 1));
    let contradictory = format!("{clean}\n{}", summary("locks", 1, 1));
    for (status, log, diagnostic) in [
        ("7", clean.as_str(), "exit 7"),
        ("0", duplicate.as_str(), "litmus props"),
        ("0", failed.as_str(), "litmus locks"),
        ("0", contradictory.as_str(), "litmus locks"),
    ] {
        let out = run(status, log);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && stderr.contains(diagnostic),
            "{stderr}"
        );
    }
}

#[test]
fn ci_checks_dav_at_its_declared_msrv() {
    let ci = include_str!("../../../.github/workflows/ci.yml");
    let (_, job) = ci.split_once("\n  rust-msrv:\n").expect("rust-msrv job");
    let before_worker_sdk = job.lines().take_while(|line| {
        (line.starts_with("    ") || line.trim().is_empty()) && !line.contains("Worker SDK minimum")
    });
    assert!(
        before_worker_sdk
            .filter(|line| line.contains("cargo check --locked"))
            .any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.windows(2).any(|pair| pair == ["-p", "velmora-dav"])
            }),
        "rust-msrv does not select velmora-dav"
    );
}

#[tokio::test]
async fn state_batch_rolls_back_on_second_op_sql_error() {
    use velmora_dav::state::{DeadProp, Op, Patch, Reply};
    use velmora_dav::StatePort;

    let states = States::default();
    let patch = |path: &str| Op::PropPatch {
        path: path.into(),
        etag: None,
        patches: vec![Patch::Set(DeadProp {
            ns: "urn:test".into(),
            name: "label".into(),
            xml: "<label xmlns=\"urn:test\">saved</label>".into(),
        })],
    };
    let get = |path: &str| Op::PropGet {
        paths: vec![(path.into(), None)],
        names: None,
        names_only: false,
    };

    assert_eq!(
        states
            .call("bucket", vec![patch("existing")])
            .await
            .unwrap(),
        vec![Reply::Patched(vec![200])]
    );
    let before = states.call("bucket", vec![get("existing")]).await.unwrap();
    states.dbs.borrow()["bucket"]
        .0
        .execute_batch(
            "CREATE TRIGGER fail_second_patch BEFORE INSERT ON dav_props
             WHEN NEW.path = 'fail' BEGIN SELECT RAISE(ABORT, 'second op failed'); END;",
        )
        .unwrap();

    let error = states
        .call("bucket", vec![patch("first"), patch("fail")])
        .await
        .unwrap_err();
    assert_eq!(error, "second op failed");
    assert_eq!(
        states.call("bucket", vec![get("first")]).await.unwrap(),
        vec![Reply::Props(vec![vec![]])],
        "first op's write must be rolled back"
    );
    assert_eq!(
        states.call("bucket", vec![get("existing")]).await.unwrap(),
        before
    );
}

const PF_BASIC: &[&str] = &[
    "getcontentlength",
    "getetag",
    "resourcetype",
    "getlastmodified",
];

#[tokio::test]
async fn options_needs_no_login_and_names_the_classes() {
    let w = World::new().await;
    let r = w.req("OPTIONS", "/", &[("authorization", "")], b"").await;
    r.expect(200);
    assert_eq!(r.header("dav"), Some("1, 2, 3"));
    assert_eq!(r.header("ms-author-via"), Some("DAV"));
    assert!(r.header("allow").unwrap().contains("PROPFIND"));
}

#[tokio::test]
async fn login_is_an_app_password_and_nothing_else() {
    let w = World::new().await;
    // No credentials: a challenge.
    let r = w
        .req(
            "PROPFIND",
            "/",
            &[("authorization", ""), ("depth", "0")],
            b"",
        )
        .await;
    r.expect(401);
    assert_eq!(
        r.header("www-authenticate"),
        Some("Basic realm=\"WebDAV\", charset=\"UTF-8\"")
    );
    // A wrong secret: refused by the storage core, a challenge again.
    for path in ["/", "/dav/", "/dav/x"] {
        let r = w
            .req_as(
                APP,
                "wrong-secret",
                "PROPFIND",
                path,
                &[("depth", "0")],
                b"",
            )
            .await;
        assert_eq!(r.status, 401, "{path}");
    }
    let r = w.req_as(APP, "wrong", "PUT", "/dav/x", &[], b"abc").await;
    r.expect(401);
    // An S3 key, even with its right secret, is not a login here.
    let r = w
        .req_as(S3KEY, S3KEY_SECRET, "PROPFIND", "/", &[("depth", "0")], b"")
        .await;
    r.expect(401);
    assert!(w.dav.up.sent.borrow().iter().all(|(_, t)| !t.is_empty()));
    // The app password works.
    w.req("PROPFIND", "/", &[("depth", "0")], b"")
        .await
        .expect(207);
}

#[tokio::test]
async fn an_app_password_is_refused_without_the_webdav_entry_point() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"abc").await.expect(201);
    // The same request, as the default entrypoint would pass it on.
    w.dav.up.unmarked.set(true);
    w.req("GET", "/dav/f", &[], b"").await.expect(401);
    w.req("PUT", "/dav/g", &[], b"abc").await.expect(401);
}

#[tokio::test]
async fn put_get_head_with_the_safe_download_headers() {
    let w = World::new().await;
    let body = pattern(1, 100_000);
    let r = w
        .req(
            "PUT",
            "/dav/a%20b.html",
            &[("content-type", "text/html")],
            &body,
        )
        .await;
    r.expect(201);
    let etag = r.header("etag").unwrap().to_owned();
    w.req("PUT", "/dav/a%20b.html", &[], &body)
        .await
        .expect(204);

    let r = w.req("GET", "/dav/a%20b.html", &[], b"").await;
    r.expect(200);
    assert_eq!(r.body, body);
    assert_eq!(r.header("etag"), Some(etag.as_str()));
    assert_eq!(r.header("content-type"), Some("text/html"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"a b.html\"; filename*=UTF-8''a%20b.html")
    );
    assert_eq!(
        r.header("content-security-policy"),
        Some("sandbox; default-src 'none'")
    );
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    // No storage header leaks through.
    assert!(r.headers.iter().all(|(n, _)| !n.starts_with("x-amz")));

    let r = w.req("HEAD", "/dav/a%20b.html", &[], b"").await;
    r.expect(200);
    assert!(r.body.is_empty());
    assert_eq!(r.header("content-length"), Some("100000"));
    assert!(r
        .header("content-disposition")
        .unwrap()
        .starts_with("attachment"));
    // Every answer carries the policy, errors too.
    let r = w.req("GET", "/dav/missing", &[], b"").await;
    r.expect(404);
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert!(r.header("content-security-policy").is_some());
}

#[tokio::test]
async fn ranges_and_if_range() {
    let w = World::new().await;
    let body = pattern(2, 10_000);
    let etag = w
        .req("PUT", "/dav/r.bin", &[], &body)
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    let r = w
        .req("GET", "/dav/r.bin", &[("range", "bytes=100-199")], b"")
        .await;
    r.expect(206);
    assert_eq!(r.body, &body[100..200]);
    assert_eq!(r.header("content-range"), Some("bytes 100-199/10000"));
    let r = w
        .req(
            "GET",
            "/dav/r.bin",
            &[("range", "bytes=-10"), ("if-range", &etag)],
            b"",
        )
        .await;
    r.expect(206);
    assert_eq!(r.body, &body[9990..]);
    // A validator that does not match: the whole body.
    let r = w
        .req(
            "GET",
            "/dav/r.bin",
            &[("range", "bytes=0-9"), ("if-range", "\"other\"")],
            b"",
        )
        .await;
    r.expect(200);
    assert_eq!(r.body.len(), 10_000);
    let r = w
        .req("GET", "/dav/r.bin", &[("if-none-match", &etag)], b"")
        .await;
    r.expect(304);
}

#[tokio::test]
async fn mkcol_rules() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    w.req("MKCOL", "/dav/d", &[], b"").await.expect(405);
    w.req("MKCOL", "/dav/x/y/", &[], b"").await.expect(409);
    w.req("MKCOL", "/dav/e/", &[], b"<body/>").await.expect(415);
    w.req("MKCOL", "/dav/", &[], b"").await.expect(403);
    w.req("MKCOL", "/newbucket/", &[], b"").await.expect(403);
    // The marker is an ordinary zero-byte key ending in `/`.
    let (status, bytes, _) = w.s3_get("d/").await;
    assert_eq!((status, bytes.len()), (200, 0));
    // A file and a folder may not share a name through WebDAV.
    w.req("PUT", "/dav/f", &[], b"x").await.expect(201);
    w.req("MKCOL", "/dav/f/", &[], b"").await.expect(405);
    w.req("PUT", "/dav/d", &[], b"x").await.expect(405);
    // A parent that does not exist.
    w.req("PUT", "/dav/nope/f", &[], b"x").await.expect(409);
    w.req("PUT", "/dav/d/f", &[], b"x").await.expect(201);
}

#[tokio::test]
async fn propfind_depths_and_the_two_views_agree() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/d/a.txt", &[], b"hello")
        .await
        .expect(201);
    w.req("PUT", "/dav/d/caf%C3%A9%20%26%20%3C%3E.txt", &[], b"x")
        .await
        .expect(201);
    // Written through S3: seen at once through WebDAV.
    assert_eq!(w.s3_put("d/s3.bin", &pattern(3, 777)).await, 200);
    assert_eq!(w.s3_put("d/sub/deep.txt", b"deep").await, 200);
    // Keys WebDAV cannot address are hidden.
    assert_eq!(w.s3_put("d//hidden", b"h").await, 200);

    let r = w
        .req(
            "PROPFIND",
            "/dav/d/",
            &[("depth", "1")],
            &propfind_body(PF_BASIC),
        )
        .await;
    r.expect(207);
    let mut hrefs = r.hrefs();
    hrefs.sort();
    assert_eq!(
        hrefs,
        [
            "/dav/d/",
            "/dav/d/a.txt",
            "/dav/d/caf%C3%A9%20%26%20%3C%3E.txt",
            "/dav/d/s3.bin",
            "/dav/d/sub/",
        ]
    );
    // Names, sizes and ETags as S3 lists them.
    let text = r.text();
    for (key, size, etag) in w.s3_list("d/").await {
        if key.ends_with('/') || key.contains("//") || key.starts_with("d/sub/") {
            continue;
        }
        let href = velmora_dav::path::href(BUCKET, &key);
        let block = text
            .split("<D:response>")
            .find(|b| {
                b.contains(&format!(
                    "<D:href>{}</D:href>",
                    velmora_dav::xml::escape_text(&href)
                ))
            })
            .unwrap_or_else(|| panic!("{href} listed"));
        assert!(
            block.contains(&format!("<D:getcontentlength>{size}</D:getcontentlength>")),
            "{block}"
        );
        assert!(
            block.contains(&format!(
                "<D:getetag>{}</D:getetag>",
                velmora_dav::xml::escape_text(&etag)
            )),
            "{block}"
        );
    }
    assert!(text.contains("<D:resourcetype><D:collection/></D:resourcetype>"));

    // Depth 0 on a file and on a folder without its slash.
    let r = w
        .req("PROPFIND", "/dav/d/a.txt", &[("depth", "0")], b"")
        .await;
    r.expect(207);
    assert_eq!(r.hrefs(), ["/dav/d/a.txt"]);
    assert!(r
        .text()
        .contains("<D:getcontentlength>5</D:getcontentlength>"));
    assert!(r
        .text()
        .contains("<D:getcontenttype>text/plain</D:getcontenttype>"));
    assert!(r.text().contains("<D:supportedlock>"));
    let r = w
        .req("PROPFIND", "/dav/d/sub", &[("depth", "0")], b"")
        .await;
    assert_eq!(r.hrefs(), ["/dav/d/sub/"]);

    // Infinity is refused, also when no Depth is sent.
    for h in [vec![("depth", "infinity")], vec![]] {
        let r = w.req("PROPFIND", "/dav/", &h, b"").await;
        r.expect(403);
        assert!(r.text().contains("<D:propfind-finite-depth/>"));
    }
    // The root lists the buckets of the key's grants.
    let r = w.req("PROPFIND", "/", &[("depth", "1")], b"").await;
    r.expect(207);
    assert_eq!(r.hrefs(), ["/", "/dav/", "/other/"]);
    // A named property that does not exist: 404 in its own propstat.
    let r = w
        .req(
            "PROPFIND",
            "/dav/d/a.txt",
            &[("depth", "0")],
            br#"<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><x:nope xmlns:x="urn:x"/></D:prop></D:propfind>"#,
        )
        .await;
    r.expect(207);
    assert!(r
        .text()
        .contains("<nope xmlns=\"urn:x\"/></D:prop><D:status>HTTP/1.1 404 Not Found"));
    w.req("PROPFIND", "/dav/nothing", &[("depth", "0")], b"")
        .await
        .expect(404);
    w.req("PROPFIND", "/dav/d/", &[("depth", "1")], b"<bad")
        .await
        .expect(400);
    w.req("PROPFIND", "/dav/a/./b", &[("depth", "0")], b"")
        .await
        .expect(404);
}

#[tokio::test]
async fn propfind_refuses_more_than_16_mib_of_dead_properties() {
    let w = World::new().await;
    // Each resource has four legal ~62 KiB properties. Across 67
    // resources that is over 16 MiB of UTF-8, but fewer characters.
    let value = "é".repeat(31 * 1024);
    let mut patch = String::from(r#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>"#);
    for name in ["a", "b", "c", "d"] {
        patch.push_str(&format!(r#"<{name} xmlns="urn:test">{value}</{name}>"#));
    }
    patch.push_str("</D:prop></D:set></D:propertyupdate>");
    for i in 0..67 {
        let key = format!("docs/report-{i}");
        assert_eq!(w.s3_put(&key, b"report").await, 200);
        let r = w
            .req("PROPPATCH", &format!("/dav/{key}"), &[], patch.as_bytes())
            .await;
        r.expect(207);
        assert!(r.text().contains("HTTP/1.1 200 OK"));
        assert!(!r.text().contains("HTTP/1.1 507"));
    }
    let r = w
        .req(
            "PROPFIND",
            "/dav/docs/",
            &[("depth", "1")],
            br#"<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#,
        )
        .await;
    assert_eq!(r.status, 507);
    assert!(!r.text().contains("multistatus"));

    let r = w
        .req(
            "PROPFIND",
            "/dav/docs/",
            &[("depth", "1")],
            br#"<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>"#,
        )
        .await;
    r.expect(207);
    assert_eq!(r.hrefs().len(), 68);
    assert!(r.text().contains(r#"<a xmlns="urn:test"/>"#));
    assert!(!r.text().contains(&value));

    // Check the state boundary, not just the HTTP status: no property
    // bytes are returned to the gateway when the budget is exhausted.
    use velmora_dav::state::{Engine, Op, Reply};
    let paths = w
        .s3_list("docs/")
        .await
        .into_iter()
        .map(|(key, _, etag)| (key, Some(etag)))
        .collect();
    let db = w.dav.state.dbs.borrow().values().next().unwrap().clone();
    let replies = Engine {
        sql: db.as_ref(),
        now: w.dav.state.now.get(),
    }
    .run(vec![Op::PropGet {
        paths,
        names: None,
        names_only: false,
    }])
    .unwrap();
    assert!(matches!(replies.as_slice(), [Reply::Full]));

    // An explicit request whose selected values fit still succeeds.
    let r = w
        .req(
            "PROPFIND",
            "/dav/docs/",
            &[("depth", "1")],
            br#"<D:propfind xmlns:D="DAV:"><D:prop><a xmlns="urn:test"/></D:prop></D:propfind>"#,
        )
        .await;
    assert_eq!(r.status, 207);
    assert_eq!(r.hrefs().len(), 68);
}

#[tokio::test]
async fn a_plain_propfind_never_touches_the_state_object() {
    let w = World::new().await;
    w.req("PUT", "/dav/a", &[], b"x").await.expect(201);
    let before = w.dav.state.calls.get();
    w.req(
        "PROPFIND",
        "/dav/",
        &[("depth", "1")],
        &propfind_body(PF_BASIC),
    )
    .await
    .expect(207);
    assert_eq!(w.dav.state.calls.get(), before);
    // lockdiscovery asks for it: one call for the whole folder.
    w.req(
        "PROPFIND",
        "/dav/",
        &[("depth", "1")],
        &propfind_body(&["lockdiscovery", "getetag"]),
    )
    .await
    .expect(207);
    assert_eq!(w.dav.state.calls.get(), before + 1);
}

#[tokio::test]
async fn delete_keeps_the_folder_of_the_last_file() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/d/only", &[], b"x").await.expect(201);
    // The marker deleted through S3: the file alone implies the folder.
    w.rig
        .call(
            &w.s3,
            velmora_bridge::Method::Delete,
            "/dav/d/",
            &[],
            &[],
            b"",
        )
        .await;
    w.req("DELETE", "/dav/d/only", &[], b"").await.expect(204);
    let r = w.req("PROPFIND", "/dav/d/", &[("depth", "0")], b"").await;
    r.expect(207);
    w.req("DELETE", "/dav/d/only", &[], b"").await.expect(404);
    // A folder with members: everything goes.
    w.req("PUT", "/dav/d/a", &[], b"1").await.expect(201);
    w.req("MKCOL", "/dav/d/s/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/d/s/b", &[], b"2").await.expect(201);
    w.req("DELETE", "/dav/d/", &[("depth", "0")], b"")
        .await
        .expect(400);
    w.req("DELETE", "/dav/d/", &[], b"").await.expect(204);
    assert!(w.s3_list("d/").await.is_empty());
    w.req("DELETE", "/dav/", &[], b"").await.expect(403);
}

#[tokio::test]
async fn folder_operations_stop_at_the_cap() {
    let w = World::with(Config {
        max_tree: 3,
        ..Config::default()
    })
    .await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    for i in 0..4 {
        w.req("PUT", &format!("/dav/d/{i}"), &[], b"x")
            .await
            .expect(201);
    }
    let r = w.req("DELETE", "/dav/d/", &[], b"").await;
    r.expect(403);
    assert!(r.text().contains("S3 endpoint"));
    w.req("MOVE", "/dav/d/", &[("destination", "/dav/e/")], b"")
        .await
        .expect(403);
    // Nothing was deleted or copied.
    assert_eq!(w.s3_list("d/").await.len(), 5);
    assert!(w.s3_list("e/").await.is_empty());
}

#[tokio::test]
async fn copy_and_move_files() {
    let w = World::new().await;
    let body = pattern(4, 5000);
    w.req("PUT", "/dav/a", &[], &body).await.expect(201);
    let dest = format!("https://{DAV_HOST}/dav/b%20c");
    w.req("COPY", "/dav/a", &[("destination", &dest)], b"")
        .await
        .expect(201);
    assert_eq!(w.s3_get("b c").await.1, body);
    // Overwrite: F refuses, T replaces.
    w.req(
        "COPY",
        "/dav/a",
        &[("destination", &dest), ("overwrite", "F")],
        b"",
    )
    .await
    .expect(412);
    w.req("COPY", "/dav/a", &[("destination", &dest)], b"")
        .await
        .expect(204);
    w.req("MOVE", "/dav/a", &[("destination", "/dav/m")], b"")
        .await
        .expect(201);
    assert_eq!(w.s3_get("a").await.0, 404);
    assert_eq!(w.s3_get("m").await.1, body);
    // Into a folder that does not exist; to itself; to another bucket;
    // to another server.
    w.req("COPY", "/dav/m", &[("destination", "/dav/no/x")], b"")
        .await
        .expect(409);
    w.req("COPY", "/dav/m", &[("destination", "/dav/m")], b"")
        .await
        .expect(403);
    w.req("COPY", "/dav/m", &[("destination", "/other/m")], b"")
        .await
        .expect(502);
    w.req(
        "COPY",
        "/dav/m",
        &[("destination", "https://elsewhere/dav/z")],
        b"",
    )
    .await
    .expect(502);
    w.req("COPY", "/dav/m", &[], b"").await.expect(400);
    w.req("COPY", "/dav/none", &[("destination", "/dav/z")], b"")
        .await
        .expect(404);
}

#[tokio::test]
async fn copy_and_move_folders() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/src/", &[], b"").await.expect(201);
    w.req("MKCOL", "/dav/src/in/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/src/a", &[], b"1").await.expect(201);
    w.req("PUT", "/dav/src/in/b", &[], b"22").await.expect(201);

    w.req("COPY", "/dav/src/", &[("destination", "/dav/cp/")], b"")
        .await
        .expect(201);
    let copied: Vec<String> = w.s3_list("cp/").await.into_iter().map(|e| e.0).collect();
    assert_eq!(copied, ["cp/", "cp/a", "cp/in/", "cp/in/b"]);
    // Depth 0: the folder alone.
    w.req(
        "COPY",
        "/dav/src/",
        &[("destination", "/dav/zero/"), ("depth", "0")],
        b"",
    )
    .await
    .expect(201);
    let zero: Vec<String> = w.s3_list("zero/").await.into_iter().map(|e| e.0).collect();
    assert_eq!(zero, ["zero/"]);
    // Into itself.
    w.req(
        "COPY",
        "/dav/src/",
        &[("destination", "/dav/src/in/x/")],
        b"",
    )
    .await
    .expect(403);

    w.req("MOVE", "/dav/src/", &[("destination", "/dav/mv/")], b"")
        .await
        .expect(201);
    assert!(w.s3_list("src/").await.is_empty());
    let moved: Vec<String> = w.s3_list("mv/").await.into_iter().map(|e| e.0).collect();
    assert_eq!(moved, ["mv/", "mv/a", "mv/in/", "mv/in/b"]);
    // A folder replaces a file with Overwrite T.
    w.req("PUT", "/dav/f", &[], b"file").await.expect(201);
    w.req("MOVE", "/dav/mv/", &[("destination", "/dav/f")], b"")
        .await
        .expect(204);
    assert_eq!(w.s3_get("f").await.0, 404);
    assert_eq!(w.s3_get("f/a").await.1, b"1");
}

#[tokio::test]
async fn recursive_mutations_preserve_hidden_objects() {
    let mut actual = Vec::new();
    for (method, hidden_at_dest) in [
        ("DELETE", false),
        ("MOVE", false),
        ("COPY", true),
        ("MOVE", true),
    ] {
        for hidden in ["docs//backup.bin", "docs/x/", "docs/./backup.bin", "docs/x"] {
            let w = World::new().await;
            assert_eq!(w.s3_put(hidden, b"hidden bytes").await, 200);
            if hidden == "docs/x" {
                assert_eq!(w.s3_put("docs/x/child", b"visible child").await, 200);
            }
            assert_eq!(w.s3_put("docs/visible", b"visible bytes").await, 200);
            assert_eq!(w.s3_put("other/member", b"other bytes").await, 200);
            let before = w.s3_list("").await;
            let (src, dst) = if hidden_at_dest {
                ("/dav/other/", "/dav/docs/")
            } else {
                ("/dav/docs/", "/dav/other/")
            };
            let headers = [("destination", dst), ("overwrite", "T")];
            let headers = if method == "DELETE" {
                &[][..]
            } else {
                &headers[..]
            };
            let r = w.req(method, src, headers, b"").await;
            actual.push((
                method,
                hidden,
                hidden_at_dest,
                r.status,
                w.s3_list("").await == before,
            ));
        }
    }
    assert!(
        actual.iter().all(|row| row.3 == 409 && row.4),
        "(method, key, at destination, status, unchanged): {actual:?}"
    );
}

#[tokio::test]
async fn recursive_overwrite_preflights_a_collection_with_a_same_named_file() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/src/", &[], b"").await.expect(201);
    assert_eq!(w.s3_put("dst", b"file").await, 200);
    assert_eq!(w.s3_put("dst/", b"not a marker").await, 200);
    let before = w.s3_list("").await;
    let r = w
        .req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await;
    assert_eq!((r.status, w.s3_list("").await == before), (409, true));
}

#[tokio::test]
async fn recursive_copy_omits_hidden_source_objects() {
    let w = World::new().await;
    for k in [
        "docs//backup.bin",
        "docs/x/",
        "docs/x",
        "docs/x/child",
        "docs/./backup.bin",
        "docs/visible",
    ] {
        assert_eq!(w.s3_put(k, b"data").await, 200);
    }
    let before = w.s3_list("docs/").await;
    w.req("COPY", "/dav/docs/", &[("destination", "/dav/out/")], b"")
        .await
        .expect(201);
    let copied: Vec<_> = w.s3_list("out/").await.into_iter().map(|e| e.0).collect();
    assert_eq!(copied, ["out/", "out/visible", "out/x/child"]);
    assert_eq!(w.s3_list("docs/").await, before);
}

#[tokio::test]
async fn recursive_copy_materializes_visible_folders_without_hidden_bytes() {
    let w = World::new().await;
    for key in ["src/empty/", "src/deep/empty//backup"] {
        assert_eq!(w.s3_put(key, b"hidden bytes").await, 200);
    }
    let visible = w.req("PROPFIND", "/dav/src/", &[("depth", "1")], b"").await;
    visible.expect(207);
    assert_eq!(
        visible.hrefs(),
        ["/dav/src/", "/dav/src/deep/", "/dav/src/empty/"]
    );
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(201);
    assert_eq!(w.s3_get("dst/empty/").await.0, 200);
    assert_eq!(w.s3_get("dst/empty/").await.1, b"");
    assert_eq!(w.s3_get("dst/deep/empty/").await.0, 200);
    assert_eq!(w.s3_get("dst/deep/empty//backup").await.0, 404);
}

#[tokio::test]
async fn recursive_mutations_preserve_markers_replaced_after_listing() {
    for method in ["DELETE", "MOVE"] {
        let w = World::new().await;
        assert_eq!(w.s3_put("docs/", b"").await, 200);
        assert_eq!(w.s3_put("docs/x/", b"").await, 200);
        w.req("PROPPATCH", "/dav/docs/", &[], SET_X)
            .await
            .expect(207);
        let locked = w
            .req(
                "LOCK",
                "/dav/docs/",
                &[("depth", "0")],
                &lockinfo("shared", "me"),
            )
            .await;
        let token = locked.expect(200).header("lock-token").unwrap();
        let ifh = format!("({token})");
        w.storage_fault_target(
            "GET",
            "/dav?encoding-type=url&list-type=2&max-keys=1000&prefix=docs%2F",
            StorageFault::Replace {
                key: "docs/x/".into(),
                body: b"keep me".to_vec(),
            },
        );
        let r = w
            .req(
                method,
                "/dav/docs/",
                &[("destination", "/dav/out/"), ("if", &ifh)],
                b"",
            )
            .await;
        assert_eq!(
            (r.status, w.s3_get("docs/x/").await.1),
            (207, b"keep me".to_vec()),
            "{method}"
        );
        assert_eq!(w.s3_get("out/x/").await.0, 404);
        assert!(
            has_x(&w, "/dav/docs/").await,
            "surviving folder lost its property"
        );
        w.req(
            "LOCK",
            "/dav/docs/",
            &[("depth", "0")],
            &lockinfo("exclusive", "other"),
        )
        .await
        .expect(423);
    }
}

#[tokio::test]
async fn recursive_overwrite_preserves_a_destination_marker_replaced_after_listing() {
    for method in ["COPY", "MOVE"] {
        let w = World::new().await;
        assert_eq!(w.s3_put("src/x/", b"").await, 200);
        assert_eq!(w.s3_put("dst/x/", b"").await, 200);
        w.storage_fault_target(
            "GET",
            "/dav?encoding-type=url&list-type=2&max-keys=1000&prefix=dst%2F",
            StorageFault::Replace {
                key: "dst/x/".into(),
                body: b"keep hidden data".to_vec(),
            },
        );
        let r = w
            .req(method, "/dav/src/", &[("destination", "/dav/dst/")], b"")
            .await;
        assert_eq!(r.status, 207, "{method}");
        assert_eq!(w.s3_get("dst/x/").await.1, b"keep hidden data");
        assert_eq!(w.s3_get("src/x/").await.0, 200);
    }
}

#[tokio::test]
async fn recursive_copy_preflights_mapped_s3_key_length() {
    let w = World::new().await;
    let long = format!("a/{}", "z".repeat(1019));
    for k in ["a/first", &long, "archive/first", "archive/old"] {
        assert_eq!(w.s3_put(k, k.as_bytes()).await, 200);
    }
    let before = w.s3_list("").await;
    let r = w
        .req("COPY", "/dav/a/", &[("destination", "/dav/archive/")], b"")
        .await;
    assert_eq!((r.status, w.s3_list("").await == before), (409, true));
}

#[tokio::test]
async fn recursive_copy_failure_keeps_obsolete_destination_members() {
    let w = World::with(Config {
        fan_out: 1,
        ..Config::default()
    })
    .await;
    for k in ["src/a", "src/b", "src/c", "dst/a", "dst/old"] {
        assert_eq!(w.s3_put(k, k.as_bytes()).await, 200);
    }
    w.req("PROPPATCH", "/dav/src/a", &[], SET_X)
        .await
        .expect(207);
    w.storage_fault("PUT", "dst/b", support::StorageFault::Fail);
    let r = w
        .req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await;
    assert_eq!(
        (
            r.status,
            w.s3_get("dst/old").await.0,
            w.s3_get("dst/c").await.0
        ),
        (207, 200, 404)
    );
    assert_eq!(r.hrefs().len(), 1);
    assert_eq!(w.s3_get("dst/old").await.1, b"dst/old");
    assert_eq!(w.s3_get("dst/a").await.1, b"src/a");
    assert!(
        has_x(&w, "/dav/dst/a").await,
        "successful member lost its property"
    );
}

#[tokio::test]
async fn recursive_copy_does_not_store_stale_file_properties() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"old").await, 200);
    w.req("PROPPATCH", "/dav/src/a", &[], SET_X)
        .await
        .expect(207);
    assert_eq!(w.s3_put("src/a", b"new").await, 200);
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(201);
    assert_eq!(w.s3_get("dst/a").await.1, b"new");
    assert_eq!(w.s3_put("dst/a", b"old").await, 200);
    assert!(
        !has_x(&w, "/dav/dst/a").await,
        "stale source property was stored at the destination"
    );
}

#[tokio::test]
async fn recursive_overwrite_preserves_an_obsolete_member_changed_during_copy() {
    let w = World::new().await;
    for k in ["src/a", "dst/a", "dst/old", "dst/obsolete"] {
        assert_eq!(w.s3_put(k, k.as_bytes()).await, 200);
    }
    for path in ["/dav/src/a", "/dav/dst/obsolete"] {
        w.req("PROPPATCH", path, &[], SET_X).await.expect(207);
    }
    let lock = w
        .req(
            "LOCK",
            "/dav/dst/obsolete",
            &[],
            &lockinfo("exclusive", "me"),
        )
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("</dav/dst/obsolete> ({token})");
    w.storage_fault(
        "PUT",
        "dst/a",
        support::StorageFault::Replace {
            key: "dst/old".into(),
            body: b"updated".to_vec(),
        },
    );
    let r = w
        .req(
            "COPY",
            "/dav/src/",
            &[("destination", "/dav/dst/"), ("if", &ifh)],
            b"",
        )
        .await;
    r.expect(207);
    assert_eq!(r.hrefs(), ["/dav/dst/old"]);
    assert!(r.text().contains("HTTP/1.1 412 Precondition Failed"));
    assert_eq!(w.s3_get("dst/old").await.1, b"updated");
    assert_eq!(w.s3_get("dst/a").await.1, b"src/a");
    assert_eq!(w.s3_get("dst/obsolete").await.0, 404);
    assert!(
        has_x(&w, "/dav/dst/a").await,
        "successful member lost its property"
    );
    assert_eq!(w.s3_put("dst/obsolete", b"dst/obsolete").await, 200);
    assert!(
        !has_x(&w, "/dav/dst/obsolete").await,
        "deleted destination retained old state"
    );
    w.req("PUT", "/dav/dst/obsolete", &[], b"unlocked")
        .await
        .expect(204);
}

#[tokio::test]
async fn partial_overwrite_copy_keeps_copied_collection_properties() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/sub/file", b"new").await, 200);
    assert_eq!(w.s3_put("dst/old", b"old").await, 200);
    w.req("PROPPATCH", "/dav/src/sub/", &[], SET_X)
        .await
        .expect(207);
    w.storage_fault("DELETE", "dst/old", StorageFault::Fail);
    let r = w
        .req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await;
    r.expect(207);
    assert_eq!(r.hrefs(), ["/dav/dst/old"]);
    assert_eq!(w.s3_get("dst/sub/file").await.1, b"new");
    assert!(has_x(&w, "/dav/dst/sub/").await);
}

#[tokio::test]
async fn overwrite_releases_the_lock_and_properties_of_a_removed_implicit_folder() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/file", b"new").await, 200);
    assert_eq!(w.s3_put("d/x/f", b"old").await, 200);
    w.req("PROPPATCH", "/dav/d/x/", &[], SET_X)
        .await
        .expect(207);
    let lock = w
        .req("LOCK", "/dav/d/x/", &[], &lockinfo("exclusive", "old"))
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("</dav/d/x/> ({token})");
    w.req(
        "COPY",
        "/dav/src/",
        &[("destination", "/dav/d/"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(204);
    assert_eq!(w.s3_get("d/x/f").await.0, 404);
    // Recreate the implicit folder through S3. Without this, LOCK on the
    // missing URL targets the file key d/x, not the collection key d/x/.
    assert_eq!(w.s3_put("d/x/f", b"restored").await, 200);
    w.req("LOCK", "/dav/d/x/", &[], &lockinfo("exclusive", "new"))
        .await
        .expect(200);
    assert!(!has_x(&w, "/dav/d/x/").await);
}

#[tokio::test]
async fn overwrite_preserves_state_when_a_direct_s3_child_keeps_a_folder_alive() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/file", b"source").await, 200);
    assert_eq!(w.s3_put("dst/x/", b"").await, 200);
    w.req("PROPPATCH", "/dav/dst/x/", &[], SET_X)
        .await
        .expect(207);
    let lock = w
        .req("LOCK", "/dav/dst/x/", &[], &lockinfo("exclusive", "holder"))
        .await;
    let ifh = format!(
        "</dav/dst/x/> ({})",
        lock.expect(200).header("lock-token").unwrap()
    );
    w.storage_fault(
        "PUT",
        "dst/file",
        StorageFault::Replace {
            key: "dst/x/new".into(),
            body: b"new".to_vec(),
        },
    );
    w.req(
        "COPY",
        "/dav/src/",
        &[("destination", "/dav/dst/"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(204);
    assert_eq!(w.s3_get("dst/x/").await.0, 404);
    assert_eq!(w.s3_get("dst/x/new").await.1, b"new");
    assert!(has_x(&w, "/dav/dst/x/").await);
    w.req("LOCK", "/dav/dst/x/", &[], &lockinfo("exclusive", "other"))
        .await
        .expect(423);
}

#[tokio::test]
async fn removed_child_state_is_cleaned_even_when_a_new_sibling_keeps_the_parent_alive() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src", b"source").await, 200);
    assert_eq!(w.s3_put("dst/x/", b"").await, 200);
    w.req("PROPPATCH", "/dav/dst/", &[], SET_X)
        .await
        .expect(207);
    w.req("PROPPATCH", "/dav/dst/x/", &[], SET_X)
        .await
        .expect(207);
    let old_lock = w
        .req("LOCK", "/dav/dst/x/", &[], &lockinfo("exclusive", "old"))
        .await;
    let ifh = format!(
        "</dav/dst/x/> ({})",
        old_lock.expect(200).header("lock-token").unwrap()
    );
    w.storage_fault(
        "PUT",
        "dst",
        StorageFault::Replace {
            key: "dst/new".into(),
            body: b"new".to_vec(),
        },
    );
    w.req(
        "COPY",
        "/dav/src",
        &[("destination", "/dav/dst"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(204);
    assert_eq!(w.s3_get("dst/x/").await.0, 404);
    assert_eq!(w.s3_get("dst/new").await.1, b"new");
    assert!(has_x(&w, "/dav/dst/").await);
    assert_eq!(w.s3_put("dst/x/", b"").await, 200);
    assert!(!has_x(&w, "/dav/dst/x/").await);
    w.req("LOCK", "/dav/dst/x/", &[], &lockinfo("exclusive", "new"))
        .await
        .expect(200);
}

#[tokio::test]
async fn large_stateful_overwrite_cleans_all_removed_folders() {
    // The general review's case (Depth 0 over 101 folders with
    // properties), and a source with a member over 150.
    for (depth, count) in [("0", 101), ("infinity", 150)] {
        let w = World::new().await;
        assert_eq!(w.s3_put("src/", b"").await, 200);
        if depth != "0" {
            assert_eq!(w.s3_put("src/new", b"source").await, 200);
        }
        for i in 0..count {
            let key = format!("dst/{i:03}/");
            assert_eq!(w.s3_put(&key, b"").await, 200);
            w.req("PROPPATCH", &format!("/dav/{key}"), &[], SET_X)
                .await
                .expect(207);
        }
        let r = w
            .req(
                "COPY",
                "/dav/src/",
                &[("destination", "/dav/dst/"), ("depth", depth)],
                b"",
            )
            .await;
        r.expect(204);
        let key = format!("dst/{:03}/", count - 1);
        assert_eq!(w.s3_get(&key).await.0, 404);
        assert_eq!(w.s3_put(&key, b"").await, 200);
        assert!(
            !has_x(&w, &format!("/dav/{key}")).await,
            "success left a deleted folder's properties behind"
        );
        let dbs = w.dav.state.dbs.borrow();
        let rows: i64 = dbs
            .values()
            .next()
            .unwrap()
            .0
            .query_row(
                "SELECT count(*) FROM dav_props WHERE path LIKE 'dst/%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "all {count} removed folders must be cleaned");
    }
}

#[tokio::test]
async fn mutation_budget_refuses_the_entire_overwrite_before_copies_or_deletes() {
    let w = World::with(Config {
        max_mutation_calls: 4,
        ..Config::default()
    })
    .await;
    assert_eq!(w.s3_put("src/new", b"source").await, 200);
    assert_eq!(w.s3_put("dst/x/", b"").await, 200);
    w.req("PROPPATCH", "/dav/dst/x/", &[], SET_X)
        .await
        .expect(207);
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(507);
    assert!(has_x(&w, "/dav/dst/x/").await);
    assert_eq!(w.s3_get("dst/new").await.0, 404);
    assert_eq!(w.s3_get("src/new").await.1, b"source");
}

#[tokio::test]
async fn a_folder_delete_drops_the_state_of_a_file_s3_deleted_before() {
    let w = World::new().await;
    assert_eq!(w.s3_put("photos/", b"").await, 200);
    assert_eq!(w.s3_put("photos/a.jpg", b"same bytes").await, 200);
    w.req("PROPPATCH", "/dav/photos/a.jpg", &[], SET_X)
        .await
        .expect(207);
    assert_eq!(w.s3_list("photos/a.jpg").await.len(), 1);
    let r = w
        .rig
        .call(
            &w.s3,
            velmora_bridge::Method::Delete,
            "/dav/photos/a.jpg",
            &[],
            &[],
            b"",
        )
        .await;
    assert_eq!(r.status, 204);
    w.req("DELETE", "/dav/photos/", &[], b"").await.expect(204);
    w.req("MKCOL", "/dav/photos/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/photos/a.jpg", &[], b"same bytes")
        .await
        .expect(201);
    assert!(
        !has_x(&w, "/dav/photos/a.jpg").await,
        "a deleted folder's file kept its old property"
    );
}

#[tokio::test]
async fn depth_zero_overwrite_does_not_list_removed_subfolders() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/", b"").await, 200);
    for i in 0..1_999 {
        assert_eq!(w.s3_put(&format!("dst/{i:04}/"), b"").await, 200);
    }
    w.dav.up.sent.borrow_mut().clear();
    w.req(
        "COPY",
        "/dav/src/",
        &[("destination", "/dav/dst/"), ("depth", "0")],
        b"",
    )
    .await
    .expect(204);
    let lists = w
        .dav
        .up
        .sent
        .borrow()
        .iter()
        .filter(|(method, target)| method == "GET" && target.contains("list-type=2"))
        .count();
    assert_eq!(lists, 4, "two resolution probes and two preflight pages");
    assert_eq!(w.s3_list("dst/").await.len(), 1);
}

#[tokio::test]
async fn file_overwrite_releases_old_collection_state() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src", b"file").await, 200);
    assert_eq!(w.s3_put("dst/", b"").await, 200);
    w.req("PROPPATCH", "/dav/dst/", &[], SET_X)
        .await
        .expect(207);
    let lock = w
        .req(
            "LOCK",
            "/dav/dst/",
            &[("depth", "0")],
            &lockinfo("exclusive", "me"),
        )
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("</dav/dst/> ({token})");
    w.req(
        "COPY",
        "/dav/src",
        &[("destination", "/dav/dst/"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(204);
    w.req("DELETE", "/dav/dst", &[], b"").await.expect(204);
    w.req("MKCOL", "/dav/dst/", &[], b"").await.expect(201);
    assert!(!has_x(&w, "/dav/dst/").await);
}

async fn move_with_changed_source(w: &World) {
    assert_eq!(w.s3_put("src/a", b"old a").await, 200);
    assert_eq!(w.s3_put("src/b", b"old b").await, 200);
    w.storage_fault(
        "PUT",
        "dst/a",
        StorageFault::Replace {
            key: "src/a".into(),
            body: b"new a".to_vec(),
        },
    );
    let r = w
        .req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await;
    r.expect(207);
    assert_eq!(r.hrefs(), ["/dav/src/a"]);
    assert!(r.text().contains("HTTP/1.1 409 Conflict"));
    assert_eq!(w.s3_get("src/b").await.0, 404);
}

#[tokio::test]
async fn overwrite_retry_of_partial_move_keeps_the_only_copy() {
    let w = World::new().await;
    move_with_changed_source(&w).await;
    let r = w
        .req(
            "MOVE",
            "/dav/src/",
            &[("destination", "/dav/dst/"), ("overwrite", "T")],
            b"",
        )
        .await;
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
    assert_eq!(w.s3_get("dst/a").await.1, b"new a");
    assert_eq!(w.s3_get("src/a").await.0, 404);
    // The retry completed the move: the earlier attempt's member is
    // released, not reported as kept.
    r.expect(204);
    let rows: i64 = w
        .dav
        .state
        .dbs
        .borrow()
        .values()
        .next()
        .unwrap()
        .0
        .query_row("SELECT count(*) FROM moved_members", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0, "a completed retry left ledger rows");
    assert_eq!(w.s3_put("fresh/c", b"fresh").await, 200);
    w.req("COPY", "/dav/fresh/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(204);
    assert_eq!(w.s3_get("dst/b").await.0, 404);
}

#[tokio::test]
async fn a_completed_move_of_another_source_keeps_a_partial_moves_rows() {
    let w = World::new().await;
    move_with_changed_source(&w).await;
    assert_eq!(w.s3_put("other/c", b"other").await, 200);
    let r = w
        .req("MOVE", "/dav/other/", &[("destination", "/dav/dst/")], b"")
        .await;
    r.expect(207);
    assert!(r.text().contains("kept after a partial MOVE"));
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
    let dbs = w.dav.state.dbs.borrow();
    let db = &dbs.values().next().unwrap().0;
    let rows = |sql: &str| -> i64 { db.query_row(sql, [], |row| row.get(0)).unwrap() };
    // The partial MOVE's rows (dst/a and dst/b, from src/) stay; the
    // completed MOVE released its own.
    assert_eq!(
        rows("SELECT count(*) FROM moved_members WHERE source LIKE 'src/%'"),
        2
    );
    assert_eq!(
        rows("SELECT count(*) FROM moved_members"),
        2,
        "only the other source's own rows are released"
    );
}

#[tokio::test]
async fn a_completed_move_with_another_mapping_keeps_a_partial_moves_rows() {
    let w = World::new().await;
    assert_eq!(w.s3_put("staging/photos/a", b"old a").await, 200);
    assert_eq!(w.s3_put("staging/photos/b", b"old b").await, 200);
    w.storage_fault(
        "PUT",
        "archive/a",
        StorageFault::Replace {
            key: "staging/photos/a".into(),
            body: b"new a".to_vec(),
        },
    );
    w.req(
        "MOVE",
        "/dav/staging/photos/",
        &[("destination", "/dav/archive/")],
        b"",
    )
    .await
    .expect(207);
    assert_eq!(w.s3_get("staging/photos/b").await.0, 404);
    // staging/ -> archive/ maps photos/b to archive/photos/b, so it is not
    // a retry of the move that left archive/b as the only copy.
    let r = w
        .req(
            "MOVE",
            "/dav/staging/",
            &[("destination", "/dav/archive/")],
            b"",
        )
        .await;
    r.expect(207);
    assert!(r.text().contains("kept after a partial MOVE"));
    let rows: i64 = w
        .dav
        .state
        .dbs
        .borrow()
        .values()
        .next()
        .unwrap()
        .0
        .query_row(
            "SELECT count(*) FROM moved_members WHERE destination = 'archive/b'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1, "another move released a partial move's only copy");
    assert_eq!(w.s3_put("other/c", b"c").await, 200);
    w.req(
        "COPY",
        "/dav/other/",
        &[("destination", "/dav/archive/")],
        b"",
    )
    .await
    .expect(207);
    assert_eq!(w.s3_get("archive/b").await.1, b"old b");
}

#[tokio::test]
async fn a_full_folder_move_releases_its_destination_members_from_the_ledger() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"a").await, 200);
    assert_eq!(w.s3_put("src/b", b"b").await, 200);
    w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(201);
    let dbs = w.dav.state.dbs.borrow();
    let db = dbs.values().next().unwrap();
    let count: i64 =
        db.0.query_row("SELECT count(*) FROM moved_members", [], |row| row.get(0))
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn overwrite_keeps_a_moved_member_a_year_later() {
    let w = World::new().await;
    move_with_changed_source(&w).await;
    w.advance_secs(365 * 24 * 60 * 60);
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(207);
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
}

#[tokio::test]
async fn moved_member_capacity_is_checked_before_any_copy() {
    use velmora_dav::handler::StatePort;
    use velmora_dav::state::{MovedMember, Op};
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"source").await, 200);
    w.req("PROPFIND", "/dav/src/a", &[("depth", "0")], b"")
        .await
        .expect(207);
    let name = w.dav.state.dbs.borrow().keys().next().unwrap().clone();
    for offset in (0..10_000).step_by(1000) {
        w.dav
            .state
            .call(
                &name,
                vec![Op::RecordMoved {
                    holder: None,
                    members: (offset..offset + 1000)
                        .map(|i| MovedMember {
                            destination: format!("other/{i}"),
                            source: format!("original/{i}"),
                            etag: "tag".into(),
                        })
                        .collect(),
                }],
            )
            .await
            .unwrap();
    }
    w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(507);
    assert_eq!(w.s3_get("src/a").await.1, b"source");
    assert!(w.s3_list("dst/").await.is_empty());
}

#[tokio::test]
async fn prune_reclaims_stale_ledger_rows_for_missing_or_replaced_keys() {
    use velmora_dav::handler::StatePort;
    use velmora_dav::state::{MovedMember, Op};
    let w = World::new().await;
    move_with_changed_source(&w).await;
    let name = w.dav.state.dbs.borrow().keys().next().unwrap().clone();
    w.dav
        .state
        .call(
            &name,
            vec![Op::RecordMoved {
                holder: None,
                members: vec![MovedMember {
                    destination: "dst/missing".into(),
                    source: "old/missing".into(),
                    etag: "old tag".into(),
                }],
            }],
        )
        .await
        .unwrap();
    assert_eq!(w.s3_put("dst/b", b"direct S3 replacement").await, 200);
    // Make the prune fail so that ClearMoved from deletion can't mask a
    // failed stale-ETag observation.
    w.storage_fault("DELETE", "dst/b", StorageFault::Fail);
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(207);
    let dbs = w.dav.state.dbs.borrow();
    let count: i64 = dbs[&name]
        .0
        .query_row("SELECT count(*) FROM moved_members", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn webdav_delete_and_overwrite_clear_the_moved_member_ledger() {
    for action in ["DELETE", "PUT"] {
        let w = World::new().await;
        move_with_changed_source(&w).await;
        if action == "DELETE" {
            w.req("DELETE", "/dav/dst/b", &[], b"").await.expect(204);
            assert_eq!(w.s3_put("dst/b", b"old b").await, 200);
        } else {
            // The replacement has the same ETag. An old row would still
            // match it when the subsequent COPY tries to prune it.
            w.req("PUT", "/dav/dst/b", &[], b"old b").await.expect(204);
        }
        w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
            .await
            .expect(204);
        assert_eq!(w.s3_get("dst/b").await.0, 404);
    }
}

#[tokio::test]
async fn partial_move_fences_overlapping_but_not_disjoint_overwrites() {
    let w = World::new().await;
    for (key, body) in [
        ("src/a", &b"old a"[..]),
        ("src/b", b"old b"),
        ("other/a", b"other"),
    ] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    // The root marker is materialized only after all member copies settle.
    w.storage_fault("PUT", "dst/", StorageFault::Pause { reached, resume });
    let mut moving =
        std::pin::pin!(w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b""));
    tokio::select! {
        r = moving.as_mut() => panic!("MOVE finished before the pause: {}", r.status),
        r = waiting => r.unwrap(),
    }
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
    let overlap = w
        .req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b"")
        .await;
    overlap.expect(503);
    assert_eq!(overlap.header("retry-after"), Some("2"));
    assert_eq!(w.s3_get("dst/a").await.1, b"old a");
    w.req(
        "COPY",
        "/dav/other/",
        &[("destination", "/dav/disjoint/")],
        b"",
    )
    .await
    .expect(201);
    assert_eq!(w.s3_put("src/a", b"new a").await, 200);
    release.send(()).unwrap();
    moving.await.expect(207);
    assert_eq!(w.s3_get("src/b").await.0, 404);
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(207);
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
}

#[tokio::test]
async fn an_abandoned_reservation_stops_blocking_after_its_lease_expires() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"a").await, 200);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (_release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("PUT", "dst/", StorageFault::Pause { reached, resume });
    let copy = || w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"");
    {
        let mut abandoned = std::pin::pin!(copy());
        tokio::select! {
            r = abandoned.as_mut() => panic!("COPY finished before the pause: {}", r.status),
            r = waiting => r.unwrap(),
        }
    }
    copy().await.expect(503);
    w.advance_secs(Config::default().lease_secs);
    copy().await.expect(204);
}

#[tokio::test]
async fn an_expired_prune_stops_before_dispatching_the_next_delete() {
    let w = World::with(Config {
        fan_out: 1,
        ..Config::default()
    })
    .await;
    for (key, body) in [
        ("other/c", &b"replacement"[..]),
        ("dst/0", b"obsolete"),
        ("dst/b", b"identical b"),
        ("src/b", b"identical b"),
        ("src/a", b"old a"),
    ] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("DELETE", "dst/0", StorageFault::Pause { reached, resume });
    let mut pruning =
        std::pin::pin!(w.req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b""));
    tokio::select! {
        r = pruning.as_mut() => panic!("COPY finished before its prune was paused: {}", r.status),
        r = waiting => r.unwrap(),
    }
    w.advance_secs(Config::default().lease_secs);
    w.storage_fault(
        "PUT",
        "dst/a",
        StorageFault::Replace {
            key: "src/a".into(),
            body: b"new a".to_vec(),
        },
    );
    w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(207);
    assert_eq!(w.s3_get("src/b").await.0, 404);
    assert_eq!(w.s3_get("dst/b").await.1, b"identical b");
    release.send(()).unwrap();
    pruning.await.expect(503);
    assert_eq!(
        w.s3_get("dst/b").await.0,
        200,
        "an expired prune deleted a later MOVE's only copy"
    );
}

#[tokio::test]
async fn recursive_delete_does_not_dispatch_the_next_batch_after_expiry() {
    let w = World::new().await;
    assert_eq!(w.s3_put("dst/", b"").await, 200);
    assert_eq!(w.s3_put("dst/file", b"first batch").await, 200);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault_target(
        "POST",
        "/dav?delete=",
        StorageFault::Pause { reached, resume },
    );
    let mut deleting = std::pin::pin!(w.req("DELETE", "/dav/dst/", &[], b""));
    tokio::select! {
        r = deleting.as_mut() => panic!("DELETE finished before the first batch paused: {}", r.status),
        r = waiting => r.unwrap(),
    }
    w.advance_secs(Config::default().lease_secs);
    release.send(()).unwrap();
    deleting.await.expect(503);
    assert_eq!(w.s3_get("dst/").await.0, 200);
}

#[tokio::test]
async fn recursive_delete_stops_before_a_batch_that_would_remove_a_later_move() {
    // The security review's schedule: the DELETE lists dst/b, stalls past
    // its reservation, a MOVE lands src/b on dst/b and deletes its
    // source, and the DELETE's next batch must not remove dst/b.
    let w = World::with(Config {
        delete_keys: 1,
        ..Config::default()
    })
    .await;
    for (key, body) in [
        ("dst/a", &b"a"[..]),
        ("dst/b", b"old b"),
        ("src/b", b"moved b"),
    ] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault_target(
        "POST",
        "/dav?delete=",
        StorageFault::Pause { reached, resume },
    );
    let mut deleting = std::pin::pin!(w.req("DELETE", "/dav/dst/", &[], b""));
    tokio::select! {
        r = deleting.as_mut() => panic!("DELETE finished before its first batch paused: {}", r.status),
        r = waiting => r.unwrap(),
    }
    assert_eq!(w.s3_get("dst/a").await.0, 404);
    w.advance_secs(Config::default().lease_secs);
    w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(204);
    assert_eq!(w.s3_get("src/b").await.0, 404);
    release.send(()).unwrap();
    deleting.await.expect(503);
    assert_eq!(
        w.s3_get("dst/b").await.1,
        b"moved b",
        "a lapsed DELETE removed the only copy a later MOVE made"
    );
}

#[tokio::test]
async fn a_renewal_that_finds_the_reservation_lost_stops_the_work() {
    // Renewed every second; the listing below never answers.
    let w = World::with(Config {
        lease_secs: 3,
        ..Config::default()
    })
    .await;
    assert_eq!(w.s3_put("src/a", b"a").await, 200);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (_release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault_target(
        "GET",
        "/dav?encoding-type=url&list-type=2&max-keys=1000&prefix=src%2F",
        StorageFault::Pause { reached, resume },
    );
    let mut copying =
        std::pin::pin!(w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b""));
    tokio::select! {
        r = copying.as_mut() => panic!("COPY finished before its listing paused: {}", r.status),
        r = waiting => r.unwrap(),
    }
    w.advance_secs(3);
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), copying)
        .await
        .expect("a lost reservation did not stop the COPY");
    r.expect(503);
    assert!(w.s3_list("dst/").await.is_empty());
    // The holder's rows are gone: another COPY onto dst/ goes ahead.
    w.req("COPY", "/dav/src/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(201);
}

#[tokio::test]
async fn a_storage_call_without_an_answer_stops_the_batch_and_dispatches_nothing_more() {
    // A quarter lease is one second.
    let w = World::with(Config {
        lease_secs: 4,
        fan_out: 1,
        ..Config::default()
    })
    .await;
    for (key, body) in [("other/c", &b"c"[..]), ("dst/0", b"0"), ("dst/b", b"b")] {
        assert_eq!(w.s3_put(key, body).await, 200);
    }
    let (reached, _waiting) = tokio::sync::oneshot::channel();
    let (_release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("DELETE", "dst/0", StorageFault::Pause { reached, resume });
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        w.req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b""),
    )
    .await
    .expect("a storage call without an answer held the COPY");
    r.expect(207);
    assert!(r.text().contains("HTTP/1.1 504 Gateway Timeout"));
    let deletes = w
        .dav
        .up
        .sent
        .borrow()
        .iter()
        // The write-grant probe is a DELETE of an upload id.
        .filter(|(method, target)| method == "DELETE" && !target.contains("uploadId"))
        .count();
    assert_eq!(deletes, 1, "a delete was dispatched after the timeout");
    assert_eq!(w.s3_get("dst/b").await.1, b"b");
    // Storage may still commit the unanswered call, so the reservation is
    // held until its lease runs out, not released at once.
    let again = || w.req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b"");
    again().await.expect(503);
    w.advance_secs(4);
    again().await.expect(204);
}

#[tokio::test]
async fn a_move_cannot_delete_its_source_after_its_reservation_expires() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"only copy").await, 200);
    assert_eq!(w.s3_put("other/b", b"separate").await, 200);
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    w.storage_fault("PUT", "dst/", StorageFault::Pause { reached, resume });
    let mut moving =
        std::pin::pin!(w.req("MOVE", "/dav/src/", &[("destination", "/dav/dst/")], b""));
    tokio::select! {
        r = moving.as_mut() => panic!("MOVE finished before the pause: {}", r.status),
        r = waiting => r.unwrap(),
    }
    w.advance_secs(Config::default().lease_secs);
    w.req("COPY", "/dav/other/", &[("destination", "/dav/dst/")], b"")
        .await
        .expect(204);
    assert_eq!(w.s3_get("dst/a").await.0, 404);
    release.send(()).unwrap();
    moving.await.expect(503);
    assert_eq!(w.s3_get("src/a").await.1, b"only copy");
}

#[tokio::test]
async fn move_retry_with_kept_members_preserves_the_source_parent() {
    let w = World::new().await;
    assert_eq!(w.s3_put("p/src/a", b"old a").await, 200);
    assert_eq!(w.s3_put("p/src/b", b"old b").await, 200);
    w.storage_fault(
        "PUT",
        "dst/a",
        StorageFault::Replace {
            key: "p/src/a".into(),
            body: b"new a".to_vec(),
        },
    );
    let moving = || w.req("MOVE", "/dav/p/src/", &[("destination", "/dav/dst/")], b"");
    moving().await.expect(207);
    assert_eq!(w.s3_get("p/").await.0, 404, "p is still implicit");
    moving().await.expect(204);
    assert!(w.s3_list("p/src/").await.is_empty());
    assert_eq!(w.s3_get("p/").await.0, 200);
    assert_eq!(w.s3_get("dst/b").await.1, b"old b");
}

#[tokio::test]
async fn partial_move_forgets_only_deleted_file_state() {
    let w = World::new().await;
    for key in ["src/a", "src/b"] {
        assert_eq!(w.s3_put(key, b"old").await, 200);
        w.req("PROPPATCH", &format!("/dav/{key}"), &[], SET_X)
            .await
            .expect(207);
    }
    let lock = w
        .req("LOCK", "/dav/src/b", &[], &lockinfo("exclusive", "me"))
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("</dav/src/b> ({token})");
    w.storage_fault(
        "PUT",
        "dst/a",
        StorageFault::Replace {
            key: "src/a".into(),
            body: b"newer".to_vec(),
        },
    );
    w.req(
        "MOVE",
        "/dav/src/",
        &[("destination", "/dav/dst/"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(207);
    assert_eq!(w.s3_get("src/a").await.1, b"newer");
    assert_eq!(w.s3_get("src/b").await.0, 404);
    assert_eq!(w.s3_put("src/a", b"old").await, 200);
    assert_eq!(w.s3_put("src/b", b"old").await, 200);
    assert!(has_x(&w, "/dav/src/a").await);
    assert!(
        !has_x(&w, "/dav/src/b").await,
        "deleted member kept its old property"
    );
    w.req("PUT", "/dav/src/b", &[], b"unlocked")
        .await
        .expect(204);
}

#[tokio::test]
async fn partial_move_releases_state_of_a_fully_removed_subfolder() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/a", b"old").await, 200);
    assert_eq!(w.s3_put("src/sub/", b"").await, 200);
    w.req("PROPPATCH", "/dav/src/sub/", &[], SET_X)
        .await
        .expect(207);
    let lock = w
        .req("LOCK", "/dav/src/sub/", &[], &lockinfo("exclusive", "me"))
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("</dav/src/sub/> ({token})");
    w.storage_fault(
        "PUT",
        "dst/a",
        StorageFault::Replace {
            key: "src/a".into(),
            body: b"new".to_vec(),
        },
    );
    w.req(
        "MOVE",
        "/dav/src/",
        &[("destination", "/dav/dst/"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(207);
    assert_eq!(w.s3_get("src/sub/").await.0, 404);
    w.req("MKCOL", "/dav/src/sub/", &[], b"").await.expect(201);
    assert!(!has_x(&w, "/dav/src/sub/").await);
}

async fn move_preserves_updated_source(collection: bool) {
    let w = World::new().await;
    let (src, dst, src_key, dst_key) = if collection {
        ("/dav/src/", "/dav/dst/", "src/a", "dst/a")
    } else {
        ("/dav/src", "/dav/dst", "src", "dst")
    };
    assert_eq!(w.s3_put(src_key, b"copied").await, 200);
    let member = format!("/dav/{src_key}");
    w.req("PROPPATCH", &member, &[], SET_X).await.expect(207);
    let lock = w
        .req("LOCK", &member, &[], &lockinfo("exclusive", "owner"))
        .await;
    let token = lock.expect(200).header("lock-token").unwrap();
    let ifh = format!("<{member}> ({token})");
    w.storage_fault(
        "PUT",
        dst_key,
        support::StorageFault::Replace {
            key: src_key.into(),
            body: b"updated".to_vec(),
        },
    );
    let r = w
        .req("MOVE", src, &[("destination", dst), ("if", &ifh)], b"")
        .await;
    let (src_status, src_body, _) = w.s3_get(src_key).await;
    assert_eq!(
        (r.status, src_status),
        (if collection { 207 } else { 409 }, 200)
    );
    assert_eq!(src_body, b"updated");
    assert_eq!(w.s3_get(dst_key).await.1, b"copied");
    w.req("DELETE", &member, &[], b"").await.expect(423);
    // Properties remain stamped with the original bytes; restore those
    // bytes through S3 and check that the failed MOVE did not drop them.
    assert_eq!(w.s3_put(src_key, b"copied").await, 200);
    assert!(has_x(&w, &member).await);
    if collection {
        assert_eq!(r.hrefs(), ["/dav/src/a"]);
        assert!(r.text().contains("HTTP/1.1 409 Conflict"));
    }
}

#[tokio::test]
async fn move_file_does_not_delete_an_uncopied_source_version() {
    move_preserves_updated_source(false).await;
}

#[tokio::test]
async fn move_tree_does_not_delete_an_uncopied_source_version() {
    move_preserves_updated_source(true).await;
}

#[tokio::test]
async fn false_if_match_prevents_copy_move_and_collection_delete() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/file", b"current").await, 200);
    assert_eq!(w.s3_put("dst", b"destination").await, 200);
    for method in ["COPY", "MOVE"] {
        w.req(
            method,
            "/dav/src/file",
            &[("destination", "/dav/dst"), ("if-match", "\"wrong\"")],
            b"",
        )
        .await
        .expect(412);
    }
    w.req("DELETE", "/dav/src/", &[("if-match", "\"wrong\"")], b"")
        .await
        .expect(412);
    assert_eq!(w.s3_get("src/file").await.1, b"current");
    assert_eq!(w.s3_get("dst").await.1, b"destination");
    w.req("DELETE", "/dav/src/", &[("if-match", "*")], b"")
        .await
        .expect(204);
}

#[tokio::test]
async fn file_copy_and_move_guard_the_conditionally_selected_source_version() {
    for method in ["COPY", "MOVE"] {
        let w = World::new().await;
        assert_eq!(w.s3_put("src", b"original").await, 200);
        assert_eq!(w.s3_put("dst", b"destination").await, 200);
        let etag = w.s3_get("src").await.2.unwrap();
        w.storage_fault(
            "HEAD",
            "src",
            StorageFault::Replace {
                key: "src".into(),
                body: b"replacement".to_vec(),
            },
        );
        w.req(
            method,
            "/dav/src",
            &[("destination", "/dav/dst"), ("if-match", &etag)],
            b"",
        )
        .await
        .expect(412);
        assert_eq!(w.s3_get("src").await.1, b"replacement");
        assert_eq!(w.s3_get("dst").await.1, b"destination");
    }
}

#[tokio::test]
async fn dav_if_header_guards_the_file_version_moved() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src", b"original").await, 200);
    assert_eq!(w.s3_put("dst", b"destination").await, 200);
    let etag = w.s3_get("src").await.2.unwrap();
    let ifh = format!("([{etag}])");
    w.storage_fault(
        "HEAD",
        "src",
        StorageFault::Replace {
            key: "src".into(),
            body: b"replacement".to_vec(),
        },
    );
    w.req(
        "MOVE",
        "/dav/src",
        &[("destination", "/dav/dst"), ("if", &ifh)],
        b"",
    )
    .await
    .expect(412);
    assert_eq!(w.s3_get("src").await.1, b"replacement");
    assert_eq!(w.s3_get("dst").await.1, b"destination");
}

#[tokio::test]
async fn depth_zero_copy_without_overwrite_returns_412_if_the_root_appears() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/", b"").await, 200);
    w.req("PROPPATCH", "/dav/src/", &[], SET_X)
        .await
        .expect(207);
    w.storage_fault_target(
        "GET",
        "/dav?encoding-type=url&list-type=2&max-keys=1&prefix=dst%2F",
        StorageFault::Replace {
            key: "dst/".into(),
            body: Vec::new(),
        },
    );
    w.req(
        "COPY",
        "/dav/src/",
        &[
            ("destination", "/dav/dst/"),
            ("depth", "0"),
            ("overwrite", "F"),
        ],
        b"",
    )
    .await
    .expect(412);
    assert_eq!(w.s3_get("dst/").await.0, 200);
    assert!(!has_x(&w, "/dav/dst/").await);
}

#[tokio::test]
async fn read_only_mutations_are_denied_before_evaluating_preconditions() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/file", b"original").await, 200);
    assert_eq!(w.s3_put("dst", b"unchanged").await, 200);
    let wrong = ("if-match", "\"wrong\"");
    for (method, target, headers) in [
        ("PUT", "/dav/src/file", vec![wrong]),
        ("DELETE", "/dav/src/file", vec![wrong]),
        ("DELETE", "/dav/src/", vec![wrong]),
        (
            "COPY",
            "/dav/src/file",
            vec![wrong, ("destination", "/dav/dst")],
        ),
        (
            "MOVE",
            "/dav/src/file",
            vec![wrong, ("destination", "/dav/dst")],
        ),
        (
            "COPY",
            "/dav/src/file",
            vec![("overwrite", "F"), ("destination", "/dav/dst")],
        ),
    ] {
        w.req_as(RO, RO_SECRET, method, target, &headers, b"")
            .await
            .expect(403);
    }
    assert_eq!(w.s3_get("src/file").await.1, b"original");
    assert_eq!(w.s3_get("dst").await.1, b"unchanged");
}

#[tokio::test]
async fn absolute_destination_must_match_request_origin() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src", b"source").await, 200);
    assert_eq!(w.s3_put("dst", b"destination").await, 200);
    for dest in [
        "ftp://dav.test/dav/dst",
        "http://dav.test/dav/dst",
        "https://dav.test:444/dav/dst",
        "https://other.test/dav/dst",
    ] {
        w.req("MOVE", "/dav/src", &[("destination", dest)], b"")
            .await
            .expect(502);
        assert_eq!(w.s3_get("src").await.1, b"source");
        assert_eq!(w.s3_get("dst").await.1, b"destination");
    }
    w.req(
        "COPY",
        "/dav/src",
        &[("destination", "https://DAV.test:443/dav/dst")],
        b"",
    )
    .await
    .expect(204);
}

#[tokio::test]
async fn tree_copy_without_overwrite_does_not_replace_a_concurrent_destination_file() {
    let w = World::new().await;
    assert_eq!(w.s3_put("src/x", b"source").await, 200);
    w.storage_fault_target(
        "GET",
        "/dav?encoding-type=url&list-type=2&max-keys=1000&prefix=src%2F",
        StorageFault::Replace {
            key: "dst/x".into(),
            body: b"concurrent".to_vec(),
        },
    );
    let r = w
        .req(
            "COPY",
            "/dav/src/",
            &[("destination", "/dav/dst/"), ("overwrite", "F")],
            b"",
        )
        .await;
    r.expect(207);
    assert!(r.text().contains("HTTP/1.1 412 Precondition Failed"));
    assert_eq!(w.s3_get("dst/x").await.1, b"concurrent");
}

#[tokio::test]
async fn read_only_put_is_rejected_without_reading_a_pending_body_or_leasing() {
    use velmora_dav::http::{Body, Request};
    let w = World::new().await;
    assert_eq!(w.s3_put("file", b"original").await, 200);
    let mut putting = std::pin::pin!(w.dav.handle(Request {
        method: "PUT".into(),
        origin: format!("https://{DAV_HOST}"),
        path: "/dav/file".into(),
        headers: vec![
            ("host".into(), DAV_HOST.into()),
            ("authorization".into(), basic(RO, RO_SECRET))
        ],
        body: Body::Native(TBody::pending()),
    }));
    let first_poll = std::future::Future::poll(
        putting.as_mut(),
        &mut std::task::Context::from_waker(std::task::Waker::noop()),
    );
    w.req("LOCK", "/dav/file", &[], &lockinfo("exclusive", "writer"))
        .await
        .expect(200);
    let std::task::Poll::Ready(response) = first_poll else {
        panic!("read-only PUT waited on its body");
    };
    assert_eq!(response.status, 403);
}

#[tokio::test]
async fn conditional_delete_preserves_a_version_written_after_head() {
    let mut actual = Vec::new();
    for kind in ["if-match", "if", "tagged if"] {
        let w = World::new().await;
        assert_eq!(w.s3_put("file", b"version A").await, 200);
        w.req("PROPPATCH", "/dav/file", &[], SET_X)
            .await
            .expect(207);
        let etag = w.s3_get("file").await.2.unwrap();
        let lock = w
            .req("LOCK", "/dav/file", &[], &lockinfo("exclusive", "owner"))
            .await;
        let token = lock.expect(200).header("lock-token").unwrap();
        let ifh = match kind {
            "if-match" => format!("({token})"),
            "if" => format!("({token} [{etag}])"),
            _ => format!("</dav/file> ({token} [{etag}])"),
        };
        let mut headers = vec![("if", ifh.as_str())];
        if kind == "if-match" {
            headers.push(("if-match", etag.as_str()));
        }
        w.storage_fault(
            "HEAD",
            "file",
            support::StorageFault::Replace {
                key: "file".into(),
                body: b"version B".to_vec(),
            },
        );
        let r = w.req("DELETE", "/dav/file", &headers, b"").await;
        let retained = w.s3_get("file").await.1 == b"version B";
        let locked = w.req("DELETE", "/dav/file", &[], b"").await.status == 423;
        assert_eq!(w.s3_put("file", b"version A").await, 200);
        let property = has_x(&w, "/dav/file").await;
        actual.push((kind, r.status, retained, locked, property));
    }
    assert!(
        actual
            .iter()
            .all(|row| row.1 == 412 && row.2 && row.3 && row.4),
        "(condition, status, version retained, lock retained, property retained): {actual:?}"
    );
}

#[tokio::test]
async fn locks_bind_writes_to_their_owner_and_token() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"v1").await.expect(201);
    let r = w
        .req(
            "LOCK",
            "/dav/f",
            &[("timeout", "Second-100")],
            &lockinfo("exclusive", "me"),
        )
        .await;
    r.expect(200);
    let token = r.header("lock-token").unwrap().to_owned();
    assert!(token.starts_with("<urn:uuid:") && token.ends_with('>'));
    assert!(r.text().contains("<D:timeout>Second-100</D:timeout>"));
    assert!(r
        .text()
        .contains("<owner xmlns=\"DAV:\"><href>me</href></owner>"));

    // Without the token: locked.
    let r = w.req("PUT", "/dav/f", &[], b"v2").await;
    r.expect(423);
    assert!(r
        .text()
        .contains("<D:lock-token-submitted><D:href>/dav/f</D:href>"));
    w.req("DELETE", "/dav/f", &[], b"").await.expect(423);
    w.req("MOVE", "/dav/f", &[("destination", "/dav/g")], b"")
        .await
        .expect(423);
    w.req("PROPPATCH", "/dav/f", &[], b"<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><x xmlns=\"urn:x\">1</x></D:prop></D:set></D:propertyupdate>")
        .await
        .expect(423);
    // Another key with the right token: still locked. A token alone is
    // not enough; the lock's owner must present it.
    let ifh = format!("({token})");
    w.req_as(APP2, APP2_SECRET, "PUT", "/dav/f", &[("if", &ifh)], b"v2")
        .await
        .expect(423);
    // A second exclusive lock, or a shared one: refused.
    w.req("LOCK", "/dav/f", &[], &lockinfo("exclusive", "x"))
        .await
        .expect(423);
    w.req_as(
        APP2,
        APP2_SECRET,
        "LOCK",
        "/dav/f",
        &[],
        &lockinfo("shared", "x"),
    )
    .await
    .expect(423);
    // The owner with the token writes.
    w.req("PUT", "/dav/f", &[("if", &ifh)], b"v2")
        .await
        .expect(204);
    assert_eq!(w.s3_get("f").await.1, b"v2");
    // A wrong token on a locked resource: the lock is not submitted, so
    // locked (before the If header is judged).
    w.req("PUT", "/dav/f", &[("if", "(<urn:uuid:nope>)")], b"v3")
        .await
        .expect(423);
    // The right token with a false condition: the If header fails.
    w.req(
        "PUT",
        "/dav/f",
        &[("if", &format!("({token} [\"nope\"])"))],
        b"v3",
    )
    .await
    .expect(412);
    // S3 writers are not bound by a WebDAV lock: a lock binds WebDAV
    // clients only.
    assert_eq!(w.s3_put("f", b"s3").await, 200);

    // lockdiscovery shows it.
    let r = w
        .req(
            "PROPFIND",
            "/dav/f",
            &[("depth", "0")],
            &propfind_body(&["lockdiscovery"]),
        )
        .await;
    assert!(r.text().contains(token.trim_matches(['<', '>'])));

    // Refresh.
    let r = w
        .req(
            "LOCK",
            "/dav/f",
            &[("if", &ifh), ("timeout", "Second-50")],
            b"",
        )
        .await;
    r.expect(200);
    assert!(r.text().contains("<D:timeout>Second-50</D:timeout>"));
    w.req("LOCK", "/dav/f", &[("if", "(<urn:uuid:nope>)")], b"")
        .await
        .expect(412);

    // UNLOCK: another key may not; the owner may, also with the bare
    // token Windows sends.
    let bare = token.trim_matches(['<', '>']).to_owned();
    w.req_as(
        APP2,
        APP2_SECRET,
        "UNLOCK",
        "/dav/f",
        &[("lock-token", &token)],
        b"",
    )
    .await
    .expect(403);
    w.req(
        "UNLOCK",
        "/dav/f",
        &[("lock-token", "<urn:uuid:nope>")],
        b"",
    )
    .await
    .expect(409);
    w.req("UNLOCK", "/dav/f", &[("lock-token", &bare)], b"")
        .await
        .expect(204);
    w.req("PUT", "/dav/f", &[], b"free").await.expect(204);
}

#[tokio::test]
async fn depth_infinity_locks_cover_new_members_and_expire() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    let r = w
        .req(
            "LOCK",
            "/dav/d/",
            &[("timeout", "Second-60")],
            &lockinfo("exclusive", "me"),
        )
        .await;
    r.expect(200);
    let token = r.header("lock-token").unwrap().to_owned();
    assert!(r.text().contains("<D:depth>infinity</D:depth>"));
    w.req("PUT", "/dav/d/new", &[], b"x").await.expect(423);
    w.req("MKCOL", "/dav/d/sub/", &[], b"").await.expect(423);
    w.req("PUT", "/dav/d/new", &[("if", &format!("({token})"))], b"x")
        .await
        .expect(201);
    // A tagged list for the folder also submits its token.
    let tagged = format!("<https://{DAV_HOST}/dav/d/> ({token})");
    w.req("PUT", "/dav/d/other", &[("if", &tagged)], b"x")
        .await
        .expect(201);
    // After the timeout the lock is gone.
    w.advance_secs(61);
    w.req("PUT", "/dav/d/later", &[], b"x").await.expect(201);
}

#[tokio::test]
async fn shared_locks_and_lock_on_an_unmapped_url() {
    let w = World::new().await;
    let r = w
        .req("LOCK", "/dav/new.txt", &[], &lockinfo("exclusive", "me"))
        .await;
    r.expect(201);
    let (status, bytes, _) = w.s3_get("new.txt").await;
    assert_eq!((status, bytes.len()), (200, 0));
    w.req(
        "LOCK",
        "/dav/nodir/new.txt",
        &[],
        &lockinfo("exclusive", "me"),
    )
    .await
    .expect(409);

    w.req("PUT", "/dav/s", &[], b"x").await.expect(201);
    let a = w.req("LOCK", "/dav/s", &[], &lockinfo("shared", "a")).await;
    a.expect(200);
    let b = w
        .req_as(
            APP2,
            APP2_SECRET,
            "LOCK",
            "/dav/s",
            &[],
            &lockinfo("shared", "b"),
        )
        .await;
    b.expect(200);
    w.req("LOCK", "/dav/s", &[], &lockinfo("exclusive", "c"))
        .await
        .expect(423);
    let ta = a.header("lock-token").unwrap();
    w.req("PUT", "/dav/s", &[("if", &format!("({ta})"))], b"y")
        .await
        .expect(204);
    let r = w
        .req(
            "PROPFIND",
            "/dav/s",
            &[("depth", "0")],
            &propfind_body(&["lockdiscovery"]),
        )
        .await;
    assert_eq!(values(&r.text(), "D:activelock").len(), 2);
}

#[tokio::test]
async fn a_shared_lock_token_covers_a_file_with_overlapping_locks() {
    let w = World::new().await;
    assert_eq!(w.s3_put("docs/report", b"old").await, 200);
    w.req("LOCK", "/dav/docs/", &[], &lockinfo("shared", "alice"))
        .await
        .expect(200);
    let bob = w
        .req_as(
            APP2,
            APP2_SECRET,
            "LOCK",
            "/dav/docs/report",
            &[],
            &lockinfo("shared", "bob"),
        )
        .await;
    let bob_if = format!("({})", bob.expect(200).header("lock-token").unwrap());
    w.req_as(
        APP2,
        APP2_SECRET,
        "PUT",
        "/dav/docs/report",
        &[("if", &bob_if)],
        b"new",
    )
    .await
    .expect(204);
    // Alice must submit her own token; borrowing Bob's does not suffice.
    for headers in [&[][..], &[("if", bob_if.as_str())][..]] {
        w.req("PUT", "/dav/docs/report", headers, b"alice")
            .await
            .expect(423);
    }
    assert_eq!(w.s3_get("docs/report").await.1, b"new");
}

#[tokio::test]
async fn a_tree_write_still_checks_independent_shared_locks() {
    for (depth, status) in [("0", 423), ("infinity", 204)] {
        let w = World::new().await;
        assert_eq!(w.s3_put("docs/report", b"old").await, 200);
        let alice = w
            .req(
                "LOCK",
                "/dav/docs/",
                &[("depth", depth)],
                &lockinfo("shared", "alice"),
            )
            .await;
        let alice_if = format!("({})", alice.expect(200).header("lock-token").unwrap());
        w.req_as(
            APP2,
            APP2_SECRET,
            "LOCK",
            "/dav/docs/report",
            &[],
            &lockinfo("shared", "bob"),
        )
        .await
        .expect(200);
        // The token covers the report only if Alice's depth is infinity.
        w.req("DELETE", "/dav/docs/", &[("if", &alice_if)], b"")
            .await
            .expect(status);
        assert_eq!(
            w.s3_get("docs/report").await.0,
            if depth == "0" { 200 } else { 404 }
        );
    }
}

#[tokio::test]
async fn a_depth_zero_token_does_not_cover_unrooted_descendants() {
    let w = World::new().await;
    assert_eq!(w.s3_put("docs/report", b"keep").await, 200);
    w.req("LOCK", "/dav/docs/", &[], &lockinfo("shared", "alice"))
        .await
        .expect(200);
    let bob = w
        .req_as(
            APP2,
            APP2_SECRET,
            "LOCK",
            "/dav/docs/",
            &[("depth", "0")],
            &lockinfo("shared", "bob"),
        )
        .await;
    let bob_if = format!("({})", bob.expect(200).header("lock-token").unwrap());
    w.req_as(
        APP2,
        APP2_SECRET,
        "DELETE",
        "/dav/docs/",
        &[("if", &bob_if)],
        b"",
    )
    .await
    .expect(423);
    assert_eq!(w.s3_get("docs/report").await.1, b"keep");
}

#[tokio::test]
async fn inherited_shared_token_can_authorize_a_membership_change() {
    let w = World::new().await;
    assert_eq!(w.s3_put("docs/team/report", b"old").await, 200);
    let alice = w
        .req("LOCK", "/dav/docs/", &[], &lockinfo("shared", "alice"))
        .await;
    let alice_if = format!("({})", alice.expect(200).header("lock-token").unwrap());
    w.req_as(
        APP2,
        APP2_SECRET,
        "LOCK",
        "/dav/docs/team/",
        &[("depth", "0")],
        &lockinfo("shared", "bob"),
    )
    .await
    .expect(200);
    w.req("PUT", "/dav/docs/team/new", &[("if", &alice_if)], b"new")
        .await
        .expect(201);
}

#[tokio::test]
async fn dead_properties_follow_copy_and_move_and_go_with_delete() {
    let w = World::new().await;
    w.req("PUT", "/dav/p", &[], b"x").await.expect(201);
    let patch = br#"<?xml version="1.0"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:z">
  <D:set><D:prop><Z:color xml:lang="en">red &amp; <Z:b>bold</Z:b></Z:color><Z:size>1</Z:size></D:prop></D:set>
  <D:remove><D:prop><Z:size/></D:prop></D:remove>
</D:propertyupdate>"#;
    let r = w.req("PROPPATCH", "/dav/p", &[], patch).await;
    r.expect(207);
    assert!(r.text().contains("HTTP/1.1 200 OK"));
    let ask = br#"<D:propfind xmlns:D="DAV:"><D:prop><Z:color xmlns:Z="urn:z"/><Z:size xmlns:Z="urn:z"/></D:prop></D:propfind>"#;
    let r = w.req("PROPFIND", "/dav/p", &[("depth", "0")], ask).await;
    let text = r.text();
    assert!(
        text.contains(r#"<color xmlns="urn:z" xml:lang="en">red &amp; <b>bold</b></color>"#),
        "{text}"
    );
    assert!(
        text.contains(r#"<size xmlns="urn:z"/></D:prop><D:status>HTTP/1.1 404"#),
        "{text}"
    );
    // allprop includes it.
    let r = w.req("PROPFIND", "/dav/p", &[("depth", "0")], b"").await;
    assert!(r.text().contains("<color xmlns=\"urn:z\""));

    // A protected property fails the whole update.
    let bad = br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:getetag>x</D:getetag><Q:q xmlns:Q="urn:q">1</Q:q></D:prop></D:set></D:propertyupdate>"#;
    let r = w.req("PROPPATCH", "/dav/p", &[], bad).await;
    r.expect(207);
    assert!(r.text().contains("403 Forbidden"));
    assert!(r.text().contains("cannot-modify-protected-property"));
    assert!(r.text().contains("424 Failed Dependency"));

    w.req("COPY", "/dav/p", &[("destination", "/dav/q")], b"")
        .await
        .expect(201);
    w.req("MOVE", "/dav/q", &[("destination", "/dav/r")], b"")
        .await
        .expect(201);
    let r = w.req("PROPFIND", "/dav/r", &[("depth", "0")], ask).await;
    assert!(r.text().contains("red &amp;"), "{}", r.text());
    // An overwrite through S3 makes the properties stale.
    assert_eq!(w.s3_put("r", b"changed").await, 200);
    let r = w.req("PROPFIND", "/dav/r", &[("depth", "0")], ask).await;
    assert!(!r.text().contains("red &amp;"));
    // Deleted with the file; a new file of that name has none.
    w.req("DELETE", "/dav/p", &[], b"").await.expect(204);
    w.req("PUT", "/dav/p", &[], b"x").await.expect(201);
    let r = w.req("PROPFIND", "/dav/p", &[("depth", "0")], ask).await;
    assert!(!r.text().contains("red &amp;"));
}

#[tokio::test]
async fn proppatch_preserves_the_nearest_xml_language() {
    let w = World::new().await;
    w.req("PUT", "/dav/p", &[], b"x").await.expect(201);
    let patch = br#"<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:z" xml:lang="fr">
      <D:set><D:prop><Z:root>bonjour</Z:root><Z:clear xml:lang="">clear</Z:clear></D:prop></D:set>
      <D:set xml:lang="de"><D:prop xml:lang="it"><Z:nearest>ciao</Z:nearest><Z:own xml:lang="en">hello</Z:own></D:prop></D:set>
    </D:propertyupdate>"#;
    w.req("PROPPATCH", "/dav/p", &[], patch).await.expect(207);
    let r = w.req("PROPFIND", "/dav/p", &[("depth", "0")], b"").await;
    r.expect(207);
    let text = r.text();
    for (name, lang) in [
        ("root", "fr"),
        ("clear", ""),
        ("nearest", "it"),
        ("own", "en"),
    ] {
        assert!(
            text.contains(&format!(r#"<{name} xmlns="urn:z" xml:lang="{lang}">"#)),
            "{text}"
        );
    }
}

#[tokio::test]
async fn copy_does_not_revive_dead_properties_after_an_s3_overwrite() {
    let w = World::new().await;
    assert_eq!(w.s3_put("report", b"old").await, 200);
    w.req("PROPPATCH", "/dav/report", &[], SET_X)
        .await
        .expect(207);
    assert!(has_x(&w, "/dav/report").await);
    assert_eq!(w.s3_put("report", b"new").await, 200);

    w.req(
        "COPY",
        "/dav/report",
        &[("destination", "/dav/copied")],
        b"",
    )
    .await
    .expect(201);
    assert_eq!(w.s3_get("copied").await.1, b"new");
    assert!(
        !has_x(&w, "/dav/copied").await,
        "copy revived a stale property"
    );
}

#[tokio::test]
async fn large_puts_go_up_in_parts() {
    let part = 5 * MIB;
    let w = World::with(Config {
        part_bytes: part,
        ..Config::default()
    })
    .await;
    let body = pattern(9, 2 * part + 1234);
    let r = w.req("PUT", "/dav/big.bin", &[], &body).await;
    r.expect(201);
    let etag = r.header("etag").unwrap().to_owned();
    assert!(etag.ends_with("-3\""), "{etag}");
    let (status, got, s3_etag) = w.s3_get("big.bin").await;
    assert_eq!(status, 200);
    assert!(got == body, "the bytes read back are the bytes sent");
    assert_eq!(s3_etag.as_deref(), Some(etag.as_str()));
    let parts = w
        .dav
        .up
        .sent
        .borrow()
        .iter()
        .filter(|(_, t)| t.contains("partNumber="))
        .count();
    assert_eq!(parts, 3);
    // A body of unknown length that fits one part: one PutObject.
    let r = w
        .req(
            "PUT",
            "/dav/small.bin",
            &[("-content-length", "")],
            &pattern(1, 1000),
        )
        .await;
    r.expect(201);
    assert!(!r.header("etag").unwrap().contains('-'));
    // Exactly one part long: one PutObject.
    w.req("PUT", "/dav/exact.bin", &[], &pattern(2, part))
        .await
        .expect(201);
    assert_eq!(w.s3_get("exact.bin").await.1.len(), part);
}

#[tokio::test]
async fn conditional_writes() {
    let w = World::new().await;
    let etag = w
        .req("PUT", "/dav/c", &[], b"1")
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    w.req("PUT", "/dav/c", &[("if-match", "\"nope\"")], b"2")
        .await
        .expect(412);
    w.req("PUT", "/dav/c", &[("if-none-match", "*")], b"2")
        .await
        .expect(412);
    w.req("PUT", "/dav/c", &[("if-none-match", &etag)], b"2")
        .await
        .expect(412);
    w.req("PUT", "/dav/c", &[("if-match", &etag)], b"2")
        .await
        .expect(204);
    w.req("PUT", "/dav/d", &[("if-none-match", "*")], b"1")
        .await
        .expect(201);
    w.req("PUT", "/dav/c", &[("if", "([\"wrong\"])")], b"3")
        .await
        .expect(412);
    let now = w
        .req("HEAD", "/dav/c", &[], b"")
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    w.req("PUT", "/dav/c", &[("if", &format!("([{now}])"))], b"3")
        .await
        .expect(204);
    w.req("PUT", "/dav/c", &[("if", "(Not <DAV:no-lock>)")], b"4")
        .await
        .expect(204);
    w.req("PUT", "/dav/c", &[("if", "garbage")], b"4")
        .await
        .expect(400);
    w.req("DELETE", "/dav/c", &[("if-match", "\"nope\"")], b"")
        .await
        .expect(412);
}

#[tokio::test]
async fn write_conditions_use_weak_and_strong_etag_comparison() {
    let w = World::new().await;
    let tag = w
        .req("PUT", "/dav/c", &[], b"old")
        .await
        .expect(201)
        .header("etag")
        .unwrap()
        .to_owned();
    let weak = format!(r#"  "other,tag" , W/{tag}  "#);
    for header in ["if-none-match", "if-match"] {
        w.req("PUT", "/dav/c", &[(header, &weak)], b"new")
            .await
            .expect(412);
        assert_eq!(w.s3_get("c").await.1, b"old");
    }
    let strong = format!(r#" W/"other,tag" , {tag} "#);
    w.req("PUT", "/dav/c", &[("if-match", &strong)], b"new")
        .await
        .expect(204);
    w.req("PUT", "/dav/c", &[("if-match", "  * ")], b"newer")
        .await
        .expect(204);
    w.req("PUT", "/dav/c", &[("if-none-match", "  * ")], b"blocked")
        .await
        .expect(412);
    w.req("PUT", "/dav/new", &[("if-none-match", "  * ")], b"new")
        .await
        .expect(201);
}

#[tokio::test]
async fn read_only_grants_read_only() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"x").await.expect(201);
    let ro = |m: &'static str, p: &'static str, h: &'static [(&'static str, &'static str)]| {
        let w = &w;
        async move { w.req_as(RO, RO_SECRET, m, p, h, b"").await }
    };
    ro("GET", "/dav/f", &[]).await.expect(200);
    ro("PROPFIND", "/dav/", &[("depth", "1")]).await.expect(207);
    assert_eq!(
        w.req_as(RO, RO_SECRET, "PUT", "/dav/g", &[], b"x")
            .await
            .status,
        403
    );
    ro("DELETE", "/dav/f", &[]).await.expect(403);
    ro("MKCOL", "/dav/n/", &[]).await.expect(403);
    // A bucket without a grant does not exist for the key.
    ro("PROPFIND", "/other/", &[("depth", "0")])
        .await
        .expect(404);
}

#[tokio::test]
async fn collection_get_is_a_plain_index() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/d/%3Cscript%3E.txt", &[], b"x")
        .await
        .expect(201);
    let r = w.req("GET", "/dav/d/", &[], b"").await;
    r.expect(200);
    assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
    assert!(r.text().contains("&lt;script&gt;.txt"));
    assert!(!r.text().contains("<script>"));
    assert_eq!(
        r.header("content-security-policy"),
        Some("sandbox; default-src 'none'")
    );
    let r = w.req("GET", "/", &[], b"").await;
    r.expect(200);
    assert!(r.text().contains("href=\"/dav/\""));
}

#[tokio::test]
async fn a_bucket_the_key_cannot_see_never_reaches_its_state_object() {
    let w = World::new().await;
    w.req("PUT", "/other/x", &[], b"x").await.expect(201);
    let before = w.dav.state.calls.get();
    // RO holds no grant on `other`: to it the bucket does not exist.
    for (method, body) in [
        ("LOCK", lockinfo("exclusive", "x")),
        ("UNLOCK", Vec::new()),
        ("PROPPATCH", b"<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><x xmlns=\"urn:x\">1</x></D:prop></D:set></D:propertyupdate>".to_vec()),
        ("PUT", b"y".to_vec()),
        ("DELETE", Vec::new()),
        ("PROPFIND", Vec::new()),
    ] {
        let r = w
            .req_as(
                RO,
                RO_SECRET,
                method,
                "/other/x",
                &[("lock-token", "<urn:uuid:x>"), ("depth", "0"), ("if", "(<urn:uuid:x>)")],
                &body,
            )
            .await;
        assert!(
            matches!(r.status, 404 | 409),
            "{method}: {} {}",
            r.status,
            r.text()
        );
    }
    assert_eq!(w.dav.state.calls.get(), before);
}

#[tokio::test]
async fn a_false_condition_on_a_locked_resource() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"x").await.expect(201);
    let etag = w
        .req("HEAD", "/dav/f", &[], b"")
        .await
        .header("etag")
        .unwrap()
        .to_owned();
    w.req("LOCK", "/dav/f", &[], &lockinfo("exclusive", "me"))
        .await
        .expect(200);
    // Names no lock and is false: 412 (litmus fail_cond_put).
    w.req(
        "PUT",
        "/dav/f",
        &[("if", &format!("(<DAV:no-lock> [{etag}])"))],
        b"y",
    )
    .await
    .expect(412);
    // Names no lock and is true: the lock is still not submitted.
    w.req("PUT", "/dav/f", &[("if", &format!("([{etag}])"))], b"y")
        .await
        .expect(423);
    // Names a lock that is not this one: 423 (litmus cond_put_corrupt_token).
    w.req("PUT", "/dav/f", &[("if", "(<urn:uuid:corrupt>)")], b"y")
        .await
        .expect(423);
    // A fragment in the target is refused, never cut off.
    w.req("DELETE", "/dav/f#frag", &[], b"").await.expect(400);
}

#[tokio::test]
async fn parallel_large_puts_share_the_isolates_part_slots() {
    let part = 5 * MIB;
    let w = World::with(Config {
        part_bytes: part,
        ..Config::default()
    })
    .await;
    let a = pattern(5, 3 * part + 7);
    let b = pattern(6, 4 * part);
    let (ra, rb) = futures_util::future::join(
        w.req("PUT", "/dav/a.bin", &[], &a),
        w.req("PUT", "/dav/b.bin", &[], &b),
    )
    .await;
    ra.expect(201);
    rb.expect(201);
    assert!(w.s3_get("a.bin").await.1 == a);
    assert!(w.s3_get("b.bin").await.1 == b);
    // Never more parts in memory than the isolate allows, and none left.
    assert!(
        w.dav.up.most_slots.get() <= 2,
        "{}",
        w.dav.up.most_slots.get()
    );
    assert_eq!(velmora_dav::slots::Slot::held(), 0);
}

// Review findings (reviewer-critical on the first version).

#[tokio::test]
async fn a_destination_that_holds_the_source_is_refused_and_nothing_is_lost() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/a/", &[], b"").await.expect(201);
    w.req("MKCOL", "/dav/a/x/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/a/x/f", &[], b"1").await.expect(201);
    w.req("PUT", "/dav/a/f", &[], b"2").await.expect(201);
    w.req("MOVE", "/dav/a/x/", &[("destination", "/dav/a/")], b"")
        .await
        .expect(403);
    w.req("COPY", "/dav/a/f", &[("destination", "/dav/a")], b"")
        .await
        .expect(403);
    w.req("MOVE", "/dav/a/x/f", &[("destination", "/dav/a/x")], b"")
        .await
        .expect(403);
    let keys: Vec<String> = w.s3_list("a/").await.into_iter().map(|e| e.0).collect();
    assert_eq!(keys, ["a/", "a/f", "a/x/", "a/x/f"]);
}

#[tokio::test]
async fn the_cap_is_judged_before_the_destination_is_deleted() {
    let w = World::with(Config {
        max_tree: 3,
        ..Config::default()
    })
    .await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    for i in 0..4 {
        w.req("PUT", &format!("/dav/d/{i}"), &[], b"x")
            .await
            .expect(201);
    }
    w.req("MKCOL", "/dav/e/", &[], b"").await.expect(201);
    w.req("PUT", "/dav/e/keep", &[], b"k").await.expect(201);
    w.req("PUT", "/dav/f", &[], b"file").await.expect(201);
    w.req("MOVE", "/dav/d/", &[("destination", "/dav/e/")], b"")
        .await
        .expect(403);
    w.req("MOVE", "/dav/d/", &[("destination", "/dav/f")], b"")
        .await
        .expect(403);
    assert_eq!(w.s3_get("e/keep").await.1, b"k");
    assert_eq!(w.s3_get("f").await.1, b"file");
    assert_eq!(w.s3_list("d/").await.len(), 5);
}

const SET_X: &[u8] = br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><x xmlns="urn:x">1</x></D:prop></D:set></D:propertyupdate>"#;
const ASK_X: &[u8] =
    br#"<D:propfind xmlns:D="DAV:"><D:prop><x xmlns="urn:x"/></D:prop></D:propfind>"#;

async fn has_x(w: &World, path: &str) -> bool {
    let r = w.req("PROPFIND", path, &[("depth", "0")], ASK_X).await;
    r.text().contains(r#"<x xmlns="urn:x">1</x>"#)
}

#[tokio::test]
async fn a_delete_that_deletes_nothing_keeps_properties_and_locks() {
    let w = World::with(Config {
        max_tree: 2,
        ..Config::default()
    })
    .await;
    w.req("MKCOL", "/dav/d/", &[], b"").await.expect(201);
    for name in ["a", "b", "c"] {
        w.req("PUT", &format!("/dav/d/{name}"), &[], b"x")
            .await
            .expect(201);
    }
    w.req("PROPPATCH", "/dav/d/a", &[], SET_X).await.expect(207);
    let lock = w
        .req("LOCK", "/dav/d/b", &[], &lockinfo("exclusive", "me"))
        .await;
    lock.expect(200);
    let token = lock.header("lock-token").unwrap().to_owned();
    // Over the cap: nothing deleted, nothing forgotten.
    let ifh = format!("</dav/d/b> ({token})");
    w.req("DELETE", "/dav/d/", &[("if", &ifh)], b"")
        .await
        .expect(403);
    assert!(has_x(&w, "/dav/d/a").await);
    w.req("PUT", "/dav/d/b", &[], b"y").await.expect(423);
    // A read-only key's refused delete forgets nothing either.
    w.req_as(RO, RO_SECRET, "DELETE", "/dav/d/a", &[], b"")
        .await
        .expect(403);
    assert!(has_x(&w, "/dav/d/a").await);
}

#[tokio::test]
async fn a_read_only_key_cannot_set_properties_or_lock() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"x").await.expect(201);
    w.req_as(RO, RO_SECRET, "PROPPATCH", "/dav/f", &[], SET_X)
        .await
        .expect(403);
    assert!(!has_x(&w, "/dav/f").await);
    w.req_as(
        RO,
        RO_SECRET,
        "LOCK",
        "/dav/f",
        &[],
        &lockinfo("exclusive", "ro"),
    )
    .await
    .expect(403);
    w.req("PUT", "/dav/f", &[], b"y").await.expect(204);
    // The probe writes nothing: the object is as it was.
    assert_eq!(w.s3_get("f").await.1, b"y");
}

#[tokio::test]
async fn malformed_names_are_refused() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"x").await.expect(201);
    for body in [
        &br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><x&y xmlns="urn:x">1</x&y></D:prop></D:set></D:propertyupdate>"#[..],
        br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><1a xmlns="urn:x">1</1a></D:prop></D:set></D:propertyupdate>"#,
    ] {
        w.req("PROPPATCH", "/dav/f", &[], body).await.expect(400);
    }
}

#[tokio::test]
async fn lock_on_an_unmapped_url_respects_the_folders_lock() {
    let w = World::new().await;
    w.req("MKCOL", "/dav/c/", &[], b"").await.expect(201);
    let r = w
        .req(
            "LOCK",
            "/dav/c/",
            &[("depth", "0")],
            &lockinfo("exclusive", "a"),
        )
        .await;
    r.expect(200);
    w.req_as(
        APP2,
        APP2_SECRET,
        "LOCK",
        "/dav/c/n",
        &[],
        &lockinfo("exclusive", "b"),
    )
    .await
    .expect(423);
    assert_eq!(w.s3_get("c/n").await.0, 404);
    // The folder's owner, with its token, may.
    let token = r.header("lock-token").unwrap().to_owned();
    let ifh = format!("</dav/c/> ({token})");
    w.req(
        "LOCK",
        "/dav/c/n",
        &[("if", &ifh)],
        &lockinfo("exclusive", "a"),
    )
    .await
    .expect(201);
}

#[tokio::test]
async fn a_webdav_overwrite_keeps_dead_properties() {
    let w = World::new().await;
    w.req("PUT", "/dav/f", &[], b"one").await.expect(201);
    w.req("PROPPATCH", "/dav/f", &[], SET_X).await.expect(207);
    w.req("PUT", "/dav/f", &[], b"two").await.expect(204);
    assert!(has_x(&w, "/dav/f").await);
    // An overwrite through S3 still makes them stale.
    assert_eq!(w.s3_put("f", b"three").await, 200);
    assert!(!has_x(&w, "/dav/f").await);
}

#[tokio::test]
async fn propfind_between_publish_and_restamp_keeps_dead_properties() {
    use velmora_dav::state::{Engine, Op, Reply};

    let w = World::new().await;
    w.req("PUT", "/dav/report", &[], b"old").await.expect(201);
    w.req("PROPPATCH", "/dav/report", &[], SET_X)
        .await
        .expect(207);
    let old = w.s3_get("report").await.2.unwrap();

    // Publish the new bytes but leave the properties at the old stamp,
    // as they are between a WebDAV PUT's storage and state calls.
    assert_eq!(w.s3_put("report", b"new").await, 200);
    let new = w.s3_get("report").await.2.unwrap();
    assert_ne!(old, new);
    assert!(!has_x(&w, "/dav/report").await);

    let db = w.dav.state.dbs.borrow().values().next().unwrap().clone();
    let replies = Engine {
        sql: db.as_ref(),
        now: w.dav.state.now.get(),
    }
    .run(vec![Op::PropRestamp {
        path: "report".to_owned(),
        from: old,
        to: new,
    }])
    .unwrap();
    assert_eq!(replies, vec![Reply::Done]);
    assert!(has_x(&w, "/dav/report").await, "restamp lost the property");
}

#[tokio::test]
async fn locks_work_on_a_deep_path() {
    let w = World::new().await;
    let mut path = String::from("/dav/");
    for i in 0..120 {
        path.push_str(&format!("d{i}/"));
    }
    // Parents are implied by the key; no MKCOL per level.
    let file = format!("{}f", &path[5..]);
    assert_eq!(w.s3_put(&file, b"x").await, 200);
    let url = format!("{path}f");
    let r = w.req("LOCK", &url, &[], &lockinfo("exclusive", "me")).await;
    r.expect(200);
    w.req("PUT", &url, &[], b"y").await.expect(423);
    let token = r.header("lock-token").unwrap().to_owned();
    w.req("PUT", &url, &[("if", &format!("({token})"))], b"y")
        .await
        .expect(204);
}
