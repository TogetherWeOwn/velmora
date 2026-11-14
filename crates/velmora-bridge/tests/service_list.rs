//! ListObjectsV2, ListObjects (V1) and ListBuckets over the SQL catalogue.

mod service_support;

use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "bkt-list";

struct Page {
    keys: Vec<String>,
    prefixes: Vec<String>,
    truncated: bool,
    token: Option<String>,
    key_count: usize,
}

async fn list<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    bucket: &str,
    query: &[(&str, &str)],
) -> Resp {
    let mut q = vec![("list-type", "2")];
    q.extend_from_slice(query);
    rig.call(signer, Method::Get, &format!("/{bucket}"), &q, &[], b"")
        .await
}

fn page(resp: &Resp) -> Page {
    resp.expect(200);
    let text = resp.text();
    // Common prefixes are the `<Prefix>` values after the request's own.
    let prefixes = text
        .split("<CommonPrefixes><Prefix>")
        .skip(1)
        .map(|rest| rest.split("</Prefix>").next().unwrap().to_string())
        .collect();
    let truncated = resp.values("IsTruncated") == ["true"];
    let token = resp.values("NextContinuationToken").pop();
    assert_eq!(truncated, token.is_some(), "a token exactly when truncated");
    Page {
        keys: resp.values("Key"),
        prefixes,
        truncated,
        token,
        key_count: resp.values("KeyCount")[0].parse().unwrap(),
    }
}

/// Follows continuation tokens to the end and returns every page.
async fn all_pages<N: NntpConnector + 'static>(
    rig: &Rig<N>,
    signer: &Signer,
    query: &[(&str, &str)],
) -> Vec<Page> {
    let mut pages = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut q = query.to_vec();
        if let Some(t) = &token {
            q.push(("continuation-token", t));
        }
        let p = page(&list(rig, signer, BUCKET, &q).await);
        token = p.token.clone();
        pages.push(p);
        assert!(pages.len() < 100, "listing does not terminate");
        if token.is_none() {
            return pages;
        }
    }
}

async fn put_all<N: NntpConnector + 'static>(rig: &Rig<N>, signer: &Signer, keys: &[String]) {
    for key in keys {
        rig.put(signer, BUCKET, key, key.as_bytes())
            .await
            .expect(200);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn empty_bucket_lists_nothing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let resp = list(&rig, &signer, BUCKET, &[]).await;
    let p = page(&resp);
    assert!(p.keys.is_empty() && p.prefixes.is_empty() && !p.truncated);
    assert_eq!(p.key_count, 0);
    assert_eq!(resp.values("Name"), [BUCKET]);
    assert_eq!(resp.header("content-type"), Some("application/xml"));
}

#[tokio::test(flavor = "current_thread")]
async fn pages_follow_tokens_without_gaps_or_repeats() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut keys: Vec<String> = (0..25).map(|i| format!("key-{i:03}")).collect();
    // Written out of order: the listing sorts.
    keys.reverse();
    put_all(&rig, &signer, &keys).await;
    keys.sort();

    let pages = all_pages(&rig, &signer, &[("max-keys", "10")]).await;
    assert_eq!(
        pages.iter().map(|p| p.keys.len()).collect::<Vec<_>>(),
        [10, 10, 5]
    );
    assert!(pages.iter().all(|p| p.key_count == p.keys.len()));
    let listed: Vec<String> = pages.into_iter().flat_map(|p| p.keys).collect();
    assert_eq!(listed, keys);

    // A page that ends exactly at the last key is not truncated.
    let pages = all_pages(&rig, &signer, &[("max-keys", "25")]).await;
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].keys, keys);

    // Size and ETag come from the catalogue.
    let resp = list(&rig, &signer, BUCKET, &[("max-keys", "1")]).await;
    assert_eq!(resp.values("Size"), ["7"]);
    let etag = format!("&quot;{}&quot;", hex(&md5::compute(b"key-000").0));
    assert_eq!(resp.values("ETag"), [etag]);
    assert_eq!(resp.values("LastModified"), ["2027-01-15T08:00:00.000Z"]);
}

#[tokio::test(flavor = "current_thread")]
async fn prefix_and_start_after_bound_the_listing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = ["a/1", "a/2", "a%/3", "a_/4", "b/1", "b/2", "c"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    put_all(&rig, &signer, &keys).await;

    let p = page(&list(&rig, &signer, BUCKET, &[("prefix", "a/")]).await);
    assert_eq!(p.keys, ["a/1", "a/2"]);
    // LIKE wildcards in a prefix are literal.
    let p = page(&list(&rig, &signer, BUCKET, &[("prefix", "a%")]).await);
    assert_eq!(p.keys, ["a%/3"]);
    let p = page(&list(&rig, &signer, BUCKET, &[("prefix", "a_")]).await);
    assert_eq!(p.keys, ["a_/4"]);
    let p = page(&list(&rig, &signer, BUCKET, &[("start-after", "a/2")]).await);
    assert_eq!(p.keys, ["a_/4", "b/1", "b/2", "c"]);
    let p = page(
        &list(
            &rig,
            &signer,
            BUCKET,
            &[("prefix", "b/"), ("start-after", "b/1")],
        )
        .await,
    );
    assert_eq!(p.keys, ["b/2"]);
    let p = page(&list(&rig, &signer, BUCKET, &[("prefix", "zzz")]).await);
    assert!(p.keys.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn delimiter_folds_common_prefixes() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys: Vec<String> = ["a/1", "a/2", "a/sub/3", "b/1", "c", "d/x/y", "d/x/z", "e"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    put_all(&rig, &signer, &keys).await;

    let p = page(&list(&rig, &signer, BUCKET, &[("delimiter", "/")]).await);
    assert_eq!(p.keys, ["c", "e"]);
    assert_eq!(p.prefixes, ["a/", "b/", "d/"]);
    assert_eq!(p.key_count, 5);

    let p = page(
        &list(
            &rig,
            &signer,
            BUCKET,
            &[("delimiter", "/"), ("prefix", "a/")],
        )
        .await,
    );
    assert_eq!(p.keys, ["a/1", "a/2"]);
    assert_eq!(p.prefixes, ["a/sub/"]);

    // Paging counts a folded prefix once and never repeats it.
    for max in ["1", "2", "3"] {
        let pages = all_pages(&rig, &signer, &[("delimiter", "/"), ("max-keys", max)]).await;
        let max: usize = max.parse().unwrap();
        assert!(pages.iter().all(|p| p.key_count <= max));
        let listed: Vec<String> = pages.iter().flat_map(|p| p.keys.clone()).collect();
        let folded: Vec<String> = pages.iter().flat_map(|p| p.prefixes.clone()).collect();
        assert_eq!(listed, ["c", "e"], "max-keys {max}");
        assert_eq!(folded, ["a/", "b/", "d/"], "max-keys {max}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn listings_larger_than_one_catalogue_batch() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut keys: Vec<String> = (0..1500).map(|i| format!("big/{i:05}")).collect();
    keys.extend((0..700).map(|i| format!("flat-{i:05}")));
    keys.push("zz/last".to_string());
    put_all(&rig, &signer, &keys).await;
    keys.sort();

    // Default page size, across catalogue batches.
    let pages = all_pages(&rig, &signer, &[]).await;
    assert_eq!(
        pages.iter().map(|p| p.keys.len()).collect::<Vec<_>>(),
        [1000, 1000, 201]
    );
    let listed: Vec<String> = pages.into_iter().flat_map(|p| p.keys).collect();
    assert_eq!(listed, keys);

    // A prefix wider than a batch folds to one entry and the keys after
    // it are still found.
    let p = page(&list(&rig, &signer, BUCKET, &[("delimiter", "/")]).await);
    assert_eq!(p.prefixes, ["big/", "zz/"]);
    assert_eq!(p.keys.len(), 700);
    assert!(!p.truncated);
    let pages = all_pages(&rig, &signer, &[("delimiter", "/"), ("max-keys", "300")]).await;
    assert_eq!(
        pages.iter().map(|p| p.key_count).collect::<Vec<_>>(),
        [300, 300, 102]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tokens_are_bound_to_their_listing() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let other = rig.bucket("bkt-other", true).await;
    rig.grant(AKID, &other, Perm::Rw).await;
    let keys: Vec<String> = (0..6).map(|i| format!("p/{i}")).collect();
    put_all(&rig, &signer, &keys).await;

    let first = page(
        &list(
            &rig,
            &signer,
            BUCKET,
            &[("prefix", "p/"), ("max-keys", "2")],
        )
        .await,
    );
    let token = first.token.unwrap();
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut q = vec![("continuation-token", token.as_str())];
        q.extend_from_slice(extra);
        q
    };

    // The same listing continues.
    let q = with(&[("prefix", "p/"), ("max-keys", "2")]);
    let p = page(&list(&rig, &signer, BUCKET, &q).await);
    assert_eq!(p.keys, ["p/2", "p/3"]);

    // Another prefix, another delimiter, another bucket.
    for extra in [
        vec![("prefix", "q/")],
        vec![],
        vec![("prefix", "p/"), ("delimiter", "/")],
    ] {
        list(&rig, &signer, BUCKET, &with(&extra))
            .await
            .expect_error(400, "InvalidArgument");
    }
    list(&rig, &signer, "bkt-other", &with(&[("prefix", "p/")]))
        .await
        .expect_error(400, "InvalidArgument");

    // A forged or damaged token.
    let mut forged = token.clone().into_bytes();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'A' { b'B' } else { b'A' };
    let forged = String::from_utf8(forged).unwrap();
    for bad in [forged.as_str(), "p/2", "AAAA"] {
        list(
            &rig,
            &signer,
            BUCKET,
            &[("prefix", "p/"), ("continuation-token", bad)],
        )
        .await
        .expect_error(400, "InvalidArgument");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn only_the_live_generation_is_listed() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "kept", b"one").await.expect(200);
    rig.put(&signer, BUCKET, "kept", b"second")
        .await
        .expect(200);
    rig.put(&signer, BUCKET, "gone", b"x").await.expect(200);
    rig.call(
        &signer,
        Method::Delete,
        &path(BUCKET, "gone"),
        &[],
        &[],
        b"",
    )
    .await
    .expect(204);

    let resp = list(&rig, &signer, BUCKET, &[]).await;
    assert_eq!(page(&resp).keys, ["kept"]);
    assert_eq!(resp.values("Size"), ["6"]);
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_keys_are_listed_verbatim() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let mut keys: Vec<String> = [
        "with space/and more.txt",
        "plus+sign+key",
        "percent%25literal",
        "ünïcödé/日本語.bin",
        "double//slash",
        "amp&lt<gt>.txt",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    put_all(&rig, &signer, &keys).await;
    keys.sort();

    let p = page(&list(&rig, &signer, BUCKET, &[]).await);
    let unescaped: Vec<String> = p
        .keys
        .iter()
        .map(|k| {
            k.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
        })
        .collect();
    assert_eq!(unescaped, keys);
    assert!(p.keys.contains(&"amp&amp;lt&lt;gt&gt;.txt".to_string()));

    // `//` is two delimiters, not one.
    let p = page(
        &list(
            &rig,
            &signer,
            BUCKET,
            &[("prefix", "double/"), ("delimiter", "/")],
        )
        .await,
    );
    assert_eq!(p.prefixes, ["double//"]);
}

#[tokio::test(flavor = "current_thread")]
async fn only_list_objects_v1_and_v2_are_served() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    // No list-type is V1 (served; see `list_objects_v1_pages_by_marker`).
    rig.call(&signer, Method::Get, "/bkt-list", &[], &[], b"")
        .await
        .expect(200);
    rig.call(
        &signer,
        Method::Get,
        "/bkt-list",
        &[("list-type", "1")],
        &[],
        b"",
    )
    .await
    .expect_error(501, "NotImplemented");
    let resp = list(&rig, &signer, BUCKET, &[("max-keys", "many")]).await;
    assert_eq!(resp.status, 400);
}

#[tokio::test(flavor = "current_thread")]
async fn list_buckets_shows_only_granted_buckets() {
    let rig = rig();
    let (_, signer) = rig.standard("bkt-zeta").await;
    let alpha = rig.bucket("bkt-alpha", true).await;
    rig.grant(AKID, &alpha, Perm::Ro).await;
    rig.bucket("bkt-hidden", true).await;
    let stranger = rig
        .key("AKIDSTRANGER00000000", secret(), KeyStatus::Active)
        .await;

    let resp = rig.call(&signer, Method::Get, "/", &[], &[], b"").await;
    resp.expect(200);
    assert_eq!(resp.values("Name"), ["bkt-alpha", "bkt-zeta"]);
    assert!(!resp.text().contains("bkt-hidden"));

    // A key with no grants sees an empty list, not an error.
    let resp = rig.call(&stranger, Method::Get, "/", &[], &[], b"").await;
    resp.expect(200);
    assert!(resp.values("Name").is_empty());

    // Unknown and disabled keys are denied like any other request.
    let unknown = Signer::new("AKIDUNKNOWN000000000", secret());
    let disabled = rig
        .key("AKIDDISABLED00000000", secret(), KeyStatus::Disabled)
        .await;
    rig.grant("AKIDDISABLED00000000", &alpha, Perm::Rw).await;
    for who in [&unknown, &disabled] {
        rig.call(who, Method::Get, "/", &[], &[], b"")
            .await
            .expect_error(403, "AccessDenied");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn list_objects_v1_pages_by_marker() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let keys = ["a/1", "a/2", "b", "c/x", "c/y", "d e", "z"];
    for k in keys {
        rig.put(&signer, BUCKET, k, k.as_bytes()).await.expect(200);
    }

    // No delimiter: the client resumes after the last key.
    let mut got = Vec::new();
    let mut marker: Option<String> = None;
    for _ in 0..20 {
        let mut q = vec![("max-keys", "2")];
        if let Some(m) = &marker {
            q.push(("marker", m.as_str()));
        }
        let resp = rig
            .call(&signer, Method::Get, &format!("/{BUCKET}"), &q, &[], b"")
            .await;
        resp.expect(200);
        assert!(resp.values("KeyCount").is_empty());
        assert!(resp.values("NextMarker").is_empty());
        let page = resp.values("Key");
        got.extend(page.clone());
        if resp.values("IsTruncated") != ["true"] {
            break;
        }
        marker = page.last().cloned();
    }
    assert_eq!(got, keys);

    // Delimiter: NextMarker, and a common prefix appears once.
    let mut got = Vec::new();
    let mut marker: Option<String> = None;
    for _ in 0..20 {
        let mut q = vec![("max-keys", "1"), ("delimiter", "/")];
        if let Some(m) = &marker {
            q.push(("marker", m.as_str()));
        }
        let resp = rig
            .call(&signer, Method::Get, &format!("/{BUCKET}"), &q, &[], b"")
            .await;
        resp.expect(200);
        got.extend(resp.values("Key"));
        let text = resp.text();
        got.extend(
            text.split("<CommonPrefixes><Prefix>")
                .skip(1)
                .map(|r| r.split("</Prefix>").next().unwrap().to_string()),
        );
        if resp.values("IsTruncated") != ["true"] {
            assert!(resp.values("NextMarker").is_empty());
            break;
        }
        marker = resp.values("NextMarker").pop();
        assert!(
            marker.is_some(),
            "a truncated page with a delimiter names NextMarker"
        );
    }
    assert_eq!(got, ["a/", "b", "c/", "d e", "z"]);

    // As at S3: a marker inside a group rolls the later members into the
    // group again; only the group itself as marker skips it.
    for (marker, prefixes) in [("a/1", vec!["a/", "c/"]), ("a/", vec!["c/"])] {
        let resp = rig
            .call(
                &signer,
                Method::Get,
                &format!("/{BUCKET}"),
                &[("delimiter", "/"), ("marker", marker), ("prefix", "")],
                &[],
                b"",
            )
            .await;
        resp.expect(200);
        assert_eq!(resp.values("Marker"), [marker]);
        assert_eq!(resp.values("Key"), ["b", "d e", "z"]);
        let text = resp.text();
        let got: Vec<String> = text
            .split("<CommonPrefixes><Prefix>")
            .skip(1)
            .map(|r| r.split("</Prefix>").next().unwrap().to_string())
            .collect();
        assert_eq!(got, prefixes, "marker {marker}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn list_objects_v1_needs_a_grant() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.bucket("bkt-hidden", true).await;
    rig.call(&signer, Method::Get, "/bkt-hidden", &[], &[], b"")
        .await
        .expect_error(403, "AccessDenied");
    rig.call(
        &signer,
        Method::Get,
        "/bkt-list",
        &[("list-type", "2"), ("list-type", "2")],
        &[],
        b"",
    )
    .await
    .expect(400);
}

/// restic (minio-go) lists with exactly this query.
#[tokio::test(flavor = "current_thread")]
async fn restic_listing_query_is_served() {
    let rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    rig.put(&signer, BUCKET, "repo/keys/k1", b"x")
        .await
        .expect(200);
    let resp = list(
        &rig,
        &signer,
        BUCKET,
        &[
            ("delimiter", "/"),
            ("encoding-type", "url"),
            ("fetch-owner", "true"),
            ("prefix", "repo/keys/"),
        ],
    )
    .await;
    resp.expect(200);
    assert_eq!(resp.values("Key"), ["repo%2Fkeys%2Fk1"]);
}
