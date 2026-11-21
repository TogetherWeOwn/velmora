//! The deny-list test: no S3 answer says what the storage behind the
//! service is.
//!
//! A customer sees a storage service and nothing of how it stores. So
//! every status, header and body the S3 surface answers with is looked
//! through for the words of the back end. The test is here before any
//! second tenant is, so that a leak is caught when it is written.
//!
//! How it reads an answer:
//!
//! 1. What the request supplied is taken out first: bucket and key
//!    names, metadata, the object's own bytes. A customer may call a
//!    key `articles/post.txt`; that is their word, not ours.
//! 2. The exact protocol tokens of the allow-list are taken out. Every
//!    entry is an S3 term and is reviewed when it is added.
//! 3. In what is left, the **words** are matched whole and without
//!    case, and the **names** are matched anywhere, also inside a
//!    longer word. Names that are not this project's to publish are
//!    kept as SHA-256 hashes: every run of letters and digits of a
//!    listed length is hashed and looked up.
//!
//! The surface covered is the S3 one. The operator plane (`/_admin`) is
//! not a customer surface and says these words on purpose.

mod service_support;

use std::collections::BTreeSet;

use service_support::*;
use velmora_bridge::config::Maintenance;
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::*;

/// Matched as whole words, without case.
const WORDS: [&str; 30] = [
    "usenet",
    "nntp",
    "newsgroup",
    "newsgroups",
    "article",
    "articles",
    "backbone",
    "backbones",
    "yenc",
    "par2",
    "nzb",
    "segment",
    "segments",
    "post",
    "posts",
    "posted",
    "posting",
    "poster",
    "group",
    "groups",
    "messageid",
    "provider",
    "providers",
    "repost",
    "reposted",
    "health",
    "scrub",
    "extent",
    "extents",
    "unit",
];

/// Matched anywhere, without case.
const NAMES: [&str; 7] = [
    "usenet",
    "nntp",
    "newsgroup",
    "backbone",
    "yenc",
    "par2",
    "message-id",
];

/// SHA-256 of names matched anywhere, in lowercase.
const HASHED_NAMES: [&str; HASHED] = [
    "0805febed88ee3f114f11b596db509d807297b6b97325446638ae97df6701b3d",
    "0aedb001db1b74b6344b5f172eb6c5507f0616ddc54864a4e44f4503321acba0",
    "0ed80614304d49d468706678f6384a1f9e3674af35fb4ae8d2222082c1dc8091",
    "27a56e822eb824fdaa3be3ceef83f45155b7c024f19bcd6847eb50ed481c0df3",
    "304584d86d0c626480601a1147ec1b784070dd7569d41abf1b5e4cc159000547",
    "4135727fb2a0f9f8e797ca7b9423c5c2ceda74d5b1e00b265fc0d2913caaa38e",
    "4a2693cccb61524b160fed27b73378e6abc0fc42cb2d455725af9f614ed68f92",
    "574623b392b52accfc77abdfbc05a05eb4ecc0f2f84cd2fe4db348a9c84fe988",
    "5bd20b1429301ffece1e15fb102ca635b14879d48431cd5aaa497b7491711545",
    "678b45d95ff7c75678781dfc03625a192042b7d832cded973eb9abc5fc78745d",
    "87e84d8d2bc2dacfe213b7966dff492352a5e30835c45ca939f7384e282fd326",
    "8801a13c3308b815bab6d6068c1cdbcd7d965f83ab31632f16d8ef4ab284240c",
    "a985b46c05be9e7f74d5f4eb7f655ec20c0946df17a32ad27f9a9ee74753f679",
    "ab39960d0fef3a6caee5cdcb7ec568464336be5a1598b3f69476d4c16c2f30fd",
    "b2e78e3a5bb1d60df728818ea576deafd6ba9b428fefe13794e012f226516dad",
    "fcb7233b835a8fea49703c0a1b44869bda47017040c1fb9228b7507db6a81c6b",
];
const HASHED: usize = 16;

/// The lengths of the hashed names.
const HASHED_LENGTHS: [usize; 8] = [5, 6, 7, 8, 9, 10, 11, 15];

/// A name of the hashed list that is no real one: it shows that the
/// hashed class finds what it should.
const CANARY: &str = "kofracanaryterm";

/// Exact S3 protocol tokens that contain a listed word. Matched with
/// their case, as whole words.
const ALLOWED: [&str; 3] = [
    // The HTTP method, in an `Allow` header or an error about a method.
    "POST",
    // An ACL grantee type.
    "Group",
    // The root element of a browser upload's answer.
    "PostResponse",
];

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// `text` without every whole-word occurrence of `token` (exact case).
fn without_token(text: &str, token: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut at = 0;
    while let Some(i) = text[at..].find(token) {
        let (start, end) = (at + i, at + i + token.len());
        let whole = (start == 0 || !is_word(bytes[start - 1]))
            && (end == bytes.len() || !is_word(bytes[end]));
        out.push_str(&text[at..start]);
        if !whole {
            out.push_str(token);
        }
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

/// What of the deny-list `text` says: empty when it says none of it.
fn findings(text: &str) -> BTreeSet<String> {
    let mut text = text.to_string();
    for token in ALLOWED {
        text = without_token(&text, token);
    }
    let lower = text.to_ascii_lowercase();
    let mut found = BTreeSet::new();
    for word in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        if WORDS.contains(&word) {
            found.insert(format!("word {word:?}"));
        }
    }
    for name in NAMES {
        if lower.contains(name) {
            found.insert(format!("name {name:?}"));
        }
    }
    let bytes = lower.as_bytes();
    for len in HASHED_LENGTHS {
        for window in bytes.windows(len) {
            if window.iter().all(|b| is_word(*b))
                && HASHED_NAMES.contains(&hex(&sha256(window)).as_str())
            {
                // The window is printed, the list is not.
                found.insert(format!("hashed name {:?}", String::from_utf8_lossy(window)));
            }
        }
    }
    found
}

/// The matcher finds each class, in any case and inside other text,
/// and lets the allow-list and nothing else through.
#[test]
fn the_matcher_finds_every_class() {
    let none = BTreeSet::new();
    assert_eq!(HASHED_NAMES.len(), HASHED);
    for len in HASHED_LENGTHS {
        assert!(len >= 5, "a short hashed name matches by chance");
    }
    assert!(HASHED_LENGTHS.contains(&CANARY.len()));

    // Words: whole, any case.
    for text in [
        "An Article.",
        "<Code>POSTED</Code>",
        "x-amz-group: 1",
        "a post",
    ] {
        assert_ne!(findings(text), none, "{text}");
    }
    // Not inside another word.
    for text in ["postpone", "grouping", "particle", "community", "healthy"] {
        assert_eq!(findings(text), none, "{text}");
    }
    // Names: anywhere.
    for text in ["x-usenetwork", "nntps://", "theBackboneOf", "Message-ID"] {
        assert_ne!(findings(text), none, "{text}");
    }
    // Hashed names: anywhere, any case.
    for text in [
        CANARY.to_string(),
        format!("x-{}-id", CANARY.to_ascii_uppercase()),
        format!("abc{CANARY}def"),
    ] {
        assert_ne!(findings(&text), none, "{text}");
    }
    assert_eq!(findings(&CANARY[1..]), none);

    // The allow-list: the exact token only.
    for text in ["Allow: GET, POST", "<Type>Group</Type>", "<PostResponse>"] {
        assert_eq!(findings(text), none, "{text}");
    }
    for text in [
        "Allow: Post",
        "<Type>group</Type>",
        "POSTS",
        "<Post-Response>",
    ] {
        assert_ne!(findings(text), none, "{text}");
    }
}

// ---------------------------------------------------------------------------
// The answers
// ---------------------------------------------------------------------------

// Names a customer could choose, full of listed words: the test must
// mask them, and must not pass because the answers left them out.
const BUCKET: &str = "usenet-articles";
const KEY: &str = "group/post segment.nzb";
const OTHER_KEY: &str = "backbone/yenc-par2.article";
const META: &str = "nntp provider health";
const CONTENT_TYPE: &str = "application/x-nzb";

/// One answer, with what its request supplied.
struct Answer {
    what: String,
    resp: Resp,
    /// Bodies the request supplied (an object read back).
    supplied: Vec<Vec<u8>>,
}

#[derive(Default)]
struct Answers(Vec<Answer>);

impl Answers {
    fn add(&mut self, what: &str, resp: Resp) {
        self.add_with(what, resp, Vec::new());
    }

    fn add_with(&mut self, what: &str, resp: Resp, supplied: Vec<Vec<u8>>) {
        self.0.push(Answer {
            what: what.to_string(),
            resp,
            supplied,
        });
    }
}

/// Every form in which an answer gives a supplied name back: as it is,
/// URL-encoded, and XML-escaped.
fn forms(name: &str) -> Vec<String> {
    let mut forms = vec![
        name.to_string(),
        uri_encode(name, true),
        uri_encode(name, false),
        name.replace(' ', "+"),
    ];
    forms.sort_by_key(|f| std::cmp::Reverse(f.len()));
    forms.dedup();
    forms
}

/// The text of an answer with the supplied parts taken out.
fn masked(answer: &Answer, supplied_names: &[&str]) -> String {
    let resp = &answer.resp;
    let mut body = resp.body.clone();
    for bytes in &answer.supplied {
        if !bytes.is_empty() && body == *bytes {
            body.clear();
        }
    }
    let mut text = format!("{}\n", resp.status);
    for (name, value) in &resp.headers {
        text.push_str(&format!("{name}: {value}\n"));
    }
    text.push_str(&String::from_utf8_lossy(&body));
    if let Some(e) = &resp.stream_error {
        text.push_str(&format!("\n{e}"));
    }
    // Longest first: a name inside another is not left half masked.
    let mut all: Vec<String> = supplied_names.iter().flat_map(|n| forms(n)).collect();
    all.sort_by_key(|f| std::cmp::Reverse(f.len()));
    all.dedup();
    for form in all {
        text = without_supplied(&text, &form);
    }
    text
}

/// `text` without `form`, a text the request supplied, where it stands
/// on its own: not where a letter or digit comes right before it. The
/// answer gives a supplied name back whole, after a `>`, a `/`, a `"`
/// or a space. Taken out anywhere, a short one (`group/`) would also
/// take the end of a word of the service (`newsgroup/`), and with it
/// the leak.
fn without_supplied(text: &str, form: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut at = 0;
    while let Some(i) = text[at..].find(form) {
        let start = at + i;
        out.push_str(&text[at..start]);
        if start > 0 && is_word(bytes[start - 1]) {
            out.push_str(form);
        } else {
            out.push('\u{1}');
        }
        at = start + form.len();
    }
    out.push_str(&text[at..]);
    out
}

async fn ask(
    rig: &Rig,
    signer: &Signer,
    method: Method,
    raw_path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    body: &[u8],
) -> Resp {
    rig.call(signer, method, raw_path, query, headers, body)
        .await
}

fn md5_b64(body: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(md5::compute(body).0)
}

/// The S3 surface, asked for one of everything it answers: each call
/// that works, and each way of refusing.
async fn answers() -> Answers {
    let mut all = Answers::default();
    let mut rig = rig();
    let (_, signer) = rig.standard(BUCKET).await;
    let object = pattern(7, 70_000);
    let at = path(BUCKET, KEY);
    let other = path(BUCKET, OTHER_KEY);
    let root = format!("/{BUCKET}");

    // Objects.
    let put_headers = [("content-type", CONTENT_TYPE), ("x-amz-meta-note", META)];
    let r = ask(&rig, &signer, Method::Put, &at, &[], &put_headers, &object).await;
    r.expect(200);
    all.add("PutObject", r);
    let r = ask(&rig, &signer, Method::Head, &at, &[], &[], b"").await;
    r.expect(200);
    all.add("HeadObject", r);
    let r = ask(&rig, &signer, Method::Get, &at, &[], &[], b"").await;
    r.expect(200);
    all.add_with("GetObject", r, vec![object.clone()]);
    let range = [("range", "bytes=10-19")];
    let r = ask(&rig, &signer, Method::Get, &at, &[], &range, b"").await;
    r.expect(206);
    all.add_with("GetObject range", r, vec![object[10..20].to_vec()]);
    let range = [("range", "bytes=900000-")];
    let r = ask(&rig, &signer, Method::Get, &at, &[], &range, b"").await;
    all.add("GetObject range past the end", r);
    let unless = [("if-none-match", "*")];
    let r = ask(&rig, &signer, Method::Put, &at, &[], &unless, b"again").await;
    all.add("PutObject If-None-Match on a key that exists", r);
    let source = format!("/{BUCKET}/{}", uri_encode(KEY, true));
    let copy = [("x-amz-copy-source", source.as_str())];
    let r = ask(&rig, &signer, Method::Put, &other, &[], &copy, b"").await;
    r.expect(200);
    all.add("CopyObject", r);
    let missing = [("x-amz-copy-source", "/usenet-articles/no-such-post")];
    let r = ask(&rig, &signer, Method::Put, &other, &[], &missing, b"").await;
    all.add("CopyObject of a missing source", r);

    // Listings.
    let r = ask(&rig, &signer, Method::Get, "/", &[], &[], b"").await;
    all.add("ListBuckets", r);
    let r = ask(&rig, &signer, Method::Head, &root, &[], &[], b"").await;
    all.add("HeadBucket", r);
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &root,
        &[("location", "")],
        &[],
        b"",
    )
    .await;
    all.add("GetBucketLocation", r);
    let v2 = [("list-type", "2"), ("prefix", "group/"), ("delimiter", "/")];
    let r = ask(&rig, &signer, Method::Get, &root, &v2, &[], b"").await;
    r.expect(200);
    all.add("ListObjectsV2", r);
    let v2 = [
        ("list-type", "2"),
        ("encoding-type", "url"),
        ("max-keys", "1"),
    ];
    let r = ask(&rig, &signer, Method::Get, &root, &v2, &[], b"").await;
    r.expect(200);
    all.add("ListObjectsV2 url-encoded, truncated", r);
    let r = ask(&rig, &signer, Method::Get, &root, &[], &[], b"").await;
    all.add("ListObjects", r);
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &root,
        &[("uploads", "")],
        &[],
        b"",
    )
    .await;
    all.add("ListMultipartUploads", r);
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &root,
        &[("versioning", "")],
        &[],
        b"",
    )
    .await;
    all.add("GetBucketVersioning", r);
    for sub in [
        "acl",
        "lifecycle",
        "cors",
        "policy",
        "tagging",
        "encryption",
    ] {
        let r = ask(&rig, &signer, Method::Get, &root, &[(sub, "")], &[], b"").await;
        all.add(&format!("GET bucket ?{sub}"), r);
        let r = ask(
            &rig,
            &signer,
            Method::Put,
            &root,
            &[(sub, "")],
            &[],
            b"<x/>",
        )
        .await;
        all.add(&format!("PUT bucket ?{sub}"), r);
        let r = ask(&rig, &signer, Method::Get, &at, &[(sub, "")], &[], b"").await;
        all.add(&format!("GET object ?{sub}"), r);
    }
    let r = ask(&rig, &signer, Method::Put, &root, &[], &[], b"").await;
    all.add("CreateBucket", r);
    let r = ask(&rig, &signer, Method::Delete, &root, &[], &[], b"").await;
    all.add("DeleteBucket", r);
    let r = ask(&rig, &signer, Method::Post, &at, &[], &[], b"form").await;
    all.add("POST to a key", r);
    let r = ask(&rig, &signer, Method::Post, &root, &[], &[], b"form").await;
    all.add("POST to a bucket", r);

    // Multipart.
    let part_key = path(BUCKET, "segments/group.par2");
    let r = ask(
        &rig,
        &signer,
        Method::Post,
        &part_key,
        &[("uploads", "")],
        &[],
        b"",
    )
    .await;
    r.expect(200);
    let id = r.values("UploadId").remove(0);
    all.add("CreateMultipartUpload", r);
    let part = pattern(9, 5 * MIB);
    let q = [("partNumber", "1"), ("uploadId", id.as_str())];
    let r = ask(&rig, &signer, Method::Put, &part_key, &q, &[], &part).await;
    r.expect(200);
    let etag = r.header("etag").unwrap().replace('"', "&quot;");
    all.add("UploadPart", r);
    let q = [("partNumber", "2"), ("uploadId", id.as_str())];
    let from = [("x-amz-copy-source", source.as_str())];
    let r = ask(&rig, &signer, Method::Put, &part_key, &q, &from, b"").await;
    all.add("UploadPartCopy", r);
    let q = [("uploadId", id.as_str())];
    let r = ask(&rig, &signer, Method::Get, &part_key, &q, &[], b"").await;
    all.add("ListParts", r);
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &root,
        &[("uploads", "")],
        &[],
        b"",
    )
    .await;
    all.add("ListMultipartUploads with one open", r);
    let bad = "<CompleteMultipartUpload><Part><PartNumber>7</PartNumber>\
               <ETag>&quot;00000000000000000000000000000000&quot;</ETag></Part>\
               </CompleteMultipartUpload>";
    let r = ask(
        &rig,
        &signer,
        Method::Post,
        &part_key,
        &q,
        &[],
        bad.as_bytes(),
    )
    .await;
    all.add("CompleteMultipartUpload with a part that is not there", r);
    let r = ask(
        &rig,
        &signer,
        Method::Post,
        &part_key,
        &q,
        &[],
        b"<Nonsense",
    )
    .await;
    all.add("CompleteMultipartUpload with a broken document", r);
    let good = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let r = ask(
        &rig,
        &signer,
        Method::Post,
        &part_key,
        &q,
        &[],
        good.as_bytes(),
    )
    .await;
    r.expect(200);
    all.add("CompleteMultipartUpload", r);
    let r = ask(&rig, &signer, Method::Delete, &part_key, &q, &[], b"").await;
    all.add("AbortMultipartUpload of an upload that is gone", r);
    let q = [("partNumber", "1"), ("uploadId", "no-such-upload")];
    let r = ask(&rig, &signer, Method::Put, &part_key, &q, &[], b"part").await;
    all.add("UploadPart to an upload that is not there", r);

    // Refusals.
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &path(BUCKET, "no/such post"),
        &[],
        &[],
        b"",
    )
    .await;
    r.expect(404);
    all.add("GetObject of a missing key", r);
    let r = ask(
        &rig,
        &signer,
        Method::Head,
        &path(BUCKET, "no/such post"),
        &[],
        &[],
        b"",
    )
    .await;
    all.add("HeadObject of a missing key", r);
    let elsewhere = path("no-such-newsgroup", KEY);
    let r = ask(&rig, &signer, Method::Get, &elsewhere, &[], &[], b"").await;
    all.add("GetObject in a bucket that is not there", r);
    let r = ask(&rig, &signer, Method::Put, &elsewhere, &[], &[], b"x").await;
    all.add("PutObject in a bucket that is not there", r);
    let stranger = Signer::new("AKIDNOSUCHKEY0000001", secret());
    let r = ask(&rig, &stranger, Method::Get, &at, &[], &[], b"").await;
    all.add("a key that is not there", r);
    let forger = Signer::new(AKID, &format!("{}-other", secret()));
    let r = ask(&rig, &forger, Method::Get, &at, &[], &[], b"").await;
    all.add("a wrong signature", r);
    let mut unsigned = signer.sign(rig.now(), Method::Get, &at, &[], &[], Vec::new());
    unsigned.headers.retain(|(n, _)| n != "authorization");
    all.add("no signature", rig.send(unsigned).await);
    let mut late = signer.sign(
        UnixMs(T0.0 - 3_600_000),
        Method::Get,
        &at,
        &[],
        &[],
        Vec::new(),
    );
    late.set_header("x-unused", "1");
    all.add("a request from an hour ago", rig.send(late).await);
    let wrong = [("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")];
    let r = ask(&rig, &signer, Method::Put, &at, &[], &wrong, b"body").await;
    all.add("PutObject with a wrong Content-MD5", r);
    let long_key = path(BUCKET, &"k".repeat(2000));
    let r = ask(&rig, &signer, Method::Put, &long_key, &[], &[], b"x").await;
    all.add("PutObject with a key that is too long", r);
    let r = ask(
        &rig,
        &signer,
        Method::Put,
        &at,
        &[],
        &[],
        &vec![0u8; 17 * MIB],
    )
    .await;
    all.add("PutObject above the size limit", r);

    // Deletes.
    let doc = format!(
        "<Delete><Object><Key>{}</Key></Object><Object><Key>never/posted</Key></Object></Delete>",
        OTHER_KEY
    );
    let md5 = md5_b64(doc.as_bytes());
    let q = [("delete", "")];
    let h = [("content-md5", md5.as_str())];
    let r = ask(&rig, &signer, Method::Post, &root, &q, &h, doc.as_bytes()).await;
    r.expect(200);
    all.add("DeleteObjects", r);
    let r = ask(&rig, &signer, Method::Post, &root, &q, &[], b"<Delete>").await;
    all.add("DeleteObjects with a broken document", r);
    let r = ask(&rig, &signer, Method::Delete, &at, &[], &[], b"").await;
    r.expect(204);
    all.add("DeleteObject", r);

    // The store fails under a write, and under a read.
    rig.bridge.safety.fail_put.set(true);
    let r = ask(&rig, &signer, Method::Put, &at, &[], &[], b"lost").await;
    all.add("PutObject while the store fails", r);
    rig.bridge.safety.fail_put.set(false);
    ask(&rig, &signer, Method::Put, &at, &[], &[], &object)
        .await
        .expect(200);
    for key in rig.bridge.safety.keys() {
        if key.starts_with("x/") {
            rig.bridge.safety.inner.lose(&key);
        }
    }
    let r = ask(&rig, &signer, Method::Get, &at, &[], &[], b"").await;
    all.add("GetObject of an object whose stored bytes are gone", r);
    let part_object = path(BUCKET, "segments/group.par2");
    let r = ask(&rig, &signer, Method::Get, &part_object, &[], &[], b"").await;
    all.add(
        "GetObject of a multipart object whose stored bytes are gone",
        r,
    );

    // The database fails.
    rig.bridge.catalog.sql.fail_writes.set(true);
    let r = ask(&rig, &signer, Method::Put, &at, &[], &[], b"x").await;
    all.add("PutObject while the database refuses writes", r);
    rig.bridge.catalog.sql.fail_writes.set(false);
    rig.bridge.catalog.sql.overloaded.set(50);
    let r = ask(
        &rig,
        &signer,
        Method::Get,
        &root,
        &[("list-type", "2")],
        &[],
        b"",
    )
    .await;
    all.add("ListObjectsV2 while the database is overloaded", r);
    rig.bridge.catalog.sql.overloaded.set(0);

    // Maintenance.
    for mode in [Maintenance::Restore] {
        std::rc::Rc::get_mut(&mut rig.bridge)
            .unwrap()
            .cfg
            .maintenance = mode;
        let r = ask(&rig, &signer, Method::Put, &at, &[], &[], b"x").await;
        all.add(&format!("PutObject in maintenance {mode:?}"), r);
        let r = ask(&rig, &signer, Method::Delete, &at, &[], &[], b"").await;
        all.add(&format!("DeleteObject in maintenance {mode:?}"), r);
        let r = ask(&rig, &signer, Method::Get, &at, &[], &[], b"").await;
        all.add(&format!("GetObject in maintenance {mode:?}"), r);
        let r = ask(
            &rig,
            &signer,
            Method::Get,
            &root,
            &[("list-type", "2")],
            &[],
            b"",
        )
        .await;
        all.add(&format!("ListObjectsV2 in maintenance {mode:?}"), r);
    }
    std::rc::Rc::get_mut(&mut rig.bridge)
        .unwrap()
        .cfg
        .maintenance = Maintenance::Off;

    // No room for the request.
    let full = rig_with_budget(NoNntp, config(Vec::new()), ByteBudget::new(1));
    let (_, signer) = full.standard(BUCKET).await;
    let r = ask(&full, &signer, Method::Put, &at, &[], &[], &object).await;
    all.add("PutObject with no room for it", r);
    all
}

/// No answer of the S3 surface says a word of the list.
#[tokio::test(flavor = "current_thread")]
async fn no_s3_answer_names_the_back_end() {
    let all = answers().await;
    let supplied = [
        BUCKET,
        KEY,
        OTHER_KEY,
        META,
        CONTENT_TYPE,
        "segments/group.par2",
        "no/such post",
        "no-such-newsgroup",
        "no-such-post",
        "never/posted",
        // The prefix of `KEY` that a listing with a delimiter answers.
        "group/",
    ];
    let mut statuses = BTreeSet::new();
    let mut leaks = Vec::new();
    for answer in &all.0 {
        statuses.insert(answer.resp.status);
        let found = findings(&masked(answer, &supplied));
        if !found.is_empty() {
            leaks.push(format!("{}: {found:?}", answer.what));
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
    // The run did reach the surface: it holds answers of every class.
    assert!(all.0.len() >= 60, "{}", all.0.len());
    for class in [2, 4, 5] {
        assert!(
            statuses.iter().any(|s| s / 100 == class),
            "no {class}xx answer in {statuses:?}"
        );
    }
}

/// The masking takes out what the request supplied and nothing more: a
/// listed word of the service's own, next to a supplied one, is found.
#[tokio::test(flavor = "current_thread")]
async fn a_word_of_the_service_is_found_next_to_a_supplied_name() {
    let answer = |body: &str| Answer {
        what: "made up".to_string(),
        resp: Resp {
            status: 404,
            headers: vec![("x-amz-request-id".to_string(), "1".to_string())],
            body: body.as_bytes().to_vec(),
            stream_error: None,
        },
        supplied: Vec::new(),
    };
    let supplied = [BUCKET, KEY];
    let clean = format!("<Error><Key>{KEY}</Key><BucketName>{BUCKET}</BucketName></Error>");
    assert!(findings(&masked(&answer(&clean), &supplied)).is_empty());
    let encoded = format!("<Key>{}</Key>", uri_encode(KEY, false));
    assert!(findings(&masked(&answer(&encoded), &supplied)).is_empty());
    let leak = format!("<Error><Key>{KEY}</Key><Message>The article is gone.</Message></Error>");
    assert!(!findings(&masked(&answer(&leak), &supplied)).is_empty());
    // A supplied name that is the end of a word of the service does
    // not hide that word.
    let supplied_short = ["group/"];
    let joined = "<Prefix>group/</Prefix><Message>newsgroup/alt.x</Message>";
    assert!(!findings(&masked(&answer(joined), &supplied_short)).is_empty());
    let own = "<Prefix>group/</Prefix><CommonPrefixes>a/group/</CommonPrefixes>";
    assert!(findings(&masked(&answer(own), &supplied_short)).is_empty());
    let header = Answer {
        resp: Resp {
            headers: vec![("x-backbone".to_string(), "2".to_string())],
            ..answer("").resp
        },
        ..answer("")
    };
    assert!(!findings(&masked(&header, &supplied)).is_empty());
}
