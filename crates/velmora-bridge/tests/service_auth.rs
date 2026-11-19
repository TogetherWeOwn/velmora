//! How every S3 operation answers every kind of caller: a table of
//! status, error code and message, held to a recorded copy
//! (`golden/auth_matrix.txt`), and what one request costs in round
//! trips to the catalogue.
//!
//! The table was recorded before the key, the bucket and the grant
//! were read in one statement, and is not to change with how they are
//! read. `UPDATE_GOLDEN=1` writes it anew.

mod service_support;

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use service_support::*;
use sha2::Sha256;
use velmora_bridge::config::Maintenance;
use velmora_bridge::recovery::write_key_revocation;
use velmora_bridge::*;

const BUCKET: &str = "bkt-auth";
const GOLDEN: &str = "tests/golden/auth_matrix.txt";

/// Who signs, for which bucket, and in what state the service is.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Case {
    /// An active key with an `rw` grant.
    Rw,
    /// An active key with an `ro` grant.
    Ro,
    /// A key the catalogue does not hold.
    Unknown,
    /// A disabled key that holds an `rw` grant.
    Disabled,
    /// An active key with a grant on another bucket only.
    Ungranted,
    /// The `rw` key, on a bucket that does not exist.
    AbsentBucket,
    /// An unknown key, on a bucket that does not exist.
    UnknownAbsentBucket,
    /// The `rw` key's id, signed with another secret.
    WrongSecret,
    /// The `rw` key, the signature replaced after signing.
    Tampered,
    /// The `rw` key, the algorithm of the header replaced after signing.
    WrongAlgorithm,
    /// The `rw` key, with a `Signature` field put first that holds the
    /// text `Credential=` and the id of another key.
    CredentialInSignature,
    /// No `Authorization` header at all.
    Anonymous,
    /// The `rw` key while a replay of the recovery records is pending.
    RwReplaying,
    /// The `ro` key while a replay is pending.
    RoReplaying,
    /// The `rw` key under `MAINTENANCE=restore`.
    RwMaintenance,
    /// An unknown key under `MAINTENANCE=restore`.
    UnknownMaintenance,
    /// The `ro` key under `MAINTENANCE=restore`.
    RoMaintenance,
    /// The key without a grant under `MAINTENANCE=restore`.
    UngrantedMaintenance,
    /// The `rw` key under `MAINTENANCE=restore`, with its row and its
    /// grant still in the catalogue and a record of its revocation in
    /// the safety store.
    RevokedMaintenance,
    /// The `rw` key, the request presigned (query only, no headers
    /// beside `host`, no body).
    PresignedRw,
    /// The `ro` key, presigned.
    PresignedRo,
    /// An unknown key, presigned.
    PresignedUnknown,
    /// The `rw` key, presigned with another secret.
    PresignedWrongSecret,
    /// The `rw` key while the catalogue fails to read a key.
    CatalogueFails,
    /// The `rw` key, its secret wrapped under a KEK the service lacks.
    LostKek,
}

const CASES: [Case; 25] = [
    Case::Rw,
    Case::Ro,
    Case::Unknown,
    Case::Disabled,
    Case::Ungranted,
    Case::AbsentBucket,
    Case::UnknownAbsentBucket,
    Case::WrongSecret,
    Case::Tampered,
    Case::WrongAlgorithm,
    Case::CredentialInSignature,
    Case::Anonymous,
    Case::RwReplaying,
    Case::RoReplaying,
    Case::RwMaintenance,
    Case::UnknownMaintenance,
    Case::RoMaintenance,
    Case::UngrantedMaintenance,
    Case::RevokedMaintenance,
    Case::PresignedRw,
    Case::PresignedRo,
    Case::PresignedUnknown,
    Case::PresignedWrongSecret,
    Case::CatalogueFails,
    Case::LostKek,
];

struct Op {
    name: &'static str,
    method: Method,
    /// Object key; empty for a bucket request, `/` for the service root.
    key: &'static str,
    query: Vec<(&'static str, String)>,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn op(name: &'static str, method: Method, key: &'static str) -> Op {
    Op {
        name,
        method,
        key,
        query: Vec::new(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

impl Op {
    fn q(mut self, name: &'static str, value: &str) -> Self {
        self.query.push((name, value.to_owned()));
        self
    }
    fn h(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }
    fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }
}

/// Every operation, in an order in which each can succeed for the `rw`
/// key: `one` and `two` are open uploads with one part each.
fn ops(bucket: &str, one: &str, two: &str, etag: &str) -> Vec<Op> {
    let delete = "<Delete><Object><Key>gone-1</Key></Object><Quiet>true</Quiet></Delete>";
    let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(delete).0);
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    vec![
        op("ListBuckets", Method::Get, "/"),
        op("HeadBucket", Method::Head, ""),
        op("GetBucketLocation", Method::Get, "").q("location", ""),
        op("ListObjectsV2", Method::Get, "").q("list-type", "2"),
        op("ListMultipartUploads", Method::Get, "").q("uploads", ""),
        op("CreateBucket", Method::Put, ""),
        op("DeleteBucket", Method::Delete, ""),
        op("GetObject", Method::Get, "k"),
        op("GetObject range", Method::Get, "k").h("range", "bytes=1-3"),
        op("GetObject absent", Method::Get, "absent"),
        op("HeadObject", Method::Head, "k"),
        op("PutObject", Method::Put, "new").body(b"new body"),
        op("CopyObject", Method::Put, "copy").h("x-amz-copy-source", &format!("/{bucket}/k")),
        op("DeleteObject", Method::Delete, "gone-0"),
        op("DeleteObjects", Method::Post, "")
            .q("delete", "")
            .h("content-md5", &md5)
            .body(delete.as_bytes()),
        op("CreateMultipartUpload", Method::Post, "mp-new").q("uploads", ""),
        op("UploadPart", Method::Put, "mp-one")
            .q("partNumber", "2")
            .q("uploadId", one)
            .body(b"part two"),
        op("UploadPartCopy", Method::Put, "mp-one")
            .q("partNumber", "3")
            .q("uploadId", one)
            .h("x-amz-copy-source", &format!("/{bucket}/k")),
        op("ListParts", Method::Get, "mp-one").q("uploadId", one),
        op("AbortMultipartUpload", Method::Delete, "mp-one").q("uploadId", one),
        op("CompleteMultipartUpload", Method::Post, "mp-two")
            .q("uploadId", two)
            .body(complete.as_bytes()),
    ]
}

impl Case {
    fn maintenance(self) -> bool {
        matches!(
            self,
            Case::RwMaintenance
                | Case::UnknownMaintenance
                | Case::RoMaintenance
                | Case::UngrantedMaintenance
                | Case::RevokedMaintenance
        )
    }

    fn presigned(self) -> bool {
        matches!(
            self,
            Case::PresignedRw
                | Case::PresignedRo
                | Case::PresignedUnknown
                | Case::PresignedWrongSecret
        )
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// A presigned request: the signature in the query, `host` the only
/// signed header, the payload unsigned.
fn presign(
    signer: &Signer,
    now: UnixMs,
    method: Method,
    raw_path: &str,
    query: &[(&str, &str)],
) -> Req {
    let (stamp, scope, key) = signer.scope(now);
    let credential = format!("{}/{scope}", signer.akid);
    let mut q: Vec<(String, String)> = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", credential.as_str()),
        ("X-Amz-Date", stamp.as_str()),
        ("X-Amz-Expires", "3600"),
        ("X-Amz-SignedHeaders", "host"),
    ]
    .iter()
    .chain(query)
    .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
    .collect();
    q.sort();
    let query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical = format!(
        "{}\n{raw_path}\n{query}\nhost:{HOST}\n\nhost\nUNSIGNED-PAYLOAD",
        method.as_str()
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        hex(&sha256(canonical.as_bytes()))
    );
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    Req {
        method,
        target: format!("{raw_path}?{query}&X-Amz-Signature={signature}"),
        headers: vec![("host".to_string(), HOST.to_string())],
        body: Vec::new(),
    }
}

struct Ran {
    line: String,
    trips: u64,
}

/// Runs every operation as `case`, on a rig of its own.
async fn run(case: Case) -> Vec<Ran> {
    let mut cfg = config(Vec::new());
    if case.maintenance() {
        cfg.maintenance = Maintenance::Restore;
    }
    let maintenance = cfg.maintenance;
    let rig = rig_with(NoNntp, cfg);
    let (bucket, rw) = rig.standard(BUCKET).await;
    let other = rig.bucket("bkt-other", true).await;
    let ro = rig
        .key("AKIDTESTKEY0000000RO", secret(), KeyStatus::Active)
        .await;
    rig.grant(&ro.akid, &bucket, Perm::Ro).await;
    let disabled = rig
        .key("AKIDTESTKEY000000OFF", secret(), KeyStatus::Disabled)
        .await;
    rig.grant(&disabled.akid, &bucket, Perm::Rw).await;
    let ungranted = rig
        .key("AKIDTESTKEY00000ELSE", secret(), KeyStatus::Active)
        .await;
    rig.grant(&ungranted.akid, &other, Perm::Rw).await;
    let unknown = Signer::new("AKIDTESTKEY000000NONE", secret());
    let wrong = Signer::new(&rw.akid, "not the secret of this key at all 00000");

    // What the operations address. Under maintenance nothing can be
    // written, and nothing is: every answer there is a refusal.
    let (mut one, mut two, mut etag) = (
        "absent-upload".to_owned(),
        "absent-upload".to_owned(),
        "\"0\"".to_owned(),
    );
    if maintenance == Maintenance::Off {
        for key in ["k", "gone-0", "gone-1"] {
            rig.put(&rw, BUCKET, key, b"stored body").await.expect(200);
        }
        let mut ids = Vec::new();
        for key in ["mp-one", "mp-two"] {
            let created = rig
                .call(
                    &rw,
                    Method::Post,
                    &path(BUCKET, key),
                    &[("uploads", "")],
                    &[],
                    b"",
                )
                .await;
            let id = created.expect(200).values("UploadId").remove(0);
            let sent = rig
                .call(
                    &rw,
                    Method::Put,
                    &path(BUCKET, key),
                    &[("partNumber", "1"), ("uploadId", &id)],
                    &[],
                    b"part one",
                )
                .await;
            etag = sent.expect(200).header("etag").unwrap().to_owned();
            ids.push(id);
        }
        two = ids.pop().unwrap();
        one = ids.pop().unwrap();
    }
    if matches!(case, Case::RwReplaying | Case::RoReplaying) {
        let now = rig.now();
        let _ = rig
            .bridge
            .catalog
            .restore_begin(UnixMs(0), now)
            .await
            .unwrap();
    }
    match case {
        Case::RevokedMaintenance => {
            write_key_revocation(&rig.bridge.safety, &rig.bridge.kek, &rw.akid, rig.now())
                .await
                .unwrap();
        }
        Case::LostKek => rig.bridge.catalog.sql.with_conn(|c| {
            c.execute_batch(&format!(
                "UPDATE access_keys SET kek_version = 99 WHERE access_key_id = '{}';",
                rw.akid
            ))
            .unwrap();
        }),
        // From here on: nothing before this may fail.
        Case::CatalogueFails => {
            *rig.bridge.catalog.sql.fail_matching.borrow_mut() =
                Some(("FROM access_keys WHERE access_key_id", 0));
        }
        _ => {}
    }

    let (signer, name) = match case {
        Case::Rw
        | Case::Tampered
        | Case::WrongAlgorithm
        | Case::CredentialInSignature
        | Case::Anonymous
        | Case::RwReplaying
        | Case::RwMaintenance
        | Case::RevokedMaintenance
        | Case::PresignedRw
        | Case::CatalogueFails
        | Case::LostKek => (&rw, BUCKET),
        Case::Ro | Case::RoReplaying | Case::RoMaintenance | Case::PresignedRo => (&ro, BUCKET),
        Case::Unknown | Case::UnknownMaintenance | Case::PresignedUnknown => (&unknown, BUCKET),
        Case::Disabled => (&disabled, BUCKET),
        Case::Ungranted | Case::UngrantedMaintenance => (&ungranted, BUCKET),
        Case::AbsentBucket => (&rw, "bkt-absent"),
        Case::UnknownAbsentBucket => (&unknown, "bkt-absent"),
        Case::WrongSecret | Case::PresignedWrongSecret => (&wrong, BUCKET),
    };
    let mut out = Vec::new();
    // Upload ids and ETags are drawn at random; the table names them.
    let plain = |text: String| text.replace(&one, "<one>").replace(&two, "<two>");
    for op in ops(name, &one, &two, &etag) {
        let target = match op.key {
            "/" => "/".to_owned(),
            "" => format!("/{name}"),
            key => path(name, key),
        };
        let query: Vec<(&str, &str)> = op.query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let headers: Vec<(&str, &str)> = op.headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut req = match case.presigned() {
            true => presign(signer, rig.now(), op.method, &target, &query),
            false => signer.sign(
                rig.now(),
                op.method,
                &target,
                &query,
                &headers,
                op.body.clone(),
            ),
        };
        let signed = req
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        match case {
            Case::Tampered => {
                let (head, _) = signed.rsplit_once("Signature=").unwrap();
                req.set_header(
                    "authorization",
                    &format!("{head}Signature={}", "0".repeat(64)),
                );
            }
            Case::WrongAlgorithm => {
                let fields = signed.strip_prefix("AWS4-HMAC-SHA256 ").unwrap();
                req.set_header("authorization", &format!("AWS4-HMAC-SHA1 {fields}"));
            }
            Case::CredentialInSignature => {
                let fields = signed.strip_prefix("AWS4-HMAC-SHA256 ").unwrap();
                let (rest, _) = fields.rsplit_once(", Signature=").unwrap();
                req.set_header(
                    "authorization",
                    &format!(
                        "AWS4-HMAC-SHA256 Signature=Credential={}/x, {rest}",
                        ro.akid
                    ),
                );
            }
            Case::Anonymous => req.headers.retain(|(n, _)| n != "authorization"),
            _ => {}
        }
        let before = rig.bridge.catalog.sql.trips.get();
        let resp = rig.send(req).await;
        let trips = rig.bridge.catalog.sql.trips.get() - before;
        let retry = resp.header("retry-after").unwrap_or("-").to_owned();
        let line = format!(
            "{case:?} | {} | {} | {} | {} | retry-after {retry}",
            op.name,
            resp.status,
            resp.code(),
            plain(resp.message()),
        );
        out.push(Ran { line, trips });
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn every_operation_answers_every_caller_as_recorded() {
    let mut table = String::new();
    for case in CASES {
        for ran in run(case).await {
            table.push_str(&ran.line);
            table.push('\n');
        }
    }
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(GOLDEN, &table).unwrap();
    }
    let recorded = std::fs::read_to_string(GOLDEN).unwrap();
    for (got, want) in table.lines().zip(recorded.lines()) {
        assert_eq!(got, want);
    }
    assert_eq!(table.lines().count(), recorded.lines().count());
    // The table is worth something only if callers are told apart.
    for needle in [
        "Rw | PutObject | 200",
        "Ro | PutObject | 403 | AccessDenied",
        "Unknown | GetObject | 403 | InvalidAccessKeyId",
        "Disabled | UploadPart | 403 | InvalidAccessKeyId",
        "Ungranted | CreateMultipartUpload | 403 | AccessDenied",
        "AbsentBucket | HeadObject | 403",
        "WrongSecret | CompleteMultipartUpload | 403 | SignatureDoesNotMatch",
        "Tampered | DeleteObject | 403 | SignatureDoesNotMatch",
        "WrongAlgorithm | GetObject | 403 | AccessDenied",
        "WrongAlgorithm | UploadPart | 403 | AccessDenied",
        "RwReplaying | UploadPart | 503",
        "RwMaintenance | CreateMultipartUpload | 503",
        "RwMaintenance | GetObject | 404",
        "RevokedMaintenance | GetObject | 403 | InvalidAccessKeyId",
        "RevokedMaintenance | ListObjectsV2 | 403 | InvalidAccessKeyId",
        "RoMaintenance | ListObjectsV2 | 200",
        "UngrantedMaintenance | ListObjectsV2 | 403 | AccessDenied",
        "PresignedRw | GetObject | 200",
        "PresignedRw | CreateMultipartUpload | 200",
        "PresignedRo | CreateMultipartUpload | 403 | AccessDenied",
        "PresignedUnknown | UploadPart | 403 | InvalidAccessKeyId",
        "PresignedWrongSecret | UploadPart | 403 | SignatureDoesNotMatch",
        "CatalogueFails | GetObject | 500 | InternalError",
        "CatalogueFails | UploadPart | 500 | InternalError",
        "LostKek | GetObject | 500 | InternalError",
        "LostKek | UploadPart | 500 | InternalError",
    ] {
        assert!(table.contains(needle), "{needle}");
    }
}

/// Round trips to the catalogue of each operation: one for who asks,
/// whatever the operation, and nothing more for a caller that is
/// refused. The whole table is printed with `--nocapture`.
#[tokio::test(flavor = "current_thread")]
async fn who_asks_is_one_round_trip_to_the_catalogue() {
    let granted = run(Case::Rw).await;
    let unknown = run(Case::Unknown).await;
    let ungranted = run(Case::Ungranted).await;
    let anonymous = run(Case::Anonymous).await;
    let mut seen = Vec::new();
    for (i, rw) in granted.iter().enumerate() {
        let name = rw.line.split(" | ").nth(1).unwrap();
        println!(
            "trips | {name:24} | rw {:2} | unknown key {} | no grant {}",
            rw.trips, unknown[i].trips, ungranted[i].trips
        );
        assert_eq!(unknown[i].trips, 1, "{name}");
        assert_eq!(anonymous[i].trips, 0, "{name}");
        // ListBuckets is granted to every key, and lists.
        if name != "ListBuckets" {
            assert_eq!(ungranted[i].trips, 1, "{name}");
        }
        seen.push((name, rw.trips));
    }
    // Operations that ask the catalogue nothing but who asks.
    for name in ["HeadBucket", "GetBucketLocation", "CreateBucket"] {
        assert!(seen.contains(&(name, 1)), "{name}");
    }
    // The four multipart calls, which read who asks on their own before.
    for (name, trips) in [
        ("CreateMultipartUpload", 2),
        ("UploadPart", 4),
        ("AbortMultipartUpload", 2),
        ("CompleteMultipartUpload", 7),
    ] {
        assert!(seen.contains(&(name, trips)), "{name}");
    }
}
