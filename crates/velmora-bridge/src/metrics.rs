//! Request metrics for an Analytics Engine dataset: what one data point
//! holds, and which requests get one.
//!
//! A data point never holds a bucket, an object key, a query, a header,
//! a token or a request id. Its text fields are picked from fixed lists
//! here; a value outside its list is written as `other` or `-`.
//!
//! One request in `METRICS_SAMPLE` gets a point, and the point says how
//! many requests it stands for (`weight`), so a sum over `weight` is the
//! request count. A request that ended in a 5xx always gets one.
//!
//! Whether a GET was served from the cache is not known when its
//! headers are sent: the body finds that out extent by extent. A read
//! from Usenet is therefore a point of its own ([`cold_read_point`]),
//! never sampled. It counts a run of reads from Usenet, not a GET: one
//! GET can have several (each sub-range of a large GET, a reader that
//! was idle and came back), and a copy reads too. The points say how
//! much is read from Usenet over time; they are not a hit rate, and are
//! not to be taken from the GET count.

use sha2::{Digest, Sha256};

/// One data point: the sampling index, the text fields and the numbers,
/// in the order the dataset's columns have (`blob1..`, `double1..`).
#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub index: &'static str,
    pub blobs: Vec<&'static str>,
    /// The colo, the one text field that is not from a list here: three
    /// letters or digits, or `-`. It is `blob5` of a request point.
    pub colo: String,
    pub doubles: Vec<f64>,
    failure: Option<RequestObservation>,
}

impl Point {
    /// The exact blobs sent to Analytics Engine. Colo stays in blob5
    /// for request points; observed failures may append blob6 and blob7.
    pub fn analytics_blobs(&self) -> impl Iterator<Item = &str> {
        self.blobs
            .iter()
            .copied()
            .chain(core::iter::once(self.colo.as_str()))
            .chain(self.failure.into_iter().flat_map(|observed| {
                [
                    observed.stage.unwrap_or(FailureStage::Other).code(),
                    observed.size.code(),
                ]
            }))
    }
}

/// The last unrecovered stage before an observed S3 error response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureStage {
    Auth,
    Lookup,
    Plan,
    Grant,
    SubrangeTransport,
    SubrangeLength,
    SubrangeStatus,
    R2,
    Nntp,
    SlotWait,
    Budget,
    Decrypt,
    Commit,
    Stamp,
    Other,
}

impl FailureStage {
    /// Where an operation spanning both the catalogue and blob store failed.
    /// Use the port error's variant, never its payload.
    pub(crate) fn storage(error: &crate::types::BridgeError) -> Self {
        use crate::types::BridgeError;
        match error {
            BridgeError::Sql(_) | BridgeError::GuardFailed => Self::Commit,
            BridgeError::Blob(_) => Self::R2,
            _ => Self::Other,
        }
    }

    /// Stamp checks and updates share a result; a SQL error does not say
    /// whether a write ran. Keep those failures out of publication commits.
    pub(crate) fn stamp(error: &crate::types::BridgeError) -> Self {
        match error {
            crate::types::BridgeError::Blob(_) => Self::R2,
            _ => Self::Stamp,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Lookup => "lookup",
            Self::Plan => "plan",
            Self::Grant => "grant",
            Self::SubrangeTransport => "subrange_transport",
            Self::SubrangeLength => "subrange_length",
            Self::SubrangeStatus => "subrange_status",
            Self::R2 => "r2",
            Self::Nntp => "nntp",
            Self::SlotWait => "slot_wait",
            Self::Budget => "budget",
            Self::Decrypt => "decrypt",
            Self::Commit => "commit",
            Self::Stamp => "stamp",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SizeClass {
    #[default]
    Unknown,
    AtMost1GiB,
    Over1GiB,
}

impl SizeClass {
    fn code(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::AtMost1GiB => "le_1gib",
            Self::Over1GiB => "gt_1gib",
        }
    }
}

/// Redacted per-request observations; not part of the S3 response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestObservation {
    stage: Option<FailureStage>,
    size: SizeClass,
    complete_multipart: bool,
}

// The GET and fan-out paths use this same observation and stage vocabulary.
pub use FailureStage as GetFailureStage;
pub use RequestObservation as GetObservation;

impl RequestObservation {
    /// Classify the full object size, even for a range GET. Do not retain
    /// the exact size or try to guess it before the generation is known.
    pub fn record_size(&mut self, bytes: u64) {
        self.size = if bytes <= 1 << 30 {
            SizeClass::AtMost1GiB
        } else {
            SizeClass::Over1GiB
        };
    }

    pub fn mark_stage(&mut self, stage: FailureStage) {
        self.stage = Some(stage);
    }

    /// Annotate an unrecovered error without reading or replacing it.
    pub(crate) fn on_error<E>(&mut self, stage: FailureStage) -> impl FnOnce(&E) + '_ {
        move |_| self.mark_stage(stage)
    }

    pub(crate) fn mark_complete_multipart(&mut self) {
        self.complete_multipart = true;
    }

    /// The response conversion can replace the intended response with
    /// a 500. For observed failures, count the wire status and attribute
    /// that 500 to conversion, not to a stage of the original response.
    pub fn response_status(&mut self, method: &str, admin: bool, intended: u16, wire: u16) -> u16 {
        if intended != wire && self.records_failure(method, admin, wire) {
            self.mark_stage(FailureStage::Other);
            wire
        } else {
            intended
        }
    }

    fn records_failure(self, method: &str, admin: bool, status: u16) -> bool {
        !admin
            && match method {
                "GET" => status >= 400,
                "PUT" | "HEAD" => status >= 500,
                "POST" => self.complete_multipart && status >= 500,
                _ => false,
            }
    }
}

/// What the Worker knows of one answered request.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: &'a str,
    /// The request went to `/_admin`.
    pub admin: bool,
    /// A sub-request of a large GET, which gets a point only when it
    /// failed: it is told apart from the GET it belongs to.
    pub sub: bool,
    pub status: u16,
    /// From the first byte of the request to the response headers.
    pub latency_ms: u64,
    /// `Content-Length` of the request and of the response; 0 = none.
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The Cloudflare data centre that answered (`cf.colo`).
    pub colo: &'a str,
    pub get: RequestObservation,
}

fn method(m: &str) -> &'static str {
    match m {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "PUT" => "PUT",
        "POST" => "POST",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}

fn class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// An IATA-style colo code, or `-`.
fn colo(c: &str) -> String {
    if (3..=4).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()) {
        c.to_ascii_uppercase()
    } else {
        "-".to_string()
    }
}

/// How many requests the point of this request stands for, or `None`
/// when it gets no point. `request_id` only picks the one in `sample`:
/// it is hashed and never stored. A 5xx is always kept, with weight 1.
pub fn weight(status: u16, sample: u32, request_id: &str) -> Option<u32> {
    if status >= 500 || sample <= 1 {
        return Some(1);
    }
    let digest = Sha256::digest(request_id.as_bytes());
    let draw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (draw % sample == 0).then_some(sample)
}

/// The point of one request.
///
/// blobs: kind (`req`), method, status class, route (`s3`, `admin`, or `sub` for
/// a failed sub-request of a large GET),
/// colo. doubles: status, latency in ms, request bytes, response bytes,
/// weight.
pub fn request_point(r: &Request<'_>, weight: u32) -> Point {
    Point {
        index: "req",
        blobs: vec![
            "req",
            method(r.method),
            class(r.status),
            match (r.sub, r.admin) {
                (true, _) => "sub",
                (false, true) => "admin",
                (false, false) => "s3",
            },
        ],
        colo: colo(r.colo),
        failure: r
            .get
            .records_failure(r.method, r.admin, r.status)
            .then_some(r.get),
        doubles: vec![
            f64::from(r.status),
            r.latency_ms as f64,
            r.bytes_in as f64,
            r.bytes_out as f64,
            f64::from(weight),
        ],
    }
}

/// An absent setting defaults to one point per eight claimed attempts.
/// Zero or a malformed setting disables points, not the consumer.
pub fn job_sample(raw: Option<&str>) -> u32 {
    raw.map_or(8, |s| s.trim().parse().unwrap_or(0))
}

/// Sample a queue message without retaining its ID. Unlike HTTP sampling,
/// failure does not change the weight; a redelivery uses the same draw.
pub fn job_weight(sample: u32, message_id: &str) -> Option<u32> {
    match sample {
        0 => None,
        1 => Some(1),
        n => weight(200, n, message_id),
    }
}

/// Normalize the actual consumer queue, not the route a new message would
/// take with the current shard count. Never copy queue names into a point.
fn job_queue(queue: &str) -> &'static str {
    match queue {
        "velmora-post" | "velmora-post-dev" => "post1",
        "velmora-post2" => "post2",
        "velmora-post3" => "post3",
        "velmora-post4" => "post4",
        "velmora-post5" => "post5",
        "velmora-post6" => "post6",
        "velmora-post7" => "post7",
        "velmora-post8" => "post8",
        "velmora-verify" | "velmora-verify-dev" => "verify1",
        "velmora-verify2" => "verify2",
        "velmora-verify3" => "verify3",
        "velmora-verify4" => "verify4",
        "velmora-verify5" => "verify5",
        "velmora-verify6" => "verify6",
        "velmora-verify7" => "verify7",
        "velmora-verify8" => "verify8",
        _ => "aux",
    }
}

/// One sampled post, verify or release attempt that claimed its outbox
/// row. A repair within verify is classified as `repost`, not a second
/// point. Queue events do not expose a trusted colo.
pub fn job_point(trace: &crate::trace::JobTrace, queue: &str, weight: u32) -> Option<Point> {
    use crate::trace::{JobKind, JobResult};
    let kind = match trace.kind? {
        JobKind::Post => "post",
        JobKind::Verify => "verify",
        JobKind::Release => "release",
        JobKind::Repost => "repost",
    };
    let outcome = match trace.result {
        JobResult::Ok => "ok",
        JobResult::NoPermit => "no_permit",
        JobResult::Cooling => "cooling",
        JobResult::Fenced => "fenced",
        JobResult::Refused => "refused",
        JobResult::Budget => "budget",
        JobResult::Failed => "failed",
    };
    let size = match trace.payload_bytes {
        None => SizeClass::Unknown,
        Some(bytes) if bytes <= 1 << 30 => SizeClass::AtMost1GiB,
        Some(_) => SizeClass::Over1GiB,
    };
    let mut doubles = Vec::with_capacity(20);
    doubles.extend([
        f64::from(weight),
        trace.payload_bytes.unwrap_or(0) as f64,
        trace.total_ms as f64,
        trace.permit_ms() as f64,
        trace.slot_wait_ms as f64,
        trace.load_ms as f64,
        trace.connect_ms as f64,
        trace.wire_ms as f64,
        trace.advance_ms as f64,
        f64::from(trace.granted),
        f64::from(trace.wanted),
        f64::from(trace.articles),
        trace.held_ms() as f64,
    ]);
    doubles.extend(trace.provider_bytes.map(|n| n as f64));
    Some(Point {
        index: "job",
        blobs: vec!["job.v1", kind, outcome, size.code(), job_queue(queue)],
        colo: "-".to_string(),
        failure: None,
        doubles,
    })
}

/// The point of one read from Usenet (a cache miss). blobs: kind
/// (`cold`). doubles: weight, always 1.
pub fn cold_read_point() -> Point {
    Point {
        index: "cold",
        blobs: vec!["cold"],
        colo: "-".to_string(),
        failure: None,
        doubles: vec![1.0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(method: &'a str, status: u16, colo: &'a str) -> Request<'a> {
        Request {
            method,
            admin: false,
            sub: false,
            status,
            latency_ms: 12,
            bytes_in: 3,
            bytes_out: 4096,
            colo,
            get: GetObservation::default(),
        }
    }

    #[test]
    fn one_request_in_n_gets_a_point_and_says_so() {
        let kept = (0..10_000)
            .filter_map(|i| weight(200, 10, &format!("ray-{i}")))
            .collect::<Vec<_>>();
        // About a tenth, each standing for ten.
        assert!((800..1200).contains(&kept.len()), "{}", kept.len());
        assert!(kept.iter().all(|w| *w == 10));
        // The same request is always decided the same way.
        assert_eq!(weight(200, 10, "ray-7"), weight(200, 10, "ray-7"));
    }

    #[test]
    fn a_server_error_always_gets_a_point() {
        for i in 0..200 {
            assert_eq!(weight(500, 10, &format!("ray-{i}")), Some(1));
            assert_eq!(weight(503, 10_000, &format!("ray-{i}")), Some(1));
        }
        // A sample of 1 keeps everything.
        assert_eq!(weight(404, 1, "x"), Some(1));
    }

    #[test]
    fn a_point_holds_only_listed_text() {
        // What a hostile or odd request could carry in each field.
        let odd = "/bucket/secret-key?X-Amz-Signature=abc";
        let p = request_point(&req(odd, 200, odd), 10);
        assert_eq!(p.blobs, ["req", "other", "2xx", "s3"]);
        assert_eq!(p.colo, "-");
        assert_eq!(p.doubles, [200.0, 12.0, 3.0, 4096.0, 10.0]);

        let p = request_point(&req("GET", 503, "iad"), 1);
        assert_eq!(p.blobs, ["req", "GET", "5xx", "s3"]);
        assert_eq!(p.colo, "IAD");
        let admin = Request {
            admin: true,
            sub: false,
            ..req("POST", 204, "EWR")
        };
        assert_eq!(request_point(&admin, 10).blobs[3], "admin");
        let sub = Request { sub: true, ..admin };
        assert_eq!(request_point(&sub, 1).blobs[3], "sub");
    }

    #[test]
    fn get_failure_dimensions_are_allowlisted_and_follow_colo() {
        let mut r = req(
            "GET",
            500,
            "/private-bucket/private-key?X-Amz-Signature=redacted",
        );
        r.get.record_size(1_073_741_825);
        r.get.mark_stage(GetFailureStage::Plan);
        let p = request_point(&r, 1);
        assert_eq!(p.index, "req");
        assert_eq!(
            p.analytics_blobs().collect::<Vec<_>>(),
            ["req", "GET", "5xx", "s3", "-", "plan", "gt_1gib"]
        );
        assert_eq!(p.doubles, [500.0, 12.0, 3.0, 4096.0, 1.0]);

        r.status = 200;
        assert_eq!(request_point(&r, 1).analytics_blobs().count(), 5);
        r.status = 500;
        r.method = "POST";
        assert_eq!(request_point(&r, 1).analytics_blobs().count(), 5);
        r.method = "GET";
        r.admin = true;
        assert_eq!(request_point(&r, 1).analytics_blobs().count(), 5);
    }

    #[test]
    fn observed_early_failures_default_to_other_and_unknown() {
        for (method, target) in [
            ("PUT", "/bucket/key"),
            ("HEAD", "/bucket/key"),
            ("POST", "/bucket/key?uploadId=opaque-id"),
        ] {
            let mut r = req(method, 500, "iad");
            r.get = crate::service::initial_observation(method, target);
            assert_eq!(
                request_point(&r, 1).analytics_blobs().collect::<Vec<_>>(),
                ["req", method, "5xx", "s3", "IAD", "other", "unknown"]
            );
        }
        let mut r = req("POST", 500, "iad");
        r.get = crate::service::initial_observation("POST", "/bucket/key?uploads");
        assert_eq!(request_point(&r, 1).analytics_blobs().count(), 5);
    }

    #[test]
    fn conversion_fallback_uses_wire_status_and_other_for_observed_routes() {
        for (method, target) in [
            ("GET", "/bucket/key"),
            ("PUT", "/bucket/key"),
            ("HEAD", "/bucket/key"),
            ("POST", "/bucket/key?uploadId=opaque-id"),
        ] {
            let mut r = req(method, 200, "IAD");
            r.get = crate::service::initial_observation(method, target);
            r.get.mark_stage(FailureStage::Auth);
            r.get.record_size(1 << 30);
            r.status = r.get.response_status(method, r.admin, r.status, 500);
            let point = request_point(&r, 1);
            assert_eq!(point.doubles[0], 500.0);
            assert_eq!(
                point.analytics_blobs().collect::<Vec<_>>(),
                ["req", method, "5xx", "s3", "IAD", "other", "le_1gib"]
            );
        }
        let mut r = req("POST", 200, "iad");
        r.get = crate::service::initial_observation("POST", "/bucket/key?uploads");
        assert_eq!(r.get.response_status(r.method, r.admin, r.status, 500), 200);
    }

    #[test]
    fn get_failure_without_read_context_is_other_and_unknown() {
        let r = req("GET", 500, "iad");
        let p = request_point(&r, 1);
        assert_eq!(
            p.analytics_blobs().collect::<Vec<_>>(),
            ["req", "GET", "5xx", "s3", "IAD", "other", "unknown"]
        );
    }

    #[test]
    fn job_point_all_fields_are_allowlisted_and_numeric_columns_stay_in_order() {
        use crate::trace::{JobKind, JobResult, JobTrace};
        use crate::types::UnixMs;

        let odd = "private-bucket/private-key news.private.test auth-token";
        let mut trace = JobTrace::default();
        trace.kind = Some(JobKind::Post);
        trace.result = JobResult::Refused;
        trace.payload_bytes = Some(2);
        trace.total_ms = 3;
        trace.ask(UnixMs(0), 11);
        for _ in 0..10 {
            trace.permit(UnixMs(4), true);
        }
        trace.released(UnixMs(17));
        trace.slot_wait_ms = 5;
        trace.load_ms = 6;
        trace.connect_ms = 7;
        trace.wire_ms = 8;
        trace.advance_ms = 9;
        trace.articles = 12;
        trace.sent(odd, u64::MAX);
        trace.sent("p01", u64::MAX);
        for (id, n) in ["p1", "p2", "p3", "p4", "p5", "p6", "p7"]
            .into_iter()
            .zip(14..=20)
        {
            trace.sent(id, n);
        }
        let p = job_point(&trace, odd, 1).expect("claimed attempt");
        assert_eq!(p.index, "job");
        assert_eq!(
            p.analytics_blobs().collect::<Vec<_>>(),
            ["job.v1", "post", "refused", "le_1gib", "aux", "-"]
        );
        assert_eq!(p.doubles, (1..=20).map(f64::from).collect::<Vec<_>>());
        for (queue, label) in [
            ("velmora-post", "post1"),
            ("velmora-post8", "post8"),
            ("velmora-verify-dev", "verify1"),
            ("velmora-verify7", "verify7"),
        ] {
            assert_eq!(
                job_point(&trace, queue, 1)
                    .unwrap()
                    .analytics_blobs()
                    .nth(4),
                Some(label)
            );
        }
        assert!(job_point(&JobTrace::default(), odd, 1).is_none());
    }

    #[test]
    fn job_sampling_weights_every_retained_attempt_even_failures() {
        assert_eq!(job_sample(None), 8);
        assert_eq!(job_sample(Some(" 1 ")), 1);
        assert_eq!(job_weight(0, "sample-private-id"), None);
        assert_eq!(job_weight(1, "sample-private-id"), Some(1));
        let kept: Vec<_> = (0..8192)
            .filter_map(|n| job_weight(8, &format!("attempt-{n}")))
            .collect();
        assert!((900..1150).contains(&kept.len()));
        assert!(kept.iter().all(|w| *w == 8));
    }

    #[test]
    fn malformed_job_sample_disables_writes() {
        for raw in ["invalid", "", "  ", "-1", "4294967296"] {
            assert_eq!(job_sample(Some(raw)), 0, "{raw:?}");
        }
        assert_eq!(job_weight(job_sample(Some("0")), "attempt"), None);
    }

    #[test]
    fn a_cold_read_is_its_own_point() {
        let p = cold_read_point();
        assert_eq!((p.index, p.blobs.as_slice()), ("cold", &["cold"][..]));
        assert_eq!(p.doubles, [1.0]);
    }
}
