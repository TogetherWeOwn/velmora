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

    pub fn code(self) -> &'static str {
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

/// What failed at the stage of an observation: the error variant and,
/// for a catalogue, blob store or NNTP error, the provider's class or
/// code. Names from fixed lists and numbers only, never message text,
/// which may hold a key, a provider reply or customer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    variant: &'static str,
    code: ProviderCode,
}

/// The provider's own account of a failure, as far as it is safe to log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProviderCode {
    #[default]
    None,
    /// A catalogue class: `d1_overloaded`, `d1_network_lost`, ...
    Sql(&'static str),
    /// An R2 operation, the class of its message and the code R2 put in
    /// parentheses at its end (`put: ... (10001)`).
    R2 {
        op: &'static str,
        class: Option<&'static str>,
        code: Option<u32>,
    },
    /// An NNTP reply code, or the kind of an I/O error.
    NntpReply(u16),
    NntpIo(&'static str),
}

impl Fault {
    /// A failure that is not a port error: `variant` names it.
    pub const fn named(variant: &'static str) -> Fault {
        Fault {
            variant,
            code: ProviderCode::None,
        }
    }

    /// The fault of a port or core error.
    pub fn of(error: &crate::types::BridgeError) -> Fault {
        use crate::types::BridgeError;
        let (variant, code) = match error {
            BridgeError::GuardFailed => ("GuardFailed", ProviderCode::None),
            BridgeError::NotImplemented(_) => ("NotImplemented", ProviderCode::None),
            BridgeError::Sql(class) => ("Sql", ProviderCode::Sql(sql_class(class))),
            BridgeError::Blob(text) => ("Blob", blob_code(text)),
            BridgeError::Nntp(e) => ("Nntp", nntp_code(e)),
            BridgeError::Queue(_) => ("Queue", ProviderCode::None),
            BridgeError::Crypto(_) => ("Crypto", ProviderCode::None),
            BridgeError::Config(_) => ("Config", ProviderCode::None),
            BridgeError::Invalid(_) => ("Invalid", ProviderCode::None),
        };
        Fault { variant, code }
    }

    pub fn variant(&self) -> &'static str {
        self.variant
    }

    /// `-` when the provider said nothing that can be logged.
    pub fn code(&self) -> String {
        match self.code {
            ProviderCode::None => "-".to_string(),
            ProviderCode::Sql(class) => class.to_string(),
            ProviderCode::R2 { op, class, code } => {
                let mut out = format!("r2_{op}");
                if let Some(class) = class {
                    out.push('_');
                    out.push_str(class);
                }
                if let Some(code) = code {
                    out.push_str(&format!("_{code}"));
                }
                out
            }
            ProviderCode::NntpReply(code) => format!("nntp_{code}"),
            ProviderCode::NntpIo(kind) => format!("nntp_io_{kind}"),
        }
    }
}

/// The classes the catalogue adapters give (`workers/s3-bridge/src/d1.rs`,
/// the PostgreSQL one): anything else is `sql_other`.
fn sql_class(class: &str) -> &'static str {
    match class {
        "d1: overloaded" => "d1_overloaded",
        "d1: network lost: statement failed" => "d1_network_lost",
        "d1: storage reset: statement failed" => "d1_storage_reset",
        "d1: timeout: statement failed" => "d1_timeout",
        "d1: transient: statement failed" => "d1_transient",
        "d1: client disconnected: statement failed" => "d1_client_disconnected",
        "d1: constraint violation" => "d1_constraint",
        "d1: statement failed" => "d1_statement",
        "d1: bind failed" => "d1_bind",
        "d1: unexpected result shape" => "d1_result_shape",
        "d1: integer outside JS safe range" | "d1: non-integer or unsafe number" => "d1_number",
        "pg: overloaded" => "pg_overloaded",
        c if c.starts_with("too many bound parameters") => "sql_too_many_params",
        c if c.starts_with("pg: ") => "pg_other",
        _ => "sql_other",
    }
}

/// An R2 adapter error: `r2: <op> failed[: <class>][ (<code>)]`, or one
/// of the adapter's own checks (`r2: short body`, ...).
fn blob_code(text: &str) -> ProviderCode {
    let Some(rest) = text.strip_prefix("r2: ") else {
        return ProviderCode::None;
    };
    let (rest, code) = match rest.rsplit_once(" (") {
        Some((head, tail)) => match tail.strip_suffix(')').map(str::parse::<u32>) {
            Some(Ok(code)) => (head, Some(code)),
            _ => (rest, None),
        },
        None => (rest, None),
    };
    let (op, class) = match rest.split_once(" failed") {
        Some((op, class)) => (op, class.strip_prefix(": ")),
        None => ("check", Some(rest)),
    };
    let op = match op {
        "put" => "put",
        "get" => "get",
        "get body" => "get_body",
        "head" => "head",
        "delete" => "delete",
        "list" => "list",
        "check" => "check",
        _ => "other",
    };
    let class = class.map(|c| match c {
        "network lost" => "network_lost",
        "timeout" => "timeout",
        "stream" => "stream",
        "internal" => "internal",
        "short body" => "short_body",
        "short range" => "short_range",
        "long body" => "long_body",
        "put returned no object" => "no_object",
        "put returned no md5" => "no_md5",
        _ => "other",
    });
    ProviderCode::R2 { op, class, code }
}

fn nntp_code(e: &velmora::Error) -> ProviderCode {
    use std::io::ErrorKind;
    match e {
        velmora::Error::NntpReply { code, .. } => ProviderCode::NntpReply(*code),
        velmora::Error::Io(io) => ProviderCode::NntpIo(match io.kind() {
            ErrorKind::TimedOut => "timed_out",
            ErrorKind::ConnectionReset => "connection_reset",
            ErrorKind::ConnectionAborted => "connection_aborted",
            ErrorKind::ConnectionRefused => "connection_refused",
            ErrorKind::UnexpectedEof => "unexpected_eof",
            ErrorKind::BrokenPipe => "broken_pipe",
            _ => "other",
        }),
        _ => ProviderCode::None,
    }
}

/// An error whose [`Fault`] an observation can keep.
pub trait Faulty {
    fn fault(&self) -> Option<Fault>;
}

impl Faulty for crate::types::BridgeError {
    fn fault(&self) -> Option<Fault> {
        Some(Fault::of(self))
    }
}

impl Faulty for crate::ingress::IngressError {
    fn fault(&self) -> Option<Fault> {
        use crate::ingress::IngressError;
        match self {
            IngressError::SlowDown => Some(Fault::named("SlowDown")),
            IngressError::Internal => Some(Fault::named("Internal")),
            _ => None,
        }
    }
}

impl Faulty for crate::ingress::UploadReadError {
    fn fault(&self) -> Option<Fault> {
        match self {
            crate::ingress::UploadReadError::Ingress(e) => e.fault(),
            crate::ingress::UploadReadError::Proto(_) => None,
        }
    }
}

/// An answer a shared helper already rendered: the helper marked its own
/// fault, if it had one.
impl Faulty for crate::types::S3Response {
    fn fault(&self) -> Option<Fault> {
        None
    }
}

/// Redacted per-request observations; not part of the S3 response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestObservation {
    stage: Option<FailureStage>,
    /// What failed at `stage`, when it is known.
    fault: Option<Fault>,
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

    /// The stage, with nothing known of what failed there.
    pub fn mark_stage(&mut self, stage: FailureStage) {
        self.stage = Some(stage);
        self.fault = None;
    }

    /// The stage and what failed there.
    pub fn mark_fault(&mut self, stage: FailureStage, fault: Fault) {
        self.stage = Some(stage);
        self.fault = Some(fault);
    }

    /// The stage and the port error that failed it.
    pub fn mark_error(&mut self, stage: FailureStage, error: &crate::types::BridgeError) {
        self.mark_fault(stage, Fault::of(error));
    }

    /// Annotate an unrecovered error without reading or replacing it.
    pub(crate) fn on_error<E: Faulty>(&mut self, stage: FailureStage) -> impl FnOnce(&E) + '_ {
        move |e| {
            self.stage = Some(stage);
            self.fault = e.fault();
        }
    }

    pub fn stage(&self) -> Option<FailureStage> {
        self.stage
    }

    pub fn fault(&self) -> Option<Fault> {
        self.fault
    }

    /// `stage=<stage> err=<variant> code=<provider code>` for the request
    /// log line of a `5xx`; `-` for what is not known.
    pub fn log_fields(&self) -> String {
        format!(
            "stage={} err={} code={}",
            self.stage.map_or("-", FailureStage::code),
            self.fault.map_or("-", |f| f.variant),
            self.fault.map_or_else(|| "-".to_string(), |f| f.code()),
        )
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

/// Sample each attempt independently, with no queue message ID lookup.
/// Missing entropy only skips the observation. Rejection sampling keeps
/// arbitrary positive divisors unbiased.
pub fn job_weight(sample: u32) -> Option<u32> {
    job_weight_with(sample, &mut velmora::rng::SystemRng)
}

fn job_weight_with(sample: u32, rng: &mut impl velmora::rng::FillRandom) -> Option<u32> {
    match sample {
        0 => None,
        1 => Some(1),
        n => (velmora::rng::uniform_below(rng, u64::from(n)).ok()? == 0).then_some(n),
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
    fn every_error_variant_is_named_in_the_log_fields() {
        use crate::types::BridgeError;
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "provider said user@host");
        let reply = velmora::Error::NntpReply {
            code: 502,
            text: "reply text with a key".into(),
        };
        let cases: Vec<(BridgeError, &str)> = vec![
            (BridgeError::GuardFailed, "err=GuardFailed code=-"),
            (
                BridgeError::NotImplemented("x"),
                "err=NotImplemented code=-",
            ),
            (
                BridgeError::Sql("d1: overloaded".into()),
                "err=Sql code=d1_overloaded",
            ),
            (
                BridgeError::Sql("d1: network lost: statement failed".into()),
                "err=Sql code=d1_network_lost",
            ),
            (
                BridgeError::Sql("d1: storage reset: statement failed".into()),
                "err=Sql code=d1_storage_reset",
            ),
            (
                BridgeError::Sql("d1: statement failed".into()),
                "err=Sql code=d1_statement",
            ),
            (
                BridgeError::Sql("too many bound parameters: 101 > 100".into()),
                "err=Sql code=sql_too_many_params",
            ),
            (
                BridgeError::Sql("pg: overloaded".into()),
                "err=Sql code=pg_overloaded",
            ),
            // Anything that is not an adapter class says nothing more.
            (
                BridgeError::Sql("no such table: private-bucket".into()),
                "err=Sql code=sql_other",
            ),
            (
                BridgeError::Blob("r2: put failed: internal (10001)".into()),
                "err=Blob code=r2_put_internal_10001",
            ),
            (
                BridgeError::Blob("r2: put failed: network lost".into()),
                "err=Blob code=r2_put_network_lost",
            ),
            (
                BridgeError::Blob("r2: get body failed (10058)".into()),
                "err=Blob code=r2_get_body_10058",
            ),
            (
                BridgeError::Blob("r2: short body".into()),
                "err=Blob code=r2_check_short_body",
            ),
            (
                BridgeError::Blob("r2: photos/private failed: x/y".into()),
                "err=Blob code=r2_other_other",
            ),
            (BridgeError::Blob("store down".into()), "err=Blob code=-"),
            (
                BridgeError::Nntp(velmora::Error::Io(io)),
                "err=Nntp code=nntp_io_timed_out",
            ),
            (BridgeError::Nntp(reply), "err=Nntp code=nntp_502"),
            (BridgeError::Queue("q private".into()), "err=Queue code=-"),
            (BridgeError::Crypto("unwrap"), "err=Crypto code=-"),
            (
                BridgeError::Config(crate::config::ConfigError::Refused("x")),
                "err=Config code=-",
            ),
            (BridgeError::Invalid("x"), "err=Invalid code=-"),
        ];
        for (error, want) in cases {
            let mut o = RequestObservation::default();
            o.mark_error(FailureStage::Commit, &error);
            assert_eq!(o.log_fields(), format!("stage=commit {want}"), "{error:?}");
            // The same through `on_error`, as the handlers mark it.
            let mut o = RequestObservation::default();
            let _ = Err::<(), _>(error).inspect_err(o.on_error(FailureStage::R2));
            assert_eq!(o.log_fields(), format!("stage=r2 {want}"));
        }
    }

    #[test]
    fn a_stage_alone_clears_the_fault_of_the_stage_before() {
        let mut o = RequestObservation::default();
        assert_eq!(o.log_fields(), "stage=- err=- code=-");
        o.mark_fault(FailureStage::R2, Fault::named("StoredSizeMismatch"));
        assert_eq!(o.log_fields(), "stage=r2 err=StoredSizeMismatch code=-");
        o.mark_stage(FailureStage::Lookup);
        assert_eq!(o.log_fields(), "stage=lookup err=- code=-");
        // An error with no fault of its own (a rendered answer) as well.
        let resp = crate::types::S3Response::error(500, "InternalError", "x");
        let _ = Err::<(), _>(resp).inspect_err(o.on_error(FailureStage::Auth));
        assert_eq!(o.log_fields(), "stage=auth err=- code=-");
        let _ = Err::<(), _>(crate::ingress::IngressError::SlowDown)
            .inspect_err(o.on_error(FailureStage::Budget));
        assert_eq!(o.log_fields(), "stage=budget err=SlowDown code=-");
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
        struct Draws<I>(I);
        impl<I: Iterator<Item = u64>> velmora::rng::FillRandom for Draws<I> {
            fn fill_bytes(&mut self, out: &mut [u8]) -> velmora::Result<()> {
                out.copy_from_slice(&self.0.next().expect("draw").to_le_bytes());
                Ok(())
            }
        }
        assert_eq!(job_weight(0), None);
        assert_eq!(job_weight(1), Some(1));
        let mut draws = Draws(0..8192);
        let kept: Vec<_> = (0..8192)
            .filter_map(|_| job_weight_with(8, &mut draws))
            .collect();
        assert_eq!(kept, vec![8; 1024]);
        // MAX would select a biased extra bucket for divisor 3; redraw.
        assert_eq!(
            job_weight_with(3, &mut Draws([u64::MAX, 1].into_iter())),
            None
        );
        assert_eq!(
            job_weight_with(3, &mut Draws([u64::MAX, 0].into_iter())),
            Some(3)
        );
    }

    #[test]
    fn malformed_job_sample_disables_writes() {
        for raw in ["invalid", "", "  ", "-1", "4294967296"] {
            assert_eq!(job_sample(Some(raw)), 0, "{raw:?}");
        }
        assert_eq!(job_weight(job_sample(Some("0"))), None);
    }

    #[test]
    fn a_cold_read_is_its_own_point() {
        let p = cold_read_point();
        assert_eq!((p.index, p.blobs.as_slice()), ("cold", &["cold"][..]));
        assert_eq!(p.doubles, [1.0]);
    }
}
