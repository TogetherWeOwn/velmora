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
        doubles: vec![
            f64::from(r.status),
            r.latency_ms as f64,
            r.bytes_in as f64,
            r.bytes_out as f64,
            f64::from(weight),
        ],
    }
}

/// The point of one read from Usenet (a cache miss). blobs: kind
/// (`cold`). doubles: weight, always 1.
pub fn cold_read_point() -> Point {
    Point {
        index: "cold",
        blobs: vec!["cold"],
        colo: "-".to_string(),
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
    fn a_cold_read_is_its_own_point() {
        let p = cold_read_point();
        assert_eq!((p.index, p.blobs.as_slice()), ("cold", &["cold"][..]));
        assert_eq!(p.doubles, [1.0]);
    }
}
