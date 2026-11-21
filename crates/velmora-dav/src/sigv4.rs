//! SigV4 for the requests the gateway sends to the storage Worker,
//! signed with the caller's own app password.
//!
//! Header authorization, path style, `UNSIGNED-PAYLOAD`: the request
//! travels over a service binding inside the account and never over the
//! Internet, and the storage Worker reads every body itself. The path
//! and query are sent exactly in their canonical form (RFC 3986
//! unreserved characters as they are, every other byte `%XX`), so what
//! is signed is what is sent.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::path::encode;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The payload value the gateway signs.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Deliberately not `Debug`: the secret must not enter logs.
pub struct Credentials {
    pub access_key: String,
    pub secret: String,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `yyyymmddThhmmssZ` and `yyyymmdd` for a time in Unix milliseconds.
pub fn amz_date(now_ms: i64) -> (String, String) {
    let secs = now_ms.div_euclid(1000);
    let (y, mo, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    let date = format!("{y:04}{mo:02}{d:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60);
    (stamp, date)
}

/// One request to sign. `path` is the decoded path (`/<bucket>/<key>`);
/// `query` holds decoded pairs; `headers` are the headers to send and
/// sign besides `host`, `x-amz-date` and `x-amz-content-sha256`.
pub struct Unsigned<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [(String, String)],
}

/// The origin-form target and every header to send (with `host`).
pub struct Signed {
    pub target: String,
    pub headers: Vec<(String, String)>,
}

/// Signs `req` at `now_ms` for `region`.
pub fn sign(req: &Unsigned<'_>, creds: &Credentials, region: &str, now_ms: i64) -> Signed {
    let path = encode(req.path, true);
    let mut q: Vec<(String, String)> = req
        .query
        .iter()
        .map(|(k, v)| (encode(k, false), encode(v, false)))
        .collect();
    q.sort();
    let query = q
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let target = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };

    let (stamp, date) = amz_date(now_ms);
    let mut signed: Vec<(String, String)> = vec![
        ("host".into(), req.host.to_ascii_lowercase()),
        ("x-amz-content-sha256".into(), UNSIGNED_PAYLOAD.into()),
        ("x-amz-date".into(), stamp.clone()),
    ];
    for (name, value) in req.headers {
        signed.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    signed.sort();
    signed.dedup_by(|a, b| a.0 == b.0);
    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let names = signed
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{}\n{path}\n{query}\n{canonical_headers}\n{names}\n{UNSIGNED_PAYLOAD}",
        req.method
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "{ALGORITHM}\n{stamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{}", creds.secret).as_bytes(), date.as_bytes());
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    let mut headers = signed;
    headers.push((
        "authorization".into(),
        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
            creds.access_key
        ),
    ));
    Signed { target, headers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(amz_date(0), ("19700101T000000Z".into(), "19700101".into()));
        assert_eq!(
            amz_date(1_800_000_000_000),
            ("20270115T080000Z".into(), "20270115".into())
        );
        assert_eq!(
            amz_date(951_782_400_000 + 86_399_000),
            ("20000229T235959Z".into(), "20000229".into())
        );
    }

    /// The example of the AWS SigV4 documentation for a GET with a
    /// header-signed request (examplebucket, `test.txt`, Range), with the
    /// payload hash replaced by `UNSIGNED-PAYLOAD`: the shape of the
    /// canonical request is fixed here; the storage Worker's verifier
    /// checks the signature in the integration tests.
    #[test]
    fn signs_a_canonical_target() {
        let creds = Credentials {
            access_key: "APVLEXAMPLE".into(),
            secret: "secret".into(),
        };
        let headers = vec![("Range".to_string(), " bytes=0-9 ".to_string())];
        let s = sign(
            &Unsigned {
                method: "GET",
                host: "S3.Test",
                path: "/b/a b/ü",
                query: &[("prefix", "a b/"), ("delimiter", "/"), ("list-type", "2")],
                headers: &headers,
            },
            &creds,
            "auto",
            0,
        );
        assert_eq!(
            s.target,
            "/b/a%20b/%C3%BC?delimiter=%2F&list-type=2&prefix=a%20b%2F"
        );
        let auth = &s
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1;
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=APVLEXAMPLE/19700101/auto/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature="
        ));
        assert!(s.headers.contains(&("host".into(), "s3.test".into())));
        assert!(s.headers.contains(&("range".into(), "bytes=0-9".into())));
    }
}
