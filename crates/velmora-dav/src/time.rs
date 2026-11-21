//! Times: ISO 8601 from listings, HTTP dates in headers and properties.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-21T10:00:00.000Z` (fraction optional) to Unix milliseconds.
pub fn iso_to_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let rest = &s[19..];
    let (frac, zone) = match rest.strip_prefix('.') {
        Some(r) => {
            let digits = r.bytes().take_while(u8::is_ascii_digit).count();
            (&r[..digits], &r[digits..])
        }
        None => ("", rest),
    };
    if zone != "Z" {
        return None;
    }
    let ms = frac
        .get(..3.min(frac.len()))
        .map(|f| format!("{f:0<3}").parse::<i64>().unwrap_or(0))
        .unwrap_or(0);
    let days = days_from_civil(y, mo as u32, d as u32);
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec) * 1000) + ms)
}

/// Unix milliseconds to `2026-11-21T10:00:00Z` (RFC 3339, for
/// `creationdate`).
pub fn ms_to_iso(ms: i64) -> String {
    let (stamp, _) = crate::sigv4::amz_date(ms);
    // yyyymmddThhmmssZ -> yyyy-mm-ddThh:mm:ssZ
    format!(
        "{}-{}-{}T{}:{}:{}Z",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15]
    )
}

/// Unix milliseconds to an HTTP date (`Sat, 21 Nov 2026 10:00:00 GMT`).
pub fn http_date(ms: i64) -> String {
    let t = UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64);
    httpdate::fmt_http_date(t)
}

/// An HTTP date to Unix milliseconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let t: SystemTime = httpdate::parse_http_date(s.trim()).ok()?;
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let ms = iso_to_ms("2026-11-21T10:00:01.234Z").unwrap();
        assert_eq!(ms_to_iso(ms), "2026-11-21T10:00:01Z");
        assert_eq!(http_date(ms), "Sat, 21 Nov 2026 10:00:01 GMT");
        assert_eq!(
            parse_http_date("Sat, 21 Nov 2026 10:00:01 GMT"),
            Some(ms - 234)
        );
        assert_eq!(iso_to_ms("2026-11-21T10:00:01Z"), Some(ms - 234));
        assert_eq!(iso_to_ms("2000-02-29T23:59:59.5Z"), Some(951_868_799_500));
        assert_eq!(iso_to_ms("1970-01-01T00:00:00Z"), Some(0));
        for bad in [
            "",
            "2026-11-21",
            "2026-13-01T00:00:00Z",
            "2026-11-21T10:00:01+01:00",
        ] {
            assert_eq!(iso_to_ms(bad), None, "{bad}");
        }
    }
}
