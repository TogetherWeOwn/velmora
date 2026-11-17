//! UTC calendar arithmetic (proleptic Gregorian, no leap-second table) and
//! the few fixed date formats this crate renders and parses.
//!
//! Hand-written so the crate needs no date library. The behaviour is that of
//! the `chrono` 0.4.45 code it replaced, byte for byte: the same range of
//! representable times (years -262143 to 262142), the same rendering of years
//! outside 0000-9999 (`+10000`, `-0001`), and the same accepted and rejected
//! inputs. Day arithmetic is Howard Hinnant's `days_from_civil` and
//! `civil_from_days` (<https://howardhinnant.github.io/date_algorithms.html>).

use std::fmt::Write;

const SECS_PER_DAY: i64 = 86_400;
const MIN_YEAR: i64 = -262_143;
const MAX_YEAR: i64 = 262_142;
/// -262143-01-01T00:00:00Z, the earliest representable second.
const MIN_SECS: i64 = days_from_civil(MIN_YEAR, 1, 1) * SECS_PER_DAY;
/// +262142-12-31T23:59:59Z, the latest representable second.
const MAX_SECS: i64 = days_from_civil(MAX_YEAR, 12, 31) * SECS_PER_DAY + SECS_PER_DAY - 1;

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days since 1970-01-01 of a valid civil date.
const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = (month as i64 + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// The civil date (year, month 1-12, day 1-31) of a day since 1970-01-01.
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // March = 0
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A broken-down UTC time. `second` is 60 only for a parsed leap second,
/// which counts as second 59 of its minute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

impl Civil {
    /// `None` outside the representable range.
    fn from_unix(secs: i64) -> Option<Self> {
        if !in_range(secs) {
            return None;
        }
        let (year, month, day) = civil_from_days(secs.div_euclid(SECS_PER_DAY));
        let tod = secs.rem_euclid(SECS_PER_DAY) as u32;
        Some(Self {
            year,
            month,
            day,
            hour: tod / 3600,
            minute: tod / 60 % 60,
            second: tod % 60,
        })
    }

    /// Validates the fields; a leap second (60) is allowed in any minute.
    fn new(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<Self> {
        ((MIN_YEAR..=MAX_YEAR).contains(&year)
            && (1..=12).contains(&month)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour < 24
            && minute < 60
            && second <= 60)
            .then_some(Self {
                year,
                month,
                day,
                hour,
                minute,
                second,
            })
    }

    fn days(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day)
    }

    /// Unix seconds; a leap second maps to second 59 of its minute.
    fn unix(&self) -> i64 {
        self.days() * SECS_PER_DAY
            + i64::from(self.hour * 3600 + self.minute * 60 + self.second.min(59))
    }

    fn weekday(&self) -> &'static str {
        // 1970-01-01 was a Thursday.
        WEEKDAYS[(self.days() + 4).rem_euclid(7) as usize]
    }

    fn month_name(&self) -> &'static str {
        MONTHS[self.month as usize - 1]
    }

    /// Four digits for years 0000-9999, otherwise signed and zero-padded to
    /// five characters (`+10000`, `-0001`).
    fn write_year(&self, out: &mut String) {
        let _ = if (0..10_000).contains(&self.year) {
            write!(out, "{:04}", self.year)
        } else {
            write!(out, "{:+05}", self.year)
        };
    }

    /// `%Y%m%dT%H%M%SZ`.
    fn compact(&self) -> String {
        let mut out = String::with_capacity(16);
        self.write_year(&mut out);
        let _ = write!(
            out,
            "{:02}{:02}T{:02}{:02}{:02}Z",
            self.month, self.day, self.hour, self.minute, self.second
        );
        out
    }

    /// `%a, %d %b %Y %H:%M:%S GMT` (RFC 9110 IMF-fixdate).
    fn imf_fixdate(&self) -> String {
        let mut out = String::with_capacity(29);
        let _ = write!(
            out,
            "{}, {:02} {} ",
            self.weekday(),
            self.day,
            self.month_name()
        );
        self.write_year(&mut out);
        let _ = write!(
            out,
            " {:02}:{:02}:{:02} GMT",
            self.hour, self.minute, self.second
        );
        out
    }

    /// `%a %b %e %H:%M:%S %Y` (C asctime; the day is space-padded).
    fn asctime(&self) -> String {
        let mut out = String::with_capacity(24);
        let _ = write!(
            out,
            "{} {} {:>2} {:02}:{:02}:{:02} ",
            self.weekday(),
            self.month_name(),
            self.day,
            self.hour,
            self.minute,
            self.second
        );
        self.write_year(&mut out);
        out
    }
}

/// Whether `secs` is a representable Unix time in seconds.
pub(crate) fn in_range(secs: i64) -> bool {
    (MIN_SECS..=MAX_SECS).contains(&secs)
}

/// `%Y-%m-%dT%H:%M:%S%.3fZ` for a Unix time in milliseconds, as S3 renders
/// `LastModified`; `None` outside the representable range.
pub(crate) fn iso_ms(unix_ms: i64) -> Option<String> {
    let t = Civil::from_unix(unix_ms.div_euclid(1000))?;
    let mut out = String::with_capacity(24);
    t.write_year(&mut out);
    let _ = write!(
        out,
        "-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.month,
        t.day,
        t.hour,
        t.minute,
        t.second,
        unix_ms.rem_euclid(1000)
    );
    Some(out)
}

/// `YYYYMMDDTHHMMSSZ` (SigV4 `X-Amz-Date`) for a Unix time in seconds from
/// 1970 through year 9999; `None` otherwise.
pub(crate) fn amz_date(unix_secs: i64) -> Option<String> {
    if unix_secs < 0 {
        return None;
    }
    Some(Civil::from_unix(unix_secs)?.compact()).filter(|date| date.len() == 16)
}

/// Parses a SigV4 `X-Amz-Date` in its canonical `YYYYMMDDTHHMMSSZ` form to
/// Unix seconds. Years 0000-9999; second 60 is accepted in any minute and
/// counts as second 59. Anything that does not render back to the same
/// bytes is rejected.
pub(crate) fn parse_amz_date(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    if b.len() != 16 {
        return None;
    }
    let t = Civil::new(
        digits(&b[0..4])?.into(),
        digits(&b[4..6])?,
        digits(&b[6..8])?,
        digits(&b[9..11])?,
        digits(&b[11..13])?,
        digits(&b[13..15])?,
    )?;
    (t.compact() == value).then(|| t.unix())
}

/// The pre-1970 HTTP dates `httpdate` cannot produce: a trimmed
/// IMF-fixdate or asctime date with a four-digit year, no leap second and a
/// time before the Unix epoch, rendering back to the same bytes (so the
/// weekday must be right and every field canonical).
pub(crate) fn parse_pre_epoch_http_date(value: &str) -> Option<i64> {
    let value = value.trim();
    let b = value.as_bytes();
    let (t, rendered) = match b.len() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        29 => {
            let t = Civil::new(
                digits(&b[12..16])?.into(),
                month(&b[8..11])?,
                digits(&b[5..7])?,
                digits(&b[17..19])?,
                digits(&b[20..22])?,
                digits(&b[23..25])?,
            )?;
            (t, t.imf_fixdate())
        }
        // Sun Nov  6 08:49:37 1994
        24 => {
            let day = match b[8] {
                b' ' => digits(&b[9..10])?,
                _ => digits(&b[8..10])?,
            };
            let t = Civil::new(
                digits(&b[20..24])?.into(),
                month(&b[4..7])?,
                day,
                digits(&b[11..13])?,
                digits(&b[14..16])?,
                digits(&b[17..19])?,
            )?;
            (t, t.asctime())
        }
        _ => return None,
    };
    let secs = t.unix();
    (secs < 0 && t.second < 60 && rendered == value).then_some(secs)
}

fn digits(field: &[u8]) -> Option<u32> {
    field.iter().try_fold(0u32, |n, &c| {
        c.is_ascii_digit().then(|| n * 10 + u32::from(c - b'0'))
    })
}

fn month(name: &[u8]) -> Option<u32> {
    MONTHS
        .iter()
        .position(|m| m.as_bytes() == name)
        .map(|i| i as u32 + 1)
}

/// HTTP date of a representable Unix time in seconds; years outside
/// 0000-9999 are rendered signed (see [`Civil::write_year`]).
pub(crate) fn http_date(unix_secs: i64) -> Option<String> {
    Civil::from_unix(unix_secs).map(|t| t.imf_fixdate())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// A small deterministic generator (SplitMix64) for property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn range(&mut self, lo: i64, hi: i64) -> i64 {
            lo + (self.next() % (hi - lo + 1) as u64) as i64
        }
    }

    #[test]
    fn range_bounds_are_chronos() {
        assert_eq!(MIN_SECS, -8_334_601_228_800);
        assert_eq!(MAX_SECS, 8_210_266_876_799);
        assert!(in_range(MIN_SECS) && in_range(MAX_SECS));
        assert!(!in_range(MIN_SECS - 1) && !in_range(MAX_SECS + 1));
        assert!(!in_range(i64::MIN) && !in_range(i64::MAX));
    }

    /// Walking day by day from the epoch, in both directions, through
    /// several 400-year cycles, matches a naive month/day counter.
    #[test]
    fn day_conversion_matches_a_naive_calendar_walk() {
        for direction in [1i64, -1] {
            let (mut y, mut m, mut d) = (1970i64, 1u32, 1u32);
            for n in 0..=(3 * 146_097) {
                let days = n * direction;
                assert_eq!(civil_from_days(days), (y, m, d), "day {days}");
                assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
                if direction > 0 {
                    d += 1;
                    if d > days_in_month(y, m) {
                        (d, m) = (1, m + 1);
                        if m > 12 {
                            (m, y) = (1, y + 1);
                        }
                    }
                } else if d > 1 {
                    d -= 1;
                } else {
                    if m > 1 {
                        m -= 1;
                    } else {
                        (m, y) = (12, y - 1);
                    }
                    d = days_in_month(y, m);
                }
            }
        }
    }

    #[test]
    fn leap_years() {
        for (year, leap) in [
            (1900, false),
            (1970, false),
            (1972, true),
            (2000, true),
            (2023, false),
            (2024, true),
            (2100, false),
            (0, true),
            (-4, true),
            (-100, false),
            (-400, true),
            (9996, true),
            (9999, false),
        ] {
            assert_eq!(is_leap_year(year), leap, "{year}");
            assert_eq!(Civil::new(year, 2, 29, 0, 0, 0).is_some(), leap, "{year}");
        }
        assert_eq!(
            http_date(951_782_400).unwrap(),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        assert_eq!(
            http_date(951_868_800).unwrap(),
            "Wed, 01 Mar 2000 00:00:00 GMT"
        );
        assert_eq!(
            http_date(4_107_542_400).unwrap(),
            "Mon, 01 Mar 2100 00:00:00 GMT"
        );
        assert_eq!(parse_amz_date("21000229T000000Z"), None);
        assert_eq!(parse_amz_date("20000229T000000Z"), Some(951_782_400));
        assert_eq!(parse_amz_date("19000229T000000Z"), None);
    }

    /// Rendered strings pinned against chrono 0.4.45, at the epoch, the
    /// year 0000-9999 limits and the ends of the representable range.
    #[test]
    fn rendering_edges() {
        assert_eq!(iso_ms(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_ms(-1).unwrap(), "1969-12-31T23:59:59.999Z");
        assert_eq!(
            iso_ms(1_700_000_000_123).unwrap(),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(
            iso_ms(253_402_300_799_999).unwrap(),
            "9999-12-31T23:59:59.999Z"
        );
        assert_eq!(
            iso_ms(253_402_300_800_000).unwrap(),
            "+10000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_ms(-62_167_219_200_000).unwrap(),
            "0000-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_ms(-62_167_219_200_001).unwrap(),
            "-0001-12-31T23:59:59.999Z"
        );
        assert_eq!(
            iso_ms(MIN_SECS * 1000).unwrap(),
            "-262143-01-01T00:00:00.000Z"
        );
        assert_eq!(
            iso_ms(MAX_SECS * 1000 + 999).unwrap(),
            "+262142-12-31T23:59:59.999Z"
        );
        assert_eq!(iso_ms(MIN_SECS * 1000 - 1), None);
        assert_eq!(iso_ms(MAX_SECS * 1000 + 1000), None);
        assert_eq!(iso_ms(i64::MIN), None);
        assert_eq!(iso_ms(i64::MAX), None);

        assert_eq!(http_date(0).unwrap(), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(-1).unwrap(), "Wed, 31 Dec 1969 23:59:59 GMT");
        assert_eq!(
            http_date(253_402_300_799).unwrap(),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
        assert_eq!(
            http_date(253_402_300_800).unwrap(),
            "Sat, 01 Jan +10000 00:00:00 GMT"
        );
        assert_eq!(
            http_date(-62_167_219_200).unwrap(),
            "Sat, 01 Jan 0000 00:00:00 GMT"
        );
        assert_eq!(
            http_date(-62_198_755_200).unwrap(),
            "Fri, 01 Jan -0001 00:00:00 GMT"
        );
        assert_eq!(
            http_date(MIN_SECS).unwrap(),
            "Thu, 01 Jan -262143 00:00:00 GMT"
        );
        assert_eq!(
            http_date(MAX_SECS).unwrap(),
            "Mon, 31 Dec +262142 23:59:59 GMT"
        );
        assert_eq!(http_date(MIN_SECS - 1), None);
        assert_eq!(http_date(MAX_SECS + 1), None);

        assert_eq!(amz_date(0).unwrap(), "19700101T000000Z");
        assert_eq!(amz_date(1_388_534_400).unwrap(), "20140101T000000Z");
        assert_eq!(amz_date(253_402_300_799).unwrap(), "99991231T235959Z");
        assert_eq!(amz_date(253_402_300_800), None);
        assert_eq!(amz_date(-1), None);
        assert_eq!(amz_date(i64::MAX), None);
    }

    #[test]
    fn amz_date_parsing_edges() {
        for (value, expect) in [
            ("19700101T000000Z", Some(0)),
            ("19691231T235959Z", Some(-1)),
            ("00000101T000000Z", Some(-62_167_219_200)),
            ("99991231T235959Z", Some(253_402_300_799)),
            // A leap second is accepted in any minute, as second 59.
            ("20161231T235960Z", Some(1_483_228_799)),
            ("20140101T000060Z", Some(1_388_534_459)),
            ("20140230T000000Z", None),
            ("20140431T000000Z", None),
            ("20141301T000000Z", None),
            ("20140001T000000Z", None),
            ("20140100T000000Z", None),
            ("20140101T240000Z", None),
            ("20140101T006000Z", None),
            ("20140101T000061Z", None),
            ("20140101t000000Z", None),
            ("20140101T000000z", None),
            ("20140101 000000Z", None),
            ("2014010T0000000Z", None),
            ("+0140101T000000Z", None),
            ("-0140101T000000Z", None),
            (" 0140101T000000Z", None),
            ("2014-01-01T00:00:00Z", None),
            ("20140101T000000", None),
            ("20140101T000000ZZ", None),
            ("20140101T00000\u{e9}", None),
            ("", None),
        ] {
            assert_eq!(parse_amz_date(value), expect, "{value:?}");
        }
    }

    #[test]
    fn pre_epoch_http_date_parsing_edges() {
        for (value, expect) in [
            ("Wed, 31 Dec 1969 23:59:59 GMT", Some(-1)),
            ("Wed Dec 31 23:59:59 1969", Some(-1)),
            ("  Wed, 31 Dec 1969 23:59:59 GMT\t", Some(-1)),
            ("Mon, 01 Jan 1900 00:00:00 GMT", Some(-2_208_988_800)),
            ("Mon Jan  1 00:00:00 1900", Some(-2_208_988_800)),
            ("Sat, 01 Jan 0000 00:00:00 GMT", Some(-62_167_219_200)),
            ("Sat Jan  1 00:00:00 0000", Some(-62_167_219_200)),
            ("Thu, 29 Feb 1968 12:00:00 GMT", Some(-58_017_600)),
            // The epoch itself and later are httpdate's, not this path's.
            ("Thu, 01 Jan 1970 00:00:00 GMT", None),
            ("Thu Jan  1 00:00:00 1970", None),
            // Wrong weekday, invalid dates, leap second, non-canonical.
            ("Thu, 31 Dec 1969 23:59:59 GMT", None),
            ("Sun, 30 Feb 1969 00:00:00 GMT", None),
            ("Thu, 29 Feb 1900 00:00:00 GMT", None),
            ("Wed, 31 Dec 1969 23:59:60 GMT", None),
            ("Wed Dec 31 23:59:60 1969", None),
            ("Wed, 31 Dec 1969 24:00:00 GMT", None),
            ("wed, 31 Dec 1969 23:59:59 GMT", None),
            ("Wed, 31 dec 1969 23:59:59 GMT", None),
            ("Wed, 31 Dec 1969 23:59:59 UTC", None),
            ("Mon Jan 01 00:00:00 1900", None),
            ("Mon Jan 1  00:00:00 1900", None),
            ("Wed, 31 Dec 1969 23:59:59 gmt", None),
            ("Fri, 01 Jan -001 00:00:00 GMT", None),
            ("Fri, 01 Jan -0001 00:00:00 GMT", None),
            ("Wednesday, 31-Dec-69 23:59:59 GMT", None),
            ("", None),
        ] {
            assert_eq!(parse_pre_epoch_http_date(value), expect, "{value:?}");
        }
    }

    /// Independent oracle for 1970-9999: `httpdate` (a different
    /// implementation) renders and parses the same IMF-fixdate strings.
    #[test]
    fn imf_fixdate_matches_httpdate_from_1970_to_9999() {
        let mut rng = Rng(0x5eed);
        let edges = [
            0,
            1,
            86_399,
            86_400,
            951_782_399,
            951_782_400,
            253_402_300_799,
        ];
        let random = (0..200_000).map(|_| rng.range(0, 253_402_300_799));
        for secs in edges.into_iter().chain(random) {
            let ours = http_date(secs).unwrap();
            let time = UNIX_EPOCH + Duration::from_secs(secs as u64);
            assert_eq!(ours, httpdate::fmt_http_date(time), "{secs}");
            assert_eq!(httpdate::parse_http_date(&ours).unwrap(), time);
        }
    }

    /// Render then parse is the identity over the whole supported span of
    /// each parser, and every rendering has its fixed width.
    #[test]
    fn render_parse_round_trips() {
        let mut rng = Rng(0xc0ffee);
        let year_0000 = -62_167_219_200;
        for _ in 0..200_000 {
            let secs = rng.range(year_0000, 253_402_300_799);
            let t = Civil::from_unix(secs).unwrap();
            assert_eq!(t.unix(), secs);
            assert_eq!(parse_amz_date(&t.compact()), Some(secs));
            assert_eq!(t.compact().len(), 16);
            assert_eq!(t.imf_fixdate().len(), 29);
            assert_eq!(t.asctime().len(), 24);
            let pre = (secs < 0).then_some(secs);
            assert_eq!(parse_pre_epoch_http_date(&t.imf_fixdate()), pre);
            assert_eq!(parse_pre_epoch_http_date(&t.asctime()), pre);
            let ms = secs * 1000 + rng.range(0, 999);
            let iso = iso_ms(ms).unwrap();
            assert_eq!(iso.len(), 24);
            assert_eq!(&iso[20..23], format!("{:03}", ms.rem_euclid(1000)));
        }
        for _ in 0..50_000 {
            let secs = rng.range(MIN_SECS, MAX_SECS);
            let t = Civil::from_unix(secs).unwrap();
            assert_eq!(
                Civil::new(t.year, t.month, t.day, t.hour, t.minute, t.second),
                Some(t)
            );
            assert_eq!(t.unix(), secs);
        }
    }
}
