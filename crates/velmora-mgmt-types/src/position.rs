//! List positions: where a page ends and the next one starts.
//!
//! A position is an opaque string to a caller, at most
//! [`MAX_POSITION_BYTES`] bytes. The plane builds it from the last row of a
//! page, never from a backend's own cursor, so a list keeps no state
//! between pages. A position whose row is gone continues after it in the
//! same order: nothing is skipped or repeated. A position that does not
//! parse answers `400 invalid_position`.
//!
//! | List | Order | Position |
//! |---|---|---|
//! | buckets, usage per bucket | name, UTF-8 bytes | `n` + the last name ([`NamePosition`]) |
//! | keys | (`created_at_ms`, id) | `k<created_ms>.<id>` ([`KeyPosition`]) |
//! | usage days | day | `d<YYYY-MM-DD>` ([`DayPosition`]) |
//! | objects | key, UTF-8 bytes | `k` + the last key, or `p` + the last prefix ([`ObjectPosition`]); in the POST body, never in a URL |
//! | tenant events | (epoch, seq) | `e<epoch>.<seq>` ([`EventPosition`]) |
//!
//! Numbers in a position are decimal, with no sign and no leading zero,
//! and at most [`MAX_SAFE_INTEGER`].

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ids::{valid_key_id, MAX_SAFE_INTEGER};

/// The most bytes in a position: below `kofra-api`'s own bound (1,342)
/// with a 1,024-byte object key and its marker.
pub const MAX_POSITION_BYTES: usize = 1100;

/// A position that does not parse: `400 invalid_position`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidPosition;

impl fmt::Display for InvalidPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid_position")
    }
}

impl std::error::Error for InvalidPosition {}

/// The body of a position after its one-letter marker, if `s` is not
/// longer than a position may be.
fn body(s: &str, marker: char) -> Result<&str, InvalidPosition> {
    if s.len() > MAX_POSITION_BYTES {
        return Err(InvalidPosition);
    }
    s.strip_prefix(marker).ok_or(InvalidPosition)
}

/// A decimal number of a position.
fn number(s: &str) -> Result<u64, InvalidPosition> {
    let canonical = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
        && s.len() <= 16;
    let n: u64 = canonical
        .then(|| s.parse().ok())
        .flatten()
        .ok_or(InvalidPosition)?;
    (n <= MAX_SAFE_INTEGER).then_some(n).ok_or(InvalidPosition)
}

/// After a name (buckets, usage per bucket).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamePosition {
    pub name: String,
}

impl NamePosition {
    pub fn encode(&self) -> String {
        format!("n{}", self.name)
    }

    pub fn parse(s: &str) -> Result<NamePosition, InvalidPosition> {
        let name = body(s, 'n')?;
        if name.is_empty() {
            return Err(InvalidPosition);
        }
        Ok(NamePosition {
            name: name.to_string(),
        })
    }
}

/// After a key, in (`created_at_ms`, id) order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPosition {
    pub created_ms: u64,
    pub id: String,
}

impl KeyPosition {
    pub fn encode(&self) -> String {
        format!("k{}.{}", self.created_ms, self.id)
    }

    pub fn parse(s: &str) -> Result<KeyPosition, InvalidPosition> {
        let (ms, id) = body(s, 'k')?.split_once('.').ok_or(InvalidPosition)?;
        let created_ms = number(ms)?;
        if !valid_key_id(id) {
            return Err(InvalidPosition);
        }
        Ok(KeyPosition {
            created_ms,
            id: id.to_string(),
        })
    }
}

/// After a day (usage days).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayPosition {
    pub day: Day,
}

impl DayPosition {
    pub fn encode(&self) -> String {
        format!("d{}", self.day)
    }

    pub fn parse(s: &str) -> Result<DayPosition, InvalidPosition> {
        let day = Day::parse(body(s, 'd')?).ok_or(InvalidPosition)?;
        Ok(DayPosition { day })
    }
}

/// After an object key, or after a common prefix (with a delimiter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectPosition {
    Key(String),
    Prefix(String),
}

impl ObjectPosition {
    pub fn encode(&self) -> String {
        match self {
            ObjectPosition::Key(k) => format!("k{k}"),
            ObjectPosition::Prefix(p) => format!("p{p}"),
        }
    }

    pub fn parse(s: &str) -> Result<ObjectPosition, InvalidPosition> {
        if s.len() > MAX_POSITION_BYTES {
            return Err(InvalidPosition);
        }
        let pos = if let Some(k) = s.strip_prefix('k') {
            ObjectPosition::Key(k.to_string())
        } else if let Some(p) = s.strip_prefix('p') {
            ObjectPosition::Prefix(p.to_string())
        } else {
            return Err(InvalidPosition);
        };
        match &pos {
            ObjectPosition::Key(v) | ObjectPosition::Prefix(v) if v.is_empty() => {
                Err(InvalidPosition)
            }
            _ => Ok(pos),
        }
    }
}

/// A place in the tenant event feed. The feed answers it as `position`;
/// an epoch that is not the current one, or a seq below the newest that
/// the prune removed for this tenant, answers `409 feed_reset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventPosition {
    pub epoch: u64,
    pub seq: u64,
}

impl EventPosition {
    pub fn encode(&self) -> String {
        format!("e{}.{}", self.epoch, self.seq)
    }

    pub fn parse(s: &str) -> Result<EventPosition, InvalidPosition> {
        let (epoch, seq) = body(s, 'e')?.split_once('.').ok_or(InvalidPosition)?;
        Ok(EventPosition {
            epoch: number(epoch)?,
            seq: number(seq)?,
        })
    }
}

/// A UTC day, `YYYY-MM-DD` on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day {
    year: u16,
    month: u8,
    day: u8,
}

impl Day {
    /// The day, if it is one (years 1970 to 9999).
    pub fn new(year: u16, month: u8, day: u8) -> Option<Day> {
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return None,
        };
        ((1970..=9999).contains(&year) && (1..=days).contains(&day)).then_some(Day {
            year,
            month,
            day,
        })
    }

    pub fn year(self) -> u16 {
        self.year
    }

    pub fn month(self) -> u8 {
        self.month
    }

    pub fn day(self) -> u8 {
        self.day
    }

    /// `YYYY-MM-DD`, exactly.
    pub fn parse(s: &str) -> Option<Day> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        let digits = |r: std::ops::Range<usize>| -> Option<u16> {
            let part = &s[r];
            part.bytes()
                .all(|c| c.is_ascii_digit())
                .then(|| part.parse().ok())
                .flatten()
        };
        Day::new(
            digits(0..4)?,
            u8::try_from(digits(5..7)?).ok()?,
            u8::try_from(digits(8..10)?).ok()?,
        )
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

impl Serialize for Day {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Day {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Day, D::Error> {
        let s = String::deserialize(d)?;
        Day::parse(&s).ok_or_else(|| serde::de::Error::custom("not a day (YYYY-MM-DD)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_round_trip() {
        let n = NamePosition {
            name: "backups".into(),
        };
        assert_eq!(NamePosition::parse(&n.encode()), Ok(n));
        let k = KeyPosition {
            created_ms: 1_763_800_000_000,
            id: "VK3F8Q2LZ0M4N7P1".into(),
        };
        assert_eq!(k.encode(), "k1763800000000.VK3F8Q2LZ0M4N7P1");
        assert_eq!(KeyPosition::parse(&k.encode()), Ok(k));
        let d = DayPosition {
            day: Day::new(2026, 11, 22).unwrap(),
        };
        assert_eq!(d.encode(), "d2026-11-22");
        assert_eq!(DayPosition::parse(&d.encode()), Ok(d));
        for o in [
            ObjectPosition::Key("photos/2026/a.jpg".into()),
            ObjectPosition::Prefix("photos/".into()),
        ] {
            assert_eq!(ObjectPosition::parse(&o.encode()), Ok(o));
        }
        let e = EventPosition { epoch: 3, seq: 0 };
        assert_eq!(e.encode(), "e3.0");
        assert_eq!(EventPosition::parse(&e.encode()), Ok(e));
    }

    #[test]
    fn a_position_that_does_not_parse_is_refused() {
        for bad in [
            "", "n", "x1.a", "k.a", "k1.", "k01.a", "k1.a-b", "k+1.a", "k1.2.3",
        ] {
            assert_eq!(
                KeyPosition::parse(bad).map(|_| ()),
                Err(InvalidPosition),
                "{bad}"
            );
        }
        assert!(NamePosition::parse("n").is_err());
        assert!(NamePosition::parse("backups").is_err());
        for bad in ["e", "e1", "e1.", "e.1", "e01.1", "e1.01", "e-1.1", "e1.1.1"] {
            assert!(EventPosition::parse(bad).is_err(), "{bad}");
        }
        // 2^53 is one above the largest number on the wire.
        assert!(EventPosition::parse("e9007199254740992.0").is_err());
        assert!(EventPosition::parse("e9007199254740991.0").is_ok());
        assert!(EventPosition::parse("e99999999999999999999.0").is_err());
        for bad in [
            "d",
            "d2026-1-22",
            "d2026-13-01",
            "d2025-02-29",
            "d1969-12-31",
            "d2026-11-22x",
        ] {
            assert!(DayPosition::parse(bad).is_err(), "{bad}");
        }
        assert!(DayPosition::parse("d2028-02-29").is_ok());
        for bad in ["", "k", "p", "x/a"] {
            assert!(ObjectPosition::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_position_is_at_most_1100_bytes() {
        let longest = format!("k{}", "a".repeat(1024));
        assert!(ObjectPosition::parse(&longest).is_ok());
        let at_bound = format!("k{}", "a".repeat(MAX_POSITION_BYTES - 1));
        assert!(ObjectPosition::parse(&at_bound).is_ok());
        let over = format!("k{}", "a".repeat(MAX_POSITION_BYTES));
        assert!(ObjectPosition::parse(&over).is_err());
        assert!(NamePosition::parse(&format!("n{}", "a".repeat(MAX_POSITION_BYTES))).is_err());
    }
}
