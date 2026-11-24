use bytes::BytesMut;
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};

use super::error;
use crate::{BridgeError, Result, Row, SqlValue, MAX_SQL_INT, MAX_SQL_PARAMS, MAX_SQL_VALUE_BYTES};

type CodecError = Box<dyn std::error::Error + Sync + Send>;

pub(super) struct Params(Vec<(Encoded, Type)>);

// Only Wire type and raw bytes are retained, not driver coercions. Debug must
// not expose bindings; in particular these can contain auth data.
struct Encoded(Option<Vec<u8>>);

impl core::fmt::Debug for Encoded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[redacted binding]")
    }
}

impl ToSql for Encoded {
    fn to_sql(&self, _ty: &Type, out: &mut BytesMut) -> core::result::Result<IsNull, CodecError> {
        match &self.0 {
            Some(bytes) => {
                out.extend_from_slice(bytes);
                Ok(IsNull::No)
            }
            None => Ok(IsNull::Yes),
        }
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }
    tokio_postgres::types::to_sql_checked!();
}

impl Params {
    pub(super) fn encode(values: &[SqlValue]) -> Result<Self> {
        if values.len() > MAX_SQL_PARAMS {
            return Err(bind_error());
        }
        values
            .iter()
            .map(|p| {
                let (value, ty) = match p {
                    SqlValue::Int(v) if (-MAX_SQL_INT..=MAX_SQL_INT).contains(v) => {
                        (Some(v.to_be_bytes().to_vec()), Type::INT8)
                    }
                    SqlValue::Int(_) => {
                        return Err(BridgeError::Sql("pg: integer outside JS safe range".into()))
                    }
                    SqlValue::Text(v) => {
                        if v.as_bytes().contains(&0) {
                            return Err(BridgeError::Invalid("catalog: text contains NUL"));
                        }
                        if v.len() > MAX_SQL_VALUE_BYTES {
                            return Err(bind_error());
                        }
                        (Some(v.as_bytes().to_vec()), Type::TEXT)
                    }
                    SqlValue::Blob(v) if v.len() <= MAX_SQL_VALUE_BYTES => {
                        (Some(v.clone()), Type::BYTEA)
                    }
                    SqlValue::Blob(_) => return Err(bind_error()),
                    SqlValue::Null => (None, Type::UNKNOWN),
                };
                Ok((Encoded(value), ty))
            })
            .collect::<Result<Vec<_>>>()
            .map(Self)
    }

    pub(super) fn typed(&self) -> impl Iterator<Item = (&(dyn ToSql + Sync), Type)> {
        self.0
            .iter()
            .map(|(b, t)| (b as &(dyn ToSql + Sync), t.clone()))
    }

    #[cfg(any(test, feature = "pg-test-record"))]
    pub(super) fn oids(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().map(|(_, t)| t.oid())
    }
}

fn bind_error() -> BridgeError {
    BridgeError::Sql("pg: bind failed".into())
}

pub(super) fn decode(row: tokio_postgres::Row) -> Result<Row> {
    fn get<'a, T: FromSql<'a>>(
        row: &'a tokio_postgres::Row,
        idx: usize,
        val: impl FnOnce(T) -> SqlValue,
    ) -> Result<SqlValue> {
        row.try_get::<_, Option<T>>(idx)
            .map(|v| v.map_or(SqlValue::Null, val))
            .map_err(|_| error::shape())
    }
    row.columns()
        .iter()
        .enumerate()
        .map(|(i, col)| match *col.type_() {
            Type::INT2 => get(&row, i, |x: i16| SqlValue::Int(x.into())),
            Type::INT4 => get(&row, i, |x: i32| SqlValue::Int(x.into())),
            Type::INT8 => get(&row, i, SqlValue::Int),
            Type::BOOL => get(&row, i, |x: bool| SqlValue::Int(x.into())),
            Type::NUMERIC => get(&row, i, |x: Numeric| SqlValue::Int(x.0)),
            Type::TEXT | Type::VARCHAR | Type::NAME => get(&row, i, SqlValue::Text),
            Type::BYTEA => get(&row, i, SqlValue::Blob),
            _ => Err(error::shape()),
        })
        .collect()
}

struct Numeric(i64);

impl FromSql<'_> for Numeric {
    fn from_sql(_ty: &Type, raw: &[u8]) -> core::result::Result<Self, CodecError> {
        numeric(raw)
            .map(Self)
            .ok_or_else(|| std::io::Error::other("not an integral i64 numeric").into())
    }
    fn accepts(ty: &Type) -> bool {
        *ty == Type::NUMERIC
    }
}

/// PostgreSQL binary NUMERIC has a signed base-10,000 weight, sign, scale,
/// and a sequence of 0..9999 digits. The scale can be nonzero even when the
/// value is exactly integral. Reject nonfinite, fractional, and overflow.
pub(super) fn numeric(raw: &[u8]) -> Option<i64> {
    let [n0, n1, w0, w1, s0, s1, _, _, digits @ ..] = raw else {
        return None;
    };
    let n = usize::from(u16::from_be_bytes([*n0, *n1]));
    let weight = i32::from(i16::from_be_bytes([*w0, *w1]));
    let sign = u16::from_be_bytes([*s0, *s1]);
    if !matches!(sign, 0 | 0x4000) || digits.len() != n * 2 {
        return None;
    }
    let mut magnitude = 0_u64;
    for (i, d) in digits.chunks_exact(2).enumerate() {
        let digit = u64::from(u16::from_be_bytes([d[0], d[1]]));
        if digit == 0 {
            continue;
        }
        let exp = weight - i as i32;
        if digit >= 10_000 || !(0..=4).contains(&exp) {
            return None;
        }
        let term = digit.checked_mul(10_000_u64.pow(exp as u32))?;
        magnitude = magnitude.checked_add(term)?;
    }
    if sign == 0 {
        return i64::try_from(magnitude).ok();
    }
    if magnitude == (1_u64 << 63) {
        return Some(i64::MIN);
    }
    i64::try_from(magnitude).ok().map(|v| -v)
}
