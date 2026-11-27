//! Several extended-protocol statements sent as one request with a single
//! Sync (vendored addition, not part of upstream tokio-postgres 0.7.18).
//!
//! The request keeps the connection's rule of one request, one Sync, one
//! ReadyForQuery: every statement is an unnamed Parse, Bind, Describe and
//! Execute in one buffer, followed by exactly one Sync, handed to the
//! connection as a single request. The server runs the statements in order
//! without waiting for the client between them. After an error it skips
//! everything up to the Sync, so a later statement (such as a COMMIT) never
//! runs after a failed one.
//!
//! Parameters are typed binary binds and rows are binary rows, exactly as in
//! [`Client::query_typed_raw`](crate::Client::query_typed_raw). Column types
//! come from the built-in type table only: an OID outside it gets a
//! placeholder type that no `FromSql` accepts, and no type lookup (a named
//! statement in a separate request) is ever made, so the request cannot
//! stall behind one of its own.
//!
//! Nothing here logs.

use crate::client::InnerClient;
use crate::codec::FrontendMessage;
use crate::connection::RequestMessages;
use crate::query::{encode_bind_raw, extract_row_affected};
use crate::types::{Kind, ToSql, Type};
use crate::{Column, Error, Row, Statement};
use fallible_iterator::FallibleIterator;
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use std::sync::Arc;

/// One statement of a pipeline: SQL text and its typed parameters.
pub struct PipelineStatement<'a> {
    /// The statement text, with `$n` parameters.
    pub query: &'a str,
    /// The parameters with their wire types, as for `query_typed_raw`.
    pub params: Vec<(&'a (dyn ToSql + Sync), Type)>,
}

/// The reply to one statement that completed.
pub struct PipelineReply {
    /// The command tag of its CommandComplete, or empty for an empty query.
    pub tag: String,
    /// The row count of the tag, as `RowStream::rows_affected` reports it.
    pub rows_affected: u64,
    /// Its rows, when the pipeline collects rows.
    pub rows: Vec<Row>,
}

/// What the server answered to a pipeline that was sent.
pub struct PipelineOutcome {
    /// The statements that completed, in order.
    pub replies: Vec<PipelineReply>,
    /// The first error and the number of statements that completed before
    /// it: a server error, the loss of the connection or an unexpected
    /// message. For an error raised by a statement this is its index. It
    /// equals the number of statements for an error at the Sync itself
    /// (for example a deferred constraint checked when an implicit
    /// transaction commits).
    pub error: Option<(usize, Error)>,
    /// The transaction status of the final ReadyForQuery (`b'I'`, `b'T'` or
    /// `b'E'`), or `None` if it was not received.
    pub status: Option<u8>,
}

fn column_type(oid: u32) -> Type {
    Type::from_oid(oid)
        .unwrap_or_else(|| Type::new(format!("unknown oid {oid}"), oid, Kind::Pseudo, String::new()))
}

/// Whether a statement starts with COPY, after whitespace and comments. COPY
/// would put the connection in copy mode, where the server ignores the Sync.
fn is_copy(query: &str) -> bool {
    let mut rest = query;
    loop {
        rest = rest.trim_start();
        if let Some(line) = rest.strip_prefix("--") {
            rest = line.split_once('\n').map_or("", |(_, r)| r);
        } else if rest.starts_with("/*") {
            // Block comments nest in PostgreSQL.
            let (mut depth, mut i) = (0_usize, 0);
            let bytes = rest.as_bytes();
            while i < bytes.len() {
                match &bytes[i..(i + 2).min(bytes.len())] {
                    b"/*" => {
                        depth += 1;
                        i += 2;
                    }
                    b"*/" => {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => i += 1,
                }
            }
            rest = &rest[i.min(rest.len())..];
        } else {
            break;
        }
    }
    rest.get(..4).is_some_and(|word| word.eq_ignore_ascii_case("copy"))
}

pub(crate) async fn pipeline_typed(
    client: &Arc<InnerClient>,
    statements: &[PipelineStatement<'_>],
    collect_rows: bool,
) -> Result<PipelineOutcome, Error> {
    if statements.iter().any(|s| is_copy(s.query)) {
        return Err(Error::encode(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "COPY is not supported in a pipeline",
        )));
    }
    // Encode everything before sending anything: an encode error in any
    // statement returns here and no byte reaches the connection.
    let buf = client.with_buf(|buf| {
        for statement in statements {
            let oids = statement.params.iter().map(|(_, t)| t.oid()).collect::<Vec<_>>();
            frontend::parse("", statement.query, oids, buf).map_err(Error::parse)?;
            encode_bind_raw("", statement.params.iter().map(|(p, t)| (*p, t.clone())), "", buf)?;
            frontend::describe(b'S', "", buf).map_err(Error::encode)?;
            frontend::execute("", 0, buf).map_err(Error::encode)?;
        }
        frontend::sync(buf);
        Ok(buf.split().freeze())
    })?;
    let mut responses = client.send(RequestMessages::Single(FrontendMessage::Raw(buf)))?;

    let mut outcome = PipelineOutcome {
        replies: Vec::with_capacity(statements.len()),
        error: None,
        status: None,
    };
    // The described statement whose replies are being read, if any.
    let mut columns: Option<Statement> = None;
    let mut rows = Vec::new();
    loop {
        let message = match responses.next().await {
            Ok(message) => message,
            Err(error) => {
                let done = outcome.replies.len();
                if outcome.error.is_none() {
                    // A server ErrorResponse: the server now skips to the
                    // Sync and answers ReadyForQuery, read below.
                    let closed = error.as_db_error().is_none();
                    outcome.error = Some((done, error));
                    if !closed {
                        continue;
                    }
                }
                return Ok(outcome);
            }
        };
        if outcome.error.is_some() {
            // After an error, only the ReadyForQuery of the Sync may follow.
            if let Message::ReadyForQuery(body) = message {
                outcome.status = Some(body.status());
            }
            return Ok(outcome);
        }
        match message {
            Message::ParseComplete | Message::BindComplete | Message::ParameterDescription(_)
                if columns.is_none() => {}
            Message::NoData if columns.is_none() => {
                columns = Some(Statement::unnamed(vec![], vec![]));
            }
            Message::RowDescription(body) if columns.is_none() => {
                let mut described = Vec::new();
                let mut fields = body.fields();
                while let Some(field) = fields.next().map_err(Error::parse)? {
                    described.push(Column {
                        name: field.name().to_string(),
                        table_oid: Some(field.table_oid()).filter(|n| *n != 0),
                        column_id: Some(field.column_id()).filter(|n| *n != 0),
                        type_modifier: field.type_modifier(),
                        r#type: column_type(field.type_oid()),
                    });
                }
                columns = Some(Statement::unnamed(vec![], described));
            }
            Message::DataRow(body) => match &columns {
                Some(statement) if collect_rows => rows.push(Row::new(statement.clone(), body)?),
                Some(_) => {}
                None => {
                    outcome.error = Some((outcome.replies.len(), Error::unexpected_message()));
                    return Ok(outcome);
                }
            },
            Message::CommandComplete(body) if columns.is_some() => {
                let tag = body.tag().map_err(Error::parse)?.to_string();
                outcome.replies.push(PipelineReply {
                    rows_affected: extract_row_affected(&body)?,
                    tag,
                    rows: std::mem::take(&mut rows),
                });
                columns = None;
            }
            Message::EmptyQueryResponse if columns.is_some() => {
                outcome.replies.push(PipelineReply {
                    tag: String::new(),
                    rows_affected: 0,
                    rows: std::mem::take(&mut rows),
                });
                columns = None;
            }
            Message::ReadyForQuery(body) if columns.is_none() => {
                outcome.status = Some(body.status());
                return Ok(outcome);
            }
            _ => {
                outcome.error = Some((outcome.replies.len(), Error::unexpected_message()));
                return Ok(outcome);
            }
        }
    }
}
