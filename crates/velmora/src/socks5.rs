//! SOCKS5 client handshake (RFC 1928) with username/password
//! authentication (RFC 1929), over any [`Transport`].
//!
//! [`connect`] asks a proxy to open a TCP connection to a host name and
//! port. After it returns `Ok`, the transport is a byte pipe to that
//! target: the caller starts TLS on it, with the target as the expected
//! server name, before a single NNTP byte is sent. The proxy then relays
//! ciphertext only.
//!
//! Fail closed:
//! - Only username/password authentication is offered, and no other
//!   method is accepted back: a proxy that answers "no authentication"
//!   is refused, so an open relay is never used by mistake.
//! - The target is always sent as a host name. The proxy resolves it, and
//!   the TLS certificate check that follows is what binds the connection
//!   to the provider.
//! - Every reply must be exactly as long as its own header says. A reply
//!   that is cut short, carries an unknown field, or is followed by bytes
//!   the client did not ask for is refused: bytes after the last reply
//!   would otherwise be read as the start of the target's stream.
//!
//! Every failure is an [`io::Error`] whose message is one of the fixed
//! strings below: never a host, a login, proxy text or a runtime message.
//! Arguments the protocol cannot carry (an empty or over-long name, a
//! zero port) are [`io::ErrorKind::InvalidInput`]. Every other failure
//! carries a [`StageError`], which tells a caller two things apart
//! without reading text:
//! - [`is_proxy_failure`]: the proxy itself failed (not reached, closed,
//!   out of protocol, login refused). The target was never asked.
//! - [`is_target_failure`]: the proxy works and reported that it did not
//!   connect to the target.
//!
//! The proxy login is sent in clear to the proxy, as RFC 1929 defines it.
//! It guards the use of the proxy only; the provider login travels inside
//! the TLS session the proxy cannot read.

use std::fmt;
use std::io;

use crate::transport::Transport;

/// Longest name, user name or password the protocol carries, in bytes.
pub const MAX_FIELD_BYTES: usize = 255;

/// Room for one reply. The longest valid reply (a bound host name of 255
/// bytes) is 262 bytes; the rest is there so that bytes sent after a
/// reply land in the buffer and are seen, instead of staying unread in
/// the transport.
const REPLY_BUF_BYTES: usize = 512;

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The proxy asked for, or agreed to, something other than a
/// username/password login.
pub const ERR_METHOD: &str = "socks5: proxy did not accept username/password authentication";
/// The proxy refused the login.
pub const ERR_AUTH: &str = "socks5: proxy refused the login";
/// The proxy could not, or would not, connect to the target.
pub const ERR_CONNECT: &str = "socks5: proxy did not connect to the target";
/// The proxy refused the request itself (its rules, or a command or
/// address type it does not support): no target was tried.
pub const ERR_REQUEST: &str = "socks5: proxy refused the request";
/// A reply was not a SOCKS5 reply.
pub const ERR_MALFORMED: &str = "socks5: malformed reply";
/// A reply was followed by bytes that were not asked for.
pub const ERR_TRAILING: &str = "socks5: unexpected bytes after a reply";
/// The proxy closed the connection inside the handshake.
pub const ERR_CLOSED: &str = "socks5: proxy closed the connection";
/// A name, login or port the protocol cannot carry.
pub const ERR_ARGUMENT: &str = "socks5: name, login or port not valid";
/// A read or write on the connection to the proxy failed.
pub const ERR_IO: &str = "socks5: connection to the proxy failed";
/// A read or write on the connection to the proxy ran out of time, or
/// the whole handshake did.
pub const ERR_TIMEOUT: &str = "socks5: proxy did not answer in time";

/// What every failure of the proxy stage carries inside its
/// [`io::Error`]: the fixed message, and whether the proxy named the
/// target as the reason.
#[derive(Debug)]
pub struct StageError {
    message: &'static str,
    target: bool,
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for StageError {}

fn stage(e: &io::Error) -> Option<&StageError> {
    e.get_ref()?.downcast_ref::<StageError>()
}

/// Whether `e` says the proxy itself failed, before the target was
/// reached: no other host of the provider would do better through it.
pub fn is_proxy_failure(e: &io::Error) -> bool {
    stage(e).is_some_and(|s| !s.target)
}

/// Whether `e` is the proxy's report that it did not connect to the
/// target: the proxy works.
pub fn is_target_failure(e: &io::Error) -> bool {
    stage(e).is_some_and(|s| s.target)
}

/// A failure of the proxy itself, for a connector's own steps of the
/// stage (opening the socket, the bound on the whole handshake).
/// `message` is one of this module's constants.
pub fn proxy_failure(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(
        kind,
        StageError {
            message,
            target: false,
        },
    )
}

/// A failed read or write, without the transport's own message.
fn io_failure(e: io::Error) -> io::Error {
    match e.kind() {
        io::ErrorKind::TimedOut => proxy_failure(io::ErrorKind::TimedOut, ERR_TIMEOUT),
        kind => proxy_failure(kind, ERR_IO),
    }
}

/// A SOCKS5 proxy and the login for it. `Debug` shows no field.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Proxy {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl fmt::Debug for Socks5Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Socks5Proxy(<redacted>)")
    }
}

fn error(kind: io::ErrorKind, msg: &'static str) -> io::Error {
    proxy_failure(kind, msg)
}

fn malformed() -> io::Error {
    error(io::ErrorKind::InvalidData, ERR_MALFORMED)
}

fn field_ok(s: &str) -> bool {
    (1..=MAX_FIELD_BYTES).contains(&s.len())
}

/// Reads one reply. `total_len` is given what has arrived and answers the
/// reply's full length once the bytes that decide it are there (`None` =
/// read on). More bytes than that length is an error, as is a closed
/// connection before it.
async fn read_reply<T: Transport>(
    transport: &mut T,
    buf: &mut [u8; REPLY_BUF_BYTES],
    total_len: impl Fn(&[u8]) -> io::Result<Option<usize>>,
) -> io::Result<usize> {
    let mut have = 0usize;
    loop {
        // The whole free part of the buffer is offered every time, so
        // nothing the proxy sent early stays behind in the transport.
        let n = transport.read(&mut buf[have..]).await.map_err(io_failure)?;
        if n == 0 {
            return Err(error(io::ErrorKind::UnexpectedEof, ERR_CLOSED));
        }
        have = have
            .checked_add(n)
            .filter(|have| *have <= buf.len())
            .ok_or_else(malformed)?;
        match total_len(&buf[..have])? {
            Some(total) if have == total => return Ok(total),
            Some(total) if have > total => {
                return Err(error(io::ErrorKind::InvalidData, ERR_TRAILING));
            }
            // A full buffer with no end in sight: no valid reply is
            // that long.
            _ if have == buf.len() => {
                return Err(error(io::ErrorKind::InvalidData, ERR_TRAILING));
            }
            _ => {}
        }
    }
}

/// The length of a two-byte reply, once its first byte is `first`.
fn two_bytes(first: u8) -> impl Fn(&[u8]) -> io::Result<Option<usize>> {
    move |got: &[u8]| match got.first() {
        Some(b) if *b != first => Err(malformed()),
        _ => Ok(Some(2)),
    }
}

/// The length of a CONNECT reply: `VER REP RSV ATYP BND.ADDR BND.PORT`.
fn connect_reply_len(got: &[u8]) -> io::Result<Option<usize>> {
    if got.first().is_some_and(|ver| *ver != VERSION) {
        return Err(malformed());
    }
    let Some(atyp) = got.get(3) else {
        return Ok(None);
    };
    let addr = match *atyp {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_NAME => match got.get(4) {
            Some(len) => 1 + usize::from(*len),
            None => return Ok(None),
        },
        _ => return Err(malformed()),
    };
    Ok(Some(4 + addr + 2))
}

/// Whether a CONNECT reply code other than success blames the target.
/// The codes for a network, host or connection the proxy could not get
/// to do (RFC 1928: 3 to 6), and the general failure (1), which simple
/// proxies answer for any failed connect. Every other code is the
/// proxy's own refusal (2 = not allowed by its rules, 7 and 8 = not
/// supported, anything unassigned): no target was tried.
fn target_reply(rep: u8) -> bool {
    matches!(rep, 1 | 3..=6)
}

/// Runs the handshake on a freshly opened connection to the proxy:
/// greeting, login, `CONNECT host:port`. On `Ok` the next byte either
/// side sends belongs to the target's stream.
///
/// On any `Err` the transport is in an unknown state and must be closed.
pub async fn connect<T: Transport>(
    transport: &mut T,
    username: &str,
    password: &str,
    host: &str,
    port: u16,
) -> io::Result<()> {
    if !field_ok(username) || !field_ok(password) || !field_ok(host) || port == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, ERR_ARGUMENT));
    }
    let mut buf = [0u8; REPLY_BUF_BYTES];

    // Greeting: one method, username/password.
    transport
        .write_all(&[VERSION, 1, METHOD_USER_PASS])
        .await
        .map_err(io_failure)?;
    read_reply(transport, &mut buf, two_bytes(VERSION)).await?;
    if buf[1] != METHOD_USER_PASS {
        return Err(error(io::ErrorKind::PermissionDenied, ERR_METHOD));
    }

    // Login (RFC 1929). The lengths fit a byte: checked above.
    let mut login = Vec::with_capacity(3 + username.len() + password.len());
    login.push(AUTH_VERSION);
    login.push(username.len() as u8);
    login.extend_from_slice(username.as_bytes());
    login.push(password.len() as u8);
    login.extend_from_slice(password.as_bytes());
    let sent = transport.write_all(&login).await;
    login.fill(0);
    sent.map_err(io_failure)?;
    read_reply(transport, &mut buf, two_bytes(AUTH_VERSION)).await?;
    if buf[1] != 0 {
        return Err(error(io::ErrorKind::PermissionDenied, ERR_AUTH));
    }

    // CONNECT to the host name; the proxy resolves it.
    let mut request = Vec::with_capacity(7 + host.len());
    request.extend_from_slice(&[VERSION, CMD_CONNECT, 0, ATYP_NAME, host.len() as u8]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    transport.write_all(&request).await.map_err(io_failure)?;
    read_reply(transport, &mut buf, connect_reply_len).await?;
    if buf[2] != 0 {
        return Err(malformed());
    }
    match buf[1] {
        0 => Ok(()),
        rep if target_reply(rep) => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            StageError {
                message: ERR_CONNECT,
                target: true,
            },
        )),
        _ => Err(error(io::ErrorKind::ConnectionRefused, ERR_REQUEST)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A transport that hands back scripted reads and records writes.
    #[derive(Default)]
    struct Script {
        reads: VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Script {
        fn new(reads: &[&[u8]]) -> Self {
            Script {
                reads: reads.iter().map(|r| r.to_vec()).collect(),
                written: Vec::new(),
            }
        }
    }

    impl Transport for Script {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(mut next) = self.reads.pop_front() else {
                return Ok(0);
            };
            let n = next.len().min(buf.len());
            buf[..n].copy_from_slice(&next[..n]);
            let rest = next.split_off(n);
            if !rest.is_empty() {
                self.reads.push_front(rest);
            }
            Ok(n)
        }

        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.written.extend_from_slice(buf);
            Ok(())
        }

        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const METHOD_OK: &[u8] = &[5, 2];
    const AUTH_OK: &[u8] = &[1, 0];
    const BOUND_V4: &[u8] = &[5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90];

    fn run(reads: &[&[u8]]) -> (io::Result<()>, Script) {
        let mut t = Script::new(reads);
        let out = futures_now(connect(&mut t, "user", "pw", "news.example", 563));
        (out, t)
    }

    /// The handshake only awaits the scripted transport, which is always
    /// ready.
    fn futures_now<T>(fut: impl std::future::Future<Output = T>) -> T {
        use std::task::{Context, Poll, Waker};
        let mut fut = std::pin::pin!(fut);
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => out,
            Poll::Pending => panic!("scripted transport is always ready"),
        }
    }

    fn fails(reads: &[&[u8]], kind: io::ErrorKind, msg: &str) {
        let (out, _) = run(reads);
        let e = out.expect_err("handshake must fail");
        assert_eq!((e.kind(), e.to_string().as_str()), (kind, msg));
        // Only the proxy's own "did not connect" is the target's.
        assert_eq!(is_target_failure(&e), msg == ERR_CONNECT);
        assert_eq!(is_proxy_failure(&e), msg != ERR_CONNECT);
    }

    #[test]
    fn success_sends_exactly_the_three_requests() {
        let (out, t) = run(&[METHOD_OK, AUTH_OK, BOUND_V4]);
        out.unwrap();
        let mut want = vec![5, 1, 2];
        want.extend_from_slice(&[1, 4]);
        want.extend_from_slice(b"user");
        want.push(2);
        want.extend_from_slice(b"pw");
        want.extend_from_slice(&[5, 1, 0, 3, 12]);
        want.extend_from_slice(b"news.example");
        want.extend_from_slice(&[0x02, 0x33]);
        assert_eq!(t.written, want);
        assert!(t.reads.is_empty());
    }

    #[test]
    fn success_with_every_bound_address_type_and_split_reads() {
        let v6: Vec<u8> = [&[5, 0, 0, 4][..], &[0u8; 16], &[0, 80]].concat();
        let name: Vec<u8> = [&[5, 0, 0, 3, 3][..], b"abc", &[0, 80]].concat();
        let empty_name: &[u8] = &[5, 0, 0, 3, 0, 0, 80];
        for bound in [BOUND_V4, &v6, &name, empty_name] {
            run(&[METHOD_OK, AUTH_OK, bound]).0.unwrap();
            // The same reply, one byte per read.
            let bytes: Vec<&[u8]> = bound.chunks(1).collect();
            let mut reads: Vec<&[u8]> = vec![&[5], &[2], &[1], &[0]];
            reads.extend(bytes);
            run(&reads).0.unwrap();
        }
    }

    #[test]
    fn a_proxy_that_wants_no_login_is_refused() {
        // "No authentication" was not offered: an open relay.
        fails(&[&[5, 0]], io::ErrorKind::PermissionDenied, ERR_METHOD);
        fails(&[&[5, 0xff]], io::ErrorKind::PermissionDenied, ERR_METHOD);
        // Nothing is sent after the refusal: no login, no request.
        let (_, t) = run(&[&[5, 0]]);
        assert_eq!(t.written, [5, 1, 2]);
    }

    #[test]
    fn a_refused_login_is_an_error_and_no_request_follows() {
        fails(
            &[METHOD_OK, &[1, 1]],
            io::ErrorKind::PermissionDenied,
            ERR_AUTH,
        );
        fails(
            &[METHOD_OK, &[1, 0xff]],
            io::ErrorKind::PermissionDenied,
            ERR_AUTH,
        );
        let (_, t) = run(&[METHOD_OK, &[1, 1]]);
        assert!(!t.written.ends_with(&[0x02, 0x33]), "no CONNECT after it");
    }

    #[test]
    fn a_refused_connect_is_an_error_for_every_reply_code() {
        // A target the proxy could not connect to is the target's
        // failure; the proxy's own refusal, and any code without a
        // meaning, is the proxy's.
        for rep in 1..=255u8 {
            let reply = [5, rep, 0, 1, 0, 0, 0, 0, 0, 0];
            let msg = match rep {
                1 | 3 | 4 | 5 | 6 => ERR_CONNECT,
                _ => ERR_REQUEST,
            };
            fails(
                &[METHOD_OK, AUTH_OK, &reply],
                io::ErrorKind::ConnectionRefused,
                msg,
            );
        }
    }

    #[test]
    fn malformed_replies_are_refused() {
        let bad = io::ErrorKind::InvalidData;
        // Wrong version in each of the three replies.
        fails(&[&[4, 2]], bad, ERR_MALFORMED);
        fails(&[b"HT"], bad, ERR_MALFORMED);
        fails(&[METHOD_OK, &[5, 0]], bad, ERR_MALFORMED);
        fails(&[METHOD_OK, &[0, 0]], bad, ERR_MALFORMED);
        fails(
            &[METHOD_OK, AUTH_OK, &[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]],
            bad,
            ERR_MALFORMED,
        );
        // A wrong version is refused on its first byte.
        fails(&[&[4]], bad, ERR_MALFORMED);
        fails(&[METHOD_OK, AUTH_OK, &[4]], bad, ERR_MALFORMED);
        // Unknown address type, non-zero reserved byte.
        for atyp in [0u8, 2, 5, 0xff] {
            fails(
                &[METHOD_OK, AUTH_OK, &[5, 0, 0, atyp, 0, 0, 0, 0, 0, 0]],
                bad,
                ERR_MALFORMED,
            );
        }
        fails(
            &[METHOD_OK, AUTH_OK, &[5, 0, 1, 1, 0, 0, 0, 0, 0, 0]],
            bad,
            ERR_MALFORMED,
        );
    }

    #[test]
    fn a_reply_cut_short_is_a_closed_connection() {
        let eof = io::ErrorKind::UnexpectedEof;
        fails(&[], eof, ERR_CLOSED);
        fails(&[&[5]], eof, ERR_CLOSED);
        fails(&[METHOD_OK], eof, ERR_CLOSED);
        fails(&[METHOD_OK, &[1]], eof, ERR_CLOSED);
        fails(&[METHOD_OK, AUTH_OK], eof, ERR_CLOSED);
        for cut in 1..BOUND_V4.len() {
            fails(&[METHOD_OK, AUTH_OK, &BOUND_V4[..cut]], eof, ERR_CLOSED);
        }
    }

    #[test]
    fn a_reply_bigger_than_expected_is_refused() {
        let bad = io::ErrorKind::InvalidData;
        // One byte too many after each reply, in the same read.
        fails(&[&[5, 2, 1]], bad, ERR_TRAILING);
        fails(&[METHOD_OK, &[1, 0, 5]], bad, ERR_TRAILING);
        let mut long = BOUND_V4.to_vec();
        long.push(b'2');
        fails(&[METHOD_OK, AUTH_OK, &long], bad, ERR_TRAILING);
        // The target's first bytes glued to the reply (a proxy that does
        // not wait for the client) are not taken for the reply's tail.
        let mut glued = BOUND_V4.to_vec();
        glued.extend_from_slice(b"200 news.example ready\r\n");
        fails(&[METHOD_OK, AUTH_OK, &glued], bad, ERR_TRAILING);
        // Two replies in one read.
        fails(&[&[5, 2, 1, 0]], bad, ERR_TRAILING);
        // A flood: more than the buffer holds, with no valid end.
        let flood = vec![5u8; 4096];
        fails(&[&flood], bad, ERR_TRAILING);
        let mut name_flood = vec![5, 0, 0, 3, 255];
        name_flood.extend_from_slice(&[b'a'; 4096]);
        fails(&[METHOD_OK, AUTH_OK, &name_flood], bad, ERR_TRAILING);
    }

    #[test]
    fn the_longest_valid_reply_fits() {
        let mut reply = vec![5, 0, 0, 3, 255];
        reply.extend_from_slice(&[b'a'; 255]);
        reply.extend_from_slice(&[0, 80]);
        run(&[METHOD_OK, AUTH_OK, &reply]).0.unwrap();
        reply.push(0);
        fails(
            &[METHOD_OK, AUTH_OK, &reply],
            io::ErrorKind::InvalidData,
            ERR_TRAILING,
        );
    }

    #[test]
    fn arguments_the_protocol_cannot_carry_send_nothing() {
        let long = "a".repeat(256);
        let max = "a".repeat(255);
        let cases: [(&str, &str, &str, u16); 7] = [
            ("", "pw", "h.example", 563),
            ("u", "", "h.example", 563),
            ("u", "pw", "", 563),
            ("u", "pw", "h.example", 0),
            (&long, "pw", "h.example", 563),
            ("u", &long, "h.example", 563),
            ("u", "pw", &long, 563),
        ];
        for (user, pass, host, port) in cases {
            let mut t = Script::new(&[METHOD_OK, AUTH_OK, BOUND_V4]);
            let e = futures_now(connect(&mut t, user, pass, host, port)).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(e.to_string(), ERR_ARGUMENT);
            assert!(!is_proxy_failure(&e) && !is_target_failure(&e));
            assert!(t.written.is_empty());
        }
        let mut t = Script::new(&[METHOD_OK, AUTH_OK, BOUND_V4]);
        futures_now(connect(&mut t, &max, &max, &max, 1)).unwrap();
        assert_eq!(t.written.len(), 3 + (3 + 255 + 255) + (7 + 255));
    }

    /// Fails the read or the write numbered `fail_at` (writes and reads
    /// counted together, from 0) with `kind` and a message that names
    /// a host, as a runtime's may.
    struct Broken {
        inner: Script,
        fail_at: usize,
        calls: usize,
        kind: io::ErrorKind,
    }

    impl Broken {
        fn step(&mut self) -> io::Result<()> {
            self.calls += 1;
            if self.calls - 1 == self.fail_at {
                return Err(io::Error::new(self.kind, "failed: proxy.example:1080"));
            }
            Ok(())
        }
    }

    impl Transport for Broken {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.step()?;
            self.inner.read(buf).await
        }
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.step()?;
            self.inner.write_all(buf).await
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_transport_error_is_a_proxy_failure_without_its_text() {
        // Six steps: write, read, write, read, write, read.
        for fail_at in 0..6 {
            for (kind, msg) in [
                (io::ErrorKind::TimedOut, ERR_TIMEOUT),
                (io::ErrorKind::ConnectionReset, ERR_IO),
                (io::ErrorKind::Other, ERR_IO),
            ] {
                let mut t = Broken {
                    inner: Script::new(&[METHOD_OK, AUTH_OK, BOUND_V4]),
                    fail_at,
                    calls: 0,
                    kind,
                };
                let e = futures_now(connect(&mut t, "u", "pw", "h.example", 563)).unwrap_err();
                assert_eq!((e.kind(), e.to_string().as_str()), (kind, msg));
                assert!(is_proxy_failure(&e) && !is_target_failure(&e));
                assert!(!format!("{e:?}").contains("proxy.example"));
            }
        }
        let mut t = Broken {
            inner: Script::new(&[METHOD_OK, AUTH_OK, BOUND_V4]),
            fail_at: 6,
            calls: 0,
            kind: io::ErrorKind::Other,
        };
        futures_now(connect(&mut t, "u", "pw", "h.example", 563)).unwrap();
    }

    #[test]
    fn an_error_from_elsewhere_is_neither_failure() {
        let plain = io::Error::new(io::ErrorKind::ConnectionRefused, ERR_CONNECT);
        assert!(!is_proxy_failure(&plain) && !is_target_failure(&plain));
        let made = proxy_failure(io::ErrorKind::TimedOut, ERR_TIMEOUT);
        assert!(is_proxy_failure(&made) && !is_target_failure(&made));
        assert_eq!(made.to_string(), ERR_TIMEOUT);
    }

    #[test]
    fn no_error_names_the_login_or_the_host() {
        let scripts: [&[&[u8]]; 5] = [
            &[&[5, 0]],
            &[METHOD_OK, &[1, 1]],
            &[METHOD_OK, AUTH_OK, &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]],
            &[b"news.example alice hunter2"],
            &[],
        ];
        for reads in scripts {
            let mut t = Script::new(reads);
            let e =
                futures_now(connect(&mut t, "alice", "hunter2", "news.example", 563)).unwrap_err();
            let text = format!("{e} {e:?}");
            for secret in ["alice", "hunter2", "news.example"] {
                assert!(!text.contains(secret), "{text}");
            }
        }
        let proxy = Socks5Proxy {
            host: "proxy.example".into(),
            port: 1080,
            username: "proxy-user".into(),
            password: "proxy-pass".into(),
        };
        assert_eq!(format!("{proxy:?}"), "Socks5Proxy(<redacted>)");
    }
}
