//! Synthetic SOCKS5 proxy (RFC 1928, username/password of RFC 1929) for
//! tests of the client handshake. Loopback only, one login, and a set of
//! ways to misbehave ([`ProxyMode`]).
//!
//! In [`ProxyMode::Relay`] it connects to the requested host and port and
//! pipes bytes both ways. It records which targets were asked for and
//! how many connections came in, never a payload.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the proxy does with a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    /// A correct proxy: checks the login, connects, relays.
    Relay,
    /// Selects "no authentication" although it was not offered.
    SelectsNoAuth,
    /// Answers that none of the offered methods is acceptable.
    NoAcceptableMethod,
    /// Refuses every login.
    RefuseLogin,
    /// Answers the CONNECT with this reply code and connects nowhere.
    RefuseConnect(u8),
    /// Answers the CONNECT with a reply of another protocol version.
    MalformedReply,
    /// Answers the CONNECT with a correct reply cut short, then closes.
    TruncatedReply,
    /// Answers the CONNECT correctly and sends these extra bytes in the
    /// same write, before relaying.
    TrailingBytes(&'static [u8]),
    /// Closes the connection after the client's greeting.
    CloseEarly,
}

#[derive(Default)]
struct Seen {
    connections: usize,
    targets: Vec<(String, u16)>,
}

struct Shared {
    user: String,
    pass: String,
    mode: Mutex<ProxyMode>,
    seen: Mutex<Seen>,
}

/// A proxy on an ephemeral loopback port. It stops when dropped.
pub struct TestSocks5Proxy {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestSocks5Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestSocks5Proxy {
    /// Starts a proxy that accepts the login `user` / `pass`.
    pub async fn spawn(user: &str, pass: &str, mode: ProxyMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let addr = listener.local_addr().expect("proxy addr");
        let shared = Arc::new(Shared {
            user: user.to_string(),
            pass: pass.to_string(),
            mode: Mutex::new(mode),
            seen: Mutex::new(Seen::default()),
        });
        let accept = Arc::clone(&shared);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                accept.seen.lock().unwrap().connections += 1;
                let shared = Arc::clone(&accept);
                tokio::spawn(async move {
                    let _ = serve(stream, &shared).await;
                });
            }
        });
        TestSocks5Proxy { addr, shared, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_mode(&self, mode: ProxyMode) {
        *self.shared.mode.lock().unwrap() = mode;
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.shared.seen.lock().unwrap().connections
    }

    /// Every target a CONNECT asked for, in order.
    pub fn targets(&self) -> Vec<(String, u16)> {
        self.shared.seen.lock().unwrap().targets.clone()
    }
}

async fn serve(mut client: TcpStream, shared: &Shared) -> std::io::Result<()> {
    let mode = *shared.mode.lock().unwrap();

    // Greeting: VER, NMETHODS, METHODS.
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods).await?;
    match mode {
        ProxyMode::CloseEarly => return Ok(()),
        ProxyMode::SelectsNoAuth => {
            client.write_all(&[5, 0]).await?;
            // Whatever comes next is not answered.
            let _ = client.read(&mut [0u8; 64]).await;
            return Ok(());
        }
        ProxyMode::NoAcceptableMethod => return client.write_all(&[5, 0xff]).await,
        _ => {}
    }
    if head[0] != 5 || !methods.contains(&2) {
        return client.write_all(&[5, 0xff]).await;
    }
    client.write_all(&[5, 2]).await?;

    // Login: VER, ULEN, UNAME, PLEN, PASSWD.
    client.read_exact(&mut head).await?;
    let mut user = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    client.read_exact(&mut pass).await?;
    let known = user == shared.user.as_bytes() && pass == shared.pass.as_bytes();
    if head[0] != 1 || !known || mode == ProxyMode::RefuseLogin {
        return client.write_all(&[1, 1]).await;
    }
    client.write_all(&[1, 0]).await?;

    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT. Host names only.
    let mut request = [0u8; 5];
    client.read_exact(&mut request).await?;
    if request[..4] != [5, 1, 0, 3] {
        return client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    }
    let mut name = vec![0u8; usize::from(request[4])];
    client.read_exact(&mut name).await?;
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let host = String::from_utf8_lossy(&name).into_owned();
    let port = u16::from_be_bytes(port);
    shared
        .seen
        .lock()
        .unwrap()
        .targets
        .push((host.clone(), port));

    const OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    match mode {
        ProxyMode::RefuseConnect(code) => {
            return client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
        ProxyMode::MalformedReply => {
            return client.write_all(&[4, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
        ProxyMode::TruncatedReply => return client.write_all(&OK[..6]).await,
        _ => {}
    }
    let Ok(mut target) = TcpStream::connect((host.as_str(), port)).await else {
        return client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    };
    let mut reply = OK.to_vec();
    if let ProxyMode::TrailingBytes(extra) = mode {
        reply.extend_from_slice(extra);
    }
    client.write_all(&reply).await?;
    copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}
