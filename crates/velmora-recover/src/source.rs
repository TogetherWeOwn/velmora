//! Native NNTP, downloads from a standard NZB client, and the drill relay.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;
use velmora::{
    nntp::{NntpClient, NntpConfig},
    transports::tokio_tls::{self, NativeTlsTransport},
};
use zeroize::Zeroize;

use crate::extent::{
    sha256, valid_message_id, Article, BodySource, FetchError, Placement, MAX_BODY_BYTES,
};

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    providers: Vec<Provider>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    host: String,
    port: Option<u16>,
    tls: bool,
    user: Option<String>,
    pass: Option<String>,
    max_conns: usize,
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.user.zeroize();
        self.pass.zeroize();
    }
}

struct Config(NntpConfig);
impl Drop for Config {
    fn drop(&mut self) {
        self.0.username.zeroize();
        self.0.password.zeroize();
    }
}

/// At most one connection across all accounts. Keep the last successful
/// provider hot, rotate on failure, and retry over two passes.
pub struct NntpSource {
    configs: Vec<Config>,
    next: usize,
    client: Option<NntpClient<NativeTlsTransport>>,
    last_body_succeeded: bool,
}

impl NntpSource {
    pub fn from_toml(bytes: &[u8]) -> Result<Self, &'static str> {
        let bad = "invalid provider configuration";
        let providers: ProviderFile =
            toml::from_str(std::str::from_utf8(bytes).map_err(|_| bad)?).map_err(|_| bad)?;
        if !(1..=16).contains(&providers.providers.len()) {
            return Err(bad);
        }
        let mut configs = Vec::new();
        for mut p in providers.providers {
            if p.host.is_empty()
                || !p
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                || p.max_conns == 0
                || p.port == Some(0)
                || p.user.is_some() != p.pass.is_some()
                || (!p.tls && p.user.is_some())
                || [&p.user, &p.pass].into_iter().flatten().any(|s| {
                    s.is_empty() || s.len() > 512 || s.bytes().any(|b| b.is_ascii_control())
                })
            {
                return Err(bad);
            }
            configs.push(Config(NntpConfig {
                host: std::mem::take(&mut p.host),
                port: p.port.unwrap_or(if p.tls { 563 } else { 119 }),
                tls: p.tls,
                allow_insecure_plaintext: !p.tls,
                username: p.user.take(),
                password: p.pass.take(),
                timeout: TIMEOUT,
                max_pipelined: 1,
                max_article_bytes: MAX_BODY_BYTES,
            }));
        }
        Ok(Self {
            configs,
            next: 0,
            client: None,
            last_body_succeeded: false,
        })
    }

    fn rotate(&mut self) {
        self.client = None;
        self.next = (self.next + 1) % self.configs.len();
        self.last_body_succeeded = false;
    }

    async fn fetch(&mut self, id: &str) -> Result<Vec<u8>, FetchError> {
        if self.client.is_none() {
            let config = &self.configs[self.next].0;
            let transport = tokio_tls::connect(config)
                .await
                .map_err(|_| FetchError::Unavailable)?;
            self.client = Some(
                NntpClient::connect(transport, config)
                    .await
                    .map_err(|_| FetchError::Unavailable)?,
            );
        }
        let mut bytes = Vec::new();
        self.client
            .as_mut()
            .expect("connected above")
            .body_to(id, &mut bytes)
            .await
            .map_err(|_| FetchError::Unavailable)?;
        Ok(bytes)
    }
}

impl BodySource for NntpSource {
    fn attempts(&self) -> usize {
        self.configs.len() * 2
    }

    async fn body(&mut self, id: &str) -> Result<Vec<u8>, FetchError> {
        if !valid_message_id(id) {
            return Err(FetchError::Unavailable);
        }
        match tokio::time::timeout(TIMEOUT, self.fetch(id)).await {
            Ok(Ok(body)) => {
                self.last_body_succeeded = true;
                Ok(body)
            }
            _ => {
                self.rotate();
                Err(FetchError::Unavailable)
            }
        }
    }

    fn rejected(&mut self) {
        if self.last_body_succeeded {
            self.rotate();
        }
    }
}

#[cfg(feature = "recovery-cli")]
pub struct RelaySource {
    client: reqwest::Client,
    url: reqwest::Url,
    token: reqwest::header::HeaderValue,
}

#[cfg(feature = "recovery-cli")]
impl RelaySource {
    pub fn new(url: &str, token: &[u8]) -> Result<Self, &'static str> {
        use reqwest::{header::HeaderValue, redirect::Policy, Url};
        use zeroize::Zeroizing;
        let url = Url::parse(url).map_err(|_| "invalid relay URL")?;
        if url.scheme() != "https"
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("relay requires a credential-free HTTPS URL");
        }
        let token = token
            .strip_suffix(b"\r\n")
            .or_else(|| token.strip_suffix(b"\n"))
            .unwrap_or(token);
        if !(32..=128).contains(&token.len()) || !token.iter().all(u8::is_ascii_alphanumeric) {
            return Err("invalid relay token file");
        }
        let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
        bearer.extend_from_slice(token);
        let mut token = HeaderValue::from_bytes(&bearer).map_err(|_| "invalid relay token file")?;
        token.set_sensitive(true);
        let client = reqwest::Client::builder()
            .user_agent(concat!("velmora-recover/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .redirect(Policy::none())
            .no_proxy()
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| "could not initialize HTTPS relay client")?;
        Ok(Self { client, url, token })
    }
}

#[cfg(feature = "recovery-cli")]
impl BodySource for RelaySource {
    async fn body(&mut self, id: &str) -> Result<Vec<u8>, FetchError> {
        if !valid_message_id(id) {
            return Err(FetchError::Unavailable);
        }
        let mut response = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::AUTHORIZATION, self.token.clone())
            .body(format!("BODY <{id}>\r\n"))
            .send()
            .await
            .map_err(|_| FetchError::Unavailable)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            return Err(FetchError::Unavailable);
        }
        let mut out = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FetchError::Unavailable)?
        {
            if chunk.len() > MAX_BODY_BYTES - out.len() {
                return Err(FetchError::Unavailable);
            }
            out.extend_from_slice(&chunk);
        }
        // The relay returns exactly NntpClient::body_to bytes: the server's
        // already de-stuffed BODY, without the status line or terminator.
        // In particular, a line containing only '.' is now a payload byte.
        Ok(out)
    }
}

#[cfg(all(test, feature = "recovery-cli"))]
mod relay_tests {
    use super::*;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
    };

    #[tokio::test]
    async fn relay_preserves_a_single_dot_in_the_yenc_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            let mut len = None;
            loop {
                line.clear();
                assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        len = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
            }
            let mut command = vec![0; len.unwrap()];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(command, b"BODY <leading-dot@example.invalid>\r\n");
            let body = b"=ybegin line=128 size=1 name=opaque.bin\r\n.\r\n=yend size=1\r\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        // Local fixture only; the real constructor always requires HTTPS.
        let mut relay = RelaySource {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(TIMEOUT)
                .build()
                .unwrap(),
            url: reqwest::Url::parse(&format!("http://{addr}/")).unwrap(),
            token: reqwest::header::HeaderValue::from_static("Bearer fixture"),
        };
        let article = Article {
            message_id: "leading-dot@example.invalid".into(),
            sha256: sha256(&[4]),
            yenc_name: Some("opaque.bin".into()),
            newsgroup: "alt.test".into(),
        };
        let place = Placement {
            offset: 0,
            len: 1,
            total: 1,
            number: 1,
            parity: false,
        };
        assert_eq!(relay.candidate(&article, place).await.unwrap(), [4]);
        server.await.unwrap();
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
struct Span {
    size: u64,
    offset: u64,
    len: usize,
}

pub struct Downloads {
    files: BTreeMap<u64, Vec<PathBuf>>,
    scanned: BTreeSet<Span>,
    indices: BTreeMap<(Span, [u8; 32]), PathBuf>,
}

impl Downloads {
    pub fn open(root: &Path) -> io::Result<Self> {
        if !fs::symlink_metadata(root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "download input is not a directory",
            ));
        }
        let mut files: BTreeMap<u64, Vec<PathBuf>> = BTreeMap::new();
        let mut entries = 0;
        let mut todo = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = todo.pop() {
            for entry in fs::read_dir(dir)? {
                entries += 1;
                if entries > 1_000_000 || depth > 32 {
                    return Err(io::Error::other("download directory exceeds scan limits"));
                }
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    todo.push((entry.path(), depth + 1));
                }
                if kind.is_file() {
                    files
                        .entry(entry.metadata()?.len())
                        .or_default()
                        .push(entry.path());
                }
            }
        }
        Ok(Self {
            files,
            scanned: BTreeSet::new(),
            indices: BTreeMap::new(),
        })
    }

    fn read(path: &Path, span: Span) -> io::Result<Vec<u8>> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.len() != span.size {
            return Err(io::Error::other(
                "download no longer matches its indexed size",
            ));
        }
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(span.offset))?;
        let mut bytes = vec![0; span.len];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn find(&mut self, span: Span, article: &Article) -> Option<Vec<u8>> {
        let paths = self.files.get(&span.size)?;
        if let Some(name) = &article.yenc_name {
            for path in paths
                .iter()
                .filter(|path| path.file_name().is_some_and(|f| f == name.as_str()))
            {
                if let Ok(bytes) = Self::read(path, span) {
                    if sha256(&bytes) == article.sha256 {
                        return Some(bytes);
                    }
                }
            }
        }
        if self.scanned.insert(span) {
            for path in paths {
                if let Ok(bytes) = Self::read(path, span) {
                    self.indices
                        .entry((span, sha256(&bytes)))
                        .or_insert_with(|| path.clone());
                }
            }
        }
        Self::read(self.indices.get(&(span, article.sha256))?, span).ok()
    }
}

impl BodySource for Downloads {
    fn attempts(&self) -> usize {
        1
    }
    async fn body(&mut self, _: &str) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Unavailable)
    }
    async fn candidate(
        &mut self,
        article: &Article,
        place: Placement,
    ) -> Result<Vec<u8>, FetchError> {
        let result = self
            .find(
                Span {
                    size: place.len as u64,
                    offset: 0,
                    len: place.len,
                },
                article,
            )
            .or_else(|| {
                (article.yenc_name.is_none() && !place.parity && place.total != place.len as u64)
                    .then(|| {
                        self.find(
                            Span {
                                size: place.total,
                                offset: place.offset,
                                len: place.len,
                            },
                            article,
                        )
                    })
                    .flatten()
            });
        result.ok_or(FetchError::Unavailable)
    }
}
