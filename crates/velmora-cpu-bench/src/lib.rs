//! CPU benchmark of the bridge's hot paths.
//!
//! Every stage here calls the code the Worker runs: `seal_extent`, the
//! article renderer of the post stage, `NntpClient::post_article` and
//! `body_to`, the payload checks of the verify stage and of a cold read,
//! and `open_range`. The crate builds as a plain `wasm32-unknown-unknown`
//! module with the release profile of the Worker and is timed under node
//! by `run.mjs` (V8, the engine Workers run on). `README.md` has the
//! commands and the measured numbers.
//!
//! The network is replaced by [`Mem`], an in-memory [`Transport`]. Its
//! `read` hands bytes over the way `worker::Socket` (worker 0.8.7) does:
//! the runtime delivers a chunk, the chunk is copied into a `Vec`, the
//! caller's buffer takes what fits and the rest is split off into a new
//! `Vec` for the next call. `write_all` copies the bytes once, as the
//! socket does into a `Uint8Array`. No TLS is involved: the in-Worker TLS
//! of a proxied provider is not part of this benchmark.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::FillRandom;
use velmora::transport::Transport;
use velmora_bridge::crypto::{open_range, seal_extent, DataKey, SealedExtent};
use velmora_bridge::fetch::{bench_check_payload, bench_place_payload};
use velmora_bridge::plan::plan_seeded;
use velmora_bridge::post::bench_render_article;
use velmora_bridge::{ArticleRow, BucketId, ExtentId, ExtentRow, ExtentState, SafetyState, UnixMs};

/// A fixed xorshift stream. The benchmark needs the same bytes on every
/// run, not secrecy: nothing sealed here leaves the process.
pub struct FixedRng(u64);

impl FillRandom for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::error::Result<()> {
        for b in dest {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = (self.0 >> 32) as u8;
        }
        Ok(())
    }
}

/// Runs a future that never waits: every [`Mem`] operation is ready at
/// once.
fn now<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("the in-memory transport never waits"),
    }
}

/// In-memory transport; see the crate documentation.
pub struct Mem<'a> {
    script: &'a [u8],
    chunk: usize,
    held: Vec<u8>,
    sent: Vec<u8>,
    sent_total: usize,
}

impl<'a> Mem<'a> {
    /// `script` is everything the server will say, delivered `chunk`
    /// bytes at a time.
    pub fn new(script: &'a [u8], chunk: usize) -> Self {
        Mem {
            script,
            chunk: chunk.max(1),
            held: Vec::new(),
            sent: Vec::new(),
            sent_total: 0,
        }
    }
}

impl Transport for Mem<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut data = match self.held.is_empty() {
            false => std::mem::take(&mut self.held),
            true => {
                let n = self.chunk.min(self.script.len());
                let (head, rest) = self.script.split_at(n);
                self.script = rest;
                head.to_vec()
            }
        };
        let n = buf.len().min(data.len());
        self.held = data.split_off(n);
        buf[..n].copy_from_slice(&data);
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.sent.clear();
        self.sent.extend_from_slice(buf);
        self.sent_total += buf.len();
        Ok(())
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn config() -> NntpConfig {
    NntpConfig {
        host: "bench.invalid".into(),
        port: 563,
        tls: true,
        allow_insecure_plaintext: false,
        username: None,
        password: None,
        timeout: Duration::from_secs(30),
        max_pipelined: 1,
        max_article_bytes: velmora::transport::MAX_ARTICLE_BYTES,
    }
}

const GREETING: &[u8] = b"200 bench\r\n200 reader\r\n";

/// One sealed extent with its plan, its rendered articles and what a
/// server would send back for each of them.
pub struct Bench {
    bdk: DataKey,
    bucket: BucketId,
    plain: Vec<u8>,
    sealed: SealedExtent,
    extent: ExtentRow,
    rows: Vec<ArticleRow>,
    /// The article of each row, as the post stage renders it.
    articles: Vec<Vec<u8>>,
    /// The body of each article as a `BODY` reply holds it after
    /// dot-unstuffing: what the payload check decodes.
    bodies: Vec<Vec<u8>>,
    /// Everything a server says while every article is posted.
    post_script: Vec<u8>,
    /// Everything a server says while every article is read with `BODY`.
    body_script: Vec<u8>,
}

fn dot_stuff(body: &[u8], out: &mut Vec<u8>) {
    for line in body.split_inclusive(|&b| b == b'\n') {
        if line.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(line);
    }
}

impl Bench {
    pub fn new(plain_len: usize) -> Self {
        let mut rng = FixedRng(0x9E37_79B9_7F4A_7C15);
        let mut plain = vec![0u8; plain_len];
        rng.fill_bytes(&mut plain).unwrap();
        let bdk = DataKey::from_bytes([7u8; 32]);
        let bucket = BucketId::mint([1; 8]);
        let id = ExtentId::mint([2; 13]);
        let sealed = seal_extent(&bdk, &bucket, &id, &plain, &mut rng).unwrap();
        let cipher = &sealed.ciphertext;
        let cipher_size = cipher.len() as u64;
        let (_, rows) = plan_seeded(
            &mut rng,
            1_800_000_000,
            &["alt.binaries.test"],
            &id,
            cipher_size,
            |span| {
                let payload = &cipher[span.start as usize..(span.start + span.len) as usize];
                Some(velmora_bridge::post::bench_sha256(payload))
            },
        )
        .unwrap();
        let extent = ExtentRow {
            id,
            bucket_id: bucket.clone(),
            generation_id: None,
            state: ExtentState::Committed,
            seq: Some(0),
            plain_offset: Some(0),
            plain_size: plain.len() as u64,
            cipher_size,
            media_header: sealed.media_header.to_vec(),
            // A random file key, as `PutObject` stores it.
            key_mode: 1,
            wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
            plain_md5: sealed.plain_md5,
            plain_sha256: sealed.plain_sha256,
            cipher_sha256: sealed.cipher_sha256,
            safety_state: SafetyState::Held,
            article_count: Some(rows.len() as u32),
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: UnixMs(0),
        };
        let total = rows.len() as u32;
        let mut articles = Vec::new();
        let mut bodies = Vec::new();
        let mut post_script = GREETING.to_vec();
        let mut body_script = GREETING.to_vec();
        for row in &rows {
            let payload = payload_of(cipher, row);
            let article = bench_render_article(row, total, cipher_size, payload).unwrap();
            let at = article.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let body = article[at..].to_vec();
            post_script.extend_from_slice(b"340 send\r\n240 posted\r\n");
            body_script
                .extend_from_slice(format!("222 0 <{}> body\r\n", row.message_id).as_bytes());
            dot_stuff(&body, &mut body_script);
            body_script.extend_from_slice(b".\r\n");
            articles.push(article);
            bodies.push(body);
        }
        Bench {
            bdk,
            bucket,
            plain,
            sealed,
            extent,
            rows,
            articles,
            bodies,
            post_script,
            body_script,
        }
    }

    pub fn plain_len(&self) -> usize {
        self.plain.len()
    }

    pub fn article_count(&self) -> usize {
        self.rows.len()
    }

    fn cipher(&self) -> &[u8] {
        &self.sealed.ciphertext
    }

    // -- ingest ------------------------------------------------------------

    /// What a `PutObject` or an `UploadPart` does to its body: seal it and
    /// hash it (`seal_extent`). Returns a byte of the result so that the
    /// work is used.
    pub fn ingest(&self) -> u8 {
        let mut rng = FixedRng(1);
        let id = ExtentId::mint([3; 13]);
        let sealed = seal_extent(&self.bdk, &self.bucket, &id, &self.plain, &mut rng).unwrap();
        sealed.cipher_sha256[0] ^ sealed.plain_md5[0] ^ sealed.plain_sha256[0]
    }

    // -- post --------------------------------------------------------------

    /// The check of the loaded ciphertext before anything is posted.
    pub fn post_load_check(&self) -> bool {
        velmora_bridge::post::bench_sha256(self.cipher()) == self.extent.cipher_sha256
    }

    /// The check of each article's payload before it is rendered.
    pub fn post_payload_check(&self) -> bool {
        self.rows.iter().all(|row| {
            velmora_bridge::post::bench_sha256(payload_of(self.cipher(), row)) == row.payload_sha256
        })
    }

    /// Renders every article: yEnc with its CRC-32, under the stored
    /// headers.
    pub fn post_render(&self) -> usize {
        let total = self.rows.len() as u32;
        self.rows
            .iter()
            .map(|row| {
                let payload = payload_of(self.cipher(), row);
                bench_render_article(row, total, self.extent.cipher_size, payload)
                    .unwrap()
                    .len()
            })
            .sum()
    }

    /// Sends every rendered article with `POST`: framing check,
    /// dot-stuffing, one write.
    pub fn post_send(&self, chunk: usize) -> usize {
        now(async {
            let mem = Mem::new(&self.post_script, chunk);
            let mut client = NntpClient::connect(mem, &config()).await.unwrap();
            for (row, article) in self.rows.iter().zip(&self.articles) {
                let out = client.post_article(&row.message_id, article).await.unwrap();
                assert!(matches!(out, PostOutcome::Posted));
            }
            self.articles.len()
        })
    }

    /// The whole post stage for the extent, as `post_extent` runs it:
    /// load check, then per article payload check, render and `POST`.
    pub fn post(&self, chunk: usize) -> usize {
        assert!(self.post_load_check());
        let total = self.rows.len() as u32;
        now(async {
            let mem = Mem::new(&self.post_script, chunk);
            let mut client = NntpClient::connect(mem, &config()).await.unwrap();
            let mut sent = 0;
            for row in &self.rows {
                let payload = payload_of(self.cipher(), row);
                assert!(velmora_bridge::post::bench_sha256(payload) == row.payload_sha256);
                let article =
                    bench_render_article(row, total, self.extent.cipher_size, payload).unwrap();
                let out = client
                    .post_article(&row.message_id, &article)
                    .await
                    .unwrap();
                assert!(matches!(out, PostOutcome::Posted));
                sent += article.len();
            }
            sent
        })
    }

    // -- verify ------------------------------------------------------------

    /// Reads every article with `BODY` and drops it: the socket hand-over,
    /// the line framing and the dot-unstuffing, without decode or check.
    pub fn verify_read(&self, chunk: usize) -> usize {
        now(async {
            let mem = Mem::new(&self.body_script, chunk);
            let mut client = NntpClient::connect(mem, &config()).await.unwrap();
            let mut wire = Vec::new();
            let mut read = 0;
            for row in &self.rows {
                wire.clear();
                client.body_to(&row.message_id, &mut wire).await.unwrap();
                read += wire.len();
            }
            read
        })
    }

    /// Decodes and checks every `BODY` reply already in memory: yEnc
    /// decode with CRC-32, then SHA-256 against the plan.
    pub fn verify_check(&self) -> usize {
        self.rows
            .iter()
            .zip(&self.bodies)
            .map(|(row, body)| bench_check_payload(row, body).unwrap().len())
            .sum()
    }

    /// The whole verify of the extent on one backbone: `BODY`, decode,
    /// check.
    pub fn verify(&self, chunk: usize) -> usize {
        now(async {
            let mem = Mem::new(&self.body_script, chunk);
            let mut client = NntpClient::connect(mem, &config()).await.unwrap();
            let mut wire = Vec::new();
            let mut good = 0;
            for row in &self.rows {
                wire.clear();
                client.body_to(&row.message_id, &mut wire).await.unwrap();
                good += bench_check_payload(row, &wire).unwrap().len();
            }
            good
        })
    }

    // -- cold read ---------------------------------------------------------

    /// Fetches the extent from Usenet as a cold read does: `BODY`, decode
    /// into place and check per article, then the check of the whole
    /// ciphertext.
    pub fn cold_fetch(&self, chunk: usize) -> Vec<u8> {
        let mut cipher = vec![0u8; self.cipher().len()];
        now(async {
            let mem = Mem::new(&self.body_script, chunk);
            let mut client = NntpClient::connect(mem, &config()).await.unwrap();
            let mut wire = Vec::new();
            for row in &self.rows {
                wire.clear();
                client.body_to(&row.message_id, &mut wire).await.unwrap();
                let start = row.cipher_offset as usize;
                let place = &mut cipher[start..start + row.cipher_len as usize];
                assert!(bench_place_payload(row, &wire, place));
            }
        });
        assert!(velmora_bridge::post::bench_sha256(&cipher) == self.extent.cipher_sha256);
        cipher
    }

    /// Decrypts the whole extent (`open_range`), as a GET of all of it
    /// does.
    pub fn open(&self, cipher: &[u8]) -> Vec<u8> {
        let mut plain = vec![0u8; self.plain.len()];
        let n = open_range(
            &self.bdk,
            &self.bucket,
            &self.extent,
            0,
            cipher,
            0,
            &mut plain,
        )
        .unwrap();
        assert_eq!(n, plain.len());
        plain
    }

    /// A cold read of the whole extent: fetch, then decrypt.
    pub fn cold(&self, chunk: usize) -> u8 {
        let cipher = self.cold_fetch(chunk);
        let plain = self.open(&cipher);
        plain[plain.len() / 2]
    }

    /// The decrypt half of [`Self::cold`] on its own (also what a read
    /// from the cache costs).
    pub fn cold_open(&self) -> u8 {
        let plain = self.open(self.cipher());
        plain[plain.len() / 2]
    }
}

/// The self-check answer every build must give: native, scalar wasm and
/// `simd128` wasm. It is the first four bytes of the digest
/// [`fingerprint`] draws. `run.mjs` refuses to time a module that
/// answers anything else, so a fast path that changes one output byte
/// cannot be measured as a saving.
pub const FINGERPRINT: u32 = 0x9698_af48;

/// A digest over every byte the hot paths produce for one fixed extent:
/// the sealed ciphertext and its hashes, each rendered article, the
/// ciphertext read back through `BODY` in several chunkings, the opened
/// plaintext, and what the decoder answers to a few thousand hostile
/// articles. Panics if the fast yEnc encoder and the reference
/// encoder (`encode_body`, byte at a time) ever differ, or if SHA-256
/// misses its known answer.
pub fn fingerprint() -> u32 {
    use velmora::yenc::{encode_body, encode_body_vec};
    use velmora_bridge::post::bench_sha256 as sha256;

    // FIPS 180-4, "abc"; then a length that takes the multi-block path.
    assert_eq!(
        sha256(b"abc")[..4],
        [0xba, 0x78, 0x16, 0xbf],
        "SHA-256 known answer"
    );
    // Three articles, the last one short.
    let bench = Bench::new(1_700_000);
    let mut all = Vec::new();
    all.extend_from_slice(bench.cipher());
    all.extend_from_slice(&bench.sealed.cipher_sha256);
    all.extend_from_slice(&bench.sealed.plain_sha256);
    all.extend_from_slice(&bench.sealed.plain_md5);
    for (row, article) in bench.rows.iter().zip(&bench.articles) {
        let payload = payload_of(bench.cipher(), row);
        assert_eq!(sha256(payload), row.payload_sha256);
        let (mut fast, mut reference) = (Vec::new(), Vec::new());
        let crc = encode_body_vec(&mut fast, payload);
        assert_eq!(encode_body(&mut reference, payload).unwrap(), crc);
        assert!(fast == reference, "yEnc encoders differ");
        all.extend_from_slice(article);
    }
    // Lengths around the 16-byte lanes and the 128-column lines, on the
    // bytes that are escaped as well as on random ones.
    let mut rng = FixedRng(3);
    for len in (0..400).chain([4095, 4096, 4097, 8191, 70_001]) {
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data).unwrap();
        for dense in [false, true] {
            if dense {
                for b in data.iter_mut().step_by(3) {
                    *b = [214, 224, 227, 19][usize::from(*b) % 4];
                }
            }
            let (mut fast, mut reference) = (Vec::new(), Vec::new());
            let crc = encode_body_vec(&mut fast, &data);
            assert_eq!(encode_body(&mut reference, &data).unwrap(), crc);
            assert!(fast == reference, "yEnc encoders differ at {len} bytes");
            all.extend_from_slice(&fast);
        }
    }
    // The decoder on hostile input: lines dense in `=` (an escape at the
    // end of a line, at every lane offset), destinations shorter and
    // longer than the declared size. The answer (bytes written or the
    // refusal) and the whole destination, including what lies past the
    // decoded bytes, go into the digest, so every build must agree on
    // them with the native one.
    let mut rng = FixedRng(5);
    let mut roll = move || {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b).unwrap();
        u32::from_le_bytes(b) as usize
    };
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..3000 {
        let mut body = Vec::new();
        let mut decoded = 0usize;
        for _ in 0..roll() % 5 {
            let len = roll() % 150;
            let line_at = body.len();
            let mut i = 0;
            while i < len {
                let r = roll();
                let b = match r % 9 {
                    0 | 1 => b'=',
                    2 => b'}',
                    _ => match (r >> 8) as u8 {
                        b'\n' | b'\r' => b'x',
                        b => b,
                    },
                };
                // No `=y` at the start of a line: that is a keyword line.
                body.push(if i == 1 && b == b'y' { b'z' } else { b });
                i += 1;
            }
            // What the line decodes to when it is well formed: an escape
            // pair is one byte.
            let mut at = line_at;
            while at < body.len() {
                at += if body[at] == b'=' { 2 } else { 1 };
                decoded += 1;
            }
            body.extend_from_slice(b"\r\n");
        }
        // Half declare the true size, so that accepted parts occur too.
        let declared = match roll() % 2 {
            0 => decoded,
            _ => decoded.saturating_sub(roll() % 40),
        };
        let dst_len = (declared + 16).saturating_sub(roll() % 33);
        let mut article = format!("=ybegin line=128 size={declared} name=t\r\n").into_bytes();
        article.extend_from_slice(&body);
        article.extend_from_slice(b"=yend\r\n");
        let mut dst = vec![0xA5u8; dst_len];
        match velmora::yenc::decode_part_to("<m@x>", &article, &mut dst) {
            Ok(part) => {
                accepted += 1;
                all.extend_from_slice(&(part.written as u64).to_be_bytes());
            }
            Err(err) => {
                refused += 1;
                all.extend_from_slice(err.to_string().as_bytes());
            }
        }
        all.extend_from_slice(&dst);
    }
    assert!(
        accepted > 200 && refused > 200,
        "{accepted} accepted, {refused} refused"
    );
    for chunk in [1, 7, 4096, 65536] {
        let cipher = bench.cold_fetch(chunk);
        assert!(cipher == bench.cipher(), "read back differs");
        assert!(
            bench.open(&cipher) == bench.plain,
            "opened plaintext differs"
        );
    }
    let d = sha256(&all);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

fn payload_of<'a>(cipher: &'a [u8], row: &ArticleRow) -> &'a [u8] {
    let start = row.cipher_offset as usize;
    &cipher[start..start + row.cipher_len as usize]
}

// ---------------------------------------------------------------------------
// The wasm exports `run.mjs` calls. One module holds one `Bench`.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
mod exports {
    use super::Bench;
    use std::cell::RefCell;

    thread_local! {
        static BENCH: RefCell<Option<Bench>> = const { RefCell::new(None) };
    }

    fn with<R>(f: impl FnOnce(&Bench) -> R) -> R {
        BENCH.with(|b| f(b.borrow().as_ref().expect("call setup first")))
    }

    /// Builds the extent: `plain_len` bytes. Returns its article count.
    #[no_mangle]
    pub extern "C" fn setup(plain_len: u32) -> u32 {
        let bench = Bench::new(plain_len as usize);
        let n = bench.article_count() as u32;
        BENCH.with(|b| *b.borrow_mut() = Some(bench));
        n
    }

    /// 1 when this build's outputs carry the pinned fingerprint.
    #[no_mangle]
    pub extern "C" fn selfcheck() -> u32 {
        (super::fingerprint() == super::FINGERPRINT) as u32
    }

    /// 1 when this module was built with `simd128`.
    #[no_mangle]
    pub extern "C" fn simd128() -> u32 {
        cfg!(target_feature = "simd128") as u32
    }

    #[no_mangle]
    pub extern "C" fn ingest() -> u32 {
        with(|b| b.ingest() as u32)
    }

    #[no_mangle]
    pub extern "C" fn post_load_check() -> u32 {
        with(|b| b.post_load_check() as u32)
    }

    #[no_mangle]
    pub extern "C" fn post_payload_check() -> u32 {
        with(|b| b.post_payload_check() as u32)
    }

    #[no_mangle]
    pub extern "C" fn post_render() -> u32 {
        with(|b| b.post_render() as u32)
    }

    #[no_mangle]
    pub extern "C" fn post_send(chunk: u32) -> u32 {
        with(|b| b.post_send(chunk as usize) as u32)
    }

    #[no_mangle]
    pub extern "C" fn post(chunk: u32) -> u32 {
        with(|b| b.post(chunk as usize) as u32)
    }

    #[no_mangle]
    pub extern "C" fn verify_read(chunk: u32) -> u32 {
        with(|b| b.verify_read(chunk as usize) as u32)
    }

    #[no_mangle]
    pub extern "C" fn verify_check() -> u32 {
        with(|b| b.verify_check() as u32)
    }

    #[no_mangle]
    pub extern "C" fn verify(chunk: u32) -> u32 {
        with(|b| b.verify(chunk as usize) as u32)
    }

    #[no_mangle]
    pub extern "C" fn cold(chunk: u32) -> u32 {
        with(|b| b.cold(chunk as usize) as u32)
    }

    #[no_mangle]
    pub extern "C" fn cold_open() -> u32 {
        with(|b| b.cold_open() as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned answer of the self-check. The wasm builds must give the
    /// same one (`run.mjs` checks before it times anything).
    #[test]
    fn fingerprint_is_pinned() {
        assert_eq!(fingerprint(), FINGERPRINT, "{:#010x}", fingerprint());
    }

    /// Every stage runs and agrees with the others: what is posted is
    /// what is read back, and what is read back opens to the plaintext.
    #[test]
    fn every_stage_runs_and_round_trips() {
        // Three articles, the last one short.
        let bench = Bench::new(1_700_000);
        assert_eq!(bench.article_count(), 3);
        bench.ingest();
        assert!(bench.post_load_check());
        assert!(bench.post_payload_check());
        let rendered: usize = bench.articles.iter().map(Vec::len).sum();
        assert_eq!(bench.post_render(), rendered);
        assert_eq!(bench.post_send(4096), 3);
        assert_eq!(bench.post(65536), rendered);
        for chunk in [1, 7, 4096, 65536, usize::MAX] {
            let read = bench.verify_read(chunk);
            assert_eq!(read, bench.bodies.iter().map(Vec::len).sum::<usize>());
            assert_eq!(bench.verify(chunk), bench.cipher().len());
            let cipher = bench.cold_fetch(chunk);
            assert_eq!(cipher, bench.cipher());
            assert_eq!(bench.open(&cipher), bench.plain);
        }
        assert_eq!(bench.verify_check(), bench.cipher().len());
        bench.cold_open();
    }
}
