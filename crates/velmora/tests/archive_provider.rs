#![cfg(feature = "archive-provider")]

#[path = "archive_provider/client.rs"]
mod client;

use std::{cell::Cell, collections::BTreeMap, rc::Rc};
use velmora::archive::v1::{nntp, s3, *};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn generated(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| (index.wrapping_mul(73) % 251) as u8)
        .collect()
}

fn intent(backend: Backend, sizes: &[usize]) -> (WriteIntent, Vec<u8>) {
    let bytes = generated(sizes.iter().sum());
    let mut offset = 0;
    let parts = sizes
        .iter()
        .enumerate()
        .map(|(index, &size)| {
            let part = Part {
                offset: offset as u64,
                bytes: size as u32,
                sha256: digest(&bytes[offset..offset + size]),
                reference: id(&format!("part{index}@synthetic.invalid")),
            };
            offset += size;
            part
        })
        .collect();
    (
        WriteIntent {
            target: Target {
                tenant: id("tenant-a"),
                backend,
                account: id("account-a"),
                locator: id("immutable/allocation-a"),
                generation: id("generation-a"),
                encryption: EncryptionIdentity {
                    format: id("velmora.media.v1"),
                    mode: 1,
                    key_epoch: id("epoch-a"),
                    envelope: id("envelope-a"),
                },
            },
            operation: id("operation-a"),
            bytes: bytes.len() as u64,
            sha256: digest(&bytes),
            parts,
        },
        bytes,
    )
}

struct Authority {
    tenant: Id,
    state: Rc<Cell<Option<Failure>>>,
}
impl Authority {
    fn new() -> Self {
        Self {
            tenant: id("tenant-a"),
            state: Rc::new(Cell::new(None)),
        }
    }
}
impl Control for Authority {
    fn check(&self, target: &Target, _: Action) -> Result<()> {
        if self.tenant != target.tenant {
            return Err(Failure::Denied);
        }
        self.state.get().map_or(Ok(()), Err)
    }
}

#[derive(Default)]
struct Output(Vec<u8>);
impl Sink for Output {
    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        assert!(bytes.len() <= STREAM_BLOCK_BYTES);
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default)]
struct ObjectStore {
    calls: usize,
    binding: Option<[u8; 32]>,
    parts: BTreeMap<usize, Vec<u8>>,
    complete: Option<(s3::Metadata, Vec<u8>)>,
    lost_part: bool,
    lost_complete: bool,
    bad_range: bool,
    corrupt: bool,
    after_complete: Option<Rc<Cell<Option<Failure>>>>,
}
impl s3::SafeTransport for ObjectStore {
    async fn begin(
        &mut self,
        _: &s3::Config,
        intent: &WriteIntent,
        _: &impl Control,
    ) -> Result<Id> {
        self.calls += 1;
        let binding = intent.binding()?;
        if self.binding.is_some_and(|old| old != binding) {
            return Err(Failure::Conflict);
        }
        self.binding = Some(binding);
        Ok(id("upload-a"))
    }
    async fn upload_part(
        &mut self,
        _: &s3::Config,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        _: &impl Control,
    ) -> Result<s3::PartAck> {
        self.calls += 1;
        if self.binding != Some(session.intent.binding()?) {
            return Err(Failure::Conflict);
        }
        self.parts.insert(index, bytes.to_vec());
        if std::mem::take(&mut self.lost_part) {
            return Err(Failure::Uncertain);
        }
        Ok(s3::PartAck {
            etag: id(&format!("opaque-etag-{index}")),
            sha256: digest(bytes),
        })
    }
    async fn complete(
        &mut self,
        _: &s3::Config,
        session: &WriteSession,
        receipts: &[PartReceipt],
        _: &impl Control,
    ) -> Result<s3::Metadata> {
        self.calls += 1;
        if let Some((metadata, _)) = &self.complete {
            return Ok(metadata.clone());
        }
        if receipts.len() != self.parts.len() {
            return Err(Failure::Conflict);
        }
        let bytes: Vec<u8> = self.parts.values().flatten().copied().collect();
        let metadata = s3::Metadata {
            version: id("immutable-version-a"),
            bytes: bytes.len() as u64,
            intent_binding: session.intent.binding()?,
            // Deliberately NOT a full SHA-256. The adapter must read all bytes.
            checksum: s3::ProviderChecksum::CompositeSha256,
        };
        self.complete = Some((metadata.clone(), bytes));
        if let Some(state) = &self.after_complete {
            state.set(Some(Failure::Cancelled));
        }
        if std::mem::take(&mut self.lost_complete) {
            return Err(Failure::Uncertain);
        }
        Ok(metadata)
    }
    async fn abort_incomplete(
        &mut self,
        _: &s3::Config,
        _: &WriteSession,
        _: &impl Control,
    ) -> Result<AbortOutcome> {
        self.calls += 1;
        if self.complete.is_some() {
            return Ok(AbortOutcome::Irreversible);
        }
        self.parts.clear();
        Ok(AbortOutcome::IncompleteRemoved)
    }
    async fn head(
        &mut self,
        _: &s3::Config,
        _: &WriteIntent,
        version: &Id,
        _: &impl Control,
    ) -> Result<s3::Metadata> {
        self.calls += 1;
        let metadata = &self.complete.as_ref().ok_or(Failure::Missing)?.0;
        if version != &metadata.version {
            return Err(Failure::Missing);
        }
        Ok(metadata.clone())
    }
    async fn get_range(
        &mut self,
        _: &s3::Config,
        record: &ObjectRecord,
        range: Range,
        out: &mut [u8],
        _: &impl Control,
    ) -> Result<s3::RangeReply> {
        self.calls += 1;
        let (metadata, bytes) = self.complete.as_ref().ok_or(Failure::Missing)?;
        if record.identity.version != metadata.version {
            return Err(Failure::Missing);
        }
        let end = range.end(bytes.len() as u64)? as usize;
        out.copy_from_slice(&bytes[range.offset as usize..end]);
        if self.corrupt && !out.is_empty() {
            out[0] ^= 1;
        }
        Ok(s3::RangeReply {
            bytes: out.len() + usize::from(self.bad_range),
            offset: range.offset,
            total: bytes.len() as u64,
            version: metadata.version.clone(),
        })
    }
    async fn reconcile(
        &mut self,
        _: &s3::Config,
        _: &WriteSession,
        _: &impl Control,
    ) -> Result<Option<s3::Metadata>> {
        self.calls += 1;
        // All this fake's requests settle synchronously before returning.
        Ok(self.complete.as_ref().map(|(metadata, _)| metadata.clone()))
    }
    async fn health(&mut self, _: &s3::Config, _: &Target, _: &impl Control) -> Result<Health> {
        self.calls += 1;
        Ok(Health::Available)
    }
}

fn config() -> s3::Config {
    s3::Config {
        enabled: true,
        account: id("account-a"),
        host: id("archive.example.com"),
        region: id("test-region"),
        bucket: id("synthetic-bucket"),
        credential_ref: id("native/archive-account"),
    }
}

async fn upload<P: ArchiveProvider>(
    provider: &mut P,
    intent: &WriteIntent,
    bytes: &[u8],
    control: &impl Control,
) -> (WriteSession, Vec<PartReceipt>) {
    let session = provider.begin(intent, control).await.unwrap();
    let mut receipts = Vec::new();
    for (index, part) in intent.parts.iter().enumerate() {
        let start = part.offset as usize;
        receipts.push(
            provider
                .write_part(
                    &session,
                    index,
                    &bytes[start..start + part.bytes as usize],
                    control,
                )
                .await
                .unwrap(),
        );
    }
    (session, receipts)
}

#[test]
fn cache_identity_separates_every_storage_and_crypto_coordinate() {
    let (intent, _) = intent(Backend::S3, &[17]);
    let identity = ObjectIdentity {
        target: intent.target,
        version: id("version-a"),
        bytes: 17,
        sha256: intent.sha256,
    };
    let mut variants = vec![identity.clone(); 11];
    variants[0].target.tenant = id("tenant-b");
    variants[1].target.backend = Backend::Nntp;
    variants[2].target.account = id("account-b");
    variants[3].target.locator = id("other/allocation");
    variants[4].target.generation = id("generation-b");
    variants[5].version = id("version-b");
    variants[6].target.encryption.format = id("other-format");
    variants[7].target.encryption.mode = 2;
    variants[8].target.encryption.key_epoch = id("epoch-b");
    variants[9].target.encryption.envelope = id("envelope-b");
    variants[10].sha256[0] ^= 1;
    for variant in variants {
        assert_ne!(identity.cache_key(), variant.cache_key());
    }
    assert!(!format!("{identity:?}").contains("tenant-a"));
}

#[test]
fn manifests_reject_gaps_overflow_duplicate_parts_and_unbounded_inputs() {
    let (original, _) = intent(Backend::S3, &[10, 10]);
    for mutate in [0, 1, 2, 3] {
        let mut bad = original.clone();
        match mutate {
            0 => bad.parts[1].offset += 1,
            1 => bad.parts[1].reference = bad.parts[0].reference.clone(),
            2 => bad.parts[0].bytes = MAX_PART_BYTES as u32 + 1,
            _ => bad.bytes = u64::MAX,
        }
        assert!(bad.validate().is_err());
    }
    assert_eq!(
        Range {
            offset: u64::MAX,
            bytes: 2
        }
        .end(u64::MAX),
        Err(Failure::Invalid)
    );
    assert!(Id::new("a\r\nb").is_err());
    assert!(serde_json::from_str::<Id>("\"\"").is_err());
}

#[test]
fn s3_missing_disabled_and_unsafe_config_fails_closed_without_io() {
    assert!(matches!(
        s3::Provider::new(None, ObjectStore::default()),
        Err(Failure::Configuration)
    ));
    let mut disabled = config();
    disabled.enabled = false;
    assert!(matches!(
        s3::Provider::new(Some(disabled), ObjectStore::default()),
        Err(Failure::Disabled)
    ));
    for host in [
        "127.0.0.1",
        "https://archive.example.com",
        "a.local",
        "a.internal",
        "a.example.com/path",
        "a.example.com:443",
        "a.example.com.",
    ] {
        let mut bad = config();
        bad.host = id(host);
        assert!(s3::Provider::new(Some(bad), ObjectStore::default()).is_err());
    }
}

#[tokio::test]
async fn s3_multipart_commit_readback_and_cross_part_range() {
    let (intent, bytes) = intent(Backend::S3, &[s3::MIN_MULTIPART_BYTES, 917]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    let proof = provider
        .commit(&session, &receipts, &authority)
        .await
        .unwrap();
    assert!(proof.acknowledged && proof.full_ciphertext_readback);
    assert_eq!(
        provider.stat(&proof.record, &authority).await.unwrap(),
        proof.record.identity
    );
    let start = s3::MIN_MULTIPART_BYTES - 31;
    let mut output = Output::default();
    provider
        .read_range(
            &proof.record,
            Range {
                offset: start as u64,
                bytes: 97,
            },
            &mut output,
            &authority,
        )
        .await
        .unwrap();
    assert_eq!(output.0, bytes[start..start + 97]);
    assert!(!provider.capabilities().physical_delete);
    assert_eq!(
        provider.abort(&session, &authority).await.unwrap(),
        AbortOutcome::Irreversible
    );
}

#[tokio::test]
async fn s3_lost_part_retries_exact_bytes_and_lost_commit_reconciles_after_restart() {
    let (intent, bytes) = intent(Backend::S3, &[173]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(
        Some(config()),
        ObjectStore {
            lost_part: true,
            lost_complete: true,
            ..Default::default()
        },
    )
    .unwrap();
    let session = provider.begin(&intent, &authority).await.unwrap();
    assert_eq!(
        provider.write_part(&session, 0, &bytes, &authority).await,
        Err(Failure::Uncertain)
    );
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert_eq!(
        provider.write_part(&session, 0, &changed, &authority).await,
        Err(Failure::Integrity)
    );
    let receipt = provider
        .write_part(&session, 0, &bytes, &authority)
        .await
        .unwrap();
    assert_eq!(
        provider.commit(&session, &[receipt], &authority).await,
        Err(Failure::Uncertain)
    );
    let persisted = serde_json::to_vec(&session).unwrap();
    let recovered: WriteSession = serde_json::from_slice(&persisted).unwrap();
    let mut restarted = s3::Provider::new(Some(config()), provider.into_transport()).unwrap();
    let Reconciled::Verified(proof) = restarted.reconcile(&recovered, &authority).await.unwrap()
    else {
        panic!("not reconciled")
    };
    assert_eq!(proof.record.identity.sha256, digest(&bytes));
}

#[tokio::test]
async fn s3_corrupt_or_overreturned_range_releases_nothing() {
    for corrupt in [false, true] {
        let (intent, bytes) = intent(Backend::S3, &[137]);
        let authority = Authority::new();
        let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
        let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
        let proof = provider
            .commit(&session, &receipts, &authority)
            .await
            .unwrap();
        let mut transport = provider.into_transport();
        transport.corrupt = corrupt;
        transport.bad_range = !corrupt;
        let mut provider = s3::Provider::new(Some(config()), transport).unwrap();
        let mut output = Output::default();
        assert_eq!(
            provider
                .read_range(
                    &proof.record,
                    Range {
                        offset: 7,
                        bytes: 31
                    },
                    &mut output,
                    &authority
                )
                .await,
            Err(Failure::Integrity)
        );
        assert!(output.0.is_empty());
    }
}

#[tokio::test]
async fn s3_cancel_before_io_and_after_completion_are_distinct() {
    let (intent, bytes) = intent(Backend::S3, &[51]);
    let authority = Authority::new();
    authority.state.set(Some(Failure::Cancelled));
    let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
    assert_eq!(
        provider.begin(&intent, &authority).await,
        Err(Failure::Cancelled)
    );
    assert_eq!(provider.into_transport().calls, 0);
    authority.state.set(None);
    let transport = ObjectStore {
        after_complete: Some(authority.state.clone()),
        ..Default::default()
    };
    let mut provider = s3::Provider::new(Some(config()), transport).unwrap();
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    assert_eq!(
        provider.commit(&session, &receipts, &authority).await,
        Err(Failure::Uncertain)
    );
    assert!(provider.into_transport().complete.is_some());
}

#[tokio::test]
async fn s3_wrong_tenant_and_receipt_binding_are_refused_before_effect() {
    let (mut intent, bytes) = intent(Backend::S3, &[73]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
    intent.target.tenant = id("tenant-b");
    assert_eq!(
        provider.begin(&intent, &authority).await,
        Err(Failure::Denied)
    );
    intent.target.tenant = id("tenant-a");
    let (session, mut receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    receipts[0].intent_binding[0] ^= 1;
    assert_eq!(
        provider.commit(&session, &receipts, &authority).await,
        Err(Failure::Conflict)
    );
    assert!(provider.into_transport().complete.is_none());
}

#[tokio::test]
async fn s3_abort_incomplete_and_zero_length_object_have_explicit_outcomes() {
    let (intent, bytes) = intent(Backend::S3, &[0]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    assert_eq!(
        provider.abort(&session, &authority).await.unwrap(),
        AbortOutcome::IncompleteRemoved
    );
    let receipt = provider
        .write_part(&session, 0, &[], &authority)
        .await
        .unwrap();
    assert_eq!(receipts, vec![receipt.clone()]);
    let proof = provider
        .commit(&session, &[receipt], &authority)
        .await
        .unwrap();
    assert_eq!(proof.record.identity.bytes, 0);
    assert!(proof.full_ciphertext_readback);
}

#[derive(Default)]
struct Spool {
    articles: BTreeMap<String, Vec<u8>>,
    fail_after: Option<usize>,
    posts: usize,
}
impl nntp::Io for Spool {
    async fn post(
        &mut self,
        _: &Target,
        message_id: &str,
        article: &[u8],
        _: &impl Control,
    ) -> Result<()> {
        self.posts += 1;
        self.articles.insert(message_id.into(), article.to_vec());
        if self.fail_after == Some(self.posts) {
            return Err(Failure::Uncertain);
        }
        Ok(())
    }
    async fn body(&mut self, _: &Target, message_id: &str, _: &impl Control) -> Result<Vec<u8>> {
        self.articles
            .get(message_id)
            .cloned()
            .ok_or(Failure::Missing)
    }
    async fn stat(&mut self, _: &Target, message_id: &str, _: &impl Control) -> Result<()> {
        self.articles
            .contains_key(message_id)
            .then_some(())
            .ok_or(Failure::Missing)
    }
}

fn posting(intent: &WriteIntent) -> nntp::PostingPlan {
    nntp::PostingPlan {
        intent_binding: intent.binding().unwrap(),
        headers: intent
            .parts
            .iter()
            .enumerate()
            .map(|(index, part)| nntp::PostHeaders {
                message_id: part.reference.clone(),
                from: id("synthetic@synthetic.invalid"),
                subject: id(&format!("synthetic-{index}")),
                date: "Thu, 1 Jan 1970 00:00:00 +0000".into(),
                newsgroup: id("alt.test"),
                yenc_name: id(&format!("synthetic-{index}")),
            })
            .collect(),
    }
}

#[tokio::test]
async fn nntp_real_codec_roundtrip_and_ranges_keep_readonly_legacy_capability() {
    let (intent, bytes) = intent(Backend::Nntp, &[1024, 1024, 317]);
    let authority = Authority::new();
    let mut provider =
        nntp::Provider::new(id("account-a"), Spool::default(), Some(posting(&intent)));
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    let proof = provider
        .commit(&session, &receipts, &authority)
        .await
        .unwrap();
    assert!(proof.full_ciphertext_readback);
    let mut old_reader = nntp::Provider::new(id("account-a"), provider.into_io(), None);
    assert!(!old_reader.capabilities().write);
    assert_eq!(
        old_reader.begin(&intent, &authority).await,
        Err(Failure::Unsupported)
    );
    let mut output = Output::default();
    old_reader
        .read_range(
            &proof.record,
            Range {
                offset: 1003,
                bytes: 1097,
            },
            &mut output,
            &authority,
        )
        .await
        .unwrap();
    assert_eq!(output.0, bytes[1003..2100]);
    assert_eq!(
        old_reader.abort(&session, &authority).await.unwrap(),
        AbortOutcome::Irreversible
    );
}

#[tokio::test]
async fn nntp_partial_posts_never_become_absent_and_restart_reuses_article_ids() {
    let (intent, bytes) = intent(Backend::Nntp, &[101, 97]);
    let authority = Authority::new();
    let mut provider = nntp::Provider::new(
        id("account-a"),
        Spool {
            fail_after: Some(1),
            ..Default::default()
        },
        Some(posting(&intent)),
    );
    let session = provider.begin(&intent, &authority).await.unwrap();
    assert_eq!(
        provider
            .write_part(&session, 0, &bytes[..101], &authority)
            .await,
        Err(Failure::Uncertain)
    );
    assert_eq!(
        provider.reconcile(&session, &authority).await.unwrap(),
        Reconciled::Uncertain
    );
    let remote = provider.into_io();
    let mut restarted = nntp::Provider::new(id("account-a"), remote, Some(posting(&intent)));
    let recovered: WriteSession =
        serde_json::from_slice(&serde_json::to_vec(&session).unwrap()).unwrap();
    let receipt0 = restarted
        .write_part(&recovered, 0, &bytes[..101], &authority)
        .await
        .unwrap();
    let receipt1 = restarted
        .write_part(&recovered, 1, &bytes[101..], &authority)
        .await
        .unwrap();
    let proof = restarted
        .commit(&recovered, &[receipt0, receipt1], &authority)
        .await
        .unwrap();
    assert_eq!(proof.record.identity.sha256, digest(&bytes));
    assert_eq!(restarted.into_io().articles.len(), 2);
}

#[tokio::test]
async fn nntp_corrupt_article_does_not_release_requested_bytes() {
    let (intent, bytes) = intent(Backend::Nntp, &[113]);
    let authority = Authority::new();
    let mut provider =
        nntp::Provider::new(id("account-a"), Spool::default(), Some(posting(&intent)));
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    let proof = provider
        .commit(&session, &receipts, &authority)
        .await
        .unwrap();
    let mut spool = provider.into_io();
    let article = spool.articles.values_mut().next().unwrap();
    let start = article.windows(2).position(|pair| pair == b"\r\n").unwrap();
    article.truncate(start);
    let mut provider = nntp::Provider::new(id("account-a"), spool, None);
    let mut output = Output::default();
    assert_eq!(
        provider
            .read_range(
                &proof.record,
                Range {
                    offset: 3,
                    bytes: 7
                },
                &mut output,
                &authority
            )
            .await,
        Err(Failure::Integrity)
    );
    assert!(output.0.is_empty());
}
