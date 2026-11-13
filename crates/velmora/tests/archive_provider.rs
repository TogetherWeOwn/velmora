#![cfg(feature = "archive-provider")]

use std::collections::BTreeMap;
use velmora::archive::v1::{s3, *};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn generated(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|index| (index.wrapping_mul(73) % 251) as u8)
        .collect()
}

fn intent(sizes: &[usize]) -> (WriteIntent, Vec<u8>) {
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
                backend: Backend::S3,
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
}
impl Authority {
    fn new() -> Self {
        Self {
            tenant: id("tenant-a"),
        }
    }
}
impl Control for Authority {
    fn check(&self, target: &Target, _: Action) -> Result<()> {
        if self.tenant != target.tenant {
            return Err(Failure::Denied);
        }
        Ok(())
    }

    async fn cancelled(&self, _: &Target, _: Action) -> Failure {
        // Only synchronous fake operations use this authority. Pending native
        // I/O uses an event-driven revocation control in later slices.
        std::future::pending().await
    }
}

#[derive(Default)]
struct ObjectStore {
    binding: Option<[u8; 32]>,
    remote: Option<Id>,
    aborted: bool,
    parts: BTreeMap<usize, Vec<u8>>,
    complete: Option<s3::Metadata>,
    lost_part: bool,
}
impl ObjectStore {
    fn check_session(&self, session: &WriteSession) -> Result<()> {
        if self.binding != Some(session.intent.binding()?)
            || self.remote.as_ref() != Some(&session.remote)
        {
            return Err(Failure::Conflict);
        }
        if self.aborted {
            return Err(Failure::Missing);
        }
        Ok(())
    }
}

impl s3::SafeTransport for ObjectStore {
    async fn begin(
        &mut self,
        _: &s3::Config,
        intent: &WriteIntent,
        _: &impl Control,
    ) -> Result<Id> {
        let binding = intent.binding()?;
        if self.binding.is_some_and(|old| old != binding) {
            return Err(Failure::Conflict);
        }
        if self.aborted {
            return Err(Failure::Missing);
        }
        self.binding = Some(binding);
        let remote = self.remote.get_or_insert_with(|| id("upload-a"));
        Ok(remote.clone())
    }
    async fn upload_part(
        &mut self,
        _: &s3::Config,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        _: &impl Control,
    ) -> Result<s3::PartAck> {
        self.check_session(session)?;
        if self.complete.is_some() {
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
    async fn health(&mut self, _: &s3::Config, _: &Target, _: &impl Control) -> Result<Health> {
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
        "127.1",
        "0x7f.0.0.1",
        "0x7f.0x.0x.1",
        "0X7F.0X.0X.1",
        "0177.0.0.1",
        "https://archive.example.com",
        "a.local",
        "a.internal",
        "a.example.com/path",
        "a.example.com:443",
    ] {
        let mut bad = config();
        bad.host = id(host);
        assert!(s3::Provider::new(Some(bad), ObjectStore::default()).is_err());
    }
}

#[tokio::test]
async fn s3_lost_part_retries_only_the_exact_same_bytes() {
    let (intent, bytes) = intent(&[173]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(
        Some(config()),
        ObjectStore {
            lost_part: true,
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
    provider
        .write_part(&session, 0, &bytes, &authority)
        .await
        .unwrap();
    // A non-final multipart part below 5 MiB is rejected before I/O; only the
    // final part may be smaller.
    let (undersized, _) = intent(&[51, 51]);
    assert_eq!(
        provider.begin(&undersized, &authority).await,
        Err(Failure::Invalid)
    );
    let mut foreign = intent.clone();
    foreign.target.tenant = id("tenant-b");
    assert_eq!(
        provider.begin(&foreign, &authority).await,
        Err(Failure::Denied)
    );
    foreign.target.tenant = id("tenant-a");
    foreign.target.account = id("account-b");
    assert_eq!(
        provider.begin(&foreign, &authority).await,
        Err(Failure::Configuration)
    );
}

#[tokio::test]
async fn s3_fake_transport_rejects_cross_upload_sessions() {
    let (intent, bytes) = intent(&[73]);
    let authority = Authority::new();
    let mut provider = s3::Provider::new(Some(config()), ObjectStore::default()).unwrap();
    let session = provider.begin(&intent, &authority).await.unwrap();
    let mut other = session.clone();
    other.remote = id("other-upload");
    assert_eq!(
        provider.write_part(&other, 0, &bytes, &authority).await,
        Err(Failure::Conflict)
    );
    provider
        .write_part(&session, 0, &bytes, &authority)
        .await
        .unwrap();
    assert_eq!(
        provider.health(&intent.target, &authority).await,
        Ok(Health::Available)
    );
}
