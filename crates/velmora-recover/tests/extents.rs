use sha2::{Digest, Sha256};
use velmora::{rng::SystemRng, yenc};
use velmora_bridge::{
    crypto,
    types::{BucketId, ExtentId},
};
use velmora_recover::extent::{open_extent, Article, BodySource, Extent, FetchError};

struct Bodies {
    replies: Vec<Option<Vec<u8>>>,
    reads: usize,
}

impl BodySource for Bodies {
    async fn body(&mut self, _: &str) -> Result<Vec<u8>, FetchError> {
        self.reads += 1;
        self.replies.remove(0).ok_or(FetchError::Unavailable)
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn setup(plain: &[u8]) -> (crypto::DataKey, Extent, Vec<u8>) {
    let bdk = crypto::DataKey::from_bytes([11; 32]);
    let bucket = BucketId::new("b_test");
    let id = ExtentId::new("x_test");
    let s = crypto::seal_extent(&bdk, &bucket, &id, plain, &mut SystemRng).unwrap();
    let extent = Extent {
        id,
        bucket,
        plain_size: plain.len() as u64,
        cipher_size: s.ciphertext.len() as u64,
        media_header: s.media_header,
        wrapped_file_key: *s.wrapped_file_key.as_bytes(),
        plain_md5: s.plain_md5,
        plain_sha256: s.plain_sha256,
        cipher_sha256: s.cipher_sha256,
        articles: vec![Article {
            message_id: "data@example.invalid".into(),
            sha256: sha(&s.ciphertext),
            yenc_name: Some("random.bin".into()),
            newsgroup: "alt.test".into(),
        }],
        parity: None,
    };
    (bdk, extent, s.ciphertext)
}

fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    yenc::encode_segment_vec(&mut out, &yenc::SegmentParams::single("random.bin"), data).unwrap();
    out
}

#[tokio::test]
async fn retries_changed_article_then_recovers() {
    let (bdk, extent, cipher) = setup(b"authenticated plaintext");
    let mut corrupt = cipher.clone();
    corrupt[0] ^= 1;
    let mut source = Bodies {
        replies: vec![Some(encode(&corrupt)), Some(encode(&cipher))],
        reads: 0,
    };
    assert_eq!(
        &*open_extent(&mut source, &bdk, &extent).await.unwrap(),
        b"authenticated plaintext"
    );
    assert_eq!(source.reads, 2);
}

#[tokio::test]
async fn wrong_file_key_and_plain_hash_release_nothing() {
    let (bdk, mut extent, cipher) = setup(b"authenticated plaintext");
    let mut source = Bodies {
        replies: vec![Some(encode(&cipher))],
        reads: 0,
    };
    assert!(
        open_extent(&mut source, &crypto::DataKey::from_bytes([22; 32]), &extent)
            .await
            .is_err()
    );
    assert_eq!(source.reads, 0);
    extent.plain_sha256[0] ^= 1;
    assert!(open_extent(&mut source, &bdk, &extent).await.is_err());
}

#[tokio::test]
async fn verifies_empty_extent() {
    let (bdk, extent, cipher) = setup(b"");
    let mut source = Bodies {
        replies: vec![Some(encode(&cipher))],
        reads: 0,
    };
    assert!(open_extent(&mut source, &bdk, &extent)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn reconstructs_lost_article_with_verified_parity() {
    use velmora_recover::extent::Parity;
    let (bdk, mut extent, cipher) = setup(b"authenticated plaintext");
    let parity = velmora::rs::encode(&[&cipher], &[0])
        .unwrap()
        .pop()
        .unwrap();
    extent.parity = Some(Parity {
        k: 1,
        shard_len: parity.len(),
        rows: vec![(
            0,
            Article {
                message_id: "parity@example.invalid".into(),
                sha256: sha(&parity),
                yenc_name: None,
                newsgroup: "alt.test".into(),
            },
        )],
    });
    let mut source = Bodies {
        replies: vec![None, None, Some(encode(&parity))],
        reads: 0,
    };
    assert_eq!(
        &*open_extent(&mut source, &bdk, &extent).await.unwrap(),
        b"authenticated plaintext"
    );
}
