use velmora_bridge::types::BucketId;
use velmora_recover::{
    catalogue::{expected_md5, Bucket, Catalogue, Object},
    extent::Extent,
    nzb::write_nzb,
};

#[test]
fn plain_etag_is_an_object_md5_but_multipart_etag_is_not() {
    assert_eq!(
        expected_md5("\"01010101010101010101010101010101\"").unwrap(),
        Some([1; 16])
    );
    assert_eq!(
        expected_md5("01010101010101010101010101010101-2").unwrap(),
        None
    );
    assert!(expected_md5("corrupt-etag").is_err());
}

#[test]
fn nzb_uses_recorded_groups_and_never_object_names() {
    use velmora_recover::extent::Article;
    let id = BucketId::new("b_test");
    let bucket = Bucket {
        id: id.clone(),
        name: "private-bucket".into(),
        wrapped: [0; 73],
        kek_version: 1,
    };
    let plain_size = velmora::article::ARTICLE_PLAINTEXT_BYTES * 2 + 1;
    let extent = Extent {
        id: velmora_bridge::types::ExtentId::new("x_test"),
        bucket: id.clone(),
        plain_size,
        cipher_size: velmora::media::ciphertext_size(plain_size).unwrap(),
        media_header: [0; 48],
        wrapped_file_key: [0; 73],
        plain_md5: [0; 16],
        plain_sha256: [0; 32],
        cipher_sha256: [0; 32],
        articles: vec![
            Article {
                message_id: "id&one@example.invalid".into(),
                sha256: [0; 32],
                yenc_name: Some("obfuscated.bin".into()),
                newsgroup: "alt.test.a".into(),
            },
            Article {
                message_id: "id&two@example.invalid".into(),
                sha256: [0; 32],
                yenc_name: None,
                newsgroup: "alt.test.b".into(),
            },
            Article {
                message_id: "id&three@example.invalid".into(),
                sha256: [0; 32],
                yenc_name: None,
                newsgroup: "alt.test.c".into(),
            },
        ],
        parity: None,
    };
    let object = Object {
        bucket_id: id,
        key: "private-object-name&".into(),
        generation: "g_test".into(),
        size: plain_size,
        md5: None,
        checksum: None,
        source_md5: None,
        extents: vec![velmora_recover::catalogue::Reference {
            id: extent.id.clone(),
            offset: 0,
            len: plain_size,
        }],
    };
    let catalogue = Catalogue::new(vec![bucket], vec![object], vec![extent]).unwrap();
    let objects = catalogue.select(Some("private-bucket"), None, None);
    let mut xml = Vec::new();
    write_nzb(&mut xml, &catalogue, &objects).unwrap();
    let text = std::str::from_utf8(&xml).unwrap();
    assert!(!text.contains("private-"));
    assert!(text.contains("id&amp;one@example.invalid"));
    let nzb = velmora::nzb::parse(&xml).unwrap();
    assert_eq!(nzb.files.len(), 2);
    assert!(text.contains("<group>alt.test.a</group>"));
    assert_eq!(nzb.files[0].segments[0].number, 1);
    assert!(text.contains("<group>alt.test.b</group><group>alt.test.c</group>"));
    assert_eq!(nzb.files[1].segments.len(), 2);
}
