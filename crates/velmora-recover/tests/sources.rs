use sha2::{Digest, Sha256};
use std::io::Read;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use velmora_recover::{
    extent::{Article, BodySource, Placement},
    source::{Downloads, NntpSource},
};

async fn fake_provider(found: bool) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        stream.write_all(b"201 read-only\r\n").await.unwrap();
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "MODE READER\r\n");
        stream.write_all(b"201 read-only\r\n").await.unwrap();
        line.clear();
        stream.read_line(&mut line).await.unwrap();
        assert_eq!(line, "BODY <part@example.invalid>\r\n");
        if found {
            stream
                .write_all(b"222 0 <part@example.invalid>\r\n..raw\r\n.\r\n")
                .await
                .unwrap();
        } else {
            stream.write_all(b"430 No such article\r\n").await.unwrap();
        }
    });
    (port, task)
}

#[tokio::test]
async fn body_rotates_on_430_and_removes_dot_framing() {
    let (first, first_task) = fake_provider(false).await;
    let (second, second_task) = fake_provider(true).await;
    let providers = format!("[[providers]]\nhost='127.0.0.1'\nport={first}\ntls=false\nmax_conns=1\n[[providers]]\nhost='127.0.0.1'\nport={second}\ntls=false\nmax_conns=1\n");
    let mut source = NntpSource::from_toml(providers.as_bytes()).unwrap();
    assert!(source.body("part@example.invalid").await.is_err());
    assert_eq!(
        source.body("part@example.invalid").await.unwrap(),
        b".raw\r\n"
    );
    first_task.await.unwrap();
    second_task.await.unwrap();
}

#[tokio::test]
async fn offline_payload_via_renamed_legacy_file_hash_not_iteration_order() {
    let root = std::env::temp_dir().join(format!("velmora-offline-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let result = async {
        std::fs::write(root.join("decoy"), b"111222333").unwrap();
        std::fs::write(root.join("anything.bin"), b"abcdefghi").unwrap();
        let mut downloads = Downloads::open(&root).unwrap();
        let article = Article {
            message_id: "part@example.invalid".into(),
            sha256: Sha256::digest(b"def").into(),
            yenc_name: None,
            newsgroup: "alt.test".into(),
        };
        let place = Placement {
            offset: 3,
            len: 3,
            total: 9,
            number: 2,
            parity: false,
        };
        downloads.candidate(&article, place).await
    }
    .await;
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(result.unwrap(), b"def");
}

#[test]
fn refuses_config_errors_without_echoing_credential() {
    let config = b"[[providers]]\nhost='example.invalid'\ntls=false\nmax_conns=1\nuser='credential-canary'\npass='not-a-secret'";
    assert_eq!(
        NntpSource::from_toml(config).err().unwrap(),
        "invalid provider configuration"
    );
    // Exercise the config from a reader without ever putting secrets in argv.
    let mut config = config.as_slice();
    let mut data = Vec::new();
    config.read_to_end(&mut data).unwrap();
    assert!(!NntpSource::from_toml(&data)
        .err()
        .unwrap()
        .contains("credential-canary"));
}

#[cfg(feature = "recovery-cli")]
#[test]
fn relay_rejects_non_tls_and_credentials_in_url() {
    use velmora_recover::source::RelaySource;
    let test_token = [b'x'; 32];
    for url in [
        "http://relay.example.invalid/",
        "https://test@relay.example.invalid/",
        "https://relay.example.invalid/?query=value",
        "https://relay.example.invalid/#fragment",
    ] {
        assert_eq!(
            RelaySource::new(url, &test_token).err().unwrap(),
            "relay requires a credential-free HTTPS URL"
        );
    }
    assert_eq!(
        RelaySource::new("https://relay.example.invalid/", b"short")
            .err()
            .unwrap(),
        "invalid relay token file"
    );
}
