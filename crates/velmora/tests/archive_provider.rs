#![cfg(feature = "archive-provider")]

use velmora::archive::v1::{s3, *};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
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
fn s3_disabled_and_unsafe_config_fails_closed_without_io() {
    let mut disabled = config();
    disabled.enabled = false;
    assert_eq!(disabled.validate(), Err(Failure::Disabled));
    for host in [
        "127.0.0.1",
        "127.1",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "https://archive.example.com",
        "a.local",
        "a.internal",
        "a.example.com/path",
        "a.example.com:443",
        "a.example.com.",
    ] {
        let mut bad = config();
        bad.host = id(host);
        assert_eq!(bad.validate(), Err(Failure::Configuration), "{host}");
    }
    assert_eq!(config().validate(), Ok(()));
}
