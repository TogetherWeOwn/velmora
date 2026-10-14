//! Contract tests for the agreed NntpConfig.max_article_bytes API.
//! The cap counts newly appended, dot-unstuffed bytes, including each CRLF.

#[path = "review_support/nntp.rs"]
mod support;

use nntune_core::nntp::{NntpClient, NntpConfig};

#[derive(Clone, Copy, Debug)]
enum Method {
    Article,
    Body,
    Raw,
}

async fn read(
    method: Method,
    client: &mut NntpClient<support::Script>,
    out: &mut Vec<u8>,
) -> nntune_core::error::Result<()> {
    match method {
        Method::Article => client.article_to("a@x", out).await,
        Method::Body => client.body_to("a@x", out).await,
        Method::Raw => {
            assert_eq!(client.raw_command("XTEST").await?.code, 222);
            client.raw_dot_block(out).await
        }
    }
}

fn reply(method: Method, body: &[u8]) -> Vec<u8> {
    let mut bytes = match method {
        Method::Article => b"220 1 <a@x>\r\n".to_vec(),
        _ => b"222 1 <a@x>\r\n".to_vec(),
    };
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(b".\r\n223 9 <next@x>\r\n");
    bytes
}

#[test]
fn default_article_cap_is_64_mib() {
    assert_eq!(NntpConfig::default().max_article_bytes, 64 * 1024 * 1024);
}

#[tokio::test]
async fn exact_cap_including_crlf_accepts_prefilled_destination_and_unstuffed_dot() {
    let config = NntpConfig {
        max_article_bytes: 8,
        ..NntpConfig::default()
    };
    for method in [Method::Article, Method::Body, Method::Raw] {
        for chunk in [1, 4096] {
            // Nine wire bytes, eight output bytes: ".a\r\nbb\r\n".
            let (mut client, _) =
                support::connect(&reply(method, b"..a\r\nbb\r\n"), chunk, &config).await;
            let mut out = b"existing bytes longer than the per-article cap:".to_vec();
            let mut expected = out.clone();
            expected.extend_from_slice(b".a\r\nbb\r\n");
            read(method, &mut client, &mut out).await.unwrap();
            assert_eq!(out, expected, "{method:?}, chunk {chunk}");
            assert_eq!(client.stat("next@x").await.unwrap(), 9);
        }
    }
}

#[tokio::test]
async fn cap_plus_one_rejects_and_leaves_every_entrypoint_unusable() {
    let config = NntpConfig {
        max_article_bytes: 8,
        ..NntpConfig::default()
    };
    for method in [Method::Article, Method::Body, Method::Raw] {
        for chunk in [1, 4096] {
            // The final CRLF makes this nine bytes, not seven.
            let (mut client, trace) =
                support::connect(&reply(method, b"aa\r\nbbb\r\n"), chunk, &config).await;
            let prefix = b"untouched-prefix:";
            let mut out = prefix.to_vec();
            assert!(
                read(method, &mut client, &mut out).await.is_err(),
                "{method:?}"
            );
            assert!(out.starts_with(prefix));
            assert!(out.len() - prefix.len() <= 8, "appended past the cap");
            let writes = trace.lock().unwrap().written.len();
            let mut next = b"sentinel".to_vec();
            assert!(client.stat("next@x").await.is_err());
            assert!(client.article_to("next@x", &mut next).await.is_err());
            assert!(client.body_to("next@x", &mut next).await.is_err());
            assert!(client.fetch_many(&["next@x"]).await.is_err());
            assert!(client.raw_command("DATE").await.is_err());
            assert!(client.raw_dot_block(&mut next).await.is_err());
            assert_eq!(next, b"sentinel");
            assert_eq!(trace.lock().unwrap().written.len(), writes);
        }
    }
}

#[tokio::test]
async fn pipelined_fetch_enforces_cap_per_article_not_per_batch() {
    let config = NntpConfig {
        max_article_bytes: 4,
        ..NntpConfig::default()
    };
    let (mut client, _) = support::connect(
        b"220 1 <a@x>\r\naa\r\n.\r\n220 2 <b@x>\r\nbb\r\n.\r\n",
        2,
        &config,
    )
    .await;
    let results = client.fetch_many(&["a@x", "b@x"]).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].article, b"aa\r\n");
    assert_eq!(results[1].article, b"bb\r\n");

    let (mut client, trace) = support::connect(
        b"220 1 <a@x>\r\naaa\r\n.\r\n220 2 <b@x>\r\nbb\r\n.\r\n",
        4096,
        &config,
    )
    .await;
    assert!(client.fetch_many(&["a@x", "b@x"]).await.is_err());
    let writes = trace.lock().unwrap().written.len();
    let mut next = Vec::new();
    assert!(client.article_to("c@x", &mut next).await.is_err());
    assert!(next.is_empty());
    assert_eq!(trace.lock().unwrap().written.len(), writes);
}
