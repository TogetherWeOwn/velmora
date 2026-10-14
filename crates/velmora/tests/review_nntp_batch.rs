//! A failed pipelined ARTICLE must not lend its queued reply to the next call.

#[path = "review_support/nntp.rs"]
mod support;

use nntune_core::error::Error;
use nntune_core::nntp::NntpConfig;

#[tokio::test]
async fn failed_batch_drains_queued_replies_or_permanently_closes_client() {
    // Exercise both replies already buffered together and fragmented reads.
    for chunk in [1, 7, 4096] {
        let (mut client, trace) = support::connect(
            b"430 a missing\r\n220 2 <b@x>\r\nB\r\n.\r\n\
              220 3 <c@x>\r\nC\r\n.\r\n220 4 <d@x>\r\nD\r\n.\r\n",
            chunk,
            &NntpConfig::default(),
        )
        .await;
        let err = client.fetch_many(&["a@x", "b@x"]).await.unwrap_err();
        assert!(matches!(err, Error::ArticleNotFound(_)), "{err:?}");
        assert_eq!(
            trace.lock().unwrap().written,
            b"MODE READER\r\nARTICLE <a@x>\r\nARTICLE <b@x>\r\n"
        );
        let before = trace.lock().unwrap().written.len();
        let mut out = b"prefix:".to_vec();
        if client.article_to("c@x", &mut out).await.is_ok() {
            assert_eq!(out, b"prefix:C\r\n", "stale B body delivered as C");
            let mut next = Vec::new();
            client.article_to("d@x", &mut next).await.unwrap();
            assert_eq!(next, b"D\r\n", "draining must preserve later ordering");
        } else {
            assert_eq!(out, b"prefix:", "failed-closed call appended stale data");
            assert!(client.article_to("d@x", &mut out).await.is_err());
            assert_eq!(out, b"prefix:");
            assert_eq!(
                trace.lock().unwrap().written.len(),
                before,
                "an unusable client must not send further commands"
            );
        }
    }
}

#[tokio::test]
async fn successful_batches_remain_ordered_across_pipeline_windows() {
    let config = NntpConfig {
        max_pipelined: 2,
        ..NntpConfig::default()
    };
    for chunk in [1, 4096] {
        let (mut client, trace) = support::connect(
            b"220 1 <a@x>\r\nA\r\n.\r\n220 2 <b@x>\r\n..B\r\n.\r\n\
              220 3 <c@x>\r\nC\r\n.\r\n220 4 <d@x>\r\nD\r\n.\r\n",
            chunk,
            &config,
        )
        .await;
        assert!(client.fetch_many(&[]).await.unwrap().is_empty());
        let replies = client.fetch_many(&["a@x", "b@x", "c@x"]).await.unwrap();
        assert_eq!(replies.len(), 3);
        for (reply, (id, body)) in replies.iter().zip([
            ("a@x", b"A\r\n".as_slice()),
            ("b@x", b".B\r\n".as_slice()),
            ("c@x", b"C\r\n".as_slice()),
        ]) {
            assert_eq!(reply.message_id, id);
            assert_eq!(reply.article, body);
        }
        let mut last = Vec::new();
        client.article_to("d@x", &mut last).await.unwrap();
        assert_eq!(last, b"D\r\n");
        assert_eq!(
            trace.lock().unwrap().written,
            b"MODE READER\r\nARTICLE <a@x>\r\nARTICLE <b@x>\r\nARTICLE <c@x>\r\nARTICLE <d@x>\r\n"
        );
    }
}
