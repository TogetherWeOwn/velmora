//! Protected behavioral acceptance for successful NNTP envelope correlation.
//!
//! STAT, ARTICLE, BODY and every pipelined ARTICLE must validate an unsigned
//! decimal u64 article number and the next, bracketed Message-ID token before
//! accepting success. IDs match exactly; explanatory text after the ID is not
//! identity. Zero is valid when requesting by Message-ID. Invalid envelopes
//! return a generic Malformed, never foreign bytes or a partial batch.
//!
//! Removing identity/number validation, validating only the first batch reply,
//! appending an unverified block, or reusing an unsynchronized client must fail
//! these tests. Only the transport is scripted; all client behavior is real.
//! No sockets, provider credentials or production implementation changes.

#[path = "review_support/nntp.rs"]
mod support;

use std::sync::{Arc, Mutex};

use nntune_core::error::{Error, Result};
use nntune_core::nntp::{NntpClient, NntpConfig};

const PREFIX: &[u8] = b"caller-prefix:\x00\xff";
const CANARY: &str = "foreign-envelope-canary-9e72";

#[derive(Clone, Copy, Debug)]
enum Method {
    Stat,
    Article,
    Body,
    Batch,
}

impl Method {
    fn code(self) -> u16 {
        match self {
            Self::Stat => 223,
            Self::Body => 222,
            Self::Article | Self::Batch => 220,
        }
    }

    fn writes(self) -> &'static [u8] {
        match self {
            Self::Stat => b"MODE READER\r\nSTAT <wanted@x>\r\n",
            Self::Article => b"MODE READER\r\nARTICLE <wanted@x>\r\n",
            Self::Body => b"MODE READER\r\nBODY <wanted@x>\r\n",
            Self::Batch => b"MODE READER\r\nARTICLE <first@x>\r\nARTICLE <wanted@x>\r\n",
        }
    }
}

async fn request(
    method: Method,
    client: &mut NntpClient<support::Script>,
    out: &mut Vec<u8>,
) -> Result<()> {
    match method {
        Method::Stat => client.stat("wanted@x").await.map(|_| ()),
        Method::Article => client.article_to("wanted@x", out).await,
        Method::Body => client.body_to("wanted@x", out).await,
        Method::Batch => client
            .fetch_many(&["first@x", "wanted@x"])
            .await
            .map(|_| ()),
    }
}

fn replies(method: Method, code: u16, envelope: &str, block: &str) -> Vec<u8> {
    let mut wire = String::new();
    if matches!(method, Method::Batch) {
        wire.push_str("220 1 <first@x> first follows\r\nfirst bytes\r\n.\r\n");
    }
    wire.push_str(&format!("{code} {envelope}\r\n"));
    if !matches!(method, Method::Stat) {
        wire.push_str(block);
    }
    wire.into_bytes()
}

fn written(trace: &Arc<Mutex<support::Trace>>) -> Vec<u8> {
    trace.lock().unwrap().written.clone()
}

fn assert_malformed(err: &Error) {
    assert!(
        matches!(err, Error::Malformed(_)),
        "invalid successful envelope must be Malformed, got {err:?}"
    );
    assert!(!err.is_auth_failure());
    for rendered in [err.to_string(), format!("{err:?}"), format!("{err:#?}")] {
        for forbidden in [
            CANARY,
            "wanted@x",
            "foreign@x",
            "\x1b",
            "untrusted-explanation",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "envelope diagnostics must not echo hostile text: {rendered:?}"
            );
        }
        assert!(rendered.len() <= 256, "unbounded diagnostic: {rendered:?}");
    }
}

async fn rejects(method: Method, envelope: &str) {
    for chunk in [1, 7, 4096] {
        let wire = replies(method, method.code(), envelope, "foreign bytes\r\n.\r\n");
        let (mut client, trace) = support::connect(&wire, chunk, &NntpConfig::default()).await;
        let mut out = PREFIX.to_vec();
        let result = request(method, &mut client, &mut out).await;
        let err =
            result.expect_err("uncorrelated envelope must not succeed or return a partial batch");
        assert_malformed(&err);
        assert_eq!(out, PREFIX, "{method:?} appended unverified bytes");
        assert_eq!(written(&trace), method.writes());
    }
}

// Each case has its own test name for assertion-RED evidence, including the
// second reply of a real two-command pipeline (not a sequential batch of one).
macro_rules! envelope_cases {
    ($module:ident, $method:expr) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn wrong_id() {
                rejects($method, "42 <foreign@x>").await;
            }

            #[tokio::test]
            async fn case_changed_id() {
                rejects($method, "42 <Wanted@x>").await;
            }

            #[tokio::test]
            async fn prefix_only_id_match() {
                rejects($method, "42 <wanted@x.extra>").await;
            }

            #[tokio::test]
            async fn missing_id() {
                rejects($method, "42").await;
            }

            #[tokio::test]
            async fn unbracketed_id() {
                rejects($method, "42 wanted@x").await;
            }

            #[tokio::test]
            async fn unterminated_id() {
                rejects($method, "42 <wanted@x").await;
            }

            #[tokio::test]
            async fn empty_id() {
                rejects($method, "42 <>").await;
            }

            #[tokio::test]
            async fn extra_closing_bracket() {
                rejects($method, "42 <wanted@x>>").await;
            }

            #[tokio::test]
            async fn id_in_explanatory_text_is_not_identity() {
                rejects($method, "42 <foreign@x> explanation <wanted@x>").await;
            }

            #[tokio::test]
            async fn missing_number() {
                rejects($method, "<wanted@x>").await;
            }

            #[tokio::test]
            async fn negative_number() {
                rejects($method, "-1 <wanted@x>").await;
            }

            #[tokio::test]
            async fn plus_signed_number() {
                rejects($method, "+1 <wanted@x>").await;
            }

            #[tokio::test]
            async fn non_decimal_number() {
                rejects($method, "0x2a <wanted@x>").await;
            }

            #[tokio::test]
            async fn number_with_attached_suffix() {
                rejects($method, "42x <wanted@x>").await;
            }

            #[tokio::test]
            async fn overflowing_number() {
                rejects($method, "18446744073709551616 <wanted@x>").await;
            }

            #[tokio::test]
            async fn empty_envelope() {
                rejects($method, "").await;
            }

            #[tokio::test]
            async fn hostile_envelope_has_generic_diagnostic() {
                rejects(
                    $method,
                    &format!("42 <{CANARY}@x> \x1b[31muntrusted-explanation"),
                )
                .await;
            }
        }
    };
}

envelope_cases!(stat, Method::Stat);
envelope_cases!(article, Method::Article);
envelope_cases!(body, Method::Body);
envelope_cases!(batch_second_reply, Method::Batch);

#[tokio::test]
async fn matching_stat_accepts_zero_u64_max_and_trailing_text() {
    for (envelope, want) in [
        ("0 <wanted@x>", 0),
        (
            "42 <wanted@x> article exists; <foreign@x> is only prose",
            42,
        ),
        ("18446744073709551615 <wanted@x> exists", u64::MAX),
    ] {
        for chunk in [1, 4096] {
            let (mut client, trace) = support::connect(
                &replies(Method::Stat, 223, envelope, ""),
                chunk,
                &NntpConfig::default(),
            )
            .await;
            assert_eq!(client.stat("wanted@x").await.unwrap(), want);
            assert_eq!(written(&trace), Method::Stat.writes());
        }
    }
}

#[tokio::test]
async fn matching_blocks_append_unstuffed_bytes_and_remain_synchronized() {
    for method in [Method::Article, Method::Body] {
        for number in ["0", "42", "18446744073709551615"] {
            for chunk in [1, 4096] {
                let mut wire = replies(
                    method,
                    method.code(),
                    &format!("{number} <wanted@x> follows; <foreign@x> is only prose"),
                    "..dot\r\nbody\r\n.\r\n",
                );
                wire.extend_from_slice(b"223 9 <next@x> exists\r\n");
                let (mut client, _) = support::connect(&wire, chunk, &NntpConfig::default()).await;
                let mut out = PREFIX.to_vec();
                request(method, &mut client, &mut out).await.unwrap();
                let mut want = PREFIX.to_vec();
                want.extend_from_slice(b".dot\r\nbody\r\n");
                assert_eq!(out, want);
                assert_eq!(client.stat("next@x").await.unwrap(), 9);
            }
        }
    }
}

#[tokio::test]
async fn matching_pipeline_accepts_zero_and_preserves_ids_bytes_and_next_window() {
    let config = NntpConfig {
        max_pipelined: 2,
        ..NntpConfig::default()
    };
    for chunk in [1, 7, 4096] {
        let (mut client, trace) = support::connect(
            b"220 0 <first@x> follows\r\nfirst\r\n.\r\n\
              220 18446744073709551615 <wanted@x> follows <foreign@x>\r\n..second\r\n.\r\n\
              220 3 <next@x> follows\r\nthird\r\n.\r\n",
            chunk,
            &config,
        )
        .await;
        assert!(client.fetch_many(&[]).await.unwrap().is_empty());
        let out = client
            .fetch_many(&["first@x", "wanted@x", "next@x"])
            .await
            .unwrap();
        assert_eq!(out.len(), 3);
        for (item, (id, bytes)) in out.iter().zip([
            ("first@x", b"first\r\n".as_slice()),
            ("wanted@x", b".second\r\n".as_slice()),
            ("next@x", b"third\r\n".as_slice()),
        ]) {
            assert_eq!(item.message_id, id);
            assert_eq!(item.article, bytes);
        }
        assert_eq!(
            written(&trace),
            b"MODE READER\r\nARTICLE <first@x>\r\nARTICLE <wanted@x>\r\nARTICLE <next@x>\r\n"
        );
    }
}

#[tokio::test]
async fn rejected_block_preserves_binary_caller_prefix() {
    for method in [Method::Article, Method::Body] {
        let wire = replies(
            method,
            method.code(),
            "42 <foreign@x>",
            "foreign bytes\r\n.\r\n",
        );
        let (mut client, _) = support::connect(&wire, 1, &NntpConfig::default()).await;
        let mut out = PREFIX.to_vec();
        let _ = request(method, &mut client, &mut out).await;
        assert_eq!(
            out, PREFIX,
            "{method:?} exposed bytes before correlating identity"
        );
    }
}

#[tokio::test]
async fn rejected_envelope_is_malformed_even_when_dot_block_never_arrives() {
    for method in [Method::Article, Method::Body, Method::Batch] {
        let wire = replies(method, method.code(), "42 <foreign@x>", "");
        let (mut client, _) = support::connect(&wire, 1, &NntpConfig::default()).await;
        let mut out = PREFIX.to_vec();
        let err = request(method, &mut client, &mut out).await.unwrap_err();
        assert_malformed(&err);
        assert_eq!(out, PREFIX);
    }
}

#[tokio::test]
async fn unverified_block_never_lends_a_reply_to_another_command() {
    for method in [Method::Article, Method::Body, Method::Batch] {
        for chunk in [1, 4096] {
            let mut wire = replies(
                method,
                method.code(),
                "42 <foreign@x>",
                "223 9 <next@x> forged inside foreign body\r\n.\r\n",
            );
            wire.extend_from_slice(b"223 9 <next@x> real next reply\r\n");
            let (mut client, trace) = support::connect(&wire, chunk, &NntpConfig::default()).await;
            let _ = request(method, &mut client, &mut Vec::new()).await;
            let before = written(&trace);
            assert!(
                client.stat("next@x").await.is_err(),
                "{method:?} reused an unverified stream"
            );
            let mut out = PREFIX.to_vec();
            assert!(client.article_to("next@x", &mut out).await.is_err());
            assert!(client.body_to("next@x", &mut out).await.is_err());
            assert!(client.fetch_many(&["next@x"]).await.is_err());
            assert!(client.raw_command("DATE").await.is_err());
            assert!(client.raw_dot_block(&mut out).await.is_err());
            assert_eq!(out, PREFIX);
            assert_eq!(written(&trace), before, "invalidated client wrote to wire");
        }
    }
}

#[tokio::test]
async fn bad_second_reply_discards_batch_and_does_not_start_next_window() {
    let config = NntpConfig {
        max_pipelined: 2,
        ..NntpConfig::default()
    };
    for chunk in [1, 4096] {
        let (mut client, trace) = support::connect(
            b"220 1 <first@x>\r\nfirst\r\n.\r\n\
              220 2 <foreign@x>\r\nforeign\r\n.\r\n\
              220 3 <next@x>\r\nnext\r\n.\r\n",
            chunk,
            &config,
        )
        .await;
        let err = client
            .fetch_many(&["first@x", "wanted@x", "next@x"])
            .await
            .expect_err("bad second identity must discard the whole batch");
        assert_malformed(&err);
        assert_eq!(
            written(&trace),
            Method::Batch.writes(),
            "next window sent after invalid identity"
        );
    }
}

#[tokio::test]
async fn bad_first_identity_invalidates_the_pipeline_with_other_replies_pending() {
    for chunk in [1, 4096] {
        let (mut client, trace) = support::connect(
            b"220 1 <foreign@x>\r\nforeign\r\n.\r\n\
              220 2 <wanted@x>\r\nwanted\r\n.\r\n",
            chunk,
            &NntpConfig::default(),
        )
        .await;
        let err = client
            .fetch_many(&["first@x", "wanted@x"])
            .await
            .expect_err("the first reply also needs identity validation");
        assert_malformed(&err);
        assert_eq!(written(&trace), Method::Batch.writes());
        assert!(client.stat("wanted@x").await.is_err());
        assert_eq!(written(&trace), Method::Batch.writes());
    }
}

#[tokio::test]
async fn bad_identity_in_next_window_discards_previously_completed_window() {
    let config = NntpConfig {
        max_pipelined: 2,
        ..NntpConfig::default()
    };
    for chunk in [1, 4096] {
        let (mut client, trace) = support::connect(
            b"220 1 <first@x>\r\nfirst\r\n.\r\n\
              220 2 <wanted@x>\r\nwanted\r\n.\r\n\
              220 3 <foreign@x>\r\nforeign\r\n.\r\n",
            chunk,
            &config,
        )
        .await;
        let err = client
            .fetch_many(&["first@x", "wanted@x", "next@x"])
            .await
            .expect_err("a completed window must not escape as a partial batch");
        assert_malformed(&err);
        let before = written(&trace);
        assert!(client.stat("next@x").await.is_err());
        assert_eq!(written(&trace), before);
    }
}

#[tokio::test]
async fn prewrite_argument_refusal_keeps_connection_usable_and_emits_no_batch() {
    let (mut client, trace) =
        support::connect(b"223 42 <wanted@x> exists\r\n", 1, &NntpConfig::default()).await;
    let before = written(&trace);
    let err = client
        .fetch_many(&["first@x", "bad id@x"])
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Malformed(_)));
    assert_eq!(
        written(&trace),
        before,
        "prewrite refusal emitted part of a batch"
    );
    assert_eq!(client.stat("wanted@x").await.unwrap(), 42);
}

#[tokio::test]
async fn unsuccessful_replies_keep_existing_taxonomy_without_needing_an_envelope() {
    for method in [Method::Stat, Method::Article, Method::Body, Method::Batch] {
        for code in [430, 480, 481, 502] {
            let wire = replies(method, code, "no envelope is required on failure", "");
            let (mut client, _) = support::connect(&wire, 7, &NntpConfig::default()).await;
            let mut out = PREFIX.to_vec();
            let err = request(method, &mut client, &mut out).await.unwrap_err();
            match code {
                430 => assert!(matches!(err, Error::ArticleNotFound(_)), "{err:?}"),
                480 | 481 => assert!(matches!(err, Error::AuthFailed(_)), "{err:?}"),
                502 => assert!(matches!(err, Error::NoPermission(_)), "{err:?}"),
                _ => unreachable!(),
            }
            assert_eq!(out, PREFIX);
        }
    }
}
