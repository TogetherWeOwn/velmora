//! Pin `Error` rendering and redaction.
//!
//! Snapshots every `Display` arm, pins `Debug` redaction for the
//! credential-bearing variants, and covers `source()`, `From<io::Error>`,
//! and `code()` for all 11 variants. No network, no credentials.
//!
//! Out of scope: no error-type, message-text, redaction-policy, or
//! call-site changes. Any `Display`/`Debug` string change here is a
//! deliberate contract break and must fail this file first.

use std::error::Error as StdError;
use std::io;

use nntune_core::error::{Error, PROVIDER_AUTH_EXPIRED_CODE};

/// Exhaustive match with no wildcard arm: adding a new `Error` variant breaks
/// compilation here, forcing this file to pin the new variant's rendering.
fn assert_all_variants_known(err: &Error) {
    match err {
        Error::Io(_)
        | Error::NntpReply { .. }
        | Error::AuthFailed(_)
        | Error::NoPermission(_)
        | Error::ArticleNotFound(_)
        | Error::Malformed(_)
        | Error::CrcMismatch { .. }
        | Error::Bounds { .. }
        | Error::Decrypt(_)
        | Error::Par2Unhealthy { .. }
        | Error::UnsupportedOnWasm(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Display: exact snapshot of every arm
// ---------------------------------------------------------------------------

#[test]
fn display_io_prefixes_transport() {
    let err = Error::Io(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
    assert_eq!(err.to_string(), "transport I/O: deadline exceeded");
}

#[test]
fn display_nntp_reply_carries_code_and_text() {
    let err = Error::NntpReply {
        code: 411,
        text: "no such group".to_string(),
    };
    assert_eq!(err.to_string(), "NNTP reply 411: no such group");
}

#[test]
fn display_auth_failed_is_generic_with_documented_code() {
    let err = Error::AuthFailed("481 bad login".to_string());
    assert_eq!(
        err.to_string(),
        format!("NNTP authentication failed: {PROVIDER_AUTH_EXPIRED_CODE}")
    );
}

#[test]
fn display_no_permission_is_redacted_marker() {
    let err = Error::NoPermission("502 denied".to_string());
    assert_eq!(err.to_string(), "NNTP permission denied: <redacted>");
}

#[test]
fn display_article_not_found_echoes_id() {
    let err = Error::ArticleNotFound("<segment-1@example.com>".to_string());
    assert_eq!(
        err.to_string(),
        "article not found: <segment-1@example.com>"
    );
}

#[test]
fn display_malformed_echoes_reason() {
    let err = Error::Malformed("bad yEnc header".to_string());
    assert_eq!(err.to_string(), "malformed input: bad yEnc header");
}

#[test]
fn display_crc_mismatch_uses_zero_padded_hex() {
    // `:08x` padding is the contract: small values must left-pad with zeros.
    let err = Error::CrcMismatch {
        message_id: "<seg-7@example.com>".to_string(),
        want: 0x1a,
        got: 0xabc,
    };
    assert_eq!(
        err.to_string(),
        "yEnc CRC32 mismatch for segment <seg-7@example.com>: want 0000001a got 00000abc"
    );
}

#[test]
fn display_crc_mismatch_full_width_no_truncation() {
    let err = Error::CrcMismatch {
        message_id: "<seg-8@example.com>".to_string(),
        want: 0xdead_beef,
        got: 0xffff_ffff,
    };
    assert_eq!(
        err.to_string(),
        "yEnc CRC32 mismatch for segment <seg-8@example.com>: want deadbeef got ffffffff"
    );
}

#[test]
fn display_bounds_names_bound_and_limit() {
    let err = Error::Bounds {
        bound: "nzb segments",
        limit: 1000,
    };
    assert_eq!(
        err.to_string(),
        "NZB/PAR2 nzb segments exceeds the hard limit of 1000"
    );
}

#[test]
fn display_decrypt_echoes_reason() {
    let err = Error::Decrypt("bad nonce length".to_string());
    assert_eq!(err.to_string(), "decrypt: bad nonce length");
}

#[test]
fn display_par2_unhealthy_names_file_and_detail() {
    let err = Error::Par2Unhealthy {
        filename: "archive.vol0+1.par2".to_string(),
        detail: "2 blocks damaged".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "par2 verify failed for archive.vol0+1.par2: 2 blocks damaged"
    );
}

#[test]
fn display_unsupported_on_wasm_is_native_only_wording() {
    let err = Error::UnsupportedOnWasm("par2 repair");
    assert_eq!(
        err.to_string(),
        "par2 repair is only available on native targets"
    );
}

// ---------------------------------------------------------------------------
// Debug: redaction for credential-bearing variants, shape for the rest
// ---------------------------------------------------------------------------

#[test]
fn debug_auth_failed_redacts_exactly_like_display() {
    let secret = "s3cret-provider-password";
    let err = Error::AuthFailed(format!("481 bad login for {secret}"));
    let rendered = format!("{err:?}");
    assert_eq!(rendered, r#"AuthFailed("<redacted>")"#);
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("481 bad login"));
}

#[test]
fn debug_no_permission_redacts_exactly_like_display() {
    let secret = "s3cret-provider-password";
    let err = Error::NoPermission(format!("502 denied for {secret}"));
    let rendered = format!("{err:?}");
    assert_eq!(rendered, r#"NoPermission("<redacted>")"#);
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("502 denied"));
}

#[test]
fn debug_credential_variants_never_leak_in_either_format() {
    // Belt-and-braces: neither `Display` nor `Debug` may carry the secret
    // or the raw server reply text for the two credential-bearing variants.
    let secret = "s3cret-provider-password";
    for err in [
        Error::AuthFailed(format!("481 bad login for {secret}")),
        Error::NoPermission(format!("502 denied for {secret}")),
    ] {
        for rendered in [err.to_string(), format!("{err:?}")] {
            assert!(!rendered.contains(secret), "leak in: {rendered}");
            assert!(
                rendered.contains("<redacted>") || rendered.contains(PROVIDER_AUTH_EXPIRED_CODE),
                "no redaction marker or documented code in: {rendered}"
            );
        }
    }
}

#[test]
fn debug_non_credential_variants_echo_payload() {
    // Non-credential variants are NOT redacted: Debug must keep echoing the
    // payload so diagnostics stay useful. Pin the exact shapes.
    assert_eq!(
        format!(
            "{:?}",
            Error::NntpReply {
                code: 411,
                text: "no such group".to_string(),
            }
        ),
        r#"NntpReply { code: 411, text: "no such group" }"#
    );
    assert_eq!(
        format!("{:?}", Error::ArticleNotFound("<a@b>".to_string())),
        r#"ArticleNotFound("<a@b>")"#
    );
    assert_eq!(
        format!("{:?}", Error::Malformed("bad yEnc header".to_string())),
        r#"Malformed("bad yEnc header")"#
    );
    assert_eq!(
        format!(
            "{:?}",
            Error::CrcMismatch {
                message_id: "<seg-7@example.com>".to_string(),
                want: 26,
                got: 2748,
            }
        ),
        r#"CrcMismatch { message_id: "<seg-7@example.com>", want: 26, got: 2748 }"#
    );
    assert_eq!(
        format!(
            "{:?}",
            Error::Bounds {
                bound: "nzb segments",
                limit: 1000,
            }
        ),
        r#"Bounds { bound: "nzb segments", limit: 1000 }"#
    );
    assert_eq!(
        format!("{:?}", Error::Decrypt("bad nonce length".to_string())),
        r#"Decrypt("bad nonce length")"#
    );
    assert_eq!(
        format!(
            "{:?}",
            Error::Par2Unhealthy {
                filename: "archive.vol0+1.par2".to_string(),
                detail: "2 blocks damaged".to_string(),
            }
        ),
        r#"Par2Unhealthy { filename: "archive.vol0+1.par2", detail: "2 blocks damaged" }"#
    );
    assert_eq!(
        format!("{:?}", Error::UnsupportedOnWasm("par2 repair")),
        r#"UnsupportedOnWasm("par2 repair")"#
    );
}

#[test]
fn debug_io_echoes_inner_error_without_redaction_marker() {
    let err = Error::Io(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
    let rendered = format!("{err:?}");
    assert!(
        rendered.starts_with("Io("),
        "unexpected Io Debug: {rendered}"
    );
    assert!(
        rendered.contains("deadline exceeded"),
        "Io Debug must echo the inner error: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// source(), From<io::Error>, code()
// ---------------------------------------------------------------------------

#[test]
fn source_is_some_only_for_io() {
    let io_err = Error::Io(io::Error::new(io::ErrorKind::TimedOut, "slow"));
    assert!(io_err.source().is_some());

    let others: Vec<Error> = vec![
        Error::NntpReply {
            code: 411,
            text: "x".to_string(),
        },
        Error::AuthFailed("x".to_string()),
        Error::NoPermission("x".to_string()),
        Error::ArticleNotFound("x".to_string()),
        Error::Malformed("x".to_string()),
        Error::CrcMismatch {
            message_id: "x".to_string(),
            want: 1,
            got: 2,
        },
        Error::Bounds {
            bound: "b",
            limit: 1,
        },
        Error::Decrypt("x".to_string()),
        Error::Par2Unhealthy {
            filename: "f".to_string(),
            detail: "d".to_string(),
        },
        Error::UnsupportedOnWasm("op"),
    ];
    for err in &others {
        assert!(err.source().is_none(), "source() must be None for {err}");
    }
}

#[test]
fn from_io_error_preserves_kind_and_source() {
    let err: Error = io::Error::new(io::ErrorKind::ConnectionRefused, "refused").into();
    match &err {
        Error::Io(inner) => assert_eq!(inner.kind(), io::ErrorKind::ConnectionRefused),
        other => panic!("From<io::Error> must build Error::Io, got {other}"),
    }
    assert!(err.source().is_some());
    assert_eq!(err.to_string(), "transport I/O: refused");
}

#[test]
fn code_covers_all_eleven_variants() {
    let cases: Vec<(Error, &'static str)> = vec![
        (Error::Io(io::Error::other("x")), "request_failed"),
        (
            Error::NntpReply {
                code: 411,
                text: "x".to_string(),
            },
            "request_failed",
        ),
        (
            Error::AuthFailed("x".to_string()),
            PROVIDER_AUTH_EXPIRED_CODE,
        ),
        (Error::NoPermission("x".to_string()), "request_failed"),
        (Error::ArticleNotFound("x".to_string()), "request_failed"),
        (Error::Malformed("x".to_string()), "request_failed"),
        (
            Error::CrcMismatch {
                message_id: "x".to_string(),
                want: 1,
                got: 2,
            },
            "request_failed",
        ),
        (
            Error::Bounds {
                bound: "b",
                limit: 1,
            },
            "request_failed",
        ),
        (Error::Decrypt("x".to_string()), "request_failed"),
        (
            Error::Par2Unhealthy {
                filename: "f".to_string(),
                detail: "d".to_string(),
            },
            "request_failed",
        ),
        (Error::UnsupportedOnWasm("op"), "request_failed"),
    ];
    assert_eq!(cases.len(), 11, "all 11 Error variants must be covered");
    for (err, expected) in &cases {
        // Compile-time guard: a new variant breaks `assert_all_variants_known`.
        assert_all_variants_known(err);
        assert_eq!(err.code(), *expected, "wrong code for {err}");
    }
    // Only AuthFailed is the auth failure signal.
    assert!(Error::AuthFailed("x".to_string()).is_auth_failure());
    for (err, _) in &cases {
        if !matches!(err, Error::AuthFailed(_)) {
            assert!(!err.is_auth_failure(), "{err} must not be an auth failure");
        }
    }
}
