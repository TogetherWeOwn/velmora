//! S7 RED: forced-401 fixture must surface the documented
//! `provider_auth_expired` code, never credential material.

use nntune_core::error::{Error, PROVIDER_AUTH_EXPIRED_CODE};

#[test]
fn documented_code_is_provider_auth_expired() {
    assert_eq!(PROVIDER_AUTH_EXPIRED_CODE, "provider_auth_expired");
}

#[test]
fn auth_failed_maps_to_documented_code() {
    let err = Error::AuthFailed("481 bad login".to_string());
    assert_eq!(err.code(), PROVIDER_AUTH_EXPIRED_CODE);
    assert!(err.is_auth_failure());
}

#[test]
fn auth_failed_display_hides_server_detail_and_secrets() {
    let secret_password = "s3cret-provider-password";
    let err = Error::AuthFailed(format!("481 bad login for {secret_password}"));
    let rendered = err.to_string();
    assert!(
        !rendered.contains(secret_password),
        "credential material in Display: {rendered}"
    );
    assert!(
        !rendered.contains("481 bad login"),
        "server detail echoed in Display: {rendered}"
    );
    assert!(
        rendered.contains(PROVIDER_AUTH_EXPIRED_CODE),
        "Display must carry the documented code: {rendered}"
    );
}

#[test]
fn no_permission_redacts_text_and_is_not_an_auth_failure() {
    // 502 replies are drawn from the same AUTHINFO exchange as 481: the
    // text must be redacted, but the code must NOT trigger re-auth (502
    // also means service unavailable).
    let secret_password = "s3cret-provider-password";
    let err = Error::NoPermission(format!("502 denied for {secret_password}"));
    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains(secret_password),
            "credential material in NoPermission rendering: {rendered}"
        );
        assert!(
            !rendered.contains("502 denied"),
            "server detail echoed in NoPermission rendering: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "no redaction marker in NoPermission rendering: {rendered}"
        );
    }
    assert_eq!(err.code(), "request_failed");
    assert!(!err.is_auth_failure());
}

#[test]
fn auth_failed_debug_hides_server_detail_and_secrets() {
    // `{:?}` is what tracing/dbg!/assert messages print: it must redact the
    // server reply text exactly like Display does.
    let secret_password = "s3cret-provider-password";
    let err = Error::AuthFailed(format!("481 bad login for {secret_password}"));
    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains(secret_password),
        "credential material in Debug: {rendered}"
    );
    assert!(
        !rendered.contains("481 bad login"),
        "server detail echoed in Debug: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "no redaction marker in Debug: {rendered}"
    );
}
