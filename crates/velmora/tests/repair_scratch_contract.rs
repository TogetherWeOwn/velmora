//! Scratch-prefix contract shared by ingest, the repair Worker and the
//! repair Container: one canonical prefix shape, safe file names, and
//! content keys derived from file names (never from caller input alone).

use nntune_core::par2::scratch::{
    object_key_for_file_name, scratch_prefix, validate_file_name, validate_object_key,
    validate_scratch_prefix, validate_staging_id,
};

#[test]
fn prefix_is_canonical_for_job_and_round() {
    assert_eq!(
        scratch_prefix("job_0123456789abcdef", 2).as_deref(),
        Some("ingest-scratch/job_0123456789abcdef/r2/")
    );
    assert!(validate_scratch_prefix(
        "ingest-scratch/job_0123456789abcdef/r2/",
        "job_0123456789abcdef",
        2
    ));
}

#[test]
fn prefix_rejects_mismatched_or_traversing_shapes() {
    let job = "job_0123456789abcdef";
    assert!(!validate_scratch_prefix(
        "ingest-scratch/job_0123456789abcdef/r1/",
        job,
        2
    ));
    assert!(!validate_scratch_prefix("ingest-scratch/other/r2/", job, 2));
    assert!(!validate_scratch_prefix(
        "ingest-scratch/job_0123456789abcdef/r2",
        job,
        2
    ));
    assert!(!validate_scratch_prefix(
        "ingest-scratch/job_0123456789abcdef/r2/in/",
        job,
        2
    ));
    assert!(!validate_scratch_prefix(
        "other/job_0123456789abcdef/r2/",
        job,
        2
    ));
    assert_eq!(scratch_prefix("../etc", 1), None);
    assert_eq!(scratch_prefix("a/b", 1), None);
    assert_eq!(scratch_prefix("", 1), None);
    assert_eq!(scratch_prefix(job, 0), None);
}

#[test]
fn file_names_are_single_safe_components() {
    assert!(validate_file_name("track01.flac"));
    assert!(validate_file_name("release.vol001+02.par2"));
    assert!(!validate_file_name(""));
    assert!(!validate_file_name("."));
    assert!(!validate_file_name(".."));
    assert!(!validate_file_name("../track.flac"));
    assert!(!validate_file_name("dir/track.flac"));
    assert!(!validate_file_name("dir\\track.flac"));
    assert!(!validate_file_name("track\0.flac"));
    assert!(!validate_file_name(&"x".repeat(256)));
}

#[test]
fn object_keys_are_sha256_of_file_name() {
    let key = object_key_for_file_name("track01.flac");
    assert!(validate_object_key(&key));
    assert_eq!(key, object_key_for_file_name("track01.flac"));
    assert_ne!(key, object_key_for_file_name("track02.flac"));
    assert!(!validate_object_key("track01.flac"));
    assert!(!validate_object_key(&"A".repeat(64)));
    assert!(!validate_object_key(&"a".repeat(63)));
}

#[test]
fn staging_ids_accept_bounded_charset() {
    // Accept: boundary lengths 16 and 128, the current 64-char hex shape,
    // and every allowed charset class (upper, lower, digit, `-`, `_`).
    assert!(validate_staging_id(&"a".repeat(16)), "len 16 accepts");
    assert!(validate_staging_id(&"a".repeat(128)), "len 128 accepts");
    assert!(
        validate_staging_id(&"0123456789abcdef".repeat(4)),
        "64-char hex accepts"
    );
    assert!(validate_staging_id(&"A".repeat(16)), "uppercase accepts");
    assert!(validate_staging_id(&"0".repeat(16)), "digits accept");
    assert!(
        validate_staging_id(&"Ab0-_".repeat(4)),
        "mixed [A-Za-z0-9_-] accepts"
    );
    assert!(
        validate_staging_id("Ab0-_Cd1-_Ef2-_G"),
        "mixed 16-char member accepts"
    );

    // Reject: one below the minimum and one above the maximum, plus empty.
    assert!(!validate_staging_id(&"a".repeat(15)), "len 15 rejects");
    assert!(!validate_staging_id(&"a".repeat(129)), "len 129 rejects");
    assert!(!validate_staging_id(""), "empty rejects");

    // Reject: bad-charset members at otherwise valid lengths. Each case is
    // 16 chars (the minimum) with one disallowed byte, plus one 64-char
    // member proving length does not excuse charset.
    for bad in ['!', '/', '.', ' ', '+', ':', '@', '#'] {
        let member = format!("{bad}{}", "a".repeat(15));
        assert_eq!(member.len(), 16);
        assert!(
            !validate_staging_id(&member),
            "charset member {bad:?} rejects at len 16"
        );
    }
    let long_bad = format!("{}!", "a".repeat(63));
    assert_eq!(long_bad.len(), 64);
    assert!(
        !validate_staging_id(&long_bad),
        "trailing '!' rejects at len 64"
    );
    assert!(
        !validate_staging_id(&format!("{} {}", "a".repeat(7), "b".repeat(8))),
        "embedded space rejects at len 16"
    );
}
