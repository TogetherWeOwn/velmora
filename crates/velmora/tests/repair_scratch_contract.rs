//! Scratch-prefix contract shared by ingest, the repair Worker and the
//! repair Container: one canonical prefix shape, safe file names, and
//! content keys derived from file names (never from caller input alone).

use nntune_core::par2::scratch::{
    object_key_for_file_name, scratch_prefix, validate_file_name, validate_object_key,
    validate_scratch_prefix,
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
