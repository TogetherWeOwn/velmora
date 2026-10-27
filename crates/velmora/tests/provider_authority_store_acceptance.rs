// NON-AUTHORITATIVE / NOT INSTALLED. Adapter is implemented by the Builder.
#![allow(dead_code)]
#[path = "support/provider_authority_store_adapter.rs"]
mod adapter;
#[path = "fixtures/provider_authority_store_cases.rs"]
mod cases;
#[path = "fixtures/provider_authority_store_contract.rs"]
mod contract;

#[test]
fn static_schema_writer_and_containment_acceptance_runs_in_cargo_ci() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .args([
            "-B",
            ".github/scripts/test_provider_authority_store_acceptance.py",
            "--static-only",
        ])
        .current_dir(root)
        .output()
        .expect("hermetic Python acceptance runner");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
