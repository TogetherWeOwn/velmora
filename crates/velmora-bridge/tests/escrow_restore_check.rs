//! The operator's restore test of a tenant-key escrow copy.
//!
//! Not a CI test: it is `#[ignore]`d and runs only when an operator
//! points it at real files, on the machine that holds the KEK's escrow:
//!
//! ```text
//! VELMORA_ESCROW_FILE=<escrow copy> \
//! VELMORA_ESCROW_KEK_ENV=<file with VELMORA_KEK_<v>= lines> \
//! VELMORA_ESCROW_BLOBS=<blob read from KEYS_A>,<blob read from KEYS_B> \
//! VELMORA_ESCROW_KEY_RECORD=<seq>:<newest key-chain record file> \
//! VELMORA_ESCROW_DATA_RECORD=<record name>:<VMR2 record file> \
//! cargo test -p velmora-bridge --test escrow_restore_check -- --ignored --nocapture
//! ```
//!
//! It prints one line per check, `<check>: match` or `<check>: mismatch`,
//! and the SHA-256 of the escrow file, and nothing else: no key, no
//! secret, no record content, no path. It fails when any check is a
//! mismatch. The KEK file is read inside the process.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use velmora_bridge::config::KekRing;
use velmora_bridge::keys::escrow::{restore_check, EscrowCopy};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn read(path: &str) -> Vec<u8> {
    // A failed read must not print the path or the error's text.
    std::fs::read(path).unwrap_or_else(|_| panic!("a file named by the environment is unreadable"))
}

/// `NAME=value` lines; anything else is skipped. Values never printed.
fn env_file(path: &str) -> BTreeMap<String, String> {
    let text = String::from_utf8(read(path)).unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().split_once('='))
        .map(|(k, v)| {
            (
                k.trim().trim_start_matches("export ").to_owned(),
                v.trim().trim_matches('"').trim_matches('\'').to_owned(),
            )
        })
        .collect()
}

#[test]
#[ignore = "operator tool: needs the escrow copy and the KEK on this machine"]
fn the_escrow_copy_restores_the_tenant_key() {
    let (Some(escrow), Some(kek_env)) = (var("VELMORA_ESCROW_FILE"), var("VELMORA_ESCROW_KEK_ENV"))
    else {
        panic!("VELMORA_ESCROW_FILE and VELMORA_ESCROW_KEK_ENV are required");
    };
    let text = read(&escrow);
    println!("escrow file sha256: {}", hex(&Sha256::digest(&text)));
    let copy = EscrowCopy::parse(std::str::from_utf8(&text).unwrap_or(""))
        .unwrap_or_else(|_| panic!("escrow: mismatch (the copy does not parse)"));

    let vars = env_file(&kek_env);
    let active = vars
        .get("VELMORA_KEK_ACTIVE")
        .and_then(|v| v.parse().ok())
        .unwrap_or(copy.kek_version);
    let kek = KekRing::from_vars(active, |n| vars.get(n).cloned())
        .unwrap_or_else(|_| panic!("the KEK file does not hold a usable KEK"));

    let blobs: Vec<Vec<u8>> = var("VELMORA_ESCROW_BLOBS")
        .map(|v| v.split(',').map(read).collect())
        .unwrap_or_default();
    let key_record = var("VELMORA_ESCROW_KEY_RECORD").map(|v| {
        let (seq, path) = v.split_once(':').expect("<seq>:<file>");
        (seq.parse::<u64>().expect("a seq"), read(path))
    });
    let data_record = var("VELMORA_ESCROW_DATA_RECORD").map(|v| {
        let (name, path) = v.rsplit_once(':').expect("<name>:<file>");
        (name.to_owned(), read(path))
    });

    let checks = restore_check(
        &copy,
        &kek,
        &blobs,
        key_record.as_ref().map(|(s, b)| (*s, b.as_slice())),
        data_record
            .as_ref()
            .map(|(n, b)| (n.as_str(), b.as_slice())),
    );
    let mut all = true;
    for (check, ok) in &checks {
        println!("{check}: {}", if *ok { "match" } else { "mismatch" });
        all &= ok;
    }
    assert!(all, "at least one check is a mismatch");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
