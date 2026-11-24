//! Opt-in native test coverage recorder. Records SQL identity and wire
//! parameter types, never bound values. Each process has its own append log.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static OUTPUT: Mutex<()> = Mutex::new(());

#[derive(serde::Serialize)]
struct Statement<'a> {
    sql: &'a str,
    parameter_oids: Vec<u32>,
}

pub(super) fn record(sql: &str, parameter_oids: impl Iterator<Item = u32>) {
    let Some(dir) = std::env::var_os("VELMORA_PG_STATEMENTS_DIR") else {
        return;
    };
    let path = PathBuf::from(dir).join(format!("{}.jsonl", std::process::id()));
    let mut entry = serde_json::to_vec(&Statement {
        sql,
        parameter_oids: parameter_oids.collect(),
    })
    .expect("serialize PG statement identity");
    entry.push(b'\n');
    let _guard = OUTPUT.lock().expect("PG statement recorder lock");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(&entry))
        .expect("write PG statement identity to VELMORA_PG_STATEMENTS_DIR");
}
