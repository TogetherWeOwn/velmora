//! The tenant seams, held by reading the source.
//!
//! [`velmora_bridge::tenant`] says where a tenant scope is made and
//! which code still names a blob without one. These tests read the
//! source of the library and of the Worker and hold both lists, so that
//! a change that makes a scope somewhere new, or names a blob past the
//! scope somewhere new, fails here and is looked at.
//!
//! Comment lines are not read: only code counts.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`, by its path from `root`.
fn sources(root: &Path, dir: &Path, into: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).expect("a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            sources(root, &path, into);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .strip_prefix(root)
                .expect("a path under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path).expect("a source file");
            into.insert(name, code(&text));
        }
    }
}

/// `text` without its comment lines.
fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The code of the library (`bridge/...`) and of the Worker
/// (`worker/...`).
fn all() -> BTreeMap<String, String> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut found = BTreeMap::new();
    for (name, dir) in [
        ("bridge", here.join("src")),
        ("worker", here.join("../../workers/s3-bridge/src")),
    ] {
        let mut files = BTreeMap::new();
        sources(&dir, &dir, &mut files);
        assert!(!files.is_empty(), "no source under {}", dir.display());
        for (file, text) in files {
            found.insert(format!("{name}/{file}"), text);
        }
    }
    found
}

/// How often each file says `what`; files that never do are left out.
fn uses(all: &BTreeMap<String, String>, what: &str) -> BTreeMap<String, usize> {
    all.iter()
        .map(|(file, text)| (file.clone(), text.matches(what).count()))
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// How often each file says `name` other than as `scope.<name>`.
fn unscoped(all: &BTreeMap<String, String>, name: &str) -> BTreeMap<String, usize> {
    all.iter()
        .map(|(file, text)| {
            let n = text
                .match_indices(name)
                .filter(|(at, _)| !text[..*at].ends_with("scope."))
                .count();
            (file.clone(), n)
        })
        .filter(|(_, n)| *n > 0)
        .collect()
}

/// Every file of `found` is in `allowed`, at most as often as there.
fn within(what: &str, found: &BTreeMap<String, usize>, allowed: &[(&str, usize)]) {
    for (file, n) in found {
        let most = allowed.iter().find(|(f, _)| f == file).map(|(_, n)| *n);
        assert!(
            most.is_some_and(|most| *n <= most),
            "{file} says `{what}` {n} times, allowed: {most:?}. \
             See the module documentation of `velmora_bridge::tenant`."
        );
    }
}

const TENANT: &str = "bridge/tenant.rs";

/// A scope is made where work enters with no tenant on it, and nowhere
/// else.
#[test]
fn a_scope_is_made_only_at_the_listed_places() {
    let all = all();
    let mut found = uses(&all, "tenant_zero");
    // The definition, and its own tests.
    assert!(found.remove(TENANT).is_some());
    within(
        "tenant_zero",
        &found,
        &[
            // The record layout `tenant` of the configuration.
            ("bridge/config.rs", 1),
            // The recovery copy: the tenant phases, and the other name
            // of a plan.
            ("bridge/copy.rs", 2),
            // The directory of a store with one tenant.
            ("bridge/directory.rs", 1),
            // The replay: the listing, and the plans of an extent.
            ("bridge/replay.rs", 3),
            // The queue consumer.
            ("worker/lib.rs", 1),
        ],
    );
    // The consumer does make one: the job path has its scope from it.
    assert_eq!(found.get("worker/lib.rs"), Some(&1));
}

/// One constructor, no `Default`, nothing that reads one from bytes.
#[test]
fn the_scope_has_one_constructor() {
    let all = all();
    let tenant = &all[TENANT];
    assert_eq!(tenant.matches("-> TenantScope").count(), 1);
    assert_eq!(
        tenant.matches("TenantScope {").count(),
        4,
        "the struct, its impl, the constructor and its one literal"
    );
    let derive = tenant
        .lines()
        .zip(tenant.lines().skip(1))
        .find(|(_, next)| next.starts_with("pub struct TenantScope"))
        .map(|(derive, _)| derive)
        .expect("the derive of the scope");
    assert_eq!(derive, "#[derive(Clone, Debug, PartialEq, Eq)]");
    for (file, text) in &all {
        for bad in [
            "Default for TenantScope",
            "Deserialize<'de> for TenantScope",
            "From<&str> for TenantScope",
            "From<String> for TenantScope",
            "FromStr for TenantScope",
        ] {
            assert!(!text.contains(bad), "{file}: {bad}");
        }
    }
    // No constructor under another spelling, and no conversion: in the
    // code of the module (its tests left out) the type is never made
    // through `Self`, and the field is named three times: the struct,
    // the one literal, and the parameter of `blob_key`.
    let module = tenant
        .split("#[cfg(test)]")
        .next()
        .expect("the module before its tests");
    assert!(!module.contains("Self"), "a second way to make a scope");
    assert_eq!(module.matches("tenant: ").count(), 3);
    assert_eq!(module.matches("fn tenant_zero").count(), 1);
    for (file, text) in &all {
        assert!(
            !text.contains(" for TenantScope"),
            "{file}: an impl of a trait"
        );
    }
    // The field is private: no other file can write the literal.
    assert!(tenant.contains("pub struct TenantScope {\n    tenant: &'static str,\n}"));
    let literals = uses(&all, "TenantScope {");
    assert_eq!(literals.keys().collect::<Vec<_>>(), [TENANT]);
}

/// The id of tenant 0 is written once, and taken by name in the two
/// modules that make names from it.
#[test]
fn the_id_of_tenant_zero_is_written_in_one_place() {
    let all = all();
    let mut literal = uses(&all, "t_0000000000000000");
    // The tests of the scope say the names in full.
    literal.remove(TENANT);
    assert_eq!(literal.keys().collect::<Vec<_>>(), ["bridge/recovery.rs"]);
    let named = uses(&all, "DEFAULT_TENANT");
    assert_eq!(
        named.keys().collect::<Vec<_>>(),
        ["bridge/recovery.rs", TENANT]
    );
}

/// The job path names no blob past its scope, and the places that still
/// do are the listed ones.
#[test]
fn a_blob_is_named_without_a_scope_only_at_the_listed_places() {
    let all = all();
    // Every way to say the two names counts, also a path to the
    // function or a variable called like it: all but a call on a scope.
    let mut found = unscoped(&all, "safety_key");
    for (file, n) in unscoped(&all, "cache_key") {
        *found.entry(file).or_default() += n;
    }
    // The scope itself: for tenant 0 it answers with the old names.
    assert!(found.remove(TENANT).is_some());
    within(
        "safety_key or cache_key, not of a scope,",
        &found,
        &[
            // The two definitions.
            ("bridge/types.rs", 2),
            // The request path: a request is not scoped yet.
            ("bridge/fetch.rs", 1),
            ("bridge/service/admin.rs", 3),
            ("bridge/service/get.rs", 2),
            // One call, and a variable of the name said twice.
            ("bridge/service/multipart.rs", 3),
            ("bridge/service/put.rs", 1),
            ("bridge/service/slices.rs", 1),
            // The replay, which goes through the whole store.
            ("bridge/replay.rs", 2),
            // The delete list the catalogue makes for garbage
            // collection: rows carry no tenant yet.
            ("bridge/sql/gc.rs", 2),
        ],
    );
    for job_path in [
        "bridge/jobs.rs",
        "bridge/post.rs",
        "bridge/verify.rs",
        "bridge/intents.rs",
    ] {
        assert!(all.contains_key(job_path), "{job_path} is gone");
        assert!(!found.contains_key(job_path), "{job_path}");
    }
    // The records the job path writes are named in the layout of its
    // scope: the configured layout is never used as it was read.
    for job_path in [
        "bridge/jobs.rs",
        "bridge/post.rs",
        "bridge/verify.rs",
        "bridge/intents.rs",
    ] {
        let text = &all[job_path];
        assert_eq!(
            text.matches(".records").count(),
            text.matches(".records.in_scope(scope)").count(),
            "{job_path}: the record layout of the configuration, not of the scope"
        );
    }
    assert_eq!(
        all["bridge/post.rs"]
            .matches(".records.in_scope(scope)")
            .count(),
        1
    );
    // And no name of the two families is written out by hand.
    for family in ["\"x/", "\"c/"] {
        let found = uses(&all, family);
        let files: Vec<&String> = found.keys().collect();
        assert_eq!(files, ["bridge/tenant.rs", "bridge/types.rs"], "{family}");
    }
}

/// The layouts are asked of a scope: the two functions that named
/// tenant 0 themselves are gone.
#[test]
fn a_layout_of_a_tenant_comes_from_a_scope() {
    let all = all();
    assert!(uses(&all, "default_tenant(").is_empty());
    assert!(uses(&all, "Layout::all()").is_empty());
    assert_eq!(
        all["bridge/recovery.rs"]
            .matches("pub fn of(scope: &TenantScope)")
            .count(),
        1
    );
    assert_eq!(
        all["bridge/recovery.rs"]
            .matches("pub fn all(scope: &TenantScope)")
            .count(),
        1
    );
}

/// Nothing writes, reads or lists the reserved names.
#[test]
fn the_reserved_names_are_used_by_nothing() {
    let all = all();
    for name in ["BUCKET_CONFIG_DIR", "CATALOGUE_DUMP_PREFIX", "\"cb/"] {
        let found = uses(&all, name);
        let files: Vec<&String> = found.keys().filter(|f| *f != TENANT).collect();
        assert!(files.is_empty(), "{name}: {files:?}");
    }
}

/// The catalogue id is read from the configuration in one place, the
/// accessor of the bridge. The request path asks the accessor too: the
/// end of a restore makes the stamp row under the id the stamp is then
/// asked with. A bridge of a unit will answer there with the id of its
/// unit.
/// The scope has no part in it: the id is not made from a tenant.
#[test]
fn the_catalogue_id_is_read_in_one_place() {
    let all = all();
    // Any reading of the field, whatever the variable before it; a
    // call of the accessor is not one.
    let found: BTreeMap<String, usize> = all
        .iter()
        .map(|(file, text)| {
            let n = text
                .split(".catalogue_id")
                .skip(1)
                .filter(|rest| !rest.starts_with('('))
                .count();
            (file.clone(), n)
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    within(
        "`.catalogue_id`",
        &found,
        &[
            // `Bridge::catalogue_id`.
            ("bridge/stamp.rs", 1),
        ],
    );
    assert_eq!(found.get("bridge/stamp.rs"), Some(&1));
    assert_eq!(
        all["bridge/stamp.rs"]
            .matches("pub fn catalogue_id(&self) -> &str")
            .count(),
        1
    );
    // The stamp is the one user of the id in the library, and it asks
    // the accessor every time.
    assert_eq!(all["bridge/stamp.rs"].matches(".catalogue_id()").count(), 9);
    // The end of a restore makes or levels the stamp row: it asks the
    // accessor, as the stamp does that is read under that row after.
    assert_eq!(
        all["bridge/service/admin.rs"]
            .matches("bridge.catalogue_id()")
            .count(),
        1
    );
    assert!(!all[TENANT].contains("catalogue_id"));
    assert!(!all["bridge/directory.rs"].contains("catalogue_id"));
}

/// The directory is a port and one adapter, and nothing asks it yet: no
/// request and no job is routed by it.
#[test]
fn the_directory_is_asked_by_nothing() {
    let all = all();
    const DIRECTORY: &str = "bridge/directory.rs";
    for name in ["Directory", "SingleTenant", "directory::", ".route("] {
        let found = uses(&all, name);
        let files: Vec<&String> = found.keys().filter(|f| *f != DIRECTORY).collect();
        assert!(files.is_empty(), "{name}: {files:?}");
    }
    // One method, and one adapter.
    let directory = &all[DIRECTORY];
    assert_eq!(directory.matches("fn ").count(), 2);
    assert_eq!(directory.matches("impl Directory for ").count(), 1);
}

/// The reader of this test is not fooled by its own helper.
#[test]
fn comment_lines_are_not_code() {
    let text = "// tenant_zero(\nlet a = 1; // b\n    /// .safety_key()\nx.safety_key()";
    assert_eq!(code(text), "let a = 1; // b\nx.safety_key()");
}
