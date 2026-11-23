//! Offline, explicitly invoked record staging adapter. Network and escrow
//! locations are the caller's concern; the key ring is read on stdin only.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use velmora_bridge::config::KekRing;
use velmora_kit::{
    build_entries, read_index, verify_packs, write_index, BuildAnnotations, Entry, Error,
};
use zeroize::Zeroizing;

mod sample;

fn staged_record(staging: &Path, name: &str) -> Result<Option<Vec<u8>>, Error> {
    if !velmora_kit::eligible_record(name) {
        return Err(Error::Format);
    }
    let path = staging.join(name);
    let canonical = path.canonicalize().map_err(|_| Error::Io)?;
    if canonical != path || !canonical.starts_with(staging) || !canonical.is_file() {
        return Err(Error::Format);
    }
    fs::read(canonical).map(Some).map_err(|_| Error::Io)
}

fn read_keys(active: u32) -> Result<KekRing, Error> {
    let mut keys = BTreeMap::new();
    let mut input = io::stdin().lock();
    loop {
        let mut line = Zeroizing::new(String::new());
        if input.read_line(&mut line).map_err(|_| Error::Io)? == 0 {
            break;
        }
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name
            .strip_prefix("VELMORA_KEK_")
            .is_some_and(|v| v.parse::<u32>().is_ok())
        {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(value);
            if keys
                .insert(name.to_owned(), Zeroizing::new(value.to_owned()))
                .is_some()
            {
                return Err(Error::Authentication);
            }
        }
    }
    KekRing::from_vars(active, |key| keys.get(key).map(|s| s.as_str().to_owned()))
        .map_err(|_| Error::Authentication)
}

fn run() -> Result<(), Error> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if let [action, full_id, sample_id, active, full_index, staging, evidence, listing, index] =
        args.as_slice()
    {
        if action == "sample" {
            let active = active
                .to_str()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::Format)?;
            let kek = read_keys(active)?;
            let all = read_index(
                File::open(full_index).map_err(|_| Error::Io)?,
                full_id.to_str().ok_or(Error::Format)?,
                &kek,
            )?;
            let evidence: Vec<sample::Evidence> = serde_json::from_reader(BufReader::new(
                File::open(evidence).map_err(|_| Error::Io)?,
            ))
            .map_err(|_| Error::Format)?;
            let sample_id = sample_id.to_str().ok_or(Error::Format)?;
            let candidates = sample::match_candidates(&all, &evidence);
            let objects = sample::choose(&all, &candidates, sample_id)?;
            let staging = Path::new(staging);
            let selected = sample::records(&all, &objects, |n| staged_record(staging, n), &kek)?;
            let source_md5 = objects
                .iter()
                .map(|o| {
                    (
                        o.generation_id.clone(),
                        o.source_md5.as_ref().unwrap().to_vec(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            drop(all);
            let ann = BuildAnnotations {
                source_md5,
                ..BuildAnnotations::default()
            };
            let entries = build_entries(
                selected.names.iter().cloned(),
                |n| staged_record(staging, n),
                &kek,
                &ann,
            )?;
            let live: std::collections::BTreeSet<_> = entries
                .iter()
                .filter_map(|e| match e {
                    Entry::Object(o) => Some(o.generation_id.as_str()),
                    _ => None,
                })
                .collect();
            if live != ann.source_md5.keys().map(String::as_str).collect() {
                return Err(Error::Coverage);
            }
            let index = File::options()
                .write(true)
                .create_new(true)
                .open(index)
                .map_err(|_| Error::Io)?;
            write_index(BufWriter::new(&index), sample_id, &kek, &entries)?;
            index.sync_all().map_err(|_| Error::Io)?;
            let file = File::options()
                .write(true)
                .create_new(true)
                .open(listing)
                .map_err(|_| Error::Io)?;
            let mut out = BufWriter::new(file);
            serde_json::to_writer(&mut out, &selected.names).map_err(|_| Error::Io)?;
            out.flush().map_err(|_| Error::Io)?;
            println!(
                "{}",
                serde_json::json!({ "live_objects": live.len(), "record_refs": selected.names.len(), "overwritten_objects": selected.overwritten, "deleted_key_included": selected.deleted })
            );
            return Ok(());
        }
    }
    if let [action, kit_id, active, index, packs @ ..] = args.as_slice() {
        if action == "verify-packs" {
            let active = active
                .to_str()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::Format)?;
            let kek = read_keys(active)?;
            let entries = read_index(
                File::open(index).map_err(|_| Error::Io)?,
                kit_id.to_str().ok_or(Error::Format)?,
                &kek,
            )?;
            let packs = packs
                .iter()
                .map(File::open)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Error::Io)?;
            return verify_packs(packs, &entries);
        }
    }
    let [action, kit_id, active, staging, listing, annotations, index, coverage @ ..] =
        args.as_slice()
    else {
        return Err(Error::Format);
    };
    if coverage.len() > 1 {
        return Err(Error::Format);
    }
    if action != "build" {
        return Err(Error::Format);
    }
    let kit_id = kit_id.to_str().ok_or(Error::Format)?;
    let active = active
        .to_str()
        .and_then(|s| s.parse().ok())
        .ok_or(Error::Format)?;
    let kek = read_keys(active)?;
    let staging = Path::new(staging);
    let names: Vec<String> =
        serde_json::from_reader(BufReader::new(File::open(listing).map_err(|_| Error::Io)?))
            .map_err(|_| Error::Format)?;
    let ann: BuildAnnotations = serde_json::from_reader(BufReader::new(
        File::open(annotations).map_err(|_| Error::Io)?,
    ))
    .map_err(|_| Error::Format)?;
    let entries = build_entries(names, |name| staged_record(staging, name), &kek, &ann)?;
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(index)
        .map_err(|_| Error::Io)?;
    write_index(BufWriter::new(&file), kit_id, &kek, &entries)?;
    file.sync_all().map_err(|_| Error::Io)?;
    let mut counts = BTreeMap::new();
    for entry in &entries {
        let key = match entry {
            Entry::Bucket(_) => "buckets",
            Entry::Object(_) => "objects",
            Entry::Extent(extent) if extent.plan_rev.is_none() => "extents_without_plan",
            Entry::Extent(_) => "extents_with_plan",
            Entry::RecordRef(_) => "record_refs",
        };
        *counts.entry(key).or_insert(0u64) += 1;
    }
    let plans: std::collections::HashMap<_, _> = entries
        .iter()
        .filter_map(|entry| match entry {
            Entry::Extent(e) => Some((e.id.as_str(), e.plan_rev)),
            _ => None,
        })
        .collect();
    let mut detail = coverage
        .first()
        .map(|path| {
            File::options()
                .write(true)
                .create_new(true)
                .open(path)
                .map(BufWriter::new)
        })
        .transpose()
        .map_err(|_| Error::Io)?;
    for entry in &entries {
        let row = match entry {
            Entry::Object(o) => {
                let all = o
                    .extents
                    .iter()
                    .all(|r| plans.get(r.id.as_str()).is_some_and(Option::is_some));
                let state = if all {
                    "plans-recorded-release-unknown"
                } else {
                    "missing-article-plan"
                };
                let key = if all {
                    "objects_with_all_plans_release_unknown"
                } else {
                    "objects_missing_plan"
                };
                *counts.entry(key).or_insert(0) += 1;
                serde_json::json!({"type":"object", "id":o.generation_id, "extent_count":o.extents.len(), "state":state})
            }
            Entry::Extent(e) => {
                let state = if e.plan_rev.is_some() {
                    "plan-recorded-release-unknown"
                } else {
                    "missing-article-plan"
                };
                serde_json::json!({"type":"extent", "id":e.id, "state":state})
            }
            _ => continue,
        };
        if let Some(out) = &mut detail {
            serde_json::to_writer(&mut *out, &row).map_err(|_| Error::Io)?;
            out.write_all(b"\n").map_err(|_| Error::Io)?;
        }
    }
    if let Some(mut file) = detail {
        file.flush().map_err(|_| Error::Io)?;
    }
    drop(plans);
    drop(entries);
    // Read our own sealed output before handing it to the packager.
    let verified = read_index(File::open(index).map_err(|_| Error::Io)?, kit_id, &kek)?;
    if counts.get("record_refs").copied().unwrap_or(0)
        != verified
            .iter()
            .filter(|e| matches!(e, Entry::RecordRef(_)))
            .count() as u64
    {
        return Err(Error::Format);
    }
    println!(
        "{}",
        serde_json::to_string(&counts).map_err(|_| Error::Format)?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("velmora-kit: {error}");
        if error == Error::Format {
            eprintln!("usage: velmora-kit build <kit-id> <active-kek-version> <canonical-staging-directory> <record-list-json> <annotations-json> <new-index-path> (KEK on stdin)");
        }
        std::process::exit(1);
    }
}
