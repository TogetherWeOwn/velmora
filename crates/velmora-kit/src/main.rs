//! Offline, explicitly invoked record staging adapter. Network and escrow
//! locations are the caller's concern; the key ring is read on stdin only.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use velmora_bridge::config::KekRing;
use velmora_kit::{
    build_entries_with_stats, read_index, verify_packs, write_index, BuildAnnotations, Entry, Error,
};
use zeroize::Zeroizing;

mod output;
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
    const INPUT_MAX: usize = 1024 * 1024;
    let mut input = Zeroizing::new(Vec::with_capacity(INPUT_MAX + 2));
    io::stdin()
        .lock()
        .take(INPUT_MAX as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| Error::Io)?;
    if input.len() > INPUT_MAX {
        return Err(Error::Authentication);
    }
    parse_key_input(active, &input)
}

fn parse_key_input(active: u32, input: &[u8]) -> Result<KekRing, Error> {
    let text = std::str::from_utf8(input).map_err(|_| Error::Authentication)?;
    let mut keys = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let Some(version) = name
            .strip_prefix("VELMORA_KEK_")
            .and_then(|v| v.parse::<u32>().ok())
        else {
            continue;
        };
        if version == 0 || version > active {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(value);
        let key = KekRing::decode_key(value).ok_or(Error::Authentication)?;
        if keys.insert(version, key).is_some() {
            return Err(Error::Authentication);
        }
    }
    KekRing::from_keys(active, keys).map_err(|_| Error::Authentication)
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
            let live_count = objects.len();
            let projection = sample::Projection::new(&objects, &selected.names);
            let entries = projection.apply(all)?;
            let index = output::Staged::new(Path::new(index))?;
            let listing = output::Staged::new(Path::new(listing))?;
            write_index(BufWriter::new(&index.file), sample_id, &kek, &entries)?;
            let mut out = BufWriter::new(&listing.file);
            serde_json::to_writer(&mut out, &selected.names).map_err(|_| Error::Io)?;
            out.flush().map_err(|_| Error::Io)?;
            output::publish(&[&listing, &index])?;
            println!(
                "{}",
                serde_json::json!({ "live_objects": live_count, "record_refs": selected.names.len(), "overwritten_objects": selected.overwritten, "deleted_key_included": selected.deleted })
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
    let (entries, build_stats) =
        build_entries_with_stats(names, |name| staged_record(staging, name), &kek, &ann)?;
    let index = output::Staged::new(Path::new(index))?;
    write_index(BufWriter::new(&index.file), kit_id, &kek, &entries)?;
    let mut counts = BTreeMap::from([("parity_omitted", build_stats.parity_omitted)]);
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
    let cover = coverage
        .first()
        .map(|path| output::Staged::new(Path::new(path)))
        .transpose()?;
    let mut detail = cover.as_ref().map(|out| BufWriter::new(&out.file));
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
    let verified = read_index(index.reopen()?, kit_id, &kek)?;
    if counts.get("record_refs").copied().unwrap_or(0)
        != verified
            .iter()
            .filter(|e| matches!(e, Entry::RecordRef(_)))
            .count() as u64
    {
        return Err(Error::Format);
    }
    let summary = serde_json::to_string(&counts).map_err(|_| Error::Format)?;
    let outputs: Vec<_> = cover.iter().chain([&index]).collect();
    output::publish(&outputs)?;
    println!("{summary}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("velmora-kit: {error}");
        if error == Error::Format {
            eprintln!(concat!(
                "usage (KEK on stdin for all verbs):\n",
                "  velmora-kit build <kit-id> <active-kek-version> <canonical-staging-dir> <record-list-json> <annotations-json> <new-index> [new-coverage-jsonl]\n",
                "  velmora-kit sample <full-id> <sample-id> <active-kek-version> <full-index> <canonical-staging-dir> <evidence-json> <new-record-list-json> <new-index>\n",
                "  velmora-kit verify-packs <kit-id> <active-kek-version> <index> [pack.tar.zst ...]",
            ));
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_bridge::ports::Kek;

    #[test]
    fn stdin_parser_accepts_owned_versioned_keys_and_rejects_duplicate_or_invalid_keys() {
        const SYNTHETIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let input = format!("unrelated=ignored\nexport VELMORA_KEK_1='{SYNTHETIC}'\nVELMORA_KEK_3=\"{SYNTHETIC}\"\n");
        let ring = parse_key_input(3, input.as_bytes()).unwrap();
        assert_eq!(ring.active().0, 3);
        assert!(ring.version(1).is_some());
        assert!(ring.version(2).is_none());
        assert!(parse_key_input(4, input.as_bytes()).is_err());
        assert!(
            parse_key_input(3, format!("{input}VELMORA_KEK_3={SYNTHETIC}").as_bytes()).is_err()
        );
        assert!(parse_key_input(3, b"VELMORA_KEK_3=AA==\n").is_err());
    }
}
