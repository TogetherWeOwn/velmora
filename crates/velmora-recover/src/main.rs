use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use velmora::rng::{uniform_below, SystemRng};
use velmora_bridge::config::KekRing;
use velmora_recover::{
    catalogue::{Catalogue, CatalogueReader, Selection},
    extent::BodySource,
    keys::{read_keyring, read_secret},
    kit::Kit,
    nzb::write_nzb,
    resume::OutputRoot,
    source::{Downloads, NntpSource, RelaySource},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Recover authenticated files from a sealed recovery kit"
)]
struct Cli {
    #[arg(long, global = true, value_name = "DIR")]
    kit: Option<PathBuf>,
    /// Path to a raw/hex KEK or versioned KEK ring, or - for stdin.
    #[arg(long, global = true, value_name = "FILE|-", allow_hyphen_values = true)]
    kek_file: Option<PathBuf>,
    /// Active KEK version override. Defaults to 1 for a single raw/hex key.
    #[arg(long, global = true)]
    kek_version: Option<u32>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List live objects; availability refers to the Usenet plan, not current retention.
    Ls(Filter),
    /// Export an NZB for a bucket or a single BUCKET/KEY.
    Nzb {
        #[arg(long, required_unless_present = "object", conflicts_with = "object")]
        bucket: Option<String>,
        #[arg(long, required_unless_present = "bucket", value_name = "BUCKET/KEY")]
        object: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Fetch ciphertext articles, authenticate and restore local files.
    Get {
        #[command(flatten)]
        filter: Filter,
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        network: Network,
    },
    /// Restore from ciphertext downloaded with an NZB client; no network use.
    Decrypt {
        #[command(flatten)]
        filter: Filter,
        #[arg(long)]
        from_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sample, fetch and authenticate live objects without writing files.
    Check {
        #[arg(long)]
        sample: u32,
        #[command(flatten)]
        network: Network,
    },
    /// Authenticate the entire kit, including original sealed record names.
    VerifyKit,
}

#[derive(Args, Default)]
struct Filter {
    #[arg(long)]
    bucket: Option<String>,
    #[arg(long, conflicts_with = "prefix", requires = "bucket")]
    key: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
}

impl Filter {
    fn select<'a>(&self, catalogue: &'a Catalogue) -> Vec<Selection<'a>> {
        catalogue.select(
            self.bucket.as_deref(),
            self.key.as_deref(),
            self.prefix.as_deref(),
        )
    }
}

#[derive(Args)]
struct Network {
    #[arg(long, value_enum, default_value_t = Transport::Nntp)]
    transport: Transport,
    #[arg(long)]
    providers: Option<PathBuf>,
    #[arg(long, requires = "relay_token_file", conflicts_with = "providers")]
    relay_url: Option<String>,
    #[arg(long, requires = "relay_url")]
    relay_token_file: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Transport {
    Nntp,
    Relay,
}

enum Source {
    Nntp(NntpSource),
    Relay(RelaySource),
}

impl Network {
    fn open(self) -> Result<Source, &'static str> {
        match (
            self.transport,
            self.providers,
            self.relay_url,
            self.relay_token_file,
        ) {
            (Transport::Nntp, Some(path), None, None) => {
                let config = read_file(&path, 64 * 1024)
                    .map_err(|_| "could not read provider configuration")?;
                Ok(Source::Nntp(NntpSource::from_toml(&config)?))
            }
            (Transport::Relay, None, Some(url), Some(path)) => {
                let token = read_file(&path, 256).map_err(|_| "could not read relay token file")?;
                Ok(Source::Relay(RelaySource::new(&url, &token)?))
            }
            (Transport::Relay, ..) => {
                Err("relay mode requires --relay-url and --relay-token-file, and no --providers")
            }
            (Transport::Nntp, ..) => Err("NNTP mode requires --providers and no relay options"),
        }
    }
}

fn read_file(path: &Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    read_secret(File::open(path)?, limit)
}

fn load_kek(path: &Path, version: Option<u32>) -> Result<KekRing, &'static str> {
    if path == Path::new("-") {
        read_keyring(io::stdin().lock(), version)
    } else {
        read_keyring(File::open(path).map_err(|_| "could not read KEK")?, version)
    }
}

fn emit(data: serde_json::Value) -> io::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &data).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}

async fn restore(
    catalogue: &Catalogue,
    objects: &[Selection<'_>],
    kek: &KekRing,
    source: &mut impl BodySource,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if objects.is_empty() {
        return Err("no matching live objects".into());
    }
    let mut output = OutputRoot::open(path)?;
    let (mut recovered, mut failed, mut unmapped) = (0, 0, 0);
    for choice in objects {
        match catalogue.restore(choice, kek, source, &mut output).await {
            Ok(result) => {
                recovered += 1;
                unmapped += usize::from(result.unmapped);
                emit(
                    serde_json::json!({"bucket": choice.bucket.name, "key": choice.object.key, "generation_id": choice.object.generation, "result": result}),
                )?;
            }
            Err(error) => {
                // JSON escaping keeps hostile or unusual filenames from being interpreted as terminal controls.
                emit(
                    serde_json::json!({"bucket": choice.bucket.name, "key": choice.object.key, "generation_id": choice.object.generation, "error": error.to_string()}),
                )?;
                // I/O failures may leave a torn journal line or indicate a full
                // volume. Reopen and replay the state before further writes.
                if error.is::<io::Error>() {
                    return Err(error);
                }
                failed += 1;
            }
        }
    }
    emit(serde_json::json!({"recovered": recovered, "failed": failed, "unmapped": unmapped}))?;
    if failed > 0 {
        return Err("one or more objects could not be recovered".into());
    }
    Ok(())
}

async fn check(
    catalogue: &Catalogue,
    items: &[Selection<'_>],
    kek: &KekRing,
    source: &mut impl BodySource,
) -> Result<(), Box<dyn std::error::Error>> {
    for item in items {
        let result = catalogue.check(item, kek, source).await?;
        emit(
            serde_json::json!({"bucket": item.bucket.name, "key": item.object.key, "generation_id": item.object.generation, "result": result}),
        )?;
    }
    emit(serde_json::json!({"checked": items.len()}))?;
    Ok(())
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let kit_dir = cli.kit.ok_or("--kit is required")?;
    let kek = load_kek(
        &cli.kek_file.ok_or("--kek-file is required")?,
        cli.kek_version,
    )?;
    let reader = Kit::open(&kit_dir)?;
    if matches!(cli.command, Command::VerifyKit) {
        reader.verify(&kek)?;
        emit(serde_json::json!({"verified": true}))?;
        return Ok(());
    }
    let catalogue = reader.read(&kek)?;
    match cli.command {
        Command::Ls(filter) => {
            for item in filter.select(&catalogue) {
                emit(
                    serde_json::json!({"bucket": item.bucket.name, "key": item.object.key, "generation_id": item.object.generation, "size": item.object.size, "recoverable": catalogue.recoverable(item.object)}),
                )?;
            }
        }
        Command::Nzb {
            bucket,
            object,
            out,
        } => {
            let (bucket, key) = match (bucket.as_deref(), object.as_deref()) {
                (_, Some(object)) => {
                    let (b, k) = object
                        .split_once('/')
                        .ok_or("--object requires BUCKET/KEY")?;
                    (Some(b), Some(k))
                }
                (b, _) => (b, None),
            };
            let items = catalogue.select(bucket, key, None);
            if items.is_empty() || items.iter().any(|item| !catalogue.recoverable(item.object)) {
                return Err("NZB requires matching objects with usable Usenet plans".into());
            }
            let mut output = BufWriter::new(File::create_new(out)?);
            write_nzb(&mut output, &catalogue, &items)?;
            output.flush()?;
        }
        Command::Get {
            filter,
            out,
            network,
        } => {
            if filter.bucket.is_none() {
                return Err("get requires --bucket".into());
            }
            let items = filter.select(&catalogue);
            match network.open()? {
                Source::Nntp(mut source) => {
                    restore(&catalogue, &items, &kek, &mut source, &out).await?
                }
                Source::Relay(mut source) => {
                    restore(&catalogue, &items, &kek, &mut source, &out).await?
                }
            }
        }
        Command::Decrypt {
            filter,
            from_dir,
            out,
        } => {
            let items = filter.select(&catalogue);
            restore(
                &catalogue,
                &items,
                &kek,
                &mut Downloads::open(&from_dir)?,
                &out,
            )
            .await?;
        }
        Command::Check { sample, network } => {
            let mut items = catalogue.select(None, None, None);
            items.retain(|item| catalogue.recoverable(item.object));
            let n = sample as usize;
            if n == 0 || n > items.len() || n > 10_000 {
                return Err(
                    "sample size must be between 1 and the available count, at most 10000".into(),
                );
            }
            for i in 0..n {
                let j = uniform_below(&mut SystemRng, (items.len() - i) as u64)? as usize;
                items.swap(i, i + j);
            }
            match network.open()? {
                Source::Nntp(mut source) => {
                    check(&catalogue, &items[..n], &kek, &mut source).await?
                }
                Source::Relay(mut source) => {
                    check(&catalogue, &items[..n], &kek, &mut source).await?
                }
            }
        }
        Command::VerifyKit => unreachable!("handled before selecting objects"),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("recovery failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
