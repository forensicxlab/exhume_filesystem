//! Command-line parsing for `exhume_filesystem export-volume`.
//!
//! Kept separate from the export engine so validation can be exercised without
//! opening evidence or creating an output file.

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use clap_num::maybe_hex;
use exhume_body::Body;
use exhume_filesystem::detected_fs::{DetectedFs, detect_filesystem};
use exhume_filesystem::export::{
    ExportControl, ExportOptions, ExportProgress, ExportProvenance, ExportStage, RawAllocation,
    ResumeMode, export_raw, preflight_export,
};
use exhume_filesystem::volume::{VolumeExtent, VolumePipeline};
use exhume_filesystem::volume_bitlocker::BitLockerLayer;
use exhume_partitions::{GptPartitionSelector, PartitionExtent, discover_gpt};
use serde_json::json;
use signal_hook::consts::SIGINT;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, UNIX_EPOCH};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportView {
    Physical,
    Decrypted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifyMode {
    None,
    Ntfs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExtentSelector {
    GptIndex(u32),
    PartitionGuid(String),
    Explicit {
        offset_bytes: u64,
        length_bytes: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FvekSource {
    File(PathBuf),
    Stdin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExportVolumeArgs {
    pub body: PathBuf,
    pub format: String,
    pub selector: ExtentSelector,
    pub view: ExportView,
    pub fvek: Option<FvekSource>,
    pub output: PathBuf,
    pub manifest: Option<PathBuf>,
    pub sparse: bool,
    pub resume: bool,
    pub verify: VerifyMode,
    pub force: bool,
    pub chunk_size: usize,
    pub sparse_block_size: usize,
    pub checkpoint_bytes: u64,
    pub pipeline_depth: usize,
}

pub(crate) fn command() -> Command {
    Command::new("export-volume")
        .about("Export a physical partition or a transformed, decrypted volume view")
        .long_about(
            "Export one bounded partition as a standalone RAW image. The physical view preserves encrypted bytes; the decrypted view applies the selected volume transform. GPT metadata is not included in the output.",
        )
        .after_help(
            "Performance: use an optimized build for large exports, for example `cargo run --release -p exhume_filesystem -- export-volume ...`.",
        )
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(PathBuf))
                .required(true)
                .help("Source disk-image path"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(["auto", "raw", "ewf", "vmdk", "aff", "aff4"])
                .default_value("auto")
                .help("Source image format"),
        )
        .arg(
            Arg::new("gpt_index")
                .long("gpt-index")
                .value_name("INDEX")
                .value_parser(maybe_hex::<u32>)
                .conflicts_with_all(["partition_guid", "offset_bytes", "length_bytes"])
                .help("Original zero-based GPT entry index"),
        )
        .arg(
            Arg::new("partition_guid")
                .long("partition-guid")
                .value_name("GUID")
                .value_parser(value_parser!(String))
                .conflicts_with_all(["gpt_index", "offset_bytes", "length_bytes"])
                .help("Canonical GPT partition GUID"),
        )
        .arg(
            Arg::new("offset_bytes")
                .long("offset-bytes")
                .value_name("BYTES")
                .value_parser(maybe_hex::<u64>)
                .requires("length_bytes")
                .conflicts_with_all(["gpt_index", "partition_guid"])
                .help("Explicit image-relative partition offset in bytes"),
        )
        .arg(
            Arg::new("length_bytes")
                .long("length-bytes")
                .value_name("BYTES")
                .value_parser(maybe_hex::<u64>)
                .requires("offset_bytes")
                .conflicts_with_all(["gpt_index", "partition_guid"])
                .help("Explicit partition length in bytes"),
        )
        .arg(
            Arg::new("view")
                .long("view")
                .value_parser(["physical", "decrypted"])
                .default_value("physical")
                .help("Export exact partition bytes or a decrypted block-volume view"),
        )
        .arg(
            Arg::new("fvek_file")
                .long("fvek-file")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .conflicts_with("fvek_stdin")
                .help("Read a hexadecimal BitLocker FVEK from a protected file"),
        )
        .arg(
            Arg::new("fvek_stdin")
                .long("fvek-stdin")
                .action(ArgAction::SetTrue)
                .conflicts_with("fvek_file")
                .help("Read a hexadecimal BitLocker FVEK from standard input"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('O')
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .required(true)
                .help("Standalone RAW partition image to create"),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .value_name("PATH")
                .value_parser(value_parser!(PathBuf))
                .help("JSON manifest path (default: <output>.manifest.json)"),
        )
        .arg(
            Arg::new("sparse")
                .long("sparse")
                .action(ArgAction::SetTrue)
                .help("Create holes for transformed blocks confirmed to contain only zeroes"),
        )
        .arg(
            Arg::new("resume")
                .long("resume")
                .action(ArgAction::SetTrue)
                .conflicts_with("force")
                .help("Resume a compatible, aligned partial export"),
        )
        .arg(
            Arg::new("verify")
                .long("verify")
                .value_parser(["none", "ntfs"])
                .default_value("none")
                .help(
                    "After publication, reopen and validate the output as the selected filesystem; failure exits non-zero and retains the output and manifest",
                ),
        )
        .arg(
            Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .conflicts_with("resume")
                .help("Replace an existing output and partial export"),
        )
        .arg(
            Arg::new("chunk_size")
                .long("chunk-size")
                .value_name("BYTES")
                .value_parser(maybe_hex::<usize>)
                .default_value("16777216")
                .help("Streaming chunk size; must be sector-aligned (default: 16 MiB)"),
        )
        .arg(
            Arg::new("sparse_block_size")
                .long("sparse-block-size")
                .value_name("BYTES")
                .value_parser(maybe_hex::<usize>)
                .default_value("1048576")
                .help(
                    "Zero-hole detection granularity within each chunk; must be sector-aligned and no larger than --chunk-size (default: 1 MiB)",
                ),
        )
        .arg(
            Arg::new("checkpoint_bytes")
                .long("checkpoint-bytes")
                .value_name("BYTES")
                .value_parser(maybe_hex::<u64>)
                .default_value("268435456")
                .help(
                    "Minimum bytes between durable checkpoints when --resume is enabled (default: 256 MiB)",
                ),
        )
        .arg(
            Arg::new("pipeline_depth")
                .long("pipeline-depth")
                .value_name("BUFFERS")
                .value_parser(value_parser!(usize))
                .default_value("3")
                .help("Reusable streaming buffers in the bounded pipeline (1-32; default: 3)"),
        )
}

pub(crate) fn parse(matches: &ArgMatches) -> Result<ExportVolumeArgs, String> {
    let selector = match (
        matches.get_one::<u32>("gpt_index"),
        matches.get_one::<String>("partition_guid"),
        matches.get_one::<u64>("offset_bytes"),
        matches.get_one::<u64>("length_bytes"),
    ) {
        (Some(index), None, None, None) => ExtentSelector::GptIndex(*index),
        (None, Some(guid), None, None) => ExtentSelector::PartitionGuid(guid.clone()),
        (None, None, Some(offset_bytes), Some(length_bytes)) => ExtentSelector::Explicit {
            offset_bytes: *offset_bytes,
            length_bytes: *length_bytes,
        },
        (None, None, None, None) => {
            return Err(
                "select one extent using --gpt-index, --partition-guid, or both --offset-bytes and --length-bytes"
                    .to_owned(),
            );
        }
        _ => {
            return Err(
                "partition selector is incomplete or contains conflicting arguments".to_owned(),
            );
        }
    };

    let view = match matches
        .get_one::<String>("view")
        .expect("clap supplies a default view")
        .as_str()
    {
        "physical" => ExportView::Physical,
        "decrypted" => ExportView::Decrypted,
        value => return Err(format!("unsupported export view {value:?}")),
    };
    let verify = match matches
        .get_one::<String>("verify")
        .expect("clap supplies a default verifier")
        .as_str()
    {
        "none" => VerifyMode::None,
        "ntfs" => VerifyMode::Ntfs,
        value => return Err(format!("unsupported verifier {value:?}")),
    };
    let fvek = if let Some(path) = matches.get_one::<PathBuf>("fvek_file") {
        Some(FvekSource::File(path.clone()))
    } else if matches.get_flag("fvek_stdin") {
        Some(FvekSource::Stdin)
    } else {
        None
    };

    if view == ExportView::Decrypted && fvek.is_none() {
        return Err("--view decrypted requires --fvek-file <PATH> or --fvek-stdin".to_owned());
    }
    if view == ExportView::Physical && fvek.is_some() {
        return Err("an FVEK is only accepted with --view decrypted".to_owned());
    }
    let chunk_size = *matches
        .get_one::<usize>("chunk_size")
        .expect("clap supplies a default chunk size");
    if chunk_size == 0 {
        return Err("--chunk-size must be greater than zero".to_owned());
    }
    let configured_sparse_block_size = *matches
        .get_one::<usize>("sparse_block_size")
        .expect("clap supplies a default sparse block size");
    let sparse_block_size = if matches.value_source("sparse_block_size")
        == Some(clap::parser::ValueSource::DefaultValue)
    {
        configured_sparse_block_size.min(chunk_size)
    } else {
        configured_sparse_block_size
    };
    if sparse_block_size == 0 || sparse_block_size > chunk_size {
        return Err(
            "--sparse-block-size must be greater than zero and no larger than --chunk-size"
                .to_owned(),
        );
    }
    let checkpoint_bytes = *matches
        .get_one::<u64>("checkpoint_bytes")
        .expect("clap supplies a default checkpoint interval");
    if checkpoint_bytes == 0 {
        return Err("--checkpoint-bytes must be greater than zero".to_owned());
    }
    let pipeline_depth = *matches
        .get_one::<usize>("pipeline_depth")
        .expect("clap supplies a default pipeline depth");
    if !(1..=32).contains(&pipeline_depth) {
        return Err("--pipeline-depth must be between 1 and 32".to_owned());
    }

    Ok(ExportVolumeArgs {
        body: matches
            .get_one::<PathBuf>("body")
            .expect("required by clap")
            .clone(),
        format: matches
            .get_one::<String>("format")
            .expect("clap supplies a default format")
            .clone(),
        selector,
        view,
        fvek,
        output: matches
            .get_one::<PathBuf>("output")
            .expect("required by clap")
            .clone(),
        manifest: matches.get_one::<PathBuf>("manifest").cloned(),
        sparse: matches.get_flag("sparse"),
        resume: matches.get_flag("resume"),
        verify,
        force: matches.get_flag("force"),
        chunk_size,
        sparse_block_size,
        checkpoint_bytes,
        pipeline_depth,
    })
}

pub(crate) fn run(mut arguments: ExportVolumeArgs) -> Result<(), String> {
    if cfg!(debug_assertions) {
        eprintln!(
            "WARNING: this exporter is running with debug assertions and can be dramatically slower. Use `cargo run --release -p exhume_filesystem -- export-volume ...` for production exports."
        );
    }
    let source_path = fs::canonicalize(&arguments.body).map_err(|error| {
        format!(
            "cannot resolve source evidence {}: {error}",
            arguments.body.display()
        )
    })?;
    if let Some(FvekSource::File(path)) = arguments.fvek.as_mut() {
        *path = fs::canonicalize(&*path)
            .map_err(|error| format!("cannot resolve protected FVEK file: {error}"))?;
    }
    if !source_path.is_file() {
        return Err(format!(
            "volume export requires a disk-image file, not {}",
            source_path.display()
        ));
    }

    let body = Body::try_new(
        source_path.to_string_lossy().into_owned(),
        &arguments.format,
    )
    .map_err(|error| format!("cannot open source evidence: {error}"))?;
    let backing_paths = body
        .backing_paths()
        .map_err(|error| format!("cannot enumerate evidence backing files: {error}"))?;
    let backing_files = inspect_backing_files(&backing_paths)?;
    let (extent, partition_metadata) = resolve_extent(&body, &arguments.selector)?;
    if arguments.chunk_size % extent.sector_size as usize != 0 {
        return Err(format!(
            "--chunk-size {} is not aligned to source sector size {}",
            arguments.chunk_size, extent.sector_size
        ));
    }

    let mut pipeline = VolumePipeline::from_body(&body, extent.clone())
        .map_err(|error| format!("cannot open selected volume: {error}"))?;
    if arguments.view == ExportView::Decrypted {
        let fvek_source = arguments
            .fvek
            .as_ref()
            .expect("decrypted view was validated to have an FVEK source");
        let fvek = read_fvek(fvek_source)?;
        let layer = BitLockerLayer::new(
            fvek,
            extent.offset_bytes,
            extent.length_bytes,
            extent.sector_size,
        )
        .map_err(|error| format!("invalid BitLocker configuration: {error}"))?;
        pipeline = pipeline
            .apply(layer)
            .map_err(|error| format!("cannot open decrypted BitLocker view: {error}"))?;
    }

    let mut provenance = ExportProvenance::from_pipeline(
        &pipeline,
        Some(source_path.to_string_lossy().into_owned()),
        Some(arguments.format.clone()),
    );
    provenance.public_metadata = partition_metadata;
    provenance.public_metadata.insert(
        "source_format_description".to_owned(),
        body.format_description().to_owned(),
    );
    provenance.public_metadata.insert(
        "source_backing_files".to_owned(),
        serde_json::to_string(&backing_files)
            .map_err(|error| format!("cannot serialize evidence backing inventory: {error}"))?,
    );
    provenance.public_metadata.insert(
        "export_view".to_owned(),
        match arguments.view {
            ExportView::Physical => "physical",
            ExportView::Decrypted => "decrypted",
        }
        .to_owned(),
    );
    provenance.public_metadata.insert(
        "post_export_verification_requested".to_owned(),
        match arguments.verify {
            VerifyMode::None => "none",
            VerifyMode::Ntfs => "ntfs",
        }
        .to_owned(),
    );

    let resume_identity = build_resume_identity(&backing_files, &body, &provenance)?;
    let options = ExportOptions {
        chunk_size: arguments.chunk_size,
        sparse_block_size: arguments.sparse_block_size,
        checkpoint_bytes: arguments.checkpoint_bytes,
        pipeline_depth: arguments.pipeline_depth,
        allocation: if arguments.sparse {
            RawAllocation::Sparse
        } else {
            RawAllocation::Dense
        },
        resume: if arguments.resume {
            ResumeMode::Validated {
                identity: resume_identity,
            }
        } else {
            ResumeMode::Disabled
        },
        manifest_path: arguments.manifest.clone(),
        overwrite: arguments.force,
        ..ExportOptions::default()
    };

    let preflight = preflight_export(&pipeline, &arguments.output, &options)
        .map_err(|error| format!("export preflight failed: {error}"))?;
    let protected_inputs = protected_input_paths(&backing_paths, arguments.fvek.as_ref());
    protect_input_files(&protected_inputs, &preflight)?;
    warn_if_source_and_output_share_device(&backing_paths, &preflight.output_path)?;
    check_available_space(&preflight)?;

    eprintln!(
        "Exporting {} view: {} bytes ({}) to {}",
        match arguments.view {
            ExportView::Physical => "physical",
            ExportView::Decrypted => "decrypted",
        },
        preflight.logical_bytes,
        human_bytes(preflight.logical_bytes),
        preflight.output_path.display()
    );
    if arguments.sparse {
        eprintln!(
            "Sparse output enabled; logical size remains {} and holes are detected in {} blocks.",
            human_bytes(preflight.logical_bytes),
            human_bytes(arguments.sparse_block_size as u64)
        );
    }
    if arguments.resume {
        eprintln!(
            "Streaming with {} × {} buffers; durable checkpoints every {}.",
            arguments.pipeline_depth,
            human_bytes(arguments.chunk_size as u64),
            human_bytes(arguments.checkpoint_bytes)
        );
        eprintln!(
            "Press Ctrl-C once to checkpoint and stop safely; rerun with --resume to continue."
        );
    } else {
        eprintln!(
            "Streaming with {} × {} buffers.",
            arguments.pipeline_depth,
            human_bytes(arguments.chunk_size as u64)
        );
        eprintln!(
            "Press Ctrl-C once to stop safely. This run is not resumable; use --resume from the start to enable checkpoints."
        );
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&cancelled))
        .map_err(|error| format!("cannot install Ctrl-C handler: {error}"))?;
    let mut printer = ProgressPrinter::new();
    let mut callback = |progress: &ExportProgress| printer.update(progress);
    let mut control = ExportControl::new(Some(cancelled.as_ref()), Some(&mut callback));
    let report = export_raw(
        &mut pipeline,
        &arguments.output,
        provenance,
        &options,
        &mut control,
    )
    .map_err(|error| format!("volume export failed: {error}"))?;

    if arguments.verify == VerifyMode::Ntfs {
        eprintln!(
            "Export and manifest are published; running post-publication NTFS verification. Both files will be retained if verification fails."
        );
        if let Err(error) = verify_ntfs(&report.output_path, report.manifest.logical_bytes) {
            return Err(retained_verification_error(
                &error,
                &report.output_path,
                &report.manifest_path,
            ));
        }
    }

    println!("Export complete: {}", report.output_path.display());
    println!("Manifest: {}", report.manifest_path.display());
    println!("SHA-256: {}", report.manifest.sha256);
    println!(
        "Logical: {}; allocated: {}",
        human_bytes(report.manifest.logical_bytes),
        report
            .manifest
            .allocated_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "unavailable".to_owned())
    );
    Ok(())
}

fn resolve_extent(
    body: &Body,
    selector: &ExtentSelector,
) -> Result<(VolumeExtent, BTreeMap<String, String>), String> {
    let sector_size = u64::from(body.get_sector_size());
    let image_size = body.get_image_size();
    match selector {
        ExtentSelector::Explicit {
            offset_bytes,
            length_bytes,
        } => {
            let extent = VolumeExtent::from_parts(*offset_bytes, *length_bytes, sector_size)
                .map_err(|error| format!("invalid explicit volume extent: {error}"))?;
            let end = extent
                .end_bytes()
                .map_err(|error| format!("invalid explicit volume extent: {error}"))?;
            if end > image_size {
                return Err(format!(
                    "explicit volume extent ends at byte {end}, beyond image length {image_size}"
                ));
            }
            let mut metadata = BTreeMap::new();
            metadata.insert("extent_selection".to_owned(), "explicit".to_owned());
            Ok((extent, metadata))
        }
        ExtentSelector::GptIndex(index) => resolve_gpt(
            body,
            GptPartitionSelector::Index(*index),
            sector_size,
            image_size,
        ),
        ExtentSelector::PartitionGuid(guid) => resolve_gpt(
            body,
            GptPartitionSelector::Guid(guid.clone()),
            sector_size,
            image_size,
        ),
    }
}

fn resolve_gpt(
    body: &Body,
    selector: GptPartitionSelector,
    sector_size: u64,
    image_size: u64,
) -> Result<(VolumeExtent, BTreeMap<String, String>), String> {
    let mut partition_body = body.clone();
    let gpt = discover_gpt(&mut partition_body)
        .map_err(|error| format!("cannot discover GPT partition table: {error}"))?;
    let partition = gpt
        .resolve_extent(&selector, sector_size, image_size)
        .map_err(|error| format!("cannot resolve GPT partition: {error}"))?;
    convert_partition_extent(partition)
}

fn convert_partition_extent(
    partition: PartitionExtent,
) -> Result<(VolumeExtent, BTreeMap<String, String>), String> {
    let extent = VolumeExtent::from_parts(
        partition.start_bytes,
        partition.length_bytes,
        partition.sector_size,
    )
    .map_err(|error| format!("invalid discovered partition extent: {error}"))?
    .with_partition_identity(
        Some(partition.id),
        partition.partition_guid.clone(),
        partition.partition_name.clone(),
    );
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "partition_scheme".to_owned(),
        format!("{:?}", partition.scheme).to_ascii_lowercase(),
    );
    metadata.insert("partition_type".to_owned(), partition.partition_type);
    if let Some(type_guid) = partition.partition_type_guid {
        metadata.insert("partition_type_guid".to_owned(), type_guid);
    }
    Ok((extent, metadata))
}

fn read_fvek(source: &FvekSource) -> Result<Vec<u8>, String> {
    const MAX_KEY_FILE_BYTES: u64 = 4096;
    let mut raw = Vec::new();
    match source {
        FvekSource::File(path) => {
            let file = File::open(path)
                .map_err(|error| format!("cannot open FVEK file {}: {error}", path.display()))?;
            file.take(MAX_KEY_FILE_BYTES + 1)
                .read_to_end(&mut raw)
                .map_err(|error| format!("cannot read FVEK file {}: {error}", path.display()))?;
        }
        FvekSource::Stdin => {
            if io::stdin().is_terminal() {
                return Err(
                    "--fvek-stdin refuses an interactive terminal because input would be echoed; pipe the key or use a protected --fvek-file"
                        .to_owned(),
                );
            }
            io::stdin()
                .take(MAX_KEY_FILE_BYTES + 1)
                .read_to_end(&mut raw)
                .map_err(|error| format!("cannot read FVEK from standard input: {error}"))?;
        }
    }
    if raw.len() as u64 > MAX_KEY_FILE_BYTES {
        raw.zeroize();
        return Err("FVEK input exceeds the 4096-byte safety limit".to_owned());
    }

    let mut compact: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    raw.zeroize();
    if compact.starts_with(b"0x") || compact.starts_with(b"0X") {
        compact.drain(..2);
    }
    let decoded = hex::decode(&compact)
        .map_err(|_| "FVEK input must contain only hexadecimal bytes".to_owned());
    compact.zeroize();
    let decoded = decoded?;
    if !matches!(decoded.len(), 32 | 64) {
        let mut decoded = decoded;
        decoded.zeroize();
        return Err(
            "FVEK must decode to 32 bytes for AES-XTS-128 or 64 bytes for AES-XTS-256".to_owned(),
        );
    }
    Ok(decoded)
}

fn inspect_backing_files(backing_paths: &[PathBuf]) -> Result<Vec<serde_json::Value>, String> {
    let mut backing_files = Vec::with_capacity(backing_paths.len());
    for path in backing_paths {
        let metadata = fs::metadata(path).map_err(|error| {
            format!(
                "cannot inspect evidence backing file {}: {error}",
                path.display()
            )
        })?;
        let modified = metadata.modified().map_err(|error| {
            format!(
                "cannot read high-resolution modification time for evidence backing file {}: {error}",
                path.display()
            )
        })?;
        let modified_unix_ns = modified
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                format!(
                    "evidence backing file {} has a modification time before the Unix epoch",
                    path.display()
                )
            })?
            .as_nanos()
            .to_string();
        backing_files.push(json!({
            "canonical_path": path,
            "size_bytes": metadata.len(),
            "modified_unix_ns": modified_unix_ns,
        }));
    }
    Ok(backing_files)
}

fn build_resume_identity(
    backing_files: &[serde_json::Value],
    body: &Body,
    provenance: &ExportProvenance,
) -> Result<String, String> {
    serde_json::to_string(&json!({
        "schema": "exhume.volume-export.identity.v2",
        "backing_files": backing_files,
        "source_logical_bytes": body.get_image_size(),
        "provenance": provenance,
    }))
    .map_err(|error| format!("cannot build resume identity: {error}"))
}

fn protected_input_paths(
    backing_paths: &[PathBuf],
    fvek_source: Option<&FvekSource>,
) -> Vec<PathBuf> {
    let mut protected = backing_paths.to_vec();
    if let Some(FvekSource::File(path)) = fvek_source
        && !protected.contains(path)
    {
        protected.push(path.clone());
    }
    protected
}

fn protect_input_files(
    input_paths: &[PathBuf],
    preflight: &exhume_filesystem::export::ExportPreflight,
) -> Result<(), String> {
    let protected = [
        &preflight.output_path,
        &preflight.manifest_path,
        &preflight.partial_path,
        &preflight.manifest_partial_path,
        &preflight.resume_path,
        &preflight.lock_path,
        &preflight.manifest_lock_path,
        &preflight.output_backup_path,
        &preflight.manifest_backup_path,
        &preflight.resume_temp_path,
        &preflight.resume_backup_path,
    ];
    for candidate in protected {
        let normalized_candidate = normalized_target(candidate)?;
        for input_path in input_paths {
            let same_canonical_path = normalized_candidate == *input_path;
            let same_existing_file = candidate.exists()
                && same_file::is_same_file(candidate, input_path).map_err(|error| {
                    format!(
                        "cannot compare export path {} with protected input file {}: {error}",
                        candidate.display(),
                        input_path.display()
                    )
                })?;
            if same_canonical_path || same_existing_file {
                return Err(format!(
                    "export path {} would overwrite or stage over protected input file {}",
                    candidate.display(),
                    input_path.display()
                ));
            }
        }
    }
    Ok(())
}

fn normalized_target(path: &std::path::Path) -> Result<PathBuf, String> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve output path {}: {error}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| std::path::Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "cannot resolve output directory {}: {error}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("output path {} has no file name", path.display()))?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(unix)]
fn warn_if_source_and_output_share_device(
    backing_paths: &[PathBuf],
    output_path: &std::path::Path,
) -> Result<(), String> {
    let same_device_sources = source_paths_on_output_device(backing_paths, output_path)?;
    if !same_device_sources.is_empty() {
        eprintln!(
            "WARNING: source evidence and output resolve to the same filesystem/device. Concurrent reads and writes may reduce throughput even when different folders are used; a separate physical SSD is recommended. Matching source: {}",
            same_device_sources
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

#[cfg(unix)]
fn source_paths_on_output_device(
    backing_paths: &[PathBuf],
    output_path: &std::path::Path,
) -> Result<Vec<PathBuf>, String> {
    use std::os::unix::fs::MetadataExt;

    let output_parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let output_device = fs::metadata(output_parent)
        .map_err(|error| {
            format!(
                "cannot inspect output filesystem {}: {error}",
                output_parent.display()
            )
        })?
        .dev();
    backing_paths
        .iter()
        .filter_map(|source| match fs::metadata(source) {
            Ok(metadata) if metadata.dev() == output_device => Some(Ok(source.clone())),
            Ok(_) => None,
            Err(error) => Some(Err(format!(
                "cannot inspect evidence backing filesystem {}: {error}",
                source.display()
            ))),
        })
        .collect()
}

#[cfg(not(unix))]
fn warn_if_source_and_output_share_device(
    _backing_paths: &[PathBuf],
    _output_path: &std::path::Path,
) -> Result<(), String> {
    Ok(())
}

fn check_available_space(
    preflight: &exhume_filesystem::export::ExportPreflight,
) -> Result<(), String> {
    let Some(required) = preflight.required_dense_bytes else {
        return Ok(());
    };
    let parent = preflight
        .output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let available = fs2::available_space(parent).map_err(|error| {
        format!(
            "cannot determine free space in output directory {}: {error}",
            parent.display()
        )
    })?;
    if available < required {
        return Err(format!(
            "insufficient free space for dense export: {} available, {} required; select another destination or use --sparse when appropriate",
            human_bytes(available),
            human_bytes(required)
        ));
    }
    Ok(())
}

fn verify_ntfs(output: &std::path::Path, length_bytes: u64) -> Result<(), String> {
    let body = Body::try_new(output.to_string_lossy().into_owned(), "raw")
        .map_err(|error| format!("cannot reopen exported RAW image: {error}"))?;
    let filesystem = detect_filesystem(&body, 0, length_bytes, None)
        .map_err(|error| format!("exported image did not pass NTFS verification: {error}"))?;
    match filesystem {
        DetectedFs::Ntfs(_) => {
            eprintln!("NTFS verification passed.");
            Ok(())
        }
        _ => Err("exported image was detected as a filesystem other than NTFS".to_owned()),
    }
}

fn retained_verification_error(
    error: &str,
    output: &std::path::Path,
    manifest: &std::path::Path,
) -> String {
    format!(
        "post-publication NTFS verification failed: {error}. The hashed derivative {} and its manifest {} were retained; the manifest SHA-256 still describes the exported bytes, but NTFS validation did not pass",
        output.display(),
        manifest.display()
    )
}

struct ProgressPrinter {
    last_stage: Option<ExportStage>,
    last_print: Instant,
    last_completed: u64,
    rolling_bytes_per_second: Option<f64>,
}

impl ProgressPrinter {
    fn new() -> Self {
        Self {
            last_stage: None,
            last_print: Instant::now(),
            last_completed: 0,
            rolling_bytes_per_second: None,
        }
    }

    fn update(&mut self, progress: &ExportProgress) {
        let percent = if progress.total_bytes == 0 {
            100
        } else {
            progress.completed_bytes.saturating_mul(100) / progress.total_bytes
        };
        let stage_changed = self.last_stage != Some(progress.stage);
        let time_elapsed = self.last_print.elapsed() >= Duration::from_secs(2);
        if !stage_changed
            && matches!(
                progress.stage,
                ExportStage::ValidatingResume | ExportStage::Exporting
            )
            && !time_elapsed
        {
            return;
        }

        if stage_changed {
            self.last_completed = progress.completed_bytes;
            self.rolling_bytes_per_second = None;
        }
        let elapsed = self.last_print.elapsed().as_secs_f64();
        let current_bytes_per_second = (!stage_changed && elapsed > 0.0)
            .then(|| progress.completed_bytes.saturating_sub(self.last_completed) as f64 / elapsed);
        if let Some(current) = current_bytes_per_second
            && current.is_finite()
            && current > 0.0
        {
            self.rolling_bytes_per_second = Some(
                self.rolling_bytes_per_second
                    .map_or(current, |rolling| rolling * 0.75 + current * 0.25),
            );
        }
        let metrics = format_transfer_metrics(
            current_bytes_per_second,
            self.rolling_bytes_per_second,
            progress
                .total_bytes
                .saturating_sub(progress.completed_bytes),
        );

        match progress.stage {
            ExportStage::Preparing => eprintln!("Preparing export..."),
            ExportStage::ValidatingResume => eprintln!(
                "Validating resumable prefix: {:>3}% — {} / {}{}",
                percent,
                human_bytes(progress.completed_bytes),
                human_bytes(progress.total_bytes),
                metrics
            ),
            ExportStage::Exporting => eprintln!(
                "Exporting: {:>3}% — {} / {}{}{}",
                percent,
                human_bytes(progress.completed_bytes),
                human_bytes(progress.total_bytes),
                if progress.resumed_from > 0 {
                    format!(" (resumed at {})", human_bytes(progress.resumed_from))
                } else {
                    String::new()
                },
                metrics
            ),
            ExportStage::Finalizing => eprintln!("Finalizing output and manifest..."),
            ExportStage::Complete => eprintln!("Export data and manifest published."),
        }
        self.last_stage = Some(progress.stage);
        self.last_completed = progress.completed_bytes;
        self.last_print = Instant::now();
    }
}

fn format_transfer_metrics(
    current_bytes_per_second: Option<f64>,
    rolling_bytes_per_second: Option<f64>,
    remaining_bytes: u64,
) -> String {
    let (Some(current), Some(rolling)) = (current_bytes_per_second, rolling_bytes_per_second)
    else {
        return String::new();
    };
    let eta = if rolling > 0.0 {
        format_duration(Duration::from_secs_f64(remaining_bytes as f64 / rolling))
    } else {
        "unknown".to_owned()
    };
    format!(
        " — current {:.1} MiB/s, rolling {:.1} MiB/s, ETA {eta}",
        current / (1024.0 * 1024.0),
        rolling / (1024.0 * 1024.0)
    )
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse_from(arguments: &[&str]) -> Result<ExportVolumeArgs, String> {
        let matches = command()
            .try_get_matches_from(arguments)
            .map_err(|error| error.to_string())?;
        parse(&matches)
    }

    #[test]
    fn parses_physical_gpt_export() {
        let args = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--gpt-index",
            "2",
            "--output",
            "partition.img",
            "--sparse",
        ])
        .unwrap();

        assert_eq!(args.selector, ExtentSelector::GptIndex(2));
        assert_eq!(args.view, ExportView::Physical);
        assert!(args.sparse);
        assert_eq!(args.chunk_size, 16 * 1024 * 1024);
        assert_eq!(args.sparse_block_size, 1024 * 1024);
        assert_eq!(args.checkpoint_bytes, 256 * 1024 * 1024);
        assert_eq!(args.pipeline_depth, 3);
    }

    #[test]
    fn parses_export_performance_controls_and_clamps_default_sparse_block() {
        let args = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--gpt-index",
            "2",
            "--output",
            "partition.img",
            "--chunk-size",
            "65536",
            "--checkpoint-bytes",
            "1073741824",
            "--pipeline-depth",
            "6",
        ])
        .unwrap();
        assert_eq!(args.chunk_size, 65536);
        assert_eq!(args.sparse_block_size, 65536);
        assert_eq!(args.checkpoint_bytes, 1024 * 1024 * 1024);
        assert_eq!(args.pipeline_depth, 6);

        let explicit = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--gpt-index",
            "2",
            "--output",
            "partition.img",
            "--chunk-size",
            "2097152",
            "--sparse-block-size",
            "524288",
        ])
        .unwrap();
        assert_eq!(explicit.sparse_block_size, 512 * 1024);
    }

    #[test]
    fn export_help_recommends_release_mode() {
        let help = command().render_long_help().to_string();
        assert!(help.contains("cargo run --release"));
        assert!(help.contains("--checkpoint-bytes"));
        assert!(help.contains("--pipeline-depth"));
    }

    #[test]
    fn parses_decrypted_explicit_export_with_stdin_key() {
        let args = parse_from(&[
            "export-volume",
            "--body",
            "evidence.raw",
            "--offset-bytes",
            "0x1000",
            "--length-bytes",
            "0x2000",
            "--view",
            "decrypted",
            "--fvek-stdin",
            "--output",
            "partition.img",
            "--verify",
            "ntfs",
        ])
        .unwrap();

        assert_eq!(
            args.selector,
            ExtentSelector::Explicit {
                offset_bytes: 0x1000,
                length_bytes: 0x2000,
            }
        );
        assert_eq!(args.fvek, Some(FvekSource::Stdin));
        assert_eq!(args.verify, VerifyMode::Ntfs);
    }

    #[test]
    fn rejects_missing_extent_selector() {
        let error = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--output",
            "partition.img",
        ])
        .unwrap_err();
        assert!(error.contains("select one extent"));
    }

    #[test]
    fn rejects_incomplete_explicit_extent() {
        let error = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--offset-bytes",
            "4096",
            "--output",
            "partition.img",
        ])
        .unwrap_err();
        assert!(error.contains("required"));
    }

    #[test]
    fn rejects_decrypted_export_without_key_source() {
        let error = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--gpt-index",
            "2",
            "--view",
            "decrypted",
            "--output",
            "partition.img",
        ])
        .unwrap_err();
        assert!(error.contains("requires --fvek-file"));
    }

    #[test]
    fn rejects_key_for_physical_export() {
        let error = parse_from(&[
            "export-volume",
            "--body",
            "evidence.aff",
            "--partition-guid",
            "0dabca09-68c1-45a2-a40a-d95860571c20",
            "--fvek-file",
            "fvek.hex",
            "--output",
            "partition.img",
        ])
        .unwrap_err();
        assert!(error.contains("only accepted"));
    }

    #[test]
    fn permits_ntfs_verification_for_a_plain_physical_volume() {
        let args = parse_from(&[
            "export-volume",
            "--body",
            "evidence.raw",
            "--gpt-index",
            "2",
            "--view",
            "physical",
            "--output",
            "partition.img",
            "--verify",
            "ntfs",
        ])
        .unwrap();
        assert_eq!(args.verify, VerifyMode::Ntfs);
    }

    #[test]
    fn verification_help_and_failure_explain_post_publication_retention() {
        let help = command().render_long_help().to_string();
        assert!(help.contains("After publication"));
        assert!(help.contains("retains the output and manifest"));

        let error = retained_verification_error(
            "invalid NTFS boot sector",
            std::path::Path::new("derivative.img"),
            std::path::Path::new("derivative.img.manifest.json"),
        );
        assert!(error.contains("post-publication NTFS verification failed"));
        assert!(error.contains("derivative.img.manifest.json"));
        assert!(error.contains("SHA-256 still describes the exported bytes"));
    }

    #[test]
    fn protection_rejects_secondary_backing_file_and_hard_link_collisions() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.raw");
        let secondary = directory.path().join("secondary.E02");
        fs::write(&source, vec![0x11; 512]).unwrap();
        fs::write(&secondary, vec![0x22; 512]).unwrap();
        let body = Body::try_new(source.to_string_lossy().into_owned(), "raw").unwrap();
        let extent = VolumeExtent::new(0, 512, 512).unwrap();
        let pipeline = VolumePipeline::from_body(&body, extent).unwrap();

        let preflight = preflight_export(
            &pipeline,
            &secondary,
            &ExportOptions {
                overwrite: true,
                ..ExportOptions::default()
            },
        )
        .unwrap();
        let backing_paths = vec![
            source.canonicalize().unwrap(),
            secondary.canonicalize().unwrap(),
        ];
        let error = protect_input_files(&backing_paths, &preflight).unwrap_err();
        assert!(error.contains("secondary.E02"));

        let output = directory.path().join("hard-link-output.img");
        let preflight = preflight_export(&pipeline, &output, &ExportOptions::default()).unwrap();
        fs::hard_link(&source, &preflight.partial_path).unwrap();
        let error = protect_input_files(&backing_paths, &preflight).unwrap_err();
        assert!(error.contains("source.raw"));

        let replacement_output = directory.path().join("replacement-output.img");
        let replacement_preflight =
            preflight_export(&pipeline, &replacement_output, &ExportOptions::default()).unwrap();
        fs::hard_link(&source, &replacement_preflight.output_backup_path).unwrap();
        let error = protect_input_files(&backing_paths, &replacement_preflight).unwrap_err();
        assert!(error.contains("source.raw"));

        let fvek_file = directory.path().join("protected-fvek.hex");
        fs::write(&fvek_file, "00".repeat(32)).unwrap();
        let canonical_fvek = fvek_file.canonicalize().unwrap();
        let key_collision_preflight = preflight_export(
            &pipeline,
            &canonical_fvek,
            &ExportOptions {
                overwrite: true,
                ..ExportOptions::default()
            },
        )
        .unwrap();
        let protected_inputs = protected_input_paths(
            &backing_paths,
            Some(&FvekSource::File(canonical_fvek.clone())),
        );
        let error = protect_input_files(&protected_inputs, &key_collision_preflight).unwrap_err();
        assert!(error.contains("protected-fvek.hex"));
    }

    #[test]
    fn resume_identity_binds_metadata_for_every_backing_file() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.raw");
        let secondary = directory.path().join("secondary.E02");
        fs::write(&source, vec![0x11; 512]).unwrap();
        fs::write(&secondary, vec![0x22; 512]).unwrap();
        let body = Body::try_new(source.to_string_lossy().into_owned(), "raw").unwrap();
        let backing_paths = vec![
            source.canonicalize().unwrap(),
            secondary.canonicalize().unwrap(),
        ];
        let first_inventory = inspect_backing_files(&backing_paths).unwrap();
        let first =
            build_resume_identity(&first_inventory, &body, &ExportProvenance::default()).unwrap();

        fs::write(&secondary, vec![0x33; 1024]).unwrap();
        let second_inventory = inspect_backing_files(&backing_paths).unwrap();
        let second =
            build_resume_identity(&second_inventory, &body, &ExportProvenance::default()).unwrap();

        assert_ne!(first, second);
        assert!(first.contains("secondary.E02"));
        assert!(first.contains("modified_unix_ns"));
    }

    #[cfg(unix)]
    #[test]
    fn same_device_detection_uses_filesystem_identity_not_folder_name() {
        let directory = tempfile::tempdir().unwrap();
        let source_folder = directory.path().join("source");
        let output_folder = directory.path().join("different-output-folder");
        fs::create_dir(&source_folder).unwrap();
        fs::create_dir(&output_folder).unwrap();
        let source = source_folder.join("evidence.aff");
        fs::write(&source, b"evidence").unwrap();

        let matches = source_paths_on_output_device(
            std::slice::from_ref(&source),
            &output_folder.join("partition.img"),
        )
        .unwrap();
        assert_eq!(matches, vec![source]);
    }

    #[test]
    fn progress_metrics_include_throughput_and_eta() {
        let metrics = format_transfer_metrics(
            Some(32.0 * 1024.0 * 1024.0),
            Some(16.0 * 1024.0 * 1024.0),
            160 * 1024 * 1024,
        );
        assert!(metrics.contains("current 32.0 MiB/s"));
        assert!(metrics.contains("rolling 16.0 MiB/s"));
        assert!(metrics.contains("ETA 10s"));
    }
}
