//! Exact-length RAW volume export.
//!
//! The exporter consumes only [`VolumeReader`], so physical evidence extents
//! and transformed/decrypted views use the same copy, hashing, progress, and
//! recovery path. Output is staged beside the destination as `*.partial` and
//! renamed only after its length and SHA-256 manifest are complete.
//! The manifest is published and directory-synced before the output commit
//! path. A custom manifest on another filesystem cannot provide atomic
//! two-file crash recovery, though each individual rename remains atomic.

use crate::volume::{VolumeExtent, VolumeLayerDescriptor, VolumePipeline};
use exhume_body::VolumeReader;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, channel, sync_channel};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST_SCHEMA: &str = "exhume.volume-export.v1";
const RESUME_SCHEMA: &str = "exhume.volume-export.resume.v1";
const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_SPARSE_BLOCK_SIZE: usize = 1024 * 1024;
const DEFAULT_PIPELINE_DEPTH: usize = 3;
const MAX_CHUNK_SIZE: usize = 1024 * 1024 * 1024;
const MAX_PIPELINE_DEPTH: usize = 32;
const MAX_PIPELINE_BUFFER_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RESUME_STATE_BYTES: u64 = 64 * 1024;

const fn default_sparse_block_size() -> usize {
    DEFAULT_SPARSE_BLOCK_SIZE
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawAllocation {
    Dense,
    Sparse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResumeMode {
    Disabled,
    /// Resume only if the staged export was created with the same caller-owned
    /// source/pipeline identity. A SHA-256 digest of this identity is persisted,
    /// so it must contain only non-secret provenance and geometry—never a key,
    /// password, recovery secret, or correlatable derivative of one.
    Validated {
        identity: String,
    },
}

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub chunk_size: usize,
    pub allocation: RawAllocation,
    /// Granularity used to find holes inside a streaming chunk. This does not
    /// alter logical output bytes and is deliberately not part of resume
    /// identity, so a compatible v1 checkpoint can continue with a different
    /// sparse granularity while retaining its prior allocation counters.
    pub sparse_block_size: usize,
    /// Number of reusable chunk buffers in the bounded read/write pipeline.
    /// This affects memory use and throughput only, not exported bytes.
    pub pipeline_depth: usize,
    pub resume: ResumeMode,
    pub checkpoint_bytes: u64,
    /// Defaults to `<output>.manifest.json` when omitted.
    pub manifest_path: Option<PathBuf>,
    pub overwrite: bool,
    pub sync_data: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            allocation: RawAllocation::Dense,
            sparse_block_size: DEFAULT_SPARSE_BLOCK_SIZE,
            pipeline_depth: DEFAULT_PIPELINE_DEPTH,
            resume: ResumeMode::Disabled,
            checkpoint_bytes: DEFAULT_CHECKPOINT_BYTES,
            manifest_path: None,
            overwrite: false,
            sync_data: true,
        }
    }
}

/// Public export provenance. Never put passwords, FVEKs, recovery keys, or
/// other secrets in these fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportProvenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extent: Option<VolumeExtent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<VolumeLayerDescriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_metadata: BTreeMap<String, String>,
}

impl ExportProvenance {
    pub fn from_pipeline(
        pipeline: &VolumePipeline,
        source_path: Option<String>,
        source_format: Option<String>,
    ) -> Self {
        Self {
            source_path,
            source_format,
            extent: pipeline.extent().cloned(),
            layers: pipeline.layers().to_vec(),
            public_metadata: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportManifest {
    pub schema: String,
    pub created_unix_ms: u64,
    pub output_path: String,
    pub logical_bytes: u64,
    pub sector_size: u32,
    pub chunk_size: usize,
    #[serde(default = "default_sparse_block_size")]
    /// Sparse scanning policy for bytes copied in the final run. When the
    /// export resumed, this applies beginning at
    /// `sparse_block_size_applies_from`; prior allocation counters are retained
    /// exactly from the checkpoint and may reflect the earlier policy.
    pub sparse_block_size: usize,
    #[serde(default)]
    pub sparse_block_size_applies_from: u64,
    pub allocation: RawAllocation,
    pub sha256: String,
    pub resumed_from: u64,
    pub data_bytes_written: u64,
    pub sparse_zero_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocated_bytes: Option<u64>,
    pub provenance: ExportProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReport {
    pub output_path: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: ExportManifest,
    pub bytes_copied_this_run: u64,
}

/// Non-mutating export validation and disk-space requirement information.
///
/// Dense output requires at least `required_dense_bytes` free at the output
/// filesystem. Sparse allocation is data-dependent, so callers should display
/// its logical size and monitor write failures instead of assuming a minimum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPreflight {
    pub output_path: PathBuf,
    /// Stable lease keyed to the final output path.
    pub lock_path: PathBuf,
    /// Stable lease keyed to the manifest path. Both leases are acquired in a
    /// deterministic order so distinct outputs cannot race on one manifest.
    pub manifest_lock_path: PathBuf,
    pub manifest_path: PathBuf,
    pub partial_path: PathBuf,
    pub manifest_partial_path: PathBuf,
    pub resume_path: PathBuf,
    pub output_backup_path: PathBuf,
    pub manifest_backup_path: PathBuf,
    pub resume_temp_path: PathBuf,
    pub resume_backup_path: PathBuf,
    pub logical_bytes: u64,
    pub sector_size: u32,
    pub resumable_bytes: u64,
    pub required_dense_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportStage {
    Preparing,
    ValidatingResume,
    Exporting,
    Finalizing,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportProgress {
    pub stage: ExportStage,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub resumed_from: u64,
    pub data_bytes_written: u64,
    pub sparse_zero_bytes: u64,
}

pub struct ExportControl<'a> {
    cancellation: Option<&'a AtomicBool>,
    progress: Option<&'a mut dyn FnMut(&ExportProgress)>,
}

impl<'a> ExportControl<'a> {
    pub fn none() -> Self {
        Self {
            cancellation: None,
            progress: None,
        }
    }

    pub fn new(
        cancellation: Option<&'a AtomicBool>,
        progress: Option<&'a mut dyn FnMut(&ExportProgress)>,
    ) -> Self {
        Self {
            cancellation,
            progress,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    fn notify(&mut self, progress: ExportProgress) {
        if let Some(callback) = self.progress.as_mut() {
            callback(&progress);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResumeState {
    schema: String,
    identity_sha256: String,
    logical_bytes: u64,
    sector_size: u32,
    chunk_size: usize,
    allocation: RawAllocation,
    completed_bytes: u64,
    prefix_sha256: String,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
}

struct PreparedOutput {
    file: File,
    completed: u64,
    resumed_from: u64,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
    hasher: Sha256,
    identity_sha256: Option<String>,
}

struct ExportLock {
    file: File,
    path: PathBuf,
}

impl ExportLock {
    fn acquire(path: PathBuf, sync_data: bool) -> Result<Self, ExportError> {
        let mut file = open_or_create_lock_file(&path)?;
        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                return Err(ExportError::ExportLocked(path));
            }
            Err(source) => {
                return Err(ExportError::Io {
                    operation: "acquire export lock",
                    path,
                    source,
                });
            }
        }
        tighten_private_permissions(&file, &path)?;
        file.set_len(0).map_err(|source| ExportError::Io {
            operation: "reset export lock metadata",
            path: path.clone(),
            source,
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| ExportError::Io {
                operation: "seek export lock metadata",
                path: path.clone(),
                source,
            })?;
        writeln!(
            file,
            "pid={} created_unix_ms={}",
            std::process::id(),
            unix_time_ms()?
        )
        .map_err(|source| ExportError::Io {
            operation: "write export lock",
            path: path.clone(),
            source,
        })?;
        if sync_data && let Err(source) = file.sync_all() {
            return Err(ExportError::Io {
                operation: "sync export lock",
                path: path.clone(),
                source,
            });
        }
        sync_parent(&path).map_err(|source| ExportError::Io {
            operation: "sync export lock directory",
            path: path.clone(),
            source,
        })?;
        Ok(Self { file, path })
    }
}

impl Drop for ExportLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            log::warn!(
                "Could not unlock export lock {}: {}",
                self.path.display(),
                error
            );
        }
    }
}

fn open_or_create_lock_file(path: &Path) -> Result<File, ExportError> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    set_no_follow(&mut create);
    set_private_create(&mut create);
    match create.open(path) {
        Ok(file) => Ok(file),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|source| ExportError::Io {
                operation: "inspect existing export lock",
                path: path.to_path_buf(),
                source,
            })?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(ExportError::InvalidConfiguration(format!(
                    "export lock path {} is not a regular file",
                    path.display()
                )));
            }
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            set_no_follow(&mut existing);
            existing.open(path).map_err(|source| ExportError::Io {
                operation: "open existing export lock",
                path: path.to_path_buf(),
                source,
            })
        }
        Err(source) => Err(ExportError::Io {
            operation: "create export lock",
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(unix)]
fn set_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn set_no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn tighten_private_permissions(file: &File, path: &Path) -> Result<(), ExportError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| ExportError::Io {
            operation: "restrict staging file permissions",
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn tighten_private_permissions(_file: &File, _path: &Path) -> Result<(), ExportError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Export the complete logical contents of `reader` as a standalone RAW image.
///
/// A successful return guarantees that the final output and JSON manifest have
/// been flushed and renamed from their staging paths. Cancellation and errors
/// before publication leave only staging data. Publication failures are rolled
/// back when possible; [`ExportError::PublishRollback`] explicitly reports the
/// paths when the filesystem prevents complete recovery.
pub fn export_raw(
    reader: &mut dyn VolumeReader,
    output_path: impl AsRef<Path>,
    provenance: ExportProvenance,
    options: &ExportOptions,
    control: &mut ExportControl<'_>,
) -> Result<ExportReport, ExportError> {
    let requested_output = output_path.as_ref().to_path_buf();
    // Validate path collisions before touching the lock path, then repeat the
    // state-sensitive preflight while holding the export lock.
    let preliminary = preflight_export(reader, &requested_output, options)?;
    let resume_recovery_path = preliminary.resume_path.clone();
    let _locks = acquire_export_locks(
        [preliminary.lock_path, preliminary.manifest_lock_path],
        options.sync_data,
    )?;
    if matches!(options.resume, ResumeMode::Validated { .. }) {
        recover_resume_sidecar(reader, options, &resume_recovery_path)?;
    }
    let preflight = preflight_export(reader, &requested_output, options)?;
    let output_path = preflight.output_path.as_path();
    let manifest_path = preflight.manifest_path;
    let partial_path = preflight.partial_path;
    let manifest_partial_path = preflight.manifest_partial_path;
    let resume_path = preflight.resume_path;
    let output_backup_path = preflight.output_backup_path;
    let manifest_backup_path = preflight.manifest_backup_path;

    protect_final_paths(
        output_path,
        &manifest_path,
        &output_backup_path,
        &manifest_backup_path,
        options.overwrite,
    )?;
    if staging_entry_exists(&manifest_partial_path)? {
        if !options.overwrite {
            return Err(ExportError::AlreadyExists(manifest_partial_path));
        }
        remove_staging_entry(&manifest_partial_path)?;
    }
    if control.is_cancelled() {
        return Err(ExportError::Cancelled { completed_bytes: 0 });
    }
    control.notify(progress(
        ExportStage::Preparing,
        0,
        reader.volume_len(),
        0,
        0,
        0,
    ));

    let mut prepared = prepare_output(reader, &partial_path, &resume_path, options, control)?;
    let total = reader.volume_len();
    let sector_size = reader.sector_size();
    let mut completed = prepared.completed;
    let resumed_from = prepared.resumed_from;
    let mut data_bytes_written = prepared.data_bytes_written;
    let mut sparse_zero_bytes = prepared.sparse_zero_bytes;

    control.notify(progress(
        ExportStage::Exporting,
        completed,
        total,
        resumed_from,
        data_bytes_written,
        sparse_zero_bytes,
    ));
    (completed, data_bytes_written, sparse_zero_bytes) = stream_export(
        reader,
        &mut prepared.file,
        &partial_path,
        &resume_path,
        options,
        prepared.identity_sha256.as_deref(),
        total,
        sector_size,
        completed,
        resumed_from,
        &mut prepared.hasher,
        data_bytes_written,
        sparse_zero_bytes,
        control,
    )?;

    control.notify(progress(
        ExportStage::Finalizing,
        completed,
        total,
        resumed_from,
        data_bytes_written,
        sparse_zero_bytes,
    ));
    prepared
        .file
        .set_len(total)
        .map_err(|source| ExportError::Io {
            operation: "set staged output length",
            path: partial_path.clone(),
            source,
        })?;
    prepared.file.flush().map_err(|source| ExportError::Io {
        operation: "flush staged output",
        path: partial_path.clone(),
        source,
    })?;
    if options.sync_data {
        prepared.file.sync_all().map_err(|source| ExportError::Io {
            operation: "sync staged output",
            path: partial_path.clone(),
            source,
        })?;
    }
    let allocated_bytes = allocated_bytes(&prepared.file).ok();
    let sha256 = hex::encode(prepared.hasher.finalize());
    let manifest = ExportManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        created_unix_ms: unix_time_ms()?,
        output_path: output_path.to_string_lossy().into_owned(),
        logical_bytes: total,
        sector_size,
        chunk_size: options.chunk_size,
        sparse_block_size: options.sparse_block_size,
        sparse_block_size_applies_from: resumed_from,
        allocation: options.allocation,
        sha256,
        resumed_from,
        data_bytes_written,
        sparse_zero_bytes,
        allocated_bytes,
        provenance,
    };

    write_json_file(&manifest_partial_path, &manifest, options.sync_data)?;
    publish_pair(
        &partial_path,
        output_path,
        &manifest_partial_path,
        &manifest_path,
        options.overwrite,
    )?;
    remove_resume_state(&resume_path);

    control.notify(progress(
        ExportStage::Complete,
        completed,
        total,
        resumed_from,
        data_bytes_written,
        sparse_zero_bytes,
    ));
    Ok(ExportReport {
        output_path: output_path.to_path_buf(),
        manifest_path,
        manifest,
        bytes_copied_this_run: total - resumed_from,
    })
}

struct ExportChunk {
    offset: u64,
    valid_bytes: usize,
    buffer: Vec<u8>,
}

enum ReaderMessage {
    Chunk(ExportChunk),
    Finished,
    Cancelled,
    Failed(ExportError),
}

fn produce_export_chunks(
    reader: &mut dyn VolumeReader,
    start: u64,
    total: u64,
    chunk_size: usize,
    cancellation: Option<&AtomicBool>,
    free_buffers: Receiver<Vec<u8>>,
    ready_chunks: SyncSender<ReaderMessage>,
) {
    let mut offset = start;
    while offset < total {
        if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            let _ = ready_chunks.send(ReaderMessage::Cancelled);
            return;
        }
        let Ok(mut buffer) = free_buffers.recv() else {
            return;
        };
        let wanted = usize::try_from((total - offset).min(chunk_size as u64))
            .expect("wanted chunk is bounded by usize chunk_size");
        if let Err(error) = read_exact_at(reader, &mut buffer[..wanted], offset) {
            let _ = ready_chunks.send(ReaderMessage::Failed(error));
            return;
        }
        if ready_chunks
            .send(ReaderMessage::Chunk(ExportChunk {
                offset,
                valid_bytes: wanted,
                buffer,
            }))
            .is_err()
        {
            return;
        }
        offset += wanted as u64;
    }
    let _ = ready_chunks.send(ReaderMessage::Finished);
}

#[allow(clippy::too_many_arguments)]
fn stream_export(
    reader: &mut dyn VolumeReader,
    file: &mut File,
    partial_path: &Path,
    resume_path: &Path,
    options: &ExportOptions,
    identity_sha256: Option<&str>,
    total: u64,
    sector_size: u32,
    mut completed: u64,
    resumed_from: u64,
    hasher: &mut Sha256,
    mut data_bytes_written: u64,
    mut sparse_zero_bytes: u64,
    control: &mut ExportControl<'_>,
) -> Result<(u64, u64, u64), ExportError> {
    if completed == total {
        return Ok((completed, data_bytes_written, sparse_zero_bytes));
    }

    let (free_sender, free_receiver) = sync_channel(options.pipeline_depth);
    for _ in 0..options.pipeline_depth {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(options.chunk_size)
            .map_err(|source| ExportError::BufferAllocation {
                requested_bytes: options.chunk_size,
                source,
            })?;
        buffer.resize(options.chunk_size, 0);
        // The channel has exactly this capacity and no other sender yet.
        free_sender
            .send(buffer)
            .expect("new buffer pool has sufficient capacity");
    }
    let (ready_sender, ready_receiver) = sync_channel(options.pipeline_depth);
    let cancellation = control.cancellation;
    let mut last_checkpoint = completed;

    thread::scope(|scope| {
        let producer = scope.spawn(move || {
            produce_export_chunks(
                reader,
                completed,
                total,
                options.chunk_size,
                cancellation,
                free_receiver,
                ready_sender,
            );
        });

        // Every early return must disconnect both channels before the scoped
        // reader thread is joined. Otherwise the producer could remain blocked
        // waiting for a free buffer or for the ready queue to drain.
        let mut producer_disconnected = false;
        let consume_result = (|| {
            loop {
                if control.is_cancelled() {
                    checkpoint(
                        file,
                        resume_path,
                        options,
                        identity_sha256,
                        total,
                        sector_size,
                        completed,
                        hasher,
                        data_bytes_written,
                        sparse_zero_bytes,
                    )?;
                    return Err(ExportError::Cancelled {
                        completed_bytes: completed,
                    });
                }

                let message = match ready_receiver.recv() {
                    Ok(message) => message,
                    Err(_) => {
                        producer_disconnected = true;
                        return Err(ExportError::InvalidConfiguration(
                            "export reader pipeline stopped without a completion status".to_owned(),
                        ));
                    }
                };
                match message {
                    ReaderMessage::Chunk(chunk) => {
                        if chunk.offset != completed {
                            return Err(ExportError::InvalidConfiguration(format!(
                                "export reader pipeline returned byte {} while byte {completed} was expected",
                                chunk.offset
                            )));
                        }
                        let bytes = &chunk.buffer[..chunk.valid_bytes];
                        hasher.update(bytes);
                        write_export_chunk(
                            file,
                            partial_path,
                            bytes,
                            options.allocation,
                            options.sparse_block_size,
                            &mut data_bytes_written,
                            &mut sparse_zero_bytes,
                        )?;
                        completed += chunk.valid_bytes as u64;

                        control.notify(progress(
                            ExportStage::Exporting,
                            completed,
                            total,
                            resumed_from,
                            data_bytes_written,
                            sparse_zero_bytes,
                        ));

                        if identity_sha256.is_some()
                            && completed < total
                            && completed.saturating_sub(last_checkpoint) >= options.checkpoint_bytes
                        {
                            checkpoint(
                                file,
                                resume_path,
                                options,
                                identity_sha256,
                                total,
                                sector_size,
                                completed,
                                hasher,
                                data_bytes_written,
                                sparse_zero_bytes,
                            )?;
                            last_checkpoint = completed;
                        }
                        // Reuse the allocation instead of allocating one large
                        // buffer per chunk. Failure only means the producer has
                        // already completed or the consumer is exiting.
                        let _ = free_sender.send(chunk.buffer);
                    }
                    ReaderMessage::Finished => {
                        if completed != total {
                            return Err(ExportError::PrematureEof {
                                offset: completed,
                                expected: usize::try_from(
                                    (total - completed).min(usize::MAX as u64),
                                )
                                .unwrap_or(usize::MAX),
                                received: 0,
                            });
                        }
                        return Ok((completed, data_bytes_written, sparse_zero_bytes));
                    }
                    ReaderMessage::Cancelled => {
                        checkpoint(
                            file,
                            resume_path,
                            options,
                            identity_sha256,
                            total,
                            sector_size,
                            completed,
                            hasher,
                            data_bytes_written,
                            sparse_zero_bytes,
                        )?;
                        return Err(ExportError::Cancelled {
                            completed_bytes: completed,
                        });
                    }
                    ReaderMessage::Failed(error) => return Err(error),
                }
            }
        })();
        drop(free_sender);
        drop(ready_receiver);
        let producer_result = producer.join().map_err(|_| {
            ExportError::InvalidConfiguration(
                "export source reader pipeline panicked while producing a chunk".to_owned(),
            )
        });
        match (consume_result, producer_result) {
            (Ok(_), Err(producer_error)) => Err(producer_error),
            (Err(_), Err(producer_error)) if producer_disconnected => Err(producer_error),
            (consume_result, _) => consume_result,
        }
    })
}

fn write_export_chunk(
    file: &mut File,
    path: &Path,
    bytes: &[u8],
    allocation: RawAllocation,
    sparse_block_size: usize,
    data_bytes_written: &mut u64,
    sparse_zero_bytes: &mut u64,
) -> Result<(), ExportError> {
    if allocation == RawAllocation::Dense {
        file.write_all(bytes).map_err(|source| ExportError::Io {
            operation: "write staged output",
            path: path.to_path_buf(),
            source,
        })?;
        *data_bytes_written += bytes.len() as u64;
        return Ok(());
    }

    let mut run_start = 0usize;
    while run_start < bytes.len() {
        let first_end = (run_start + sparse_block_size).min(bytes.len());
        let zero_run = bytes[run_start..first_end].iter().all(|byte| *byte == 0);
        let mut run_end = first_end;
        while run_end < bytes.len() {
            let block_end = (run_end + sparse_block_size).min(bytes.len());
            let block_is_zero = bytes[run_end..block_end].iter().all(|byte| *byte == 0);
            if block_is_zero != zero_run {
                break;
            }
            run_end = block_end;
        }
        let run_len = run_end - run_start;
        if zero_run {
            file.seek(SeekFrom::Current(run_len as i64))
                .map_err(|source| ExportError::Io {
                    operation: "seek sparse output",
                    path: path.to_path_buf(),
                    source,
                })?;
            *sparse_zero_bytes += run_len as u64;
        } else {
            file.write_all(&bytes[run_start..run_end])
                .map_err(|source| ExportError::Io {
                    operation: "write staged output",
                    path: path.to_path_buf(),
                    source,
                })?;
            *data_bytes_written += run_len as u64;
        }
        run_start = run_end;
    }
    Ok(())
}

fn acquire_export_locks(
    paths: impl IntoIterator<Item = PathBuf>,
    sync_data: bool,
) -> Result<Vec<ExportLock>, ExportError> {
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| ExportLock::acquire(path, sync_data))
        .collect()
}

/// Validate geometry/options and return paths plus conservative space needs
/// without creating, truncating, or deleting anything.
pub fn preflight_export(
    reader: &dyn VolumeReader,
    output_path: impl AsRef<Path>,
    options: &ExportOptions,
) -> Result<ExportPreflight, ExportError> {
    validate_options(reader, options)?;
    let output_path = output_path.as_ref().to_path_buf();
    let lock_path = appended_path(&output_path, ".export.lock");
    let manifest_path = options
        .manifest_path
        .clone()
        .unwrap_or_else(|| appended_path(&output_path, ".manifest.json"));
    let manifest_lock_path = appended_path(&manifest_path, ".export.lock");
    let partial_path = appended_path(&output_path, ".partial");
    let resume_path = appended_path(&output_path, ".partial.resume.json");
    let manifest_partial_path = appended_path(&manifest_path, ".partial");
    let output_backup_path = appended_path(&output_path, ".replace-backup");
    let manifest_backup_path = appended_path(&manifest_path, ".replace-backup");
    let resume_temp_path = appended_path(&resume_path, ".tmp");
    let resume_backup_path = appended_path(&resume_path, ".replace-backup");
    let named_paths = [
        ("output", &output_path),
        ("export lock", &lock_path),
        ("manifest", &manifest_path),
        ("manifest export lock", &manifest_lock_path),
        ("output staging", &partial_path),
        ("resume state", &resume_path),
        ("manifest staging", &manifest_partial_path),
        ("output replacement backup", &output_backup_path),
        ("manifest replacement backup", &manifest_backup_path),
        ("resume temporary state", &resume_temp_path),
        ("resume replacement backup", &resume_backup_path),
    ];
    for (index, (left_name, left_path)) in named_paths.iter().enumerate() {
        for (right_name, right_path) in &named_paths[index + 1..] {
            if left_path == right_path {
                return Err(ExportError::InvalidConfiguration(format!(
                    "{left_name} path collides with {right_name} path: {}",
                    left_path.display()
                )));
            }
        }
    }
    let resumable_bytes = preflight_resume_bytes(reader, options, &partial_path, &resume_path)?;
    Ok(ExportPreflight {
        output_path,
        lock_path,
        manifest_lock_path,
        manifest_path,
        partial_path,
        manifest_partial_path,
        resume_path,
        output_backup_path,
        manifest_backup_path,
        resume_temp_path,
        resume_backup_path,
        logical_bytes: reader.volume_len(),
        sector_size: reader.sector_size(),
        resumable_bytes,
        required_dense_bytes: (options.allocation == RawAllocation::Dense)
            .then_some(reader.volume_len() - resumable_bytes),
    })
}

fn preflight_resume_bytes(
    reader: &dyn VolumeReader,
    options: &ExportOptions,
    partial_path: &Path,
    resume_path: &Path,
) -> Result<u64, ExportError> {
    let ResumeMode::Validated { identity } = &options.resume else {
        return Ok(0);
    };
    let partial_exists = staging_entry_exists(partial_path)?;
    let state_path = resume_state_candidate(resume_path)?;
    if partial_exists != state_path.is_some() {
        return Err(ExportError::ResumeMismatch(
            "staged output and resume state must either both exist or both be absent".to_owned(),
        ));
    }
    if !partial_exists {
        return Ok(0);
    }

    let state_path = state_path.expect("partial and resume-state presence were compared");
    let state: ResumeState = read_json_file(&state_path, false)?;
    let identity_sha256 = resume_identity_hash(reader, options, identity);
    validate_resume_state(&state, reader, options, &identity_sha256)?;
    ensure_regular_staging(partial_path)?;
    ensure_regular_staging(&state_path)?;
    let partial_len = fs::symlink_metadata(partial_path)
        .map_err(|source| ExportError::Io {
            operation: "inspect staged output during preflight",
            path: partial_path.to_path_buf(),
            source,
        })?
        .len();
    if partial_len < state.completed_bytes {
        return Err(ExportError::ResumeMismatch(format!(
            "staged output length {partial_len} is shorter than checkpoint {}",
            state.completed_bytes
        )));
    }
    Ok(state.completed_bytes)
}

fn resume_state_candidate(resume_path: &Path) -> Result<Option<PathBuf>, ExportError> {
    let backup_path = appended_path(resume_path, ".replace-backup");
    let temp_path = appended_path(resume_path, ".tmp");
    for candidate in [resume_path.to_path_buf(), backup_path, temp_path] {
        if staging_entry_exists(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Recover an interrupted checkpoint-sidecar replacement while both export
/// destination leases are held. The active sidecar is the commit point; an
/// orphaned backup is the last committed state when no active file exists,
/// while a lone temporary file is the first checkpoint of a new export.
fn recover_resume_sidecar(
    reader: &dyn VolumeReader,
    options: &ExportOptions,
    resume_path: &Path,
) -> Result<(), ExportError> {
    let ResumeMode::Validated { identity } = &options.resume else {
        return Ok(());
    };
    let backup_path = appended_path(resume_path, ".replace-backup");
    let temp_path = appended_path(resume_path, ".tmp");
    let active_exists = staging_entry_exists(resume_path)?;
    let backup_exists = staging_entry_exists(&backup_path)?;
    let temp_exists = staging_entry_exists(&temp_path)?;
    if !active_exists && !backup_exists && !temp_exists {
        return Ok(());
    }

    for path in [
        active_exists.then_some(resume_path),
        backup_exists.then_some(backup_path.as_path()),
        temp_exists.then_some(temp_path.as_path()),
    ]
    .into_iter()
    .flatten()
    {
        ensure_regular_staging(path)?;
    }

    let selected_path = if active_exists {
        resume_path
    } else if backup_exists {
        backup_path.as_path()
    } else {
        temp_path.as_path()
    };
    let state: ResumeState = read_json_file(selected_path, false)?;
    let identity_sha256 = resume_identity_hash(reader, options, identity);
    validate_resume_state(&state, reader, options, &identity_sha256)?;

    let mut changed = false;
    if active_exists {
        if backup_exists {
            fs::remove_file(&backup_path).map_err(|source| ExportError::Io {
                operation: "remove recovered resume checkpoint backup",
                path: backup_path.clone(),
                source,
            })?;
            changed = true;
        }
        if temp_exists {
            fs::remove_file(&temp_path).map_err(|source| ExportError::Io {
                operation: "remove stale resume checkpoint temporary file",
                path: temp_path.clone(),
                source,
            })?;
            changed = true;
        }
    } else {
        if backup_exists {
            fs::rename(&backup_path, resume_path).map_err(|source| ExportError::Io {
                operation: "restore interrupted resume checkpoint backup",
                path: resume_path.to_path_buf(),
                source,
            })?;
        } else {
            fs::rename(&temp_path, resume_path).map_err(|source| ExportError::Io {
                operation: "publish recovered initial resume checkpoint",
                path: resume_path.to_path_buf(),
                source,
            })?;
        }
        changed = true;
        if backup_exists && temp_exists {
            fs::remove_file(&temp_path).map_err(|source| ExportError::Io {
                operation: "remove abandoned resume checkpoint temporary file",
                path: temp_path.clone(),
                source,
            })?;
        }
    }

    if changed && options.sync_data {
        sync_parent(resume_path).map_err(|source| ExportError::Io {
            operation: "sync recovered resume checkpoint directory",
            path: resume_path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn validate_options(reader: &dyn VolumeReader, options: &ExportOptions) -> Result<(), ExportError> {
    if reader.volume_len() == 0 {
        return Err(ExportError::InvalidConfiguration(
            "volume length must be greater than zero".to_owned(),
        ));
    }
    let sector_size = reader.sector_size();
    if sector_size == 0 || !sector_size.is_power_of_two() {
        return Err(ExportError::InvalidConfiguration(
            "sector size must be a non-zero power of two".to_owned(),
        ));
    }
    if !reader.volume_len().is_multiple_of(u64::from(sector_size)) {
        return Err(ExportError::InvalidConfiguration(format!(
            "volume length {} is not aligned to sector size {sector_size}",
            reader.volume_len()
        )));
    }
    if options.chunk_size == 0 || !options.chunk_size.is_multiple_of(sector_size as usize) {
        return Err(ExportError::InvalidConfiguration(format!(
            "chunk size must be non-zero and aligned to sector size {sector_size}"
        )));
    }
    if options.chunk_size > MAX_CHUNK_SIZE {
        return Err(ExportError::InvalidConfiguration(format!(
            "chunk size {} exceeds the maximum supported size of {} bytes",
            options.chunk_size, MAX_CHUNK_SIZE
        )));
    }
    if options.sparse_block_size == 0
        || !options
            .sparse_block_size
            .is_multiple_of(sector_size as usize)
        || options.sparse_block_size > options.chunk_size
    {
        return Err(ExportError::InvalidConfiguration(format!(
            "sparse block size must be non-zero, aligned to sector size {sector_size}, and no larger than chunk size {}",
            options.chunk_size
        )));
    }
    if options.pipeline_depth == 0 || options.pipeline_depth > MAX_PIPELINE_DEPTH {
        return Err(ExportError::InvalidConfiguration(format!(
            "pipeline depth must be between 1 and {MAX_PIPELINE_DEPTH}"
        )));
    }
    let pipeline_buffer_bytes = (options.chunk_size as u64)
        .checked_mul(options.pipeline_depth as u64)
        .ok_or_else(|| {
            ExportError::InvalidConfiguration(
                "pipeline buffer memory requirement overflows u64".to_owned(),
            )
        })?;
    if pipeline_buffer_bytes > MAX_PIPELINE_BUFFER_BYTES {
        return Err(ExportError::InvalidConfiguration(format!(
            "pipeline buffers require {pipeline_buffer_bytes} bytes; maximum supported buffered memory is {MAX_PIPELINE_BUFFER_BYTES} bytes"
        )));
    }
    if options.checkpoint_bytes == 0 {
        return Err(ExportError::InvalidConfiguration(
            "checkpoint interval must be greater than zero".to_owned(),
        ));
    }
    if let ResumeMode::Validated { identity } = &options.resume
        && identity.trim().is_empty()
    {
        return Err(ExportError::InvalidConfiguration(
            "validated resume requires a non-empty source/pipeline identity".to_owned(),
        ));
    }
    Ok(())
}

fn protect_final_paths(
    output_path: &Path,
    manifest_path: &Path,
    output_backup_path: &Path,
    manifest_backup_path: &Path,
    overwrite: bool,
) -> Result<(), ExportError> {
    for backup_path in [output_backup_path, manifest_backup_path] {
        if staging_entry_exists(backup_path)? {
            return Err(ExportError::AlreadyExists(backup_path.to_path_buf()));
        }
    }
    for destination in [output_path, manifest_path] {
        if !staging_entry_exists(destination)? {
            continue;
        }
        if overwrite {
            refuse_directory_replacement(destination)?;
        } else {
            return Err(ExportError::AlreadyExists(destination.to_path_buf()));
        }
    }
    Ok(())
}

fn staging_entry_exists(path: &Path) -> Result<bool, ExportError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(ExportError::Io {
            operation: "inspect staging path",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn ensure_regular_staging(path: &Path) -> Result<(), ExportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ExportError::Io {
        operation: "inspect staging path",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ExportError::InvalidConfiguration(format!(
            "staging path {} is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

fn remove_staging_entry(path: &Path) -> Result<(), ExportError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ExportError::Io {
                operation: "inspect stale staging path",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_dir() {
        return Err(ExportError::InvalidConfiguration(format!(
            "refusing to remove staging directory {}",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(|source| ExportError::Io {
        operation: "remove stale staging entry",
        path: path.to_path_buf(),
        source,
    })
}

fn open_existing_staging(
    path: &Path,
    write: bool,
    tighten_permissions: bool,
) -> Result<File, ExportError> {
    ensure_regular_staging(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    set_no_follow(&mut options);
    let file = options.open(path).map_err(|source| ExportError::Io {
        operation: "open existing staging file",
        path: path.to_path_buf(),
        source,
    })?;
    if tighten_permissions {
        tighten_private_permissions(&file, path)?;
    }
    Ok(file)
}

fn create_private_staging(
    path: &Path,
    read: bool,
    operation: &'static str,
) -> Result<File, ExportError> {
    let mut options = OpenOptions::new();
    options.read(read).write(true).create_new(true);
    set_no_follow(&mut options);
    set_private_create(&mut options);
    options.open(path).map_err(|source| ExportError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

fn prepare_output(
    reader: &mut dyn VolumeReader,
    partial_path: &Path,
    resume_path: &Path,
    options: &ExportOptions,
    control: &mut ExportControl<'_>,
) -> Result<PreparedOutput, ExportError> {
    match &options.resume {
        ResumeMode::Disabled => {
            for path in [partial_path, resume_path] {
                if staging_entry_exists(path)? {
                    if !options.overwrite {
                        return Err(ExportError::AlreadyExists(path.to_path_buf()));
                    }
                    remove_staging_entry(path)?;
                }
            }
            let file = create_private_staging(partial_path, true, "create staged output")?;
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|source| ExportError::Io {
                    operation: "seek source",
                    path: partial_path.to_path_buf(),
                    source,
                })?;
            Ok(PreparedOutput {
                file,
                completed: 0,
                resumed_from: 0,
                data_bytes_written: 0,
                sparse_zero_bytes: 0,
                hasher: Sha256::new(),
                identity_sha256: None,
            })
        }
        ResumeMode::Validated { identity } => {
            let identity_sha256 = resume_identity_hash(reader, options, identity);
            let partial_exists = staging_entry_exists(partial_path)?;
            let state_exists = staging_entry_exists(resume_path)?;
            if partial_exists != state_exists {
                return Err(ExportError::ResumeMismatch(
                    "staged output and resume state must either both exist or both be absent"
                        .to_owned(),
                ));
            }

            if !partial_exists {
                let file = create_private_staging(partial_path, true, "create staged output")?;
                reader
                    .seek(SeekFrom::Start(0))
                    .map_err(|source| ExportError::Io {
                        operation: "seek source",
                        path: partial_path.to_path_buf(),
                        source,
                    })?;
                let prepared = PreparedOutput {
                    file,
                    completed: 0,
                    resumed_from: 0,
                    data_bytes_written: 0,
                    sparse_zero_bytes: 0,
                    hasher: Sha256::new(),
                    identity_sha256: Some(identity_sha256),
                };
                save_resume_state(
                    resume_path,
                    options,
                    prepared.identity_sha256.as_deref().unwrap(),
                    reader.volume_len(),
                    reader.sector_size(),
                    0,
                    &prepared.hasher,
                    0,
                    0,
                )?;
                return Ok(prepared);
            }

            ensure_regular_staging(partial_path)?;
            ensure_regular_staging(resume_path)?;
            let state: ResumeState = read_json_file(resume_path, true)?;
            validate_resume_state(&state, reader, options, &identity_sha256)?;
            let mut file = open_existing_staging(partial_path, true, true)?;
            let file_len = file
                .metadata()
                .map_err(|source| ExportError::Io {
                    operation: "inspect staged output",
                    path: partial_path.to_path_buf(),
                    source,
                })?
                .len();
            if file_len < state.completed_bytes {
                return Err(ExportError::ResumeMismatch(format!(
                    "staged output length {file_len} is shorter than checkpoint {}",
                    state.completed_bytes
                )));
            }
            if file_len > state.completed_bytes {
                file.set_len(state.completed_bytes)
                    .map_err(|source| ExportError::Io {
                        operation: "discard uncheckpointed staged tail",
                        path: partial_path.to_path_buf(),
                        source,
                    })?;
            }

            let hasher = validate_resume_prefixes_concurrently(
                reader,
                state.completed_bytes,
                partial_path,
                &state.prefix_sha256,
                control,
                state.data_bytes_written,
                state.sparse_zero_bytes,
            )?;
            file.seek(SeekFrom::Start(state.completed_bytes))
                .map_err(|source| ExportError::Io {
                    operation: "seek staged output for resume",
                    path: partial_path.to_path_buf(),
                    source,
                })?;
            reader
                .seek(SeekFrom::Start(state.completed_bytes))
                .map_err(|source| ExportError::Io {
                    operation: "seek source for resume",
                    path: partial_path.to_path_buf(),
                    source,
                })?;

            Ok(PreparedOutput {
                file,
                completed: state.completed_bytes,
                resumed_from: state.completed_bytes,
                data_bytes_written: state.data_bytes_written,
                sparse_zero_bytes: state.sparse_zero_bytes,
                hasher,
                identity_sha256: Some(identity_sha256),
            })
        }
    }
}

const RESUME_VALIDATION_BUFFER_SIZE: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
enum ResumeValidationSide {
    Staged,
    Source,
}

fn validate_resume_prefixes_concurrently(
    reader: &mut dyn VolumeReader,
    completed_bytes: u64,
    partial_path: &Path,
    expected_sha256: &str,
    control: &mut ExportControl<'_>,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
) -> Result<Sha256, ExportError> {
    if completed_bytes == 0 {
        return Ok(Sha256::new());
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| ExportError::Io {
            operation: "seek source for resume prefix validation",
            path: PathBuf::new(),
            source,
        })?;
    let mut staged_file = open_existing_staging(partial_path, false, false)?;
    staged_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| ExportError::Io {
            operation: "seek staged output for prefix validation",
            path: partial_path.to_path_buf(),
            source,
        })?;

    let cancellation = control.cancellation;
    let total_work = completed_bytes.saturating_mul(2);
    control.notify(progress(
        ExportStage::ValidatingResume,
        0,
        total_work,
        completed_bytes,
        data_bytes_written,
        sparse_zero_bytes,
    ));

    let (progress_sender, progress_receiver) = channel();
    let partial_path = partial_path.to_path_buf();
    let internal_abort = Arc::new(AtomicBool::new(false));
    let source_reader = &mut *reader;
    let (staged_hasher, source_hasher) = thread::scope(|scope| {
        let staged_sender = progress_sender.clone();
        let staged_path = partial_path.clone();
        let staged_abort = Arc::clone(&internal_abort);
        let staged_worker = scope.spawn(move || {
            let result = hash_staged_prefix_worker(
                &mut staged_file,
                completed_bytes,
                &staged_path,
                cancellation,
                &staged_abort,
                staged_sender,
            );
            if result.is_err() {
                staged_abort.store(true, Ordering::Relaxed);
            }
            result
        });
        let source_sender = progress_sender.clone();
        let source_abort = Arc::clone(&internal_abort);
        let source_worker = scope.spawn(move || {
            let result = hash_source_prefix_worker(
                source_reader,
                completed_bytes,
                cancellation,
                &source_abort,
                source_sender,
            );
            if result.is_err() {
                source_abort.store(true, Ordering::Relaxed);
            }
            result
        });
        drop(progress_sender);

        let mut staged_progress = 0_u64;
        let mut source_progress = 0_u64;
        for (side, bytes) in progress_receiver {
            match side {
                ResumeValidationSide::Staged => staged_progress = bytes,
                ResumeValidationSide::Source => source_progress = bytes,
            }
            control.notify(progress(
                ExportStage::ValidatingResume,
                staged_progress.saturating_add(source_progress),
                total_work,
                completed_bytes,
                data_bytes_written,
                sparse_zero_bytes,
            ));
        }

        let staged = staged_worker.join().map_err(|_| {
            ExportError::InvalidConfiguration(
                "staged-output resume validation worker panicked".to_owned(),
            )
        })?;
        let source = source_worker.join().map_err(|_| {
            ExportError::InvalidConfiguration("source resume validation worker panicked".to_owned())
        })?;
        match (staged, source) {
            (Ok(staged), Ok(source)) => Ok((staged, source)),
            (Err(staged), Ok(_)) => Err(staged),
            (Ok(_), Err(source)) => Err(source),
            (Err(staged), Err(source)) => {
                if matches!(staged, ExportError::Cancelled { .. })
                    && !matches!(source, ExportError::Cancelled { .. })
                {
                    Err(source)
                } else {
                    Err(staged)
                }
            }
        }
    })?;

    let staged_sha256 = hex::encode(staged_hasher.finalize());
    if staged_sha256 != expected_sha256 {
        return Err(ExportError::ResumeMismatch(
            "staged output prefix hash differs from checkpoint".to_owned(),
        ));
    }
    let source_sha256 = hex::encode(source_hasher.clone().finalize());
    if source_sha256 != expected_sha256 {
        return Err(ExportError::ResumeMismatch(format!(
            "current source prefix 0..{completed_bytes} differs from the staged checkpoint"
        )));
    }
    reader
        .seek(SeekFrom::Start(completed_bytes))
        .map_err(|source| ExportError::Io {
            operation: "restore source cursor after resume prefix validation",
            path: PathBuf::new(),
            source,
        })?;
    Ok(source_hasher)
}

fn hash_staged_prefix_worker(
    file: &mut File,
    completed_bytes: u64,
    path: &Path,
    cancellation: Option<&AtomicBool>,
    internal_abort: &AtomicBool,
    progress_sender: std::sync::mpsc::Sender<(ResumeValidationSide, u64)>,
) -> Result<Sha256, ExportError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; RESUME_VALIDATION_BUFFER_SIZE];
    let mut offset = 0_u64;
    while offset < completed_bytes {
        if internal_abort.load(Ordering::Relaxed)
            || cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return Err(ExportError::Cancelled { completed_bytes });
        }
        let wanted = usize::try_from((completed_bytes - offset).min(buffer.len() as u64))
            .expect("prefix chunk is bounded by its buffer length");
        file.read_exact(&mut buffer[..wanted])
            .map_err(|source| ExportError::Io {
                operation: "read staged output prefix",
                path: path.to_path_buf(),
                source,
            })?;
        hasher.update(&buffer[..wanted]);
        offset += wanted as u64;
        let _ = progress_sender.send((ResumeValidationSide::Staged, offset));
    }
    Ok(hasher)
}

fn hash_source_prefix_worker(
    reader: &mut dyn VolumeReader,
    completed_bytes: u64,
    cancellation: Option<&AtomicBool>,
    internal_abort: &AtomicBool,
    progress_sender: std::sync::mpsc::Sender<(ResumeValidationSide, u64)>,
) -> Result<Sha256, ExportError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; RESUME_VALIDATION_BUFFER_SIZE];
    let mut offset = 0_u64;
    while offset < completed_bytes {
        if internal_abort.load(Ordering::Relaxed)
            || cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            return Err(ExportError::Cancelled { completed_bytes });
        }
        let wanted = usize::try_from((completed_bytes - offset).min(buffer.len() as u64))
            .expect("prefix chunk is bounded by its buffer length");
        read_exact_at(reader, &mut buffer[..wanted], offset)?;
        hasher.update(&buffer[..wanted]);
        offset += wanted as u64;
        let _ = progress_sender.send((ResumeValidationSide::Source, offset));
    }
    Ok(hasher)
}

fn publish_pair(
    staged_output: &Path,
    output: &Path,
    staged_manifest: &Path,
    manifest: &Path,
    overwrite: bool,
) -> Result<(), ExportError> {
    let output_backup = appended_path(output, ".replace-backup");
    let manifest_backup = appended_path(manifest, ".replace-backup");
    if staging_entry_exists(&output_backup)? {
        return Err(ExportError::AlreadyExists(output_backup));
    }
    if staging_entry_exists(&manifest_backup)? {
        return Err(ExportError::AlreadyExists(manifest_backup));
    }
    if !overwrite && staging_entry_exists(output)? {
        return Err(ExportError::AlreadyExists(output.to_path_buf()));
    }
    if !overwrite && staging_entry_exists(manifest)? {
        return Err(ExportError::AlreadyExists(manifest.to_path_buf()));
    }
    if overwrite {
        let output_exists = staging_entry_exists(output)?;
        let manifest_exists = staging_entry_exists(manifest)?;
        if output_exists {
            refuse_directory_replacement(output)?;
        }
        if manifest_exists {
            refuse_directory_replacement(manifest)?;
        }
        if output_exists {
            fs::rename(output, &output_backup).map_err(|source| ExportError::Io {
                operation: "stage existing output for replacement",
                path: output.to_path_buf(),
                source,
            })?;
            if let Err(source) = sync_parent(output) {
                return Err(publication_failure(
                    "sync staged output replacement",
                    output,
                    staged_output,
                    source,
                    &[],
                    &[(&output_backup, output)],
                ));
            }
        }
        if manifest_exists {
            if let Err(source) = fs::rename(manifest, &manifest_backup) {
                return Err(publication_failure(
                    "stage existing manifest for replacement",
                    manifest,
                    staged_manifest,
                    source,
                    &[],
                    &[(&output_backup, output), (&manifest_backup, manifest)],
                ));
            }
            if let Err(source) = sync_parent(manifest) {
                return Err(publication_failure(
                    "sync staged manifest replacement",
                    manifest,
                    staged_manifest,
                    source,
                    &[],
                    &[(&output_backup, output), (&manifest_backup, manifest)],
                ));
            }
        }
    }

    // Publish the manifest first. The output path is the commit marker: it is
    // never made visible before its matching manifest is durable.
    if let Err(source) = fs::rename(staged_manifest, manifest) {
        return Err(publication_failure(
            "publish manifest",
            manifest,
            staged_manifest,
            source,
            &[],
            &[(&output_backup, output), (&manifest_backup, manifest)],
        ));
    }
    if let Err(source) = sync_parent(manifest) {
        return Err(publication_failure(
            "sync published manifest directory",
            manifest,
            staged_manifest,
            source,
            &[(manifest, staged_manifest)],
            &[(&output_backup, output), (&manifest_backup, manifest)],
        ));
    }
    if let Err(source) = fs::rename(staged_output, output) {
        return Err(publication_failure(
            "publish output",
            output,
            staged_output,
            source,
            &[(manifest, staged_manifest)],
            &[(&output_backup, output), (&manifest_backup, manifest)],
        ));
    }
    if let Err(source) = sync_parent(output) {
        return Err(publication_failure(
            "sync published output directory",
            output,
            staged_output,
            source,
            &[(output, staged_output), (manifest, staged_manifest)],
            &[(&output_backup, output), (&manifest_backup, manifest)],
        ));
    }

    remove_backup(&output_backup, output);
    remove_backup(&manifest_backup, manifest);
    Ok(())
}

fn refuse_directory_replacement(path: &Path) -> Result<(), ExportError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ExportError::Io {
        operation: "inspect replacement destination",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_dir() {
        return Err(ExportError::InvalidConfiguration(format!(
            "refusing to replace directory {}",
            path.display()
        )));
    }
    Ok(())
}

fn publication_failure(
    operation: &'static str,
    path: &Path,
    staged_path: &Path,
    publish: io::Error,
    published: &[(&Path, &Path)],
    backups: &[(&Path, &Path)],
) -> ExportError {
    match recover_publication(published, backups) {
        Ok(()) => ExportError::Io {
            operation,
            path: path.to_path_buf(),
            source: publish,
        },
        Err(rollback) => ExportError::PublishRollback {
            publish,
            rollback,
            published_path: path.to_path_buf(),
            staged_path: staged_path.to_path_buf(),
        },
    }
}

fn recover_publication(published: &[(&Path, &Path)], backups: &[(&Path, &Path)]) -> io::Result<()> {
    let mut first_error = None;
    for (published_path, staged_path) in published {
        if path_entry_exists(published_path) {
            record_io_error(
                &mut first_error,
                fs::rename(published_path, staged_path).and_then(|_| sync_parent(published_path)),
            );
        }
    }
    for (backup, destination) in backups {
        if path_entry_exists(backup) {
            record_io_error(
                &mut first_error,
                fs::rename(backup, destination).and_then(|_| sync_parent(destination)),
            );
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn record_io_error(first_error: &mut Option<io::Error>, result: io::Result<()>) {
    if let Err(error) = result
        && first_error.is_none()
    {
        *first_error = Some(error);
    }
}

fn path_entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn remove_backup(path: &Path, published_path: &Path) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != io::ErrorKind::NotFound
    {
        log::warn!(
            "Export succeeded but replacement backup {} could not be removed: {}",
            path.display(),
            error
        );
    }
    if let Err(error) = sync_parent(published_path) {
        log::warn!(
            "Export succeeded but directory for {} could not be synced: {}",
            published_path.display(),
            error
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn checkpoint(
    file: &mut File,
    resume_path: &Path,
    options: &ExportOptions,
    identity_sha256: Option<&str>,
    logical_bytes: u64,
    sector_size: u32,
    completed_bytes: u64,
    hasher: &Sha256,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
) -> Result<(), ExportError> {
    file.set_len(completed_bytes)
        .map_err(|source| ExportError::Io {
            operation: "checkpoint staged output length",
            path: resume_path.to_path_buf(),
            source,
        })?;
    file.flush().map_err(|source| ExportError::Io {
        operation: "flush staged output checkpoint",
        path: resume_path.to_path_buf(),
        source,
    })?;
    if options.sync_data {
        file.sync_data().map_err(|source| ExportError::Io {
            operation: "sync staged output checkpoint",
            path: resume_path.to_path_buf(),
            source,
        })?;
    }
    if let Some(identity_sha256) = identity_sha256 {
        save_resume_state(
            resume_path,
            options,
            identity_sha256,
            logical_bytes,
            sector_size,
            completed_bytes,
            hasher,
            data_bytes_written,
            sparse_zero_bytes,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn save_resume_state(
    resume_path: &Path,
    options: &ExportOptions,
    identity_sha256: &str,
    logical_bytes: u64,
    sector_size: u32,
    completed_bytes: u64,
    hasher: &Sha256,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
) -> Result<(), ExportError> {
    let state = ResumeState {
        schema: RESUME_SCHEMA.to_owned(),
        identity_sha256: identity_sha256.to_owned(),
        logical_bytes,
        sector_size,
        chunk_size: options.chunk_size,
        allocation: options.allocation,
        completed_bytes,
        prefix_sha256: hex::encode(hasher.clone().finalize()),
        data_bytes_written,
        sparse_zero_bytes,
    };
    let temp_path = appended_path(resume_path, ".tmp");
    remove_staging_entry(&temp_path)?;
    write_json_file(&temp_path, &state, options.sync_data)?;
    replace_resume_sidecar(&temp_path, resume_path, options.sync_data)
}

fn replace_resume_sidecar(
    temp_path: &Path,
    resume_path: &Path,
    sync_data: bool,
) -> Result<(), ExportError> {
    let backup = appended_path(resume_path, ".replace-backup");
    if staging_entry_exists(&backup)? {
        return Err(ExportError::AlreadyExists(backup));
    }
    let had_previous = staging_entry_exists(resume_path)?;
    if had_previous {
        ensure_regular_staging(resume_path)?;
        fs::rename(resume_path, &backup).map_err(|source| ExportError::Io {
            operation: "stage previous resume checkpoint",
            path: resume_path.to_path_buf(),
            source,
        })?;
        if sync_data && let Err(source) = sync_parent(resume_path) {
            let rollback = fs::rename(&backup, resume_path).and_then(|_| sync_parent(resume_path));
            return match rollback {
                Ok(()) => Err(ExportError::Io {
                    operation: "sync staged resume checkpoint directory",
                    path: resume_path.to_path_buf(),
                    source,
                }),
                Err(rollback) => Err(ExportError::PublishRollback {
                    publish: source,
                    rollback,
                    published_path: resume_path.to_path_buf(),
                    staged_path: temp_path.to_path_buf(),
                }),
            };
        }
    }

    if let Err(source) = fs::rename(temp_path, resume_path) {
        let rollback = if had_previous {
            fs::rename(&backup, resume_path).and_then(|_| {
                if sync_data {
                    sync_parent(resume_path)?;
                }
                Ok(())
            })
        } else {
            Ok(())
        };
        return match rollback {
            Ok(()) => Err(ExportError::Io {
                operation: "publish resume checkpoint",
                path: resume_path.to_path_buf(),
                source,
            }),
            Err(rollback) => Err(ExportError::PublishRollback {
                publish: source,
                rollback,
                published_path: resume_path.to_path_buf(),
                staged_path: temp_path.to_path_buf(),
            }),
        };
    }
    if sync_data && let Err(source) = sync_parent(resume_path) {
        let rollback = fs::rename(resume_path, temp_path).and_then(|_| {
            if had_previous {
                fs::rename(&backup, resume_path)?;
            }
            sync_parent(resume_path)
        });
        return match rollback {
            Ok(()) => Err(ExportError::Io {
                operation: "sync published resume checkpoint directory",
                path: resume_path.to_path_buf(),
                source,
            }),
            Err(rollback) => Err(ExportError::PublishRollback {
                publish: source,
                rollback,
                published_path: resume_path.to_path_buf(),
                staged_path: temp_path.to_path_buf(),
            }),
        };
    }
    if had_previous {
        fs::remove_file(&backup).map_err(|source| ExportError::Io {
            operation: "remove previous resume checkpoint",
            path: backup.clone(),
            source,
        })?;
        if sync_data {
            sync_parent(resume_path).map_err(|source| ExportError::Io {
                operation: "sync resume checkpoint cleanup",
                path: resume_path.to_path_buf(),
                source,
            })?;
        }
    }
    Ok(())
}

fn validate_resume_state(
    state: &ResumeState,
    reader: &dyn VolumeReader,
    options: &ExportOptions,
    identity_sha256: &str,
) -> Result<(), ExportError> {
    if state.schema != RESUME_SCHEMA
        || state.identity_sha256 != identity_sha256
        || state.logical_bytes != reader.volume_len()
        || state.sector_size != reader.sector_size()
        || state.chunk_size != options.chunk_size
        || state.allocation != options.allocation
    {
        return Err(ExportError::ResumeMismatch(
            "resume state does not match source, pipeline, geometry, or export options".to_owned(),
        ));
    }
    if state.completed_bytes > state.logical_bytes
        || !state
            .completed_bytes
            .is_multiple_of(u64::from(state.sector_size))
        || state
            .data_bytes_written
            .checked_add(state.sparse_zero_bytes)
            != Some(state.completed_bytes)
    {
        return Err(ExportError::ResumeMismatch(
            "resume checkpoint contains inconsistent byte counts".to_owned(),
        ));
    }
    Ok(())
}

fn resume_identity_hash(
    reader: &dyn VolumeReader,
    options: &ExportOptions,
    caller_identity: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RESUME_SCHEMA.as_bytes());
    hasher.update(caller_identity.as_bytes());
    hasher.update(reader.volume_len().to_le_bytes());
    hasher.update(reader.sector_size().to_le_bytes());
    hasher.update((options.chunk_size as u64).to_le_bytes());
    hasher.update([match options.allocation {
        RawAllocation::Dense => 0,
        RawAllocation::Sparse => 1,
    }]);
    hex::encode(hasher.finalize())
}

fn read_exact_at(
    reader: &mut dyn VolumeReader,
    mut output: &mut [u8],
    logical_offset: u64,
) -> Result<(), ExportError> {
    let wanted = output.len();
    let mut received = 0usize;
    while !output.is_empty() {
        match reader.read(output) {
            Ok(0) => {
                return Err(ExportError::PrematureEof {
                    offset: logical_offset + received as u64,
                    expected: wanted,
                    received,
                });
            }
            Ok(read) => {
                received += read;
                output = &mut output[read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(ExportError::Io {
                    operation: "read source volume",
                    path: PathBuf::new(),
                    source,
                });
            }
        }
    }
    Ok(())
}

fn write_json_file<T: Serialize>(
    path: &Path,
    value: &T,
    sync_data: bool,
) -> Result<(), ExportError> {
    let mut file = create_private_staging(path, false, "create JSON sidecar")?;
    serde_json::to_writer_pretty(&mut file, value).map_err(ExportError::Serialize)?;
    file.write_all(b"\n").map_err(|source| ExportError::Io {
        operation: "write JSON sidecar",
        path: path.to_path_buf(),
        source,
    })?;
    file.flush().map_err(|source| ExportError::Io {
        operation: "flush JSON sidecar",
        path: path.to_path_buf(),
        source,
    })?;
    if sync_data {
        file.sync_all().map_err(|source| ExportError::Io {
            operation: "sync JSON sidecar",
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn read_json_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    tighten_permissions: bool,
) -> Result<T, ExportError> {
    let file = open_existing_staging(path, false, tighten_permissions)?;
    let length = file
        .metadata()
        .map_err(|source| ExportError::Io {
            operation: "inspect JSON sidecar",
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if length > MAX_RESUME_STATE_BYTES {
        return Err(ExportError::ResumeMismatch(format!(
            "resume state {} is {length} bytes; maximum is {MAX_RESUME_STATE_BYTES}",
            path.display()
        )));
    }
    serde_json::from_reader(file).map_err(ExportError::Serialize)
}

fn appended_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn unix_time_ms() -> Result<u64, ExportError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ExportError::Clock(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| ExportError::Clock("Unix timestamp does not fit in u64".to_owned()))
}

#[cfg(unix)]
fn allocated_bytes(file: &File) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn allocated_bytes(_file: &File) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "allocated byte count is not available on this platform",
    ))
}

fn remove_resume_state(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Err(error) = sync_parent(path) {
                log::warn!(
                    "Export completed but resume sidecar directory {} could not be synced: {}",
                    path.display(),
                    error
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            log::warn!(
                "Export completed but resume sidecar {} could not be removed: {}",
                path.display(),
                error
            );
        }
    }
}

fn progress(
    stage: ExportStage,
    completed_bytes: u64,
    total_bytes: u64,
    resumed_from: u64,
    data_bytes_written: u64,
    sparse_zero_bytes: u64,
) -> ExportProgress {
    ExportProgress {
        stage,
        completed_bytes,
        total_bytes,
        resumed_from,
        data_bytes_written,
        sparse_zero_bytes,
    }
}

#[derive(Debug)]
pub enum ExportError {
    InvalidConfiguration(String),
    AlreadyExists(PathBuf),
    ExportLocked(PathBuf),
    ResumeMismatch(String),
    Cancelled {
        completed_bytes: u64,
    },
    PrematureEof {
        offset: u64,
        expected: usize,
        received: usize,
    },
    BufferAllocation {
        requested_bytes: usize,
        source: std::collections::TryReserveError,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    PublishRollback {
        publish: io::Error,
        rollback: io::Error,
        published_path: PathBuf,
        staged_path: PathBuf,
    },
    Serialize(serde_json::Error),
    Clock(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "invalid export configuration: {message}")
            }
            Self::AlreadyExists(path) => write!(f, "output already exists: {}", path.display()),
            Self::ExportLocked(path) => write!(
                f,
                "another export holds a required output or manifest lease: {}",
                path.display()
            ),
            Self::ResumeMismatch(message) => write!(f, "cannot safely resume export: {message}"),
            Self::Cancelled { completed_bytes } => {
                write!(f, "export cancelled after {completed_bytes} bytes")
            }
            Self::PrematureEof {
                offset,
                expected,
                received,
            } => write!(
                f,
                "source ended at byte {offset}; chunk expected {expected} bytes, received {received}"
            ),
            Self::BufferAllocation {
                requested_bytes,
                source,
            } => write!(
                f,
                "cannot allocate {requested_bytes} bytes for an export pipeline buffer: {source}"
            ),
            Self::Io {
                operation,
                path,
                source,
            } if path.as_os_str().is_empty() => write!(f, "{operation}: {source}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "{operation} ({}): {source}", path.display()),
            Self::PublishRollback {
                publish,
                rollback,
                published_path,
                staged_path,
            } => write!(
                f,
                "publication failed ({publish}) and rollback {} -> {} also failed ({rollback})",
                published_path.display(),
                staged_path.display()
            ),
            Self::Serialize(error) => write!(f, "JSON sidecar error: {error}"),
            Self::Clock(message) => write!(f, "system clock error: {message}"),
        }
    }
}

impl Error for ExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BufferAllocation { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::PublishRollback { publish, .. } => Some(publish),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    struct TestVolume {
        cursor: Cursor<Vec<u8>>,
        advertised_len: u64,
        sector_size: u32,
    }

    impl TestVolume {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                advertised_len: bytes.len() as u64,
                cursor: Cursor::new(bytes),
                sector_size: 512,
            }
        }
    }

    impl Read for TestVolume {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buf)
        }
    }

    impl Seek for TestVolume {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.cursor.seek(pos)
        }
    }

    impl VolumeReader for TestVolume {
        fn volume_len(&self) -> u64 {
            self.advertised_len
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    struct FragmentedVolume {
        inner: TestVolume,
        max_read: usize,
    }

    impl Read for FragmentedVolume {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let wanted = buf.len().min(self.max_read);
            self.inner.read(&mut buf[..wanted])
        }
    }

    impl Seek for FragmentedVolume {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    impl VolumeReader for FragmentedVolume {
        fn volume_len(&self) -> u64 {
            self.inner.volume_len()
        }

        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }
    }

    struct PanickingVolume {
        position: u64,
    }

    impl Read for PanickingVolume {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("synthetic source decoder panic");
        }
    }

    impl Seek for PanickingVolume {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.position = match position {
                SeekFrom::Start(offset) => offset,
                SeekFrom::Current(delta) => {
                    self.position.checked_add_signed(delta).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "synthetic seek overflow")
                    })?
                }
                SeekFrom::End(delta) => 512_u64.checked_add_signed(delta).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "synthetic seek overflow")
                })?,
            };
            Ok(self.position)
        }
    }

    impl VolumeReader for PanickingVolume {
        fn volume_len(&self) -> u64 {
            512
        }

        fn sector_size(&self) -> u32 {
            512
        }
    }

    fn test_options() -> ExportOptions {
        ExportOptions {
            chunk_size: 512,
            sparse_block_size: 512,
            checkpoint_bytes: 512,
            sync_data: false,
            ..ExportOptions::default()
        }
    }

    #[test]
    fn dense_export_is_exact_and_publishes_manifest() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("partition.img");
        let bytes: Vec<u8> = (0..1536).map(|value| (value % 251) as u8).collect();
        let mut source = TestVolume::new(bytes.clone());
        let mut stages = Vec::new();
        let mut callback = |progress: &ExportProgress| stages.push(progress.stage);
        let mut control = ExportControl::new(None, Some(&mut callback));

        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &test_options(),
            &mut control,
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(report.manifest.logical_bytes, 1536);
        assert_eq!(report.manifest.data_bytes_written, 1536);
        assert_eq!(report.manifest.sparse_zero_bytes, 0);
        assert_eq!(report.manifest.sha256.len(), 64);
        assert!(report.manifest_path.exists());
        assert!(!appended_path(&output, ".partial").exists());
        assert_eq!(stages.first(), Some(&ExportStage::Preparing));
        assert_eq!(stages.last(), Some(&ExportStage::Complete));

        let disk_manifest: ExportManifest =
            serde_json::from_slice(&fs::read(&report.manifest_path).unwrap()).unwrap();
        assert_eq!(disk_manifest, report.manifest);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&report.manifest_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn bounded_pipeline_preserves_chunk_order_with_fragmented_reads() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("ordered.img");
        let bytes: Vec<u8> = (0..16 * 1024)
            .map(|value| ((value * 17 + 11) % 251) as u8)
            .collect();
        let mut source = FragmentedVolume {
            inner: TestVolume::new(bytes.clone()),
            max_read: 37,
        };
        let options = ExportOptions {
            chunk_size: 1024,
            sparse_block_size: 512,
            pipeline_depth: 4,
            checkpoint_bytes: 4096,
            sync_data: false,
            ..ExportOptions::default()
        };

        export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), bytes);
    }

    #[test]
    fn sparse_export_preserves_zero_ranges_and_length() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("sparse.img");
        let mut bytes = vec![0x41; 512];
        bytes.extend(vec![0; 1024]);
        bytes.extend(vec![0x42; 512]);
        let mut source = TestVolume::new(bytes.clone());
        let options = ExportOptions {
            allocation: RawAllocation::Sparse,
            ..test_options()
        };

        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(fs::metadata(&output).unwrap().len(), 2048);
        assert_eq!(report.manifest.data_bytes_written, 1024);
        assert_eq!(report.manifest.sparse_zero_bytes, 1024);
    }

    #[test]
    fn sparse_export_detects_and_coalesces_zero_blocks_inside_one_chunk() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("subchunk-sparse.img");
        let mut bytes = vec![0x41; 512];
        bytes.extend(vec![0; 1024]);
        bytes.extend(vec![0x42; 512]);
        let mut source = TestVolume::new(bytes.clone());
        let options = ExportOptions {
            chunk_size: 2048,
            sparse_block_size: 512,
            allocation: RawAllocation::Sparse,
            checkpoint_bytes: 2048,
            sync_data: false,
            ..ExportOptions::default()
        };

        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();

        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(report.manifest.data_bytes_written, 1024);
        assert_eq!(report.manifest.sparse_zero_bytes, 1024);
        assert_eq!(report.manifest.sparse_block_size, 512);
    }

    #[test]
    fn export_sha256_remains_the_standard_digest_with_asm_enabled() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("digest.img");
        let mut source = TestVolume::new(b"abc".to_vec());
        source.sector_size = 1;
        let options = ExportOptions {
            chunk_size: 1,
            sparse_block_size: 1,
            checkpoint_bytes: 1,
            sync_data: false,
            ..ExportOptions::default()
        };

        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();
        assert_eq!(
            report.manifest.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn older_v1_manifests_default_the_new_sparse_granularity_field() {
        let manifest: ExportManifest = serde_json::from_value(serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "created_unix_ms": 1,
            "output_path": "partition.img",
            "logical_bytes": 512,
            "sector_size": 512,
            "chunk_size": 16777216,
            "allocation": "sparse",
            "sha256": "00".repeat(32),
            "resumed_from": 0,
            "data_bytes_written": 512,
            "sparse_zero_bytes": 0,
            "provenance": {}
        }))
        .unwrap();
        assert_eq!(manifest.sparse_block_size, DEFAULT_SPARSE_BLOCK_SIZE);
    }

    #[test]
    fn cancellation_checkpoints_and_validated_resume_discards_tail() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("resume.img");
        let bytes: Vec<u8> = (0..4096).map(|value| (value % 239) as u8).collect();
        let cancelled = AtomicBool::new(false);
        let mut source = TestVolume::new(bytes.clone());
        let options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "evidence-A:gpt-2:physical".to_owned(),
            },
            ..test_options()
        };
        let mut callback = |progress: &ExportProgress| {
            if progress.stage == ExportStage::Exporting && progress.completed_bytes >= 1024 {
                cancelled.store(true, Ordering::Relaxed);
            }
        };
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::new(Some(&cancelled), Some(&mut callback)),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ExportError::Cancelled {
                completed_bytes: 1024
            }
        ));
        assert!(!output.exists());

        let partial = appended_path(&output, ".partial");
        OpenOptions::new()
            .append(true)
            .open(&partial)
            .unwrap()
            .write_all(b"uncheckpointed tail")
            .unwrap();

        let resume_preflight =
            preflight_export(&source, &output, &options).expect("resume preflight");
        assert_eq!(resume_preflight.resumable_bytes, 1024);
        assert_eq!(resume_preflight.required_dense_bytes, Some(3072));

        let mut source = TestVolume::new(bytes.clone());
        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();
        assert_eq!(report.manifest.resumed_from, 1024);
        assert_eq!(report.bytes_copied_this_run, 3072);
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert!(!appended_path(&output, ".partial.resume.json").exists());
    }

    #[test]
    fn v1_resume_remains_compatible_with_new_performance_knobs() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("v1-compatible.img");
        let mut bytes = vec![0x5a; 512];
        bytes.extend(vec![0; 3584]);
        let cancelled = AtomicBool::new(false);
        let initial_options = ExportOptions {
            chunk_size: 2048,
            sparse_block_size: 2048,
            pipeline_depth: 1,
            checkpoint_bytes: 2048,
            allocation: RawAllocation::Sparse,
            resume: ResumeMode::Validated {
                identity: "stable-v1-resume-identity".to_owned(),
            },
            sync_data: false,
            ..ExportOptions::default()
        };
        let mut source = TestVolume::new(bytes.clone());
        let mut stop = |progress: &ExportProgress| {
            if progress.stage == ExportStage::Exporting && progress.completed_bytes >= 2048 {
                cancelled.store(true, Ordering::Relaxed);
            }
        };
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &initial_options,
            &mut ExportControl::new(Some(&cancelled), Some(&mut stop)),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ExportError::Cancelled {
                completed_bytes: 2048
            }
        ));
        let resume_path = appended_path(&output, ".partial.resume.json");
        let resume_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&resume_path).unwrap()).unwrap();
        assert_eq!(resume_json["schema"], RESUME_SCHEMA);
        assert!(resume_json.get("pipeline_depth").is_none());
        assert!(resume_json.get("sparse_block_size").is_none());

        let resumed_options = ExportOptions {
            sparse_block_size: 512,
            pipeline_depth: 4,
            checkpoint_bytes: 4096,
            ..initial_options.clone()
        };
        assert_eq!(
            resume_identity_hash(&source, &initial_options, "stable-v1-resume-identity"),
            resume_identity_hash(&source, &resumed_options, "stable-v1-resume-identity")
        );
        let mut source = TestVolume::new(bytes.clone());
        let report = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &resumed_options,
            &mut ExportControl::none(),
        )
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), bytes);
        assert_eq!(report.manifest.resumed_from, 2048);
        assert_eq!(report.manifest.sparse_block_size, 512);
        assert_eq!(report.manifest.sparse_block_size_applies_from, 2048);
        // The first checkpoint's old whole-chunk accounting is preserved;
        // the resumed tail uses the finer sparse-block granularity.
        assert_eq!(report.manifest.data_bytes_written, 2048);
        assert_eq!(report.manifest.sparse_zero_bytes, 2048);
    }

    #[test]
    fn resume_rejects_a_different_identity() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("resume-mismatch.img");
        let bytes = vec![0x55; 2048];
        let cancelled = AtomicBool::new(true);
        let mut source = TestVolume::new(bytes.clone());
        let first_options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "source-one".to_owned(),
            },
            ..test_options()
        };
        // Initial cancellation occurs before staging, so allow one chunk first.
        cancelled.store(false, Ordering::Relaxed);
        let mut callback = |progress: &ExportProgress| {
            if progress.completed_bytes >= 512 {
                cancelled.store(true, Ordering::Relaxed);
            }
        };
        let _ = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &first_options,
            &mut ExportControl::new(Some(&cancelled), Some(&mut callback)),
        );

        let second_options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "source-two".to_owned(),
            },
            ..test_options()
        };
        let mut source = TestVolume::new(bytes);
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &second_options,
            &mut ExportControl::none(),
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::ResumeMismatch(_)));
    }

    #[test]
    fn malformed_resume_counts_and_oversized_sidecars_fail_closed() {
        let source = TestVolume::new(vec![0; 512]);
        let options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "public-source-identity".to_owned(),
            },
            ..test_options()
        };
        let identity_sha256 = resume_identity_hash(&source, &options, "public-source-identity");
        let state = ResumeState {
            schema: RESUME_SCHEMA.to_owned(),
            identity_sha256: identity_sha256.clone(),
            logical_bytes: 512,
            sector_size: 512,
            chunk_size: options.chunk_size,
            allocation: options.allocation,
            completed_bytes: 512,
            prefix_sha256: "00".repeat(32),
            data_bytes_written: u64::MAX,
            sparse_zero_bytes: 1,
        };
        assert!(matches!(
            validate_resume_state(&state, &source, &options, &identity_sha256),
            Err(ExportError::ResumeMismatch(_))
        ));

        let dir = tempdir().unwrap();
        let path = dir.path().join("oversized.resume.json");
        fs::write(&path, vec![b' '; MAX_RESUME_STATE_BYTES as usize + 1]).unwrap();
        assert!(matches!(
            read_json_file::<ResumeState>(&path, false),
            Err(ExportError::ResumeMismatch(_))
        ));
    }

    #[test]
    fn resume_rejects_changed_early_source_prefix_even_when_tail_matches() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("source-prefix.img");
        let bytes = vec![0x55; 2048];
        let cancelled = AtomicBool::new(false);
        let options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "stable-caller-identity".to_owned(),
            },
            ..test_options()
        };
        let mut source = TestVolume::new(bytes.clone());
        let mut callback = |progress: &ExportProgress| {
            if progress.completed_bytes >= 1024 {
                cancelled.store(true, Ordering::Relaxed);
            }
        };
        let _ = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::new(Some(&cancelled), Some(&mut callback)),
        );

        let mut changed = bytes;
        // The final 512-byte checkpoint chunk remains unchanged. Validation
        // must still detect this mutation in the earlier source prefix.
        changed[0] ^= 0xff;
        let mut changed_source = TestVolume::new(changed);
        let error = export_raw(
            &mut changed_source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::ResumeMismatch(_)));
    }

    #[test]
    fn resume_validation_reports_progress_and_honors_cancellation() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("validation-cancel.img");
        let bytes = vec![0x39; 2048];
        let initial_cancel = AtomicBool::new(false);
        let options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: "validation-cancel-source".to_owned(),
            },
            ..test_options()
        };
        let mut source = TestVolume::new(bytes.clone());
        let mut stop_after_checkpoint = |progress: &ExportProgress| {
            if progress.stage == ExportStage::Exporting && progress.completed_bytes >= 1024 {
                initial_cancel.store(true, Ordering::Relaxed);
            }
        };
        let first_error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::new(Some(&initial_cancel), Some(&mut stop_after_checkpoint)),
        )
        .unwrap_err();
        assert!(matches!(
            first_error,
            ExportError::Cancelled {
                completed_bytes: 1024
            }
        ));

        let validation_cancel = AtomicBool::new(false);
        let saw_validation = AtomicBool::new(false);
        let mut cancel_validation = |progress: &ExportProgress| {
            if progress.stage == ExportStage::ValidatingResume {
                saw_validation.store(true, Ordering::Relaxed);
                if progress.completed_bytes > 0 {
                    validation_cancel.store(true, Ordering::Relaxed);
                }
            }
        };
        let mut source = TestVolume::new(bytes);
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::new(Some(&validation_cancel), Some(&mut cancel_validation)),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ExportError::Cancelled {
                completed_bytes: 1024
            }
        ));
        assert!(saw_validation.load(Ordering::Relaxed));
        assert!(!output.exists());
        assert!(appended_path(&output, ".partial").exists());
    }

    #[test]
    fn failed_manifest_publish_rolls_output_back_to_staging() {
        let dir = tempdir().unwrap();
        let staged_output = dir.path().join("output.partial");
        let output = dir.path().join("output.img");
        let missing_staged_manifest = dir.path().join("missing-manifest.partial");
        let manifest = dir.path().join("output.manifest.json");
        fs::write(&staged_output, b"complete output").unwrap();

        let error = publish_pair(
            &staged_output,
            &output,
            &missing_staged_manifest,
            &manifest,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::Io { .. }));
        assert!(!output.exists());
        assert_eq!(fs::read(&staged_output).unwrap(), b"complete output");
    }

    #[test]
    fn failed_output_publish_rolls_manifest_back_to_staging() {
        let dir = tempdir().unwrap();
        let missing_staged_output = dir.path().join("missing-output.partial");
        let output = dir.path().join("output.img");
        let staged_manifest = dir.path().join("manifest.partial");
        let manifest = dir.path().join("output.manifest.json");
        fs::write(&staged_manifest, b"complete manifest").unwrap();

        let error = publish_pair(
            &missing_staged_output,
            &output,
            &staged_manifest,
            &manifest,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::Io { .. }));
        assert!(!output.exists());
        assert!(!manifest.exists());
        assert_eq!(fs::read(&staged_manifest).unwrap(), b"complete manifest");
    }

    #[test]
    fn failed_overwrite_publish_restores_previous_output_pair() {
        let dir = tempdir().unwrap();
        let staged_output = dir.path().join("output.partial");
        let output = dir.path().join("output.img");
        let missing_staged_manifest = dir.path().join("missing-manifest.partial");
        let manifest = dir.path().join("output.manifest.json");
        fs::write(&staged_output, b"new output").unwrap();
        fs::write(&output, b"old output").unwrap();
        fs::write(&manifest, b"old manifest").unwrap();

        let error = publish_pair(
            &staged_output,
            &output,
            &missing_staged_manifest,
            &manifest,
            true,
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::Io { .. }));
        assert_eq!(fs::read(&output).unwrap(), b"old output");
        assert_eq!(fs::read(&manifest).unwrap(), b"old manifest");
        assert_eq!(fs::read(&staged_output).unwrap(), b"new output");
        assert!(!appended_path(&output, ".replace-backup").exists());
        assert!(!appended_path(&manifest, ".replace-backup").exists());
    }

    #[test]
    fn preflight_reports_dense_space_and_custom_manifest_without_writes() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("preflight.img");
        let custom_manifest = dir.path().join("audit.json");
        let source = TestVolume::new(vec![0; 1024]);
        let options = ExportOptions {
            manifest_path: Some(custom_manifest.clone()),
            ..test_options()
        };

        let preflight = preflight_export(&source, &output, &options).unwrap();
        assert_eq!(preflight.required_dense_bytes, Some(1024));
        assert_eq!(preflight.resumable_bytes, 0);
        assert_eq!(preflight.manifest_path, custom_manifest);
        assert!(!output.exists());
        assert!(!preflight.partial_path.exists());

        let sparse = ExportOptions {
            allocation: RawAllocation::Sparse,
            ..test_options()
        };
        assert_eq!(
            preflight_export(&source, &output, &sparse)
                .unwrap()
                .required_dense_bytes,
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_preserves_existing_resume_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let output = dir.path().join("read-only-preflight.img");
        let source = TestVolume::new(vec![0; 512]);
        let identity = "public-preflight-identity".to_owned();
        let options = ExportOptions {
            resume: ResumeMode::Validated {
                identity: identity.clone(),
            },
            ..test_options()
        };
        let paths = preflight_export(&source, &output, &options).unwrap();
        fs::write(&paths.partial_path, vec![0; 512]).unwrap();
        let state = ResumeState {
            schema: RESUME_SCHEMA.to_owned(),
            identity_sha256: resume_identity_hash(&source, &options, &identity),
            logical_bytes: 512,
            sector_size: 512,
            chunk_size: options.chunk_size,
            allocation: options.allocation,
            completed_bytes: 512,
            prefix_sha256: "00".repeat(32),
            data_bytes_written: 512,
            sparse_zero_bytes: 0,
        };
        fs::write(&paths.resume_path, serde_json::to_vec(&state).unwrap()).unwrap();
        fs::set_permissions(&paths.partial_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&paths.resume_path, fs::Permissions::from_mode(0o644)).unwrap();

        preflight_export(&source, &output, &options).unwrap();

        assert_eq!(
            fs::metadata(&paths.partial_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(&paths.resume_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn preflight_rejects_manifest_collision_with_export_lock() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("collision.img");
        let lock_path = appended_path(&output, ".export.lock");
        let source = TestVolume::new(vec![0; 512]);
        let options = ExportOptions {
            manifest_path: Some(lock_path),
            ..test_options()
        };
        let error = preflight_export(&source, &output, &options).unwrap_err();
        assert!(matches!(error, ExportError::InvalidConfiguration(_)));
    }

    #[test]
    fn resume_sidecar_replacement_works_when_destination_exists() {
        let dir = tempdir().unwrap();
        let temp = dir.path().join("resume.tmp");
        let destination = dir.path().join("resume.json");
        fs::write(&temp, b"new checkpoint").unwrap();
        fs::write(&destination, b"old checkpoint").unwrap();

        replace_resume_sidecar(&temp, &destination, false).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new checkpoint");
        assert!(!temp.exists());
        assert!(!appended_path(&destination, ".replace-backup").exists());
    }

    #[test]
    fn interrupted_resume_sidecar_transactions_recover_under_the_export_lock() {
        for active_was_published in [false, true] {
            let dir = tempdir().unwrap();
            let output = dir.path().join("recover-resume.img");
            let bytes = vec![0x5a; 1024];
            let mut source = TestVolume::new(bytes.clone());
            let identity = "public-recovery-identity".to_owned();
            let options = ExportOptions {
                resume: ResumeMode::Validated {
                    identity: identity.clone(),
                },
                ..test_options()
            };
            let paths = preflight_export(&source, &output, &options).unwrap();
            fs::write(&paths.partial_path, &bytes[..512]).unwrap();
            let state = ResumeState {
                schema: RESUME_SCHEMA.to_owned(),
                identity_sha256: resume_identity_hash(&source, &options, &identity),
                logical_bytes: 1024,
                sector_size: 512,
                chunk_size: options.chunk_size,
                allocation: options.allocation,
                completed_bytes: 512,
                prefix_sha256: hex::encode(Sha256::digest(&bytes[..512])),
                data_bytes_written: 512,
                sparse_zero_bytes: 0,
            };
            let encoded = serde_json::to_vec(&state).unwrap();
            fs::write(&paths.resume_backup_path, &encoded).unwrap();
            fs::write(&paths.resume_temp_path, &encoded).unwrap();
            if active_was_published {
                fs::write(&paths.resume_path, &encoded).unwrap();
            }

            export_raw(
                &mut source,
                &output,
                ExportProvenance::default(),
                &options,
                &mut ExportControl::none(),
            )
            .unwrap();

            assert_eq!(fs::read(&output).unwrap(), bytes);
            assert!(!paths.resume_path.exists());
            assert!(!paths.resume_backup_path.exists());
            assert!(!paths.resume_temp_path.exists());
        }
    }

    #[test]
    fn concurrent_export_to_same_output_is_rejected_by_lock() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("locked.img");
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker_output = output.clone();
        let worker = std::thread::spawn(move || {
            let mut source = TestVolume::new(vec![0x44; 1024]);
            let mut callback = move |progress: &ExportProgress| {
                if progress.stage == ExportStage::Preparing {
                    worker_barrier.wait();
                    worker_barrier.wait();
                }
            };
            export_raw(
                &mut source,
                &worker_output,
                ExportProvenance::default(),
                &test_options(),
                &mut ExportControl::new(None, Some(&mut callback)),
            )
        });

        barrier.wait();
        let mut competing_source = TestVolume::new(vec![0x55; 1024]);
        let error = export_raw(
            &mut competing_source,
            &output,
            ExportProvenance::default(),
            &test_options(),
            &mut ExportControl::none(),
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::ExportLocked(_)));
        barrier.wait();
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn distinct_outputs_sharing_a_custom_manifest_are_serialized() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("shared-audit.json");
        let source = TestVolume::new(vec![0; 512]);
        let first = preflight_export(
            &source,
            dir.path().join("first.img"),
            &ExportOptions {
                manifest_path: Some(manifest.clone()),
                ..test_options()
            },
        )
        .unwrap();
        let second = preflight_export(
            &source,
            dir.path().join("second.img"),
            &ExportOptions {
                manifest_path: Some(manifest),
                ..test_options()
            },
        )
        .unwrap();
        assert_eq!(first.manifest_lock_path, second.manifest_lock_path);

        let held = acquire_export_locks([first.lock_path, first.manifest_lock_path.clone()], false)
            .unwrap();
        let error = match acquire_export_locks(
            [second.lock_path, second.manifest_lock_path.clone()],
            false,
        ) {
            Ok(_) => panic!("shared manifest must be exclusively leased"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExportError::ExportLocked(path) if path == second.manifest_lock_path
        ));
        drop(held);
    }

    #[test]
    fn stable_lock_sidecar_is_reusable_after_unlock() {
        let dir = tempdir().unwrap();
        let lock_path = dir.path().join("reusable.export.lock");
        let first = ExportLock::acquire(lock_path.clone(), false).unwrap();
        drop(first);
        assert!(lock_path.is_file());
        let second = ExportLock::acquire(lock_path, false).unwrap();
        drop(second);
    }

    #[cfg(unix)]
    #[test]
    fn force_removes_staging_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let output = dir.path().join("safe-force.img");
        let partial = appended_path(&output, ".partial");
        let victim = dir.path().join("victim.bin");
        fs::write(&victim, b"do not truncate").unwrap();
        symlink(&victim, &partial).unwrap();
        let mut source = TestVolume::new(vec![0x66; 512]);
        let options = ExportOptions {
            overwrite: true,
            ..test_options()
        };

        export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &options,
            &mut ExportControl::none(),
        )
        .unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"do not truncate");
        assert_eq!(fs::read(&output).unwrap(), vec![0x66; 512]);
    }

    #[test]
    fn rejects_chunk_sizes_above_one_gib_before_allocating() {
        let source = TestVolume::new(vec![0; 512]);
        let options = ExportOptions {
            chunk_size: MAX_CHUNK_SIZE + 512,
            ..test_options()
        };
        let error = preflight_export(&source, "never-created.img", &options).unwrap_err();
        assert!(matches!(error, ExportError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("maximum supported size"));
    }

    #[test]
    fn rejects_invalid_sparse_granularity_and_pipeline_depth_before_allocating() {
        let source = TestVolume::new(vec![0; 512]);
        let oversized_sparse = ExportOptions {
            chunk_size: 512,
            sparse_block_size: 1024,
            ..test_options()
        };
        assert!(matches!(
            preflight_export(&source, "never-created.img", &oversized_sparse),
            Err(ExportError::InvalidConfiguration(_))
        ));

        let unbounded_pipeline = ExportOptions {
            pipeline_depth: MAX_PIPELINE_DEPTH + 1,
            ..test_options()
        };
        assert!(matches!(
            preflight_export(&source, "never-created.img", &unbounded_pipeline),
            Err(ExportError::InvalidConfiguration(_))
        ));

        let excessive_pipeline_memory = ExportOptions {
            chunk_size: 512 * 1024 * 1024,
            sparse_block_size: 1024 * 1024,
            pipeline_depth: 3,
            ..test_options()
        };
        let error =
            preflight_export(&source, "never-created.img", &excessive_pipeline_memory).unwrap_err();
        assert!(matches!(error, ExportError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("buffered memory"));
    }

    #[test]
    fn producer_panics_are_returned_without_unwinding_the_exporter() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("panicking-source.img");
        let mut source = PanickingVolume { position: 0 };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            export_raw(
                &mut source,
                &output,
                ExportProvenance::default(),
                &test_options(),
                &mut ExportControl::none(),
            )
        }));

        let error = result
            .expect("a producer panic must not unwind the caller")
            .expect_err("a producer panic must fail the export");
        assert!(matches!(error, ExportError::InvalidConfiguration(_)));
        assert!(
            error
                .to_string()
                .contains("source reader pipeline panicked")
        );
        assert!(!output.exists());
    }

    #[test]
    fn overwrite_rejects_directories_and_stale_backups_before_reading_source() {
        for stale_backup in [false, true] {
            let dir = tempdir().unwrap();
            let output = dir.path().join("blocked-output.img");
            if stale_backup {
                fs::write(appended_path(&output, ".replace-backup"), b"stale").unwrap();
            } else {
                fs::create_dir(&output).unwrap();
            }
            let mut source = PanickingVolume { position: 0 };
            let options = ExportOptions {
                overwrite: true,
                ..test_options()
            };

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                export_raw(
                    &mut source,
                    &output,
                    ExportProvenance::default(),
                    &options,
                    &mut ExportControl::none(),
                )
            }));
            let error = result
                .expect("preflight must not read the source")
                .expect_err("unsafe overwrite destination must fail before streaming");
            assert!(matches!(
                error,
                ExportError::AlreadyExists(_) | ExportError::InvalidConfiguration(_)
            ));
        }
    }

    #[test]
    fn premature_eof_never_publishes_output() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("short.img");
        let mut source = TestVolume::new(vec![0x11; 512]);
        source.advertised_len = 1024;
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &test_options(),
            &mut ExportControl::none(),
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::PrematureEof { .. }));
        assert!(!output.exists());
        assert!(appended_path(&output, ".partial").exists());
    }

    #[test]
    fn existing_output_is_never_overwritten_by_default() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("existing.img");
        fs::write(&output, b"keep me").unwrap();
        let mut source = TestVolume::new(vec![0; 512]);
        let error = export_raw(
            &mut source,
            &output,
            ExportProvenance::default(),
            &test_options(),
            &mut ExportControl::none(),
        )
        .unwrap_err();
        assert!(matches!(error, ExportError::AlreadyExists(_)));
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
    }
}
