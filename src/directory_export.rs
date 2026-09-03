//! Safe logical export of one real filesystem directory.
//!
//! The exporter deliberately walks directory-entry occurrences instead of
//! calling [`Filesystem::walk_fs`]. That preserves hard-link names, retains the
//! selected path occurrence, and allows directory cycles to be guarded only
//! along the active ancestor chain.

use crate::filesystem::{
    DirectoryCommon, DirectoryEntryLimitError, FileCommon, FileIdentity, FileKind, Filesystem,
    FilesystemSourceView,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File as StdFile, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

const MANIFEST_NAME: &str = ".exhume-manifest.json";
const MANIFEST_SCHEMA: &str = "exhume.directory-export.v1";
const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 1_024;
// Manifest entries intentionally retain only bounded, normalized V1 fields.
// The hard ceiling keeps a malicious directory graph from growing the in-memory
// traversal and manifest vectors without bound.
const DEFAULT_MAX_ENTRIES: u64 = 250_000;
const HARD_MAX_ENTRIES: u64 = 250_000;
const MAX_COMPONENT_BYTES: usize = 200;
const MAX_SOURCE_COMPONENT_BYTES: usize = 4 * 1024;
const MAX_LOGICAL_PATH_BYTES: usize = 32 * 1024;
const MAX_MANIFEST_TEXT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FAILURE_MESSAGE_BYTES: usize = 4 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A source directory that the caller has already resolved against the
/// intended evidence filesystem and partition.
pub struct DirectoryExportSource<T> {
    pub record: T,
    /// Filesystem identifier stored by the caller for this selected occurrence.
    pub identifier: u64,
    /// Logical evidence path used in provenance and child paths.
    pub logical_path: String,
    /// Requested name of the directory created beneath the destination parent.
    pub output_name: String,
}

impl<T> DirectoryExportSource<T> {
    pub fn new(
        record: T,
        identifier: u64,
        logical_path: impl Into<String>,
        output_name: impl Into<String>,
    ) -> Self {
        Self {
            record,
            identifier,
            logical_path: logical_path.into(),
            output_name: output_name.into(),
        }
    }
}

/// Plaintext acquisition context written to the export manifest.
///
/// Callers must include only non-secret identifiers and descriptors. In
/// particular, decryption keys, passwords, tokens, and raw key material must
/// never be placed in these fields or `public_metadata`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryExportProvenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct DirectoryExportOptions {
    /// Maximum source bytes requested per ranged read.
    pub chunk_size: usize,
    /// Flush and sync staged file data and directories before publication.
    pub sync_data: bool,
    /// Maximum child depth below the selected directory.
    pub max_depth: usize,
    /// Maximum number of non-structural directory-entry occurrences, including
    /// the selected directory.
    pub max_entries: u64,
    /// Non-secret acquisition provenance copied into the plaintext manifest.
    pub provenance: DirectoryExportProvenance,
}

impl Default for DirectoryExportOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            sync_data: true,
            max_depth: DEFAULT_MAX_DEPTH,
            max_entries: DEFAULT_MAX_ENTRIES,
            provenance: DirectoryExportProvenance::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryExportStage {
    Preparing,
    Exporting,
    Finalizing,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryExportProgress {
    pub stage: DirectoryExportStage,
    pub current_logical_path: String,
    pub entries_processed: u64,
    pub files_exported: u64,
    pub directories_exported: u64,
    /// Monotonic bytes written during this run. It can include bytes from a
    /// source file later discarded after a read failure.
    pub bytes_written: u64,
    pub current_file_bytes: u64,
    pub current_file_total: u64,
    pub skipped_entries: u64,
    pub failed_entries: u64,
}

pub struct DirectoryExportControl<'a> {
    cancellation: Option<&'a AtomicBool>,
    progress: Option<&'a mut dyn FnMut(&DirectoryExportProgress)>,
}

impl<'a> DirectoryExportControl<'a> {
    pub fn none() -> Self {
        Self {
            cancellation: None,
            progress: None,
        }
    }

    pub fn new(
        cancellation: Option<&'a AtomicBool>,
        progress: Option<&'a mut dyn FnMut(&DirectoryExportProgress)>,
    ) -> Self {
        Self {
            cancellation,
            progress,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    fn notify(&mut self, progress: DirectoryExportProgress) {
        if let Some(callback) = self.progress.as_mut() {
            callback(&progress);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryExportStatus {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryEntryDisposition {
    Exported,
    Skipped,
    Failed,
}

/// Bounded normalized source metadata retained for forensic fidelity. Raw
/// filesystem JSON, display strings, and signatures are deliberately omitted.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryExportEntryMetadata {
    pub created_unix_seconds: Option<u64>,
    pub modified_unix_seconds: Option<u64>,
    pub accessed_unix_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryExportEntry {
    pub source_identifier: u64,
    pub source_identity: Option<FileIdentity>,
    pub source_logical_path: String,
    pub output_relative_path: String,
    pub kind: Option<FileKind>,
    pub logical_size: u64,
    pub bytes_exported: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub disposition: DirectoryEntryDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Absent only when the directory entry could not be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_metadata: Option<DirectoryExportEntryMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryExportFailure {
    pub source_identifier: u64,
    pub source_logical_path: String,
    pub operation: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryExportManifest {
    pub schema: String,
    pub created_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub status: DirectoryExportStatus,
    pub filesystem_type: String,
    pub source_view: FilesystemSourceView,
    pub source_identifier: u64,
    pub source_identity: FileIdentity,
    pub source_logical_path: String,
    pub provenance: DirectoryExportProvenance,
    pub output_path: String,
    pub manifest_relative_path: String,
    /// V1 exports only the primary/unnamed logical data fork.
    pub primary_data_fork_only: bool,
    pub entries_processed: u64,
    pub files_exported: u64,
    pub directories_exported: u64,
    pub bytes_exported: u64,
    pub bytes_written: u64,
    pub skipped_entries: u64,
    pub failed_entries: u64,
    pub entries: Vec<DirectoryExportEntry>,
    pub failures: Vec<DirectoryExportFailure>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryExportReport {
    pub output_path: PathBuf,
    pub manifest_path: PathBuf,
    pub status: DirectoryExportStatus,
    pub entries_processed: u64,
    pub files_exported: u64,
    pub directories_exported: u64,
    pub bytes_exported: u64,
    pub bytes_written: u64,
    pub skipped_entries: u64,
    pub failed_entries: u64,
    pub failures: Vec<DirectoryExportFailure>,
}

#[derive(Debug)]
pub enum DirectoryExportError {
    InvalidConfiguration(String),
    SourceNotDirectory,
    DestinationParent(PathBuf),
    AlreadyExists(PathBuf),
    ExportLocked(PathBuf),
    EntryLimitExceeded {
        maximum: u64,
    },
    ManifestLimitExceeded {
        maximum_bytes: u64,
    },
    Cancelled {
        entries_processed: u64,
        bytes_written: u64,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Serialize(serde_json::Error),
    Clock(String),
}

impl fmt::Display for DirectoryExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(
                    formatter,
                    "invalid directory export configuration: {message}"
                )
            }
            Self::SourceNotDirectory => {
                write!(formatter, "directory export source is not a directory")
            }
            Self::DestinationParent(path) => write!(
                formatter,
                "directory export destination parent is not a real directory: {}",
                path.display()
            ),
            Self::AlreadyExists(path) => {
                write!(
                    formatter,
                    "directory export output already exists: {}",
                    path.display()
                )
            }
            Self::ExportLocked(path) => write!(
                formatter,
                "another directory export holds the output lease: {}",
                path.display()
            ),
            Self::EntryLimitExceeded { maximum } => write!(
                formatter,
                "directory export exceeded its {maximum}-entry safety limit"
            ),
            Self::ManifestLimitExceeded { maximum_bytes } => write!(
                formatter,
                "directory export exceeded its {maximum_bytes}-byte in-memory manifest safety limit"
            ),
            Self::Cancelled {
                entries_processed,
                bytes_written,
            } => write!(
                formatter,
                "directory export cancelled after {entries_processed} entries and {bytes_written} bytes"
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} ({}): {source}", path.display()),
            Self::Serialize(error) => write!(formatter, "directory export manifest error: {error}"),
            Self::Clock(message) => write!(formatter, "system clock error: {message}"),
        }
    }
}

impl Error for DirectoryExportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Default)]
struct ExportStats {
    entries_processed: u64,
    files_exported: u64,
    directories_exported: u64,
    bytes_written: u64,
    bytes_exported: u64,
    skipped_entries: u64,
    failed_entries: u64,
}

struct DirectoryFrame<R, D> {
    directory: R,
    logical_path: String,
    output_relative_path: PathBuf,
    depth: usize,
    ancestor_directories: Vec<FileIdentity>,
    entries: VecDeque<D>,
    names: NameAllocator,
}

struct NameAllocator {
    used: HashSet<String>,
}

impl NameAllocator {
    fn new(reserve_manifest: bool) -> Self {
        let mut used = HashSet::new();
        if reserve_manifest {
            used.insert(collision_key(MANIFEST_NAME));
        }
        Self { used }
    }

    fn allocate(&mut self, source_name: &str, identifier: u64) -> String {
        let base = safe_component(source_name);
        if self.used.insert(collision_key(&base)) {
            return base;
        }

        let suffix = format!("~{identifier:016x}");
        let shortened = truncate_for_suffix(&base, suffix.len());
        let first = format!("{shortened}{suffix}");
        if self.used.insert(collision_key(&first)) {
            return first;
        }

        for sequence in 2_u64.. {
            let suffix = format!("~{identifier:016x}-{sequence}");
            let shortened = truncate_for_suffix(&base, suffix.len());
            let candidate = format!("{shortened}{suffix}");
            if self.used.insert(collision_key(&candidate)) {
                return candidate;
            }
        }
        unreachable!("unbounded collision sequence")
    }
}

struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

enum CopyFileError {
    Source(String),
    Output(io::Error),
    Cancelled,
}

/// Export the selected real directory beneath `destination_parent`.
///
/// Source read, child-resolution, and directory-listing failures are recorded
/// and sibling occurrences continue. Configuration, destination I/O,
/// cancellation, and publication failures return an error and never publish
/// the final directory.
pub fn export_directory<F>(
    fs: &mut F,
    source: DirectoryExportSource<F::FileType>,
    destination_parent: impl AsRef<Path>,
    options: &DirectoryExportOptions,
    control: &mut DirectoryExportControl<'_>,
) -> Result<DirectoryExportReport, DirectoryExportError>
where
    F: Filesystem,
    F::FileType: FileCommon,
    F::DirectoryType: DirectoryCommon,
{
    validate_options(options, &source)?;
    if source.record.entry_kind() != FileKind::Directory {
        return Err(DirectoryExportError::SourceNotDirectory);
    }
    let resolved_source_identifier = fs.file_identifier(&source.record);
    if resolved_source_identifier != source.identifier {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "resolved source identifier {resolved_source_identifier} does not match selected identifier {}",
            source.identifier
        )));
    }

    let requested_parent = destination_parent.as_ref();
    let parent_metadata =
        fs::symlink_metadata(requested_parent).map_err(|source| DirectoryExportError::Io {
            operation: "inspect destination parent",
            path: requested_parent.to_path_buf(),
            source,
        })?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(DirectoryExportError::DestinationParent(
            requested_parent.to_path_buf(),
        ));
    }
    let destination_parent =
        fs::canonicalize(requested_parent).map_err(|source| DirectoryExportError::Io {
            operation: "resolve destination parent",
            path: requested_parent.to_path_buf(),
            source,
        })?;
    let canonical_protected_root = if let Some(protected_root) = fs.protected_host_root() {
        Some(
            fs::canonicalize(protected_root).map_err(|source| DirectoryExportError::Io {
                operation: "resolve protected FolderFS root",
                path: protected_root.to_path_buf(),
                source,
            })?,
        )
    } else {
        None
    };

    let root_name = safe_component(&source.output_name);
    let output_path = destination_parent.join(&root_name);
    if let Some(protected_root) = canonical_protected_root.as_deref()
        && (output_path.starts_with(protected_root) || protected_root.starts_with(&output_path))
    {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "final output {} overlaps protected FolderFS evidence root {}",
            output_path.display(),
            protected_root.display()
        )));
    }

    let lock_path = destination_parent.join(format!(".{root_name}.exhume-export.lock"));
    let _output_lock = acquire_output_lock(&lock_path)?;
    refuse_existing(&output_path)?;

    if control.is_cancelled() {
        return Err(DirectoryExportError::Cancelled {
            entries_processed: 0,
            bytes_written: 0,
        });
    }

    control.notify(DirectoryExportProgress {
        stage: DirectoryExportStage::Preparing,
        current_logical_path: source.logical_path.clone(),
        entries_processed: 0,
        files_exported: 0,
        directories_exported: 0,
        bytes_written: 0,
        current_file_bytes: 0,
        current_file_total: 0,
        skipped_entries: 0,
        failed_entries: 0,
    });

    let staging_path = create_staging_directory(&destination_parent, &root_name)?;
    let mut staging_guard = StagingGuard::new(staging_path.clone());
    let created_unix_ms = unix_time_ms()?;
    let filesystem_type = fs.filesystem_type();
    let source_view = fs.source_view();
    let source_identity = fs.file_identity(&source.record);
    let separator = fs.path_separator();
    let mut stats = ExportStats {
        entries_processed: 1,
        directories_exported: 1,
        ..ExportStats::default()
    };
    let mut manifest_entries = Vec::new();
    let mut failures = Vec::new();
    let mut manifest_text_bytes = 0_u64;
    let root_metadata =
        normalized_source_metadata(fs, &source.record, source.identifier, &source.logical_path);
    push_manifest_entry(
        &mut manifest_entries,
        &mut manifest_text_bytes,
        DirectoryExportEntry {
            source_identifier: source.identifier,
            source_identity: Some(source_identity),
            source_logical_path: source.logical_path.clone(),
            output_relative_path: ".".to_string(),
            kind: Some(FileKind::Directory),
            logical_size: source.record.size(),
            bytes_exported: 0,
            sha256: None,
            disposition: DirectoryEntryDisposition::Exported,
            reason: None,
            source_metadata: Some(root_metadata),
        },
    )?;

    control.notify(progress(
        DirectoryExportStage::Exporting,
        &source.logical_path,
        &stats,
        0,
        0,
    ));

    let mut stack = Vec::<DirectoryFrame<F::FileType, F::DirectoryType>>::new();
    let mut queued_entries = 0_u64;
    let root_remaining = options.max_entries.saturating_sub(stats.entries_processed);
    match sorted_entries(fs, &source.record, root_remaining as usize) {
        Ok(entries) => {
            queued_entries = entries.len() as u64;
            stack.push(DirectoryFrame {
                directory: source.record,
                logical_path: source.logical_path.clone(),
                output_relative_path: PathBuf::new(),
                depth: 0,
                ancestor_directories: vec![source_identity],
                entries,
                names: NameAllocator::new(true),
            });
        }
        Err(error) => {
            if is_directory_entry_limit(error.as_ref()) {
                return Err(DirectoryExportError::EntryLimitExceeded {
                    maximum: options.max_entries,
                });
            }
            record_failure(
                &mut stats,
                &mut failures,
                &mut manifest_text_bytes,
                source.identifier,
                &source.logical_path,
                "list_directory",
                error.to_string(),
            )?;
            let root = manifest_entries
                .first_mut()
                .expect("root manifest entry exists");
            mark_manifest_entry_failed(root, &mut manifest_text_bytes, error.to_string())?;
        }
    }

    while let Some(mut frame) = stack.pop() {
        check_cancelled(control, &stats)?;
        let Some(entry) = frame.entries.pop_front() else {
            if options.sync_data {
                sync_directory(&staging_path.join(&frame.output_relative_path))?;
            }
            continue;
        };
        queued_entries = queued_entries.saturating_sub(1);

        if entry.name().len() > MAX_SOURCE_COMPONENT_BYTES {
            return Err(DirectoryExportError::InvalidConfiguration(format!(
                "source entry {:#x} has a name longer than {MAX_SOURCE_COMPONENT_BYTES} bytes",
                fs.entry_identifier(&frame.directory, &entry)
            )));
        }
        let entry_name = entry.name().to_owned();
        if entry_name == "." || entry_name == ".." {
            stack.push(frame);
            continue;
        }
        if stats.entries_processed >= options.max_entries {
            return Err(DirectoryExportError::EntryLimitExceeded {
                maximum: options.max_entries,
            });
        }

        let child_identifier = fs.entry_identifier(&frame.directory, &entry);
        let logical_path_bytes = frame
            .logical_path
            .len()
            .saturating_add(separator.len())
            .saturating_add(entry_name.len());
        if logical_path_bytes > MAX_LOGICAL_PATH_BYTES {
            return Err(DirectoryExportError::InvalidConfiguration(format!(
                "source path for entry {child_identifier:#x} exceeds {MAX_LOGICAL_PATH_BYTES} bytes"
            )));
        }
        let mapped_name = frame.names.allocate(&entry_name, child_identifier);
        let child_logical_path = append_logical_path(&frame.logical_path, &separator, &entry_name);
        let child_relative_path = frame.output_relative_path.join(mapped_name);
        let child_output_path = staging_path.join(&child_relative_path);
        let child_depth = frame.depth.saturating_add(1);
        let child_record = fs.resolve_child(&frame.directory, &entry);

        // Keep the parent frame immediately beneath a possible child frame so
        // traversal remains depth-first without cloning filesystem records.
        let child_ancestors = frame.ancestor_directories.clone();
        stack.push(frame);

        let child_record = match child_record {
            Ok(record) => record,
            Err(error) => {
                stats.entries_processed += 1;
                record_failure(
                    &mut stats,
                    &mut failures,
                    &mut manifest_text_bytes,
                    child_identifier,
                    &child_logical_path,
                    "resolve_child",
                    error.to_string(),
                )?;
                push_manifest_entry(
                    &mut manifest_entries,
                    &mut manifest_text_bytes,
                    DirectoryExportEntry {
                        source_identifier: child_identifier,
                        source_identity: None,
                        source_logical_path: child_logical_path.clone(),
                        output_relative_path: portable_relative_path(&child_relative_path),
                        kind: None,
                        logical_size: 0,
                        bytes_exported: 0,
                        sha256: None,
                        disposition: DirectoryEntryDisposition::Failed,
                        reason: Some(error.to_string()),
                        source_metadata: None,
                    },
                )?;
                control.notify(progress(
                    DirectoryExportStage::Exporting,
                    &child_logical_path,
                    &stats,
                    0,
                    0,
                ));
                continue;
            }
        };

        let kind = child_record.entry_kind();
        let identity = fs.file_identity(&child_record);
        let logical_size = child_record.size();
        let source_metadata =
            normalized_source_metadata(fs, &child_record, child_identifier, &child_logical_path);

        match kind {
            FileKind::Directory => {
                if child_depth > options.max_depth {
                    stats.entries_processed += 1;
                    stats.skipped_entries += 1;
                    let reason = format!(
                        "directory depth {child_depth} exceeds configured maximum {}",
                        options.max_depth
                    );
                    push_manifest_entry(
                        &mut manifest_entries,
                        &mut manifest_text_bytes,
                        skipped_entry(
                            child_identifier,
                            identity,
                            child_logical_path.clone(),
                            child_relative_path.clone(),
                            kind,
                            logical_size,
                            source_metadata,
                            reason,
                        ),
                    )?;
                } else if child_ancestors.contains(&identity) {
                    stats.entries_processed += 1;
                    stats.skipped_entries += 1;
                    push_manifest_entry(
                        &mut manifest_entries,
                        &mut manifest_text_bytes,
                        skipped_entry(
                            child_identifier,
                            identity,
                            child_logical_path.clone(),
                            child_relative_path.clone(),
                            kind,
                            logical_size,
                            source_metadata,
                            "cyclic directory reference".to_string(),
                        ),
                    )?;
                } else {
                    create_private_directory(&child_output_path)?;
                    stats.entries_processed += 1;
                    stats.directories_exported += 1;
                    let manifest_index = push_manifest_entry(
                        &mut manifest_entries,
                        &mut manifest_text_bytes,
                        DirectoryExportEntry {
                            source_identifier: child_identifier,
                            source_identity: Some(identity),
                            source_logical_path: child_logical_path.clone(),
                            output_relative_path: portable_relative_path(&child_relative_path),
                            kind: Some(kind),
                            logical_size,
                            bytes_exported: 0,
                            sha256: None,
                            disposition: DirectoryEntryDisposition::Exported,
                            reason: None,
                            source_metadata: Some(source_metadata),
                        },
                    )?;

                    let remaining_capacity = options
                        .max_entries
                        .saturating_sub(stats.entries_processed)
                        .saturating_sub(queued_entries);
                    match sorted_entries(fs, &child_record, remaining_capacity as usize) {
                        Ok(entries) => {
                            queued_entries = queued_entries.saturating_add(entries.len() as u64);
                            let mut ancestors = child_ancestors;
                            ancestors.push(identity);
                            stack.push(DirectoryFrame {
                                directory: child_record,
                                logical_path: child_logical_path.clone(),
                                output_relative_path: child_relative_path,
                                depth: child_depth,
                                ancestor_directories: ancestors,
                                entries,
                                names: NameAllocator::new(false),
                            });
                        }
                        Err(error) => {
                            if is_directory_entry_limit(error.as_ref()) {
                                return Err(DirectoryExportError::EntryLimitExceeded {
                                    maximum: options.max_entries,
                                });
                            }
                            if options.sync_data {
                                sync_directory(&child_output_path)?;
                            }
                            record_failure(
                                &mut stats,
                                &mut failures,
                                &mut manifest_text_bytes,
                                child_identifier,
                                &child_logical_path,
                                "list_directory",
                                error.to_string(),
                            )?;
                            mark_manifest_entry_failed(
                                &mut manifest_entries[manifest_index],
                                &mut manifest_text_bytes,
                                error.to_string(),
                            )?;
                        }
                    }
                }
                control.notify(progress(
                    DirectoryExportStage::Exporting,
                    &child_logical_path,
                    &stats,
                    0,
                    0,
                ));
            }
            FileKind::Regular => {
                let mut destination = create_private_file(&child_output_path)?;
                let file_work_start = stats.bytes_written;
                match copy_primary_file_exact(
                    fs,
                    &child_record,
                    &mut destination,
                    &child_output_path,
                    options,
                    control,
                    &mut stats,
                    &child_logical_path,
                ) {
                    Ok(sha256) => {
                        stats.entries_processed += 1;
                        stats.files_exported += 1;
                        stats.bytes_exported = stats.bytes_exported.saturating_add(logical_size);
                        push_manifest_entry(
                            &mut manifest_entries,
                            &mut manifest_text_bytes,
                            DirectoryExportEntry {
                                source_identifier: child_identifier,
                                source_identity: Some(identity),
                                source_logical_path: child_logical_path.clone(),
                                output_relative_path: portable_relative_path(&child_relative_path),
                                kind: Some(kind),
                                logical_size,
                                bytes_exported: logical_size,
                                sha256: Some(sha256),
                                disposition: DirectoryEntryDisposition::Exported,
                                reason: None,
                                source_metadata: Some(source_metadata),
                            },
                        )?;
                    }
                    Err(CopyFileError::Source(message)) => {
                        drop(destination);
                        fs::remove_file(&child_output_path).map_err(|source| {
                            DirectoryExportError::Io {
                                operation: "remove failed staged file",
                                path: child_output_path.clone(),
                                source,
                            }
                        })?;
                        stats.entries_processed += 1;
                        record_failure(
                            &mut stats,
                            &mut failures,
                            &mut manifest_text_bytes,
                            child_identifier,
                            &child_logical_path,
                            "read_file",
                            message.clone(),
                        )?;
                        push_manifest_entry(
                            &mut manifest_entries,
                            &mut manifest_text_bytes,
                            DirectoryExportEntry {
                                source_identifier: child_identifier,
                                source_identity: Some(identity),
                                source_logical_path: child_logical_path.clone(),
                                output_relative_path: portable_relative_path(&child_relative_path),
                                kind: Some(kind),
                                logical_size,
                                bytes_exported: 0,
                                sha256: None,
                                disposition: DirectoryEntryDisposition::Failed,
                                reason: Some(message),
                                source_metadata: Some(source_metadata),
                            },
                        )?;
                    }
                    Err(CopyFileError::Output(source)) => {
                        return Err(DirectoryExportError::Io {
                            operation: "write staged file",
                            path: child_output_path,
                            source,
                        });
                    }
                    Err(CopyFileError::Cancelled) => {
                        return Err(DirectoryExportError::Cancelled {
                            entries_processed: stats.entries_processed,
                            bytes_written: stats.bytes_written,
                        });
                    }
                }
                control.notify(progress(
                    DirectoryExportStage::Exporting,
                    &child_logical_path,
                    &stats,
                    stats.bytes_written.saturating_sub(file_work_start),
                    logical_size,
                ));
            }
            FileKind::Symlink | FileKind::Special => {
                stats.entries_processed += 1;
                stats.skipped_entries += 1;
                let reason = match kind {
                    FileKind::Symlink => {
                        "symbolic links are reported but not followed or created in V1"
                    }
                    FileKind::Special => "special entries are reported but not created in V1",
                    _ => unreachable!(),
                };
                push_manifest_entry(
                    &mut manifest_entries,
                    &mut manifest_text_bytes,
                    skipped_entry(
                        child_identifier,
                        identity,
                        child_logical_path.clone(),
                        child_relative_path,
                        kind,
                        logical_size,
                        source_metadata,
                        reason.to_string(),
                    ),
                )?;
                control.notify(progress(
                    DirectoryExportStage::Exporting,
                    &child_logical_path,
                    &stats,
                    0,
                    0,
                ));
            }
        }
    }

    check_cancelled(control, &stats)?;
    control.notify(progress(
        DirectoryExportStage::Finalizing,
        &source.logical_path,
        &stats,
        0,
        0,
    ));

    let status = if stats.failed_entries == 0 && stats.skipped_entries == 0 {
        DirectoryExportStatus::Complete
    } else {
        DirectoryExportStatus::Partial
    };
    let mut manifest = DirectoryExportManifest {
        schema: MANIFEST_SCHEMA.to_string(),
        created_unix_ms,
        completed_unix_ms: unix_time_ms()?,
        status,
        filesystem_type,
        source_view,
        source_identifier: source.identifier,
        source_identity,
        source_logical_path: source.logical_path.clone(),
        provenance: options.provenance.clone(),
        output_path: output_path.to_string_lossy().into_owned(),
        manifest_relative_path: MANIFEST_NAME.to_string(),
        primary_data_fork_only: true,
        entries_processed: stats.entries_processed,
        files_exported: stats.files_exported,
        directories_exported: stats.directories_exported,
        bytes_exported: stats.bytes_exported,
        bytes_written: stats.bytes_written,
        skipped_entries: stats.skipped_entries,
        failed_entries: stats.failed_entries,
        entries: manifest_entries,
        failures,
    };
    let staged_manifest_path = staging_path.join(MANIFEST_NAME);
    write_manifest(&staged_manifest_path, &manifest, options.sync_data)?;
    let failures = std::mem::take(&mut manifest.failures);
    drop(manifest);

    if options.sync_data {
        sync_directory(&staging_path)?;
    }
    check_cancelled(control, &stats)?;
    refuse_existing(&output_path)?;
    publish_noreplace(&staging_path, &output_path)?;
    staging_guard.disarm();
    if options.sync_data {
        // The tree has already been published atomically. A parent-directory
        // sync improves crash durability, but failure cannot be reported as a
        // fatal export error without violating the no-published-output-on-error
        // contract.
        let _ = sync_directory(&destination_parent);
    }

    control.notify(progress(
        DirectoryExportStage::Complete,
        &source.logical_path,
        &stats,
        0,
        0,
    ));
    Ok(DirectoryExportReport {
        manifest_path: output_path.join(MANIFEST_NAME),
        output_path,
        status,
        entries_processed: stats.entries_processed,
        files_exported: stats.files_exported,
        directories_exported: stats.directories_exported,
        bytes_exported: stats.bytes_exported,
        bytes_written: stats.bytes_written,
        skipped_entries: stats.skipped_entries,
        failed_entries: stats.failed_entries,
        failures,
    })
}

fn validate_options<F>(
    options: &DirectoryExportOptions,
    source: &DirectoryExportSource<F>,
) -> Result<(), DirectoryExportError> {
    if options.chunk_size == 0 || options.chunk_size > MAX_CHUNK_SIZE {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "chunk size must be between 1 and {MAX_CHUNK_SIZE} bytes"
        )));
    }
    if options.max_entries == 0 || options.max_entries > HARD_MAX_ENTRIES {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "max_entries must be between 1 and {HARD_MAX_ENTRIES}"
        )));
    }
    if source.logical_path.trim().is_empty() {
        return Err(DirectoryExportError::InvalidConfiguration(
            "source logical path must not be empty".to_string(),
        ));
    }
    if source.logical_path.len() > MAX_LOGICAL_PATH_BYTES {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "source logical path exceeds {MAX_LOGICAL_PATH_BYTES} bytes"
        )));
    }
    if source.output_name.trim().is_empty() {
        return Err(DirectoryExportError::InvalidConfiguration(
            "source output name must not be empty".to_string(),
        ));
    }
    if source.output_name.len() > MAX_SOURCE_COMPONENT_BYTES {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "source output name exceeds {MAX_SOURCE_COMPONENT_BYTES} bytes"
        )));
    }
    validate_provenance(&options.provenance)?;
    Ok(())
}

fn validate_provenance(provenance: &DirectoryExportProvenance) -> Result<(), DirectoryExportError> {
    const MAX_VALUE_BYTES: usize = 4 * 1024;
    const MAX_METADATA_FIELDS: usize = 64;
    const MAX_METADATA_KEY_BYTES: usize = 128;

    if provenance.public_metadata.len() > MAX_METADATA_FIELDS {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "provenance public_metadata has more than {MAX_METADATA_FIELDS} fields"
        )));
    }
    for (field, value) in [
        ("evidence_id", provenance.evidence_id.as_deref()),
        ("partition_id", provenance.partition_id.as_deref()),
        ("source_path", provenance.source_path.as_deref()),
        (
            "source_description",
            provenance.source_description.as_deref(),
        ),
    ] {
        if let Some(value) = value
            && (value.len() > MAX_VALUE_BYTES || value.contains('\0'))
        {
            return Err(DirectoryExportError::InvalidConfiguration(format!(
                "provenance {field} is too long or contains NUL"
            )));
        }
    }
    for (key, value) in &provenance.public_metadata {
        if key.is_empty()
            || key.len() > MAX_METADATA_KEY_BYTES
            || key.contains('\0')
            || value.len() > MAX_VALUE_BYTES
            || value.contains('\0')
        {
            return Err(DirectoryExportError::InvalidConfiguration(
                "provenance public_metadata contains an invalid key or value".to_string(),
            ));
        }
    }
    Ok(())
}

fn sorted_entries<F>(
    fs: &mut F,
    directory: &F::FileType,
    maximum: usize,
) -> Result<VecDeque<F::DirectoryType>, Box<dyn Error>>
where
    F: Filesystem,
{
    let mut entries = fs.list_dir_limited(directory, maximum.saturating_add(2))?;
    entries.retain(|entry| entry.name() != "." && entry.name() != "..");
    if entries.len() > maximum {
        return Err(Box::new(DirectoryEntryLimitError { maximum }));
    }
    entries.sort_by(|left, right| {
        left.name()
            .as_bytes()
            .cmp(right.name().as_bytes())
            .then_with(|| {
                fs.entry_identifier(directory, left)
                    .cmp(&fs.entry_identifier(directory, right))
            })
    });
    Ok(entries.into())
}

fn is_directory_entry_limit(error: &(dyn Error + 'static)) -> bool {
    error.downcast_ref::<DirectoryEntryLimitError>().is_some()
}

fn normalized_source_metadata<F>(
    fs: &F,
    record: &F::FileType,
    identifier: u64,
    logical_path: &str,
) -> DirectoryExportEntryMetadata
where
    F: Filesystem,
{
    let normalized = fs.record_to_file(record, identifier, logical_path);
    DirectoryExportEntryMetadata {
        created_unix_seconds: normalized.created,
        modified_unix_seconds: normalized.modified,
        accessed_unix_seconds: normalized.accessed,
        permissions: normalized
            .permissions
            .map(|value| bounded_manifest_text(value, MAX_FAILURE_MESSAGE_BYTES)),
        owner: normalized
            .owner
            .map(|value| bounded_manifest_text(value, MAX_FAILURE_MESSAGE_BYTES)),
        group: normalized
            .group
            .map(|value| bounded_manifest_text(value, MAX_FAILURE_MESSAGE_BYTES)),
    }
}

fn push_manifest_entry(
    entries: &mut Vec<DirectoryExportEntry>,
    used_bytes: &mut u64,
    mut entry: DirectoryExportEntry,
) -> Result<usize, DirectoryExportError> {
    entry.reason = entry
        .reason
        .map(|value| bounded_manifest_text(value, MAX_FAILURE_MESSAGE_BYTES));
    let metadata_bytes = entry.source_metadata.as_ref().map_or(0_usize, |metadata| {
        metadata.permissions.as_ref().map_or(0, String::len)
            + metadata.owner.as_ref().map_or(0, String::len)
            + metadata.group.as_ref().map_or(0, String::len)
    });
    let estimated = 256_usize
        .saturating_add(entry.source_logical_path.len())
        .saturating_add(entry.output_relative_path.len())
        .saturating_add(entry.sha256.as_ref().map_or(0, String::len))
        .saturating_add(entry.reason.as_ref().map_or(0, String::len))
        .saturating_add(metadata_bytes);
    reserve_manifest_bytes(used_bytes, estimated)?;
    let index = entries.len();
    entries.push(entry);
    Ok(index)
}

fn mark_manifest_entry_failed(
    entry: &mut DirectoryExportEntry,
    used_bytes: &mut u64,
    message: String,
) -> Result<(), DirectoryExportError> {
    let message = bounded_manifest_text(message, MAX_FAILURE_MESSAGE_BYTES);
    reserve_manifest_bytes(used_bytes, message.len())?;
    entry.disposition = DirectoryEntryDisposition::Failed;
    entry.reason = Some(message);
    Ok(())
}

fn reserve_manifest_bytes(
    used_bytes: &mut u64,
    additional: usize,
) -> Result<(), DirectoryExportError> {
    let additional = u64::try_from(additional).unwrap_or(u64::MAX);
    let next = used_bytes.saturating_add(additional);
    if next > MAX_MANIFEST_TEXT_BYTES {
        return Err(DirectoryExportError::ManifestLimitExceeded {
            maximum_bytes: MAX_MANIFEST_TEXT_BYTES,
        });
    }
    *used_bytes = next;
    Ok(())
}

fn bounded_manifest_text(value: String, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value;
    }
    let digest = Sha256::digest(value.as_bytes());
    let suffix = format!("~sha256:{}", hex::encode(&digest[..8]));
    let prefix = truncate_utf8(&value, maximum_bytes.saturating_sub(suffix.len()));
    format!("{prefix}{suffix}")
}

fn record_failure(
    stats: &mut ExportStats,
    failures: &mut Vec<DirectoryExportFailure>,
    manifest_bytes: &mut u64,
    identifier: u64,
    logical_path: &str,
    operation: &str,
    message: String,
) -> Result<(), DirectoryExportError> {
    let message = bounded_manifest_text(message, MAX_FAILURE_MESSAGE_BYTES);
    reserve_manifest_bytes(
        manifest_bytes,
        128_usize
            .saturating_add(logical_path.len())
            .saturating_add(operation.len())
            .saturating_add(message.len()),
    )?;
    stats.failed_entries = stats.failed_entries.saturating_add(1);
    failures.push(DirectoryExportFailure {
        source_identifier: identifier,
        source_logical_path: logical_path.to_string(),
        operation: operation.to_string(),
        message,
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn skipped_entry(
    identifier: u64,
    identity: FileIdentity,
    logical_path: String,
    output_relative_path: PathBuf,
    kind: FileKind,
    logical_size: u64,
    source_metadata: DirectoryExportEntryMetadata,
    reason: String,
) -> DirectoryExportEntry {
    DirectoryExportEntry {
        source_identifier: identifier,
        source_identity: Some(identity),
        source_logical_path: logical_path,
        output_relative_path: portable_relative_path(&output_relative_path),
        kind: Some(kind),
        logical_size,
        bytes_exported: 0,
        sha256: None,
        disposition: DirectoryEntryDisposition::Skipped,
        reason: Some(reason),
        source_metadata: Some(source_metadata),
    }
}

#[allow(clippy::too_many_arguments)]
fn copy_primary_file_exact<F>(
    fs: &mut F,
    source: &F::FileType,
    destination: &mut StdFile,
    destination_path: &Path,
    options: &DirectoryExportOptions,
    control: &mut DirectoryExportControl<'_>,
    stats: &mut ExportStats,
    logical_path: &str,
) -> Result<String, CopyFileError>
where
    F: Filesystem,
{
    let total = source.size();
    let mut offset = 0_u64;
    let mut hasher = Sha256::new();

    while offset < total {
        if control.is_cancelled() {
            return Err(CopyFileError::Cancelled);
        }
        let wanted = usize::try_from((total - offset).min(options.chunk_size as u64))
            .expect("chunk size is bounded by usize");
        let bytes = fs
            .read_file_slice(source, offset, wanted)
            .map_err(|error| CopyFileError::Source(error.to_string()))?;
        if bytes.is_empty() {
            return Err(CopyFileError::Source(format!(
                "premature EOF at byte {offset}; expected {wanted} more byte(s)"
            )));
        }
        if bytes.len() > wanted || bytes.len() as u64 > total - offset {
            return Err(CopyFileError::Source(format!(
                "source returned {} bytes for a {wanted}-byte request at offset {offset}",
                bytes.len()
            )));
        }

        destination
            .write_all(&bytes)
            .map_err(CopyFileError::Output)?;
        hasher.update(&bytes);
        offset += bytes.len() as u64;
        stats.bytes_written = stats.bytes_written.saturating_add(bytes.len() as u64);
        control.notify(progress(
            DirectoryExportStage::Exporting,
            logical_path,
            stats,
            offset,
            total,
        ));
    }

    destination.flush().map_err(CopyFileError::Output)?;
    if options.sync_data {
        destination.sync_all().map_err(CopyFileError::Output)?;
    }
    let actual = destination.metadata().map_err(CopyFileError::Output)?.len();
    if actual != total {
        return Err(CopyFileError::Output(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "staged file {} has length {actual}, expected {total}",
                destination_path.display()
            ),
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn progress(
    stage: DirectoryExportStage,
    logical_path: &str,
    stats: &ExportStats,
    current_file_bytes: u64,
    current_file_total: u64,
) -> DirectoryExportProgress {
    DirectoryExportProgress {
        stage,
        current_logical_path: logical_path.to_string(),
        entries_processed: stats.entries_processed,
        files_exported: stats.files_exported,
        directories_exported: stats.directories_exported,
        bytes_written: stats.bytes_written,
        current_file_bytes,
        current_file_total,
        skipped_entries: stats.skipped_entries,
        failed_entries: stats.failed_entries,
    }
}

fn check_cancelled(
    control: &DirectoryExportControl<'_>,
    stats: &ExportStats,
) -> Result<(), DirectoryExportError> {
    if control.is_cancelled() {
        Err(DirectoryExportError::Cancelled {
            entries_processed: stats.entries_processed,
            bytes_written: stats.bytes_written,
        })
    } else {
        Ok(())
    }
}

fn append_logical_path(parent: &str, separator: &str, child: &str) -> String {
    if parent == separator || parent.ends_with(separator) {
        format!("{parent}{child}")
    } else {
        format!("{parent}{separator}{child}")
    }
}

fn portable_relative_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        return ".".to_string();
    }
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn safe_component(source: &str) -> String {
    let chars = source.chars().collect::<Vec<_>>();
    let trailing_start = chars
        .iter()
        .rposition(|character| !matches!(character, '.' | ' '))
        .map_or(0, |index| index + 1);
    let mut mapped = String::new();
    for (index, character) in chars.iter().copied().enumerate() {
        let must_escape = character == '%'
            || character == '/'
            || character == '\\'
            || matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|')
            || character == '\0'
            || character.is_control()
            || (index >= trailing_start && matches!(character, '.' | ' '));
        if must_escape {
            let mut encoded = [0_u8; 4];
            for byte in character.encode_utf8(&mut encoded).as_bytes() {
                mapped.push_str(&format!("%{byte:02X}"));
            }
        } else {
            mapped.push(character);
        }
    }

    if mapped.is_empty() {
        mapped.push_str("_empty");
    }
    if source == "." || source == ".." || is_windows_reserved(source) {
        mapped.insert_str(0, "%5F");
    }
    truncate_component(&mapped, source)
}

fn is_windows_reserved(source: &str) -> bool {
    let stem = source
        .trim_end_matches(['.', ' '])
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

fn truncate_component(mapped: &str, original: &str) -> String {
    if mapped.len() <= MAX_COMPONENT_BYTES {
        return mapped.to_string();
    }
    let digest = Sha256::digest(original.as_bytes());
    let suffix = format!("~{}", hex::encode(&digest[..8]));
    let prefix = truncate_utf8(mapped, MAX_COMPONENT_BYTES - suffix.len());
    format!("{prefix}{suffix}")
}

fn truncate_for_suffix(component: &str, suffix_bytes: usize) -> &str {
    let maximum = MAX_COMPONENT_BYTES.saturating_sub(suffix_bytes);
    truncate_utf8(component, maximum)
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> &str {
    if value.len() <= maximum_bytes {
        return value;
    }
    let mut end = maximum_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn collision_key(component: &str) -> String {
    // Decompose before full non-Turkic case folding, then recompose so both
    // canonical-equivalence and multi-character folds (for example ß -> ss)
    // collide deterministically on case-insensitive destinations.
    component.nfd().case_fold().nfc().collect()
}

fn acquire_output_lock(path: &Path) -> Result<StdFile, DirectoryExportError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "output lock path is not a regular file: {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options
        .open(path)
        .map_err(|source| DirectoryExportError::Io {
            operation: "open output lock",
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = lock.metadata().map_err(|source| DirectoryExportError::Io {
        operation: "inspect opened output lock",
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(DirectoryExportError::InvalidConfiguration(format!(
            "opened output lock is not a regular file: {}",
            path.display()
        )));
    }
    FileExt::try_lock_exclusive(&lock)
        .map_err(|_| DirectoryExportError::ExportLocked(path.to_path_buf()))?;
    Ok(lock)
}

fn refuse_existing(path: &Path) -> Result<(), DirectoryExportError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(DirectoryExportError::AlreadyExists(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DirectoryExportError::Io {
            operation: "inspect final output",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn create_staging_directory(
    destination_parent: &Path,
    root_name: &str,
) -> Result<PathBuf, DirectoryExportError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DirectoryExportError::Clock(error.to_string()))?
        .as_nanos();
    for _ in 0..128 {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging_root = truncate_utf8(root_name, 120);
        let name = format!(
            ".{staging_root}.exhume-partial-{}-{timestamp}-{sequence}",
            std::process::id()
        );
        let path = destination_parent.join(name);
        match create_private_directory(&path) {
            Ok(()) => return Ok(path),
            Err(DirectoryExportError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(DirectoryExportError::InvalidConfiguration(
        "could not allocate a unique staging directory".to_string(),
    ))
}

fn create_private_directory(path: &Path) -> Result<(), DirectoryExportError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| DirectoryExportError::Io {
            operation: "create staged directory",
            path: path.to_path_buf(),
            source,
        })
}

fn create_private_file(path: &Path) -> Result<StdFile, DirectoryExportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|source| DirectoryExportError::Io {
            operation: "create staged file",
            path: path.to_path_buf(),
            source,
        })
}

fn write_manifest(
    path: &Path,
    manifest: &DirectoryExportManifest,
    sync_data: bool,
) -> Result<(), DirectoryExportError> {
    let mut file = create_private_file(path)?;
    serde_json::to_writer_pretty(&mut file, manifest).map_err(DirectoryExportError::Serialize)?;
    file.write_all(b"\n")
        .map_err(|source| DirectoryExportError::Io {
            operation: "write staged manifest",
            path: path.to_path_buf(),
            source,
        })?;
    file.flush().map_err(|source| DirectoryExportError::Io {
        operation: "flush staged manifest",
        path: path.to_path_buf(),
        source,
    })?;
    if sync_data {
        file.sync_all().map_err(|source| DirectoryExportError::Io {
            operation: "sync staged manifest",
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DirectoryExportError> {
    let directory = StdFile::open(path).map_err(|source| DirectoryExportError::Io {
        operation: "open directory for sync",
        path: path.to_path_buf(),
        source,
    })?;
    directory
        .sync_all()
        .map_err(|source| DirectoryExportError::Io {
            operation: "sync directory",
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), DirectoryExportError> {
    // Opening directories with std::fs::File is not portable (notably on
    // Windows). File contents are still synced individually when requested.
    Ok(())
}

fn unix_time_ms() -> Result<u64, DirectoryExportError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DirectoryExportError::Clock(error.to_string()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| DirectoryExportError::Clock("timestamp overflow".into()))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn publish_noreplace(from: &Path, to: &Path) -> Result<(), DirectoryExportError> {
    let from_bytes = CString::new(from.as_os_str().as_bytes()).map_err(|_| {
        DirectoryExportError::InvalidConfiguration("staging path contains NUL".to_string())
    })?;
    let to_bytes = CString::new(to.as_os_str().as_bytes()).map_err(|_| {
        DirectoryExportError::InvalidConfiguration("output path contains NUL".to_string())
    })?;
    // SAFETY: both C strings remain alive for the call and are NUL terminated.
    let result =
        unsafe { libc::renamex_np(from_bytes.as_ptr(), to_bytes.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        return Ok(());
    }
    publish_error(to, io::Error::last_os_error())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn publish_noreplace(from: &Path, to: &Path) -> Result<(), DirectoryExportError> {
    let from_bytes = CString::new(from.as_os_str().as_bytes()).map_err(|_| {
        DirectoryExportError::InvalidConfiguration("staging path contains NUL".to_string())
    })?;
    let to_bytes = CString::new(to.as_os_str().as_bytes()).map_err(|_| {
        DirectoryExportError::InvalidConfiguration("output path contains NUL".to_string())
    })?;
    // SAFETY: both C strings remain alive for the call and are NUL terminated.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_bytes.as_ptr(),
            libc::AT_FDCWD,
            to_bytes.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    publish_error(to, io::Error::last_os_error())
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn publish_noreplace(from: &Path, to: &Path) -> Result<(), DirectoryExportError> {
    // The stable exclusive lock serializes Exhume writers. Recheck immediately
    // before the best portable atomic rename on platforms without a no-replace
    // rename primitive.
    refuse_existing(to)?;
    fs::rename(from, to).map_err(|source| DirectoryExportError::Io {
        operation: "publish staged directory",
        path: to.to_path_buf(),
        source,
    })
}

fn publish_error(path: &Path, error: io::Error) -> Result<(), DirectoryExportError> {
    if matches!(
        error.kind(),
        io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
    ) {
        Err(DirectoryExportError::AlreadyExists(path.to_path_buf()))
    } else {
        Err(DirectoryExportError::Io {
            operation: "publish staged directory without replacement",
            path: path.to_path_buf(),
            source: error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::File;
    use crate::folder_impl::FolderFS;
    use serde_json::{Value, json};
    use std::collections::{HashMap, HashSet};
    use std::error::Error;
    use std::fs as host_fs;
    use std::sync::atomic::Ordering;
    use tempfile::tempdir;

    #[derive(Clone, Debug)]
    struct MockRecord {
        id: u64,
        kind: FileKind,
        content: Vec<u8>,
        advertised_size: u64,
    }

    impl FileCommon for MockRecord {
        fn id(&self) -> u64 {
            self.id
        }

        fn size(&self) -> u64 {
            self.advertised_size
        }

        fn is_dir(&self) -> bool {
            self.kind == FileKind::Directory
        }

        fn entry_kind(&self) -> FileKind {
            self.kind
        }

        fn to_string(&self) -> String {
            format!("mock:{}", self.id)
        }

        fn to_json(&self) -> Value {
            json!({ "id": self.id, "kind": self.kind })
        }
    }

    #[derive(Clone, Debug)]
    struct MockDirectoryEntry {
        file_id: u64,
        name: String,
    }

    impl DirectoryCommon for MockDirectoryEntry {
        fn file_id(&self) -> u64 {
            self.file_id
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn to_string(&self) -> String {
            format!("{}:{}", self.file_id, self.name)
        }

        fn to_json(&self) -> Value {
            json!({ "file_id": self.file_id, "name": self.name })
        }
    }

    struct MockFilesystem {
        records: HashMap<u64, MockRecord>,
        directories: HashMap<u64, Vec<MockDirectoryEntry>>,
        read_failures: HashSet<u64>,
        list_failures: HashSet<u64>,
        resolve_failures: HashSet<u64>,
        read_calls: Vec<u64>,
    }

    impl MockFilesystem {
        fn new() -> Self {
            Self {
                records: HashMap::new(),
                directories: HashMap::new(),
                read_failures: HashSet::new(),
                list_failures: HashSet::new(),
                resolve_failures: HashSet::new(),
                read_calls: Vec::new(),
            }
        }

        fn add_record(&mut self, id: u64, kind: FileKind, content: &[u8]) {
            self.records.insert(
                id,
                MockRecord {
                    id,
                    kind,
                    content: content.to_vec(),
                    advertised_size: content.len() as u64,
                },
            );
        }

        fn add_record_with_size(
            &mut self,
            id: u64,
            kind: FileKind,
            content: &[u8],
            advertised_size: u64,
        ) {
            self.records.insert(
                id,
                MockRecord {
                    id,
                    kind,
                    content: content.to_vec(),
                    advertised_size,
                },
            );
        }

        fn add_entry(&mut self, parent: u64, child: u64, name: &str) {
            self.directories
                .entry(parent)
                .or_default()
                .push(MockDirectoryEntry {
                    file_id: child,
                    name: name.to_string(),
                });
        }
    }

    impl Filesystem for MockFilesystem {
        type FileType = MockRecord;
        type DirectoryType = MockDirectoryEntry;

        fn filesystem_type(&self) -> String {
            "MockFS".to_string()
        }

        fn path_separator(&self) -> String {
            "/".to_string()
        }

        fn record_count(&mut self) -> u64 {
            self.records.len() as u64
        }

        fn block_size(&self) -> u64 {
            4096
        }

        fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
            Ok(json!({ "kind": "mock" }))
        }

        fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
            Ok("MockFS".to_string())
        }

        fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
            self.records
                .get(&file_id)
                .cloned()
                .ok_or_else(|| format!("mock record {file_id} not found").into())
        }

        fn resolve_child(
            &mut self,
            _parent: &Self::FileType,
            entry: &Self::DirectoryType,
        ) -> Result<Self::FileType, Box<dyn Error>> {
            if self.resolve_failures.contains(&entry.file_id) {
                return Err(format!("mock resolve failure for {}", entry.file_id).into());
            }
            self.get_file(entry.file_id)
        }

        fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
            if self.read_failures.contains(&file.id) {
                return Err(format!("mock read failure for {}", file.id).into());
            }
            self.read_calls.push(file.id);
            Ok(file.content.clone())
        }

        fn read_file_prefix(
            &mut self,
            file: &Self::FileType,
            length: usize,
        ) -> Result<Vec<u8>, Box<dyn Error>> {
            let mut bytes = self.read_file_content(file)?;
            bytes.truncate(length);
            Ok(bytes)
        }

        fn read_file_slice(
            &mut self,
            file: &Self::FileType,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, Box<dyn Error>> {
            if self.read_failures.contains(&file.id) {
                return Err(format!("mock read failure for {}", file.id).into());
            }
            self.read_calls.push(file.id);
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= file.content.len() {
                return Ok(Vec::new());
            }
            let end = start.saturating_add(length).min(file.content.len());
            Ok(file.content[start..end].to_vec())
        }

        fn list_dir(
            &mut self,
            file: &Self::FileType,
        ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
            if self.list_failures.contains(&file.id) {
                return Err(format!("mock list failure for {}", file.id).into());
            }
            Ok(self.directories.get(&file.id).cloned().unwrap_or_default())
        }

        fn record_to_file(&self, file: &Self::FileType, file_id: u64, path: &str) -> File {
            File {
                id: None,
                identifier: file_id,
                absolute_path: path.to_string(),
                name: path.rsplit('/').next().unwrap_or(path).to_string(),
                ftype: format!("{:?}", file.kind),
                size: file.size(),
                created: Some(100 + file.id),
                modified: Some(200 + file.id),
                accessed: Some(300 + file.id),
                permissions: Some("r--r-----".to_string()),
                owner: Some("mock-owner".to_string()),
                group: Some("mock-group".to_string()),
                display: None,
                sig_name: None,
                sig_mime: None,
                sig_exts: None,
                metadata: file.to_json(),
            }
        }

        fn get_root_file_id(&self) -> u64 {
            1
        }
    }

    fn source(fs: &mut MockFilesystem, output_name: &str) -> DirectoryExportSource<MockRecord> {
        DirectoryExportSource::new(
            fs.get_file(1).expect("mock root"),
            1,
            "/selected",
            output_name,
        )
    }

    #[test]
    fn exports_occurrences_empty_directories_and_safe_names_without_following_links() {
        let temp = tempdir().unwrap();
        let parent = temp.path().join("exports");
        host_fs::create_dir(&parent).unwrap();
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record(2, FileKind::Directory, &[]);
        fs.add_record(3, FileKind::Regular, b"hello");
        fs.add_record(4, FileKind::Regular, b"safe");
        fs.add_record(5, FileKind::Symlink, b"/outside/secret");
        fs.add_record(6, FileKind::Special, b"special");
        fs.add_record(7, FileKind::Regular, b"manifest collision");
        fs.add_entry(1, 2, "empty");
        fs.add_entry(1, 3, "a.txt");
        fs.add_entry(1, 3, "b.txt");
        fs.add_entry(1, 4, "../escape");
        fs.add_entry(1, 5, "outside-link");
        fs.add_entry(1, 6, "device");
        fs.add_entry(1, 1, "cycle");
        fs.add_entry(1, 7, MANIFEST_NAME);

        let mut public_metadata = BTreeMap::new();
        public_metadata.insert("partitionKind".to_string(), "gpt".to_string());
        let provenance = DirectoryExportProvenance {
            evidence_id: Some("evidence-7".to_string()),
            partition_id: Some("partition-2".to_string()),
            source_path: Some("/registered/evidence.raw".to_string()),
            source_description: Some("raw disk image".to_string()),
            public_metadata,
        };

        let selected = source(&mut fs, "dump");
        let report = export_directory(
            &mut fs,
            selected,
            &parent,
            &DirectoryExportOptions {
                chunk_size: 2,
                sync_data: false,
                provenance: provenance.clone(),
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        )
        .unwrap();

        assert_eq!(report.status, DirectoryExportStatus::Partial);
        assert_eq!(report.files_exported, 4);
        assert_eq!(report.directories_exported, 2);
        assert_eq!(report.skipped_entries, 3);
        assert!(report.output_path.join("empty").is_dir());
        assert_eq!(
            host_fs::read(report.output_path.join("a.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            host_fs::read(report.output_path.join("b.txt")).unwrap(),
            b"hello"
        );
        assert!(report.output_path.join("..%2Fescape").is_file());
        assert!(!report.output_path.join("outside-link").exists());
        assert!(!report.output_path.join("device").exists());
        assert!(!fs.read_calls.contains(&5));
        assert!(!fs.read_calls.contains(&6));

        let manifest: DirectoryExportManifest =
            serde_json::from_slice(&host_fs::read(&report.manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.provenance, provenance);
        assert_eq!(manifest.source_view, FilesystemSourceView::Native);
        let collision = manifest
            .entries
            .iter()
            .find(|entry| entry.source_logical_path.ends_with(MANIFEST_NAME))
            .unwrap();
        assert_ne!(collision.output_relative_path, MANIFEST_NAME);
        assert!(
            report
                .output_path
                .join(&collision.output_relative_path)
                .is_file()
        );
        let expected_hash = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(
            manifest
                .entries
                .iter()
                .find(|entry| entry.source_logical_path.ends_with("a.txt"))
                .unwrap()
                .sha256
                .as_deref(),
            Some(expected_hash.as_str())
        );
        let metadata = manifest
            .entries
            .iter()
            .find(|entry| entry.source_logical_path.ends_with("a.txt"))
            .unwrap()
            .source_metadata
            .as_ref()
            .unwrap();
        assert_eq!(metadata.created_unix_seconds, Some(103));
        assert_eq!(metadata.modified_unix_seconds, Some(203));
        assert_eq!(metadata.accessed_unix_seconds, Some(303));
        assert_eq!(metadata.permissions.as_deref(), Some("r--r-----"));
        assert_eq!(metadata.owner.as_deref(), Some("mock-owner"));
        assert_eq!(metadata.group.as_deref(), Some("mock-group"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                host_fs::metadata(&report.output_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                host_fs::metadata(report.output_path.join("a.txt"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn default_path_resolution_preserves_non_separator_backslashes() {
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record(2, FileKind::Regular, b"backslash");
        fs.add_entry(1, 2, "a\\b");

        let resolved = fs.get_file_by_path("/a\\b", 2).unwrap();
        assert_eq!(resolved.id(), 2);
    }

    #[test]
    fn source_read_failure_is_partial_and_later_sibling_is_exported() {
        let temp = tempdir().unwrap();
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record(2, FileKind::Regular, b"bad");
        fs.add_record(3, FileKind::Regular, b"good");
        fs.add_entry(1, 2, "a-bad.bin");
        fs.add_entry(1, 3, "z-good.bin");
        fs.read_failures.insert(2);

        let selected = source(&mut fs, "partial");
        let report = export_directory(
            &mut fs,
            selected,
            temp.path(),
            &DirectoryExportOptions {
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        )
        .unwrap();

        assert_eq!(report.status, DirectoryExportStatus::Partial);
        assert_eq!(report.failed_entries, 1);
        assert_eq!(report.bytes_exported, 4);
        assert_eq!(report.bytes_written, 4);
        assert_eq!(report.files_exported, 1);
        assert!(!report.output_path.join("a-bad.bin").exists());
        assert_eq!(
            host_fs::read(report.output_path.join("z-good.bin")).unwrap(),
            b"good"
        );
        assert_eq!(report.failures[0].operation, "read_file");
    }

    #[test]
    fn premature_eof_removes_partial_file_and_later_sibling_continues() {
        let temp = tempdir().unwrap();
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record_with_size(2, FileKind::Regular, b"abc", 5);
        fs.add_record(3, FileKind::Regular, b"complete");
        fs.add_entry(1, 2, "a-short.bin");
        fs.add_entry(1, 3, "z-complete.bin");

        let selected = source(&mut fs, "premature-eof");
        let report = export_directory(
            &mut fs,
            selected,
            temp.path(),
            &DirectoryExportOptions {
                chunk_size: 2,
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        )
        .unwrap();

        assert_eq!(report.status, DirectoryExportStatus::Partial);
        assert_eq!(report.failed_entries, 1);
        assert_eq!(report.bytes_exported, 8);
        assert_eq!(report.bytes_written, 11);
        assert!(!report.output_path.join("a-short.bin").exists());
        assert_eq!(
            host_fs::read(report.output_path.join("z-complete.bin")).unwrap(),
            b"complete"
        );
        assert_eq!(report.failures[0].operation, "read_file");
        assert!(report.failures[0].message.contains("premature EOF"));
        let manifest: DirectoryExportManifest =
            serde_json::from_slice(&host_fs::read(&report.manifest_path).unwrap()).unwrap();
        let failed = manifest
            .entries
            .iter()
            .find(|entry| entry.source_logical_path.ends_with("a-short.bin"))
            .unwrap();
        assert_eq!(failed.disposition, DirectoryEntryDisposition::Failed);
        assert!(failed.sha256.is_none());
        assert_eq!(failed.bytes_exported, 0);
    }

    #[test]
    fn cancellation_removes_staging_and_never_publishes_final() {
        let temp = tempdir().unwrap();
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record(2, FileKind::Regular, b"0123456789");
        fs.add_entry(1, 2, "large.bin");
        let cancelled = AtomicBool::new(false);
        let mut callback = |progress: &DirectoryExportProgress| {
            if progress.current_file_bytes >= 2 {
                cancelled.store(true, Ordering::Relaxed);
            }
        };
        let mut control = DirectoryExportControl::new(Some(&cancelled), Some(&mut callback));

        let selected = source(&mut fs, "cancelled");
        let result = export_directory(
            &mut fs,
            selected,
            temp.path(),
            &DirectoryExportOptions {
                chunk_size: 2,
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut control,
        );
        assert!(matches!(
            result,
            Err(DirectoryExportError::Cancelled { .. })
        ));
        assert!(!temp.path().join("cancelled").exists());
        assert!(host_fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("exhume-partial")
        }));
    }

    #[test]
    fn no_replace_publish_does_not_replace_directory_created_during_export() {
        let temp = tempdir().unwrap();
        let final_path = temp.path().join("race");
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        let mut callback = |progress: &DirectoryExportProgress| {
            if progress.stage == DirectoryExportStage::Finalizing && !final_path.exists() {
                host_fs::create_dir(&final_path).unwrap();
            }
        };
        let mut control = DirectoryExportControl::new(None, Some(&mut callback));

        let selected = source(&mut fs, "race");
        let result = export_directory(
            &mut fs,
            selected,
            temp.path(),
            &DirectoryExportOptions {
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut control,
        );
        assert!(matches!(
            result,
            Err(DirectoryExportError::AlreadyExists(path)) if path.ends_with("race")
        ));
        assert!(final_path.is_dir());
        assert_eq!(host_fs::read_dir(&final_path).unwrap().count(), 0);
        assert!(host_fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("exhume-partial")
        }));
    }

    #[test]
    fn folder_export_preserves_hardlink_occurrences_and_skips_outside_symlink() {
        let temp = tempdir().unwrap();
        let evidence = temp.path().join("evidence");
        let exports = temp.path().join("exports");
        host_fs::create_dir(&evidence).unwrap();
        host_fs::create_dir(&exports).unwrap();
        host_fs::create_dir(evidence.join("empty")).unwrap();
        host_fs::write(evidence.join("original.txt"), b"evidence").unwrap();
        host_fs::hard_link(evidence.join("original.txt"), evidence.join("linked.txt")).unwrap();
        let outside = temp.path().join("outside.txt");
        host_fs::write(&outside, b"outside secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, evidence.join("outside-link")).unwrap();

        let mut folder = FolderFS::new(evidence.clone());
        let root_id = folder.get_root_file_id();
        let root = folder.get_file(root_id).unwrap();
        let report = export_directory(
            &mut folder,
            DirectoryExportSource::new(root, root_id, "/evidence", "folder-copy"),
            &exports,
            &DirectoryExportOptions {
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        )
        .unwrap();

        assert_eq!(
            host_fs::read(report.output_path.join("original.txt")).unwrap(),
            b"evidence"
        );
        assert_eq!(
            host_fs::read(report.output_path.join("linked.txt")).unwrap(),
            b"evidence"
        );
        assert!(report.output_path.join("empty").is_dir());
        #[cfg(unix)]
        assert!(!report.output_path.join("outside-link").exists());
        #[cfg(unix)]
        assert_eq!(report.status, DirectoryExportStatus::Partial);
    }

    #[test]
    fn folder_paths_are_contained_and_export_destination_cannot_be_inside_evidence() {
        let temp = tempdir().unwrap();
        let evidence = temp.path().join("evidence");
        host_fs::create_dir(&evidence).unwrap();
        host_fs::write(evidence.join("inside.txt"), b"inside").unwrap();
        host_fs::write(evidence.join("\\foo"), b"backslash").unwrap();
        host_fs::write(temp.path().join("outside.txt"), b"outside").unwrap();
        let mut folder = FolderFS::new(evidence.clone());
        assert!(folder.get_file_by_path("../outside.txt", 0).is_err());
        let inside = folder.get_file_by_path("/inside.txt", 0).unwrap();
        let backslash = folder.get_file_by_path("/\\foo", 0).unwrap();
        assert_eq!(folder.read_file_content(&backslash).unwrap(), b"backslash");
        assert!(
            folder
                .get_file_by_path("/inside.txt", inside.id().saturating_add(1))
                .is_err()
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path(), evidence.join("jump")).unwrap();
            assert!(folder.get_file_by_path("/jump/outside.txt", 0).is_err());
            assert_eq!(
                folder.get_file_by_path("/jump", 0).unwrap().entry_kind(),
                FileKind::Symlink
            );
        }

        let destination = evidence.join("exports");
        host_fs::create_dir(&destination).unwrap();
        let root_id = folder.get_root_file_id();
        let root = folder.get_file(root_id).unwrap();
        let result = export_directory(
            &mut folder,
            DirectoryExportSource::new(root, root_id, "/evidence", "forbidden"),
            &destination,
            &DirectoryExportOptions {
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        );
        assert!(matches!(
            result,
            Err(DirectoryExportError::InvalidConfiguration(message))
                if message.contains("overlaps protected FolderFS evidence root")
        ));

        // An ancestor destination parent is safe when the computed final tree
        // is a sibling, but not when the final tree equals/contains evidence.
        let root = folder.get_file(root_id).unwrap();
        let overlap = export_directory(
            &mut folder,
            DirectoryExportSource::new(root, root_id, "/evidence", "evidence"),
            temp.path(),
            &DirectoryExportOptions {
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        );
        assert!(matches!(
            overlap,
            Err(DirectoryExportError::InvalidConfiguration(message))
                if message.contains("overlaps protected FolderFS evidence root")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn folder_reads_reject_replaced_file_and_directory_occurrences() {
        let temp = tempdir().unwrap();
        let evidence = temp.path().join("evidence");
        let outside = temp.path().join("outside");
        host_fs::create_dir(&evidence).unwrap();
        host_fs::create_dir(&outside).unwrap();
        host_fs::write(evidence.join("file.bin"), b"inside").unwrap();
        host_fs::write(outside.join("file.bin"), b"outside").unwrap();
        host_fs::create_dir(evidence.join("dir")).unwrap();
        host_fs::write(evidence.join("dir/child.bin"), b"child").unwrap();

        let mut folder = FolderFS::new(evidence.clone());
        let file = folder.get_file_by_path("/file.bin", 0).unwrap();
        host_fs::rename(evidence.join("file.bin"), evidence.join("original.bin")).unwrap();
        std::os::unix::fs::symlink(outside.join("file.bin"), evidence.join("file.bin")).unwrap();
        assert!(folder.read_file_slice(&file, 0, 64).is_err());

        let directory = folder.get_file_by_path("/dir", 0).unwrap();
        let child = folder.list_dir(&directory).unwrap().remove(0);
        host_fs::rename(evidence.join("dir"), evidence.join("original-dir")).unwrap();
        std::os::unix::fs::symlink(&outside, evidence.join("dir")).unwrap();
        assert!(folder.list_dir(&directory).is_err());
        assert!(folder.resolve_child(&directory, &child).is_err());
    }

    #[test]
    fn safe_component_is_deterministic_portable_and_bounded() {
        assert_eq!(safe_component("normal.txt"), "normal.txt");
        assert_eq!(safe_component("a/b\\c"), "a%2Fb%5Cc");
        assert_eq!(
            safe_component("a:b*c?d\"e<f>g|h"),
            "a%3Ab%2Ac%3Fd%22e%3Cf%3Eg%7Ch"
        );
        assert_eq!(safe_component("CON"), "%5FCON");
        assert_eq!(safe_component("trailing. "), "trailing%2E%20");
        assert!(safe_component(&"é".repeat(300)).len() <= MAX_COMPONENT_BYTES);
        assert_eq!(
            safe_component(&"é".repeat(300)),
            safe_component(&"é".repeat(300))
        );
    }

    #[test]
    fn name_allocator_disambiguates_unicode_normalization_collisions() {
        let mut names = NameAllocator::new(false);
        let composed = names.allocate("é.txt", 1);
        let decomposed = names.allocate("e\u{301}.txt", 2);
        assert_ne!(composed, decomposed);
        assert!(decomposed.contains("~0000000000000002"));
        assert_eq!(collision_key(&composed), collision_key("e\u{301}.txt"));

        let street = names.allocate("Straße.txt", 3);
        let uppercase = names.allocate("STRASSE.txt", 4);
        assert_ne!(street, uppercase);
        assert!(uppercase.contains("~0000000000000004"));
    }

    #[cfg(unix)]
    #[test]
    fn output_lock_refuses_symbolic_links() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("target");
        host_fs::write(&target, b"unchanged").unwrap();
        let lock = temp.path().join("lock");
        std::os::unix::fs::symlink(&target, &lock).unwrap();

        let result = acquire_output_lock(&lock);
        assert!(result.is_err());
        assert_eq!(host_fs::read(target).unwrap(), b"unchanged");
    }

    #[test]
    fn entry_limit_is_hard_bounded() {
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        let selected = source(&mut fs, "bounded");
        let options = DirectoryExportOptions {
            max_entries: HARD_MAX_ENTRIES + 1,
            ..DirectoryExportOptions::default()
        };
        assert!(matches!(
            validate_options(&options, &selected),
            Err(DirectoryExportError::InvalidConfiguration(message))
                if message.contains("max_entries")
        ));
    }

    #[test]
    fn bounded_listing_fails_without_publishing_a_partial_tree() {
        let temp = tempdir().unwrap();
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        fs.add_record(2, FileKind::Regular, b"one");
        fs.add_record(3, FileKind::Regular, b"two");
        fs.add_entry(1, 2, "one");
        fs.add_entry(1, 3, "two");
        let selected = source(&mut fs, "limited");

        let result = export_directory(
            &mut fs,
            selected,
            temp.path(),
            &DirectoryExportOptions {
                max_entries: 2,
                sync_data: false,
                ..DirectoryExportOptions::default()
            },
            &mut DirectoryExportControl::none(),
        );
        assert!(matches!(
            result,
            Err(DirectoryExportError::EntryLimitExceeded { maximum: 2 })
        ));
        assert!(!temp.path().join("limited").exists());
        assert!(host_fs::read_dir(temp.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("exhume-partial")
        }));
    }

    #[test]
    fn source_paths_and_manifest_memory_are_bounded() {
        let mut fs = MockFilesystem::new();
        fs.add_record(1, FileKind::Directory, &[]);
        let mut selected = source(&mut fs, "bounded");
        selected.logical_path = "x".repeat(MAX_LOGICAL_PATH_BYTES + 1);
        assert!(matches!(
            validate_options(&DirectoryExportOptions::default(), &selected),
            Err(DirectoryExportError::InvalidConfiguration(message))
                if message.contains("logical path")
        ));

        let mut used = MAX_MANIFEST_TEXT_BYTES - 1;
        assert!(matches!(
            reserve_manifest_bytes(&mut used, 2),
            Err(DirectoryExportError::ManifestLimitExceeded { .. })
        ));
    }
}
