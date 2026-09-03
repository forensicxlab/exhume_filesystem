use crate::filesystem::{DirectoryCommon, FileCommon, FileIdentity, FileKind};
use crate::filesystem::{File, Filesystem, WalkEvent};
use exhume_ntfs::NTFS;
use exhume_ntfs::mft::{Attribute, AttributeType, DirectoryEntry, MFTRecord, StandardInformation};
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::io::{Read, Seek};
use std::sync::Arc;

/// Defensive limits for corrupted directory graphs. NTFS does not normally
/// permit directory hard links, but malformed indexes must not make a forensic
/// walk consume unbounded memory or recurse forever.
const NTFS_WALK_MAX_DEPTH: usize = 1_024;
const NTFS_WALK_DEFAULT_MAX_OCCURRENCES: usize = 2_000_000;
const NTFS_WALK_HARD_MAX_OCCURRENCES: usize = 10_000_000;
const NTFS_WALK_MAX_DIAGNOSTIC_EVENTS: usize = 100;
const NTFS_WALK_MAX_OCCURRENCES_ENV: &str = "EXHUME_NTFS_WALK_MAX_OCCURRENCES";

type NtfsDirectoryEntryIdentity = (u64, u16, Arc<str>);

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;

fn ntfs_reparse_kind(attributes: &[Attribute]) -> Option<FileKind> {
    attributes.iter().find_map(|attribute| match attribute {
        Attribute::Resident { header, value, .. }
            if header.attr_type == AttributeType::ReparsePoint =>
        {
            let tag = value
                .get(..4)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_le_bytes);
            Some(match tag {
                Some(IO_REPARSE_TAG_MOUNT_POINT | IO_REPARSE_TAG_SYMLINK) => FileKind::Symlink,
                _ => FileKind::Special,
            })
        }
        Attribute::NonResident { header, .. }
            if header.attr_type == AttributeType::ReparsePoint =>
        {
            Some(FileKind::Special)
        }
        _ => None,
    })
}

fn walked_entry_name(absolute_path: &str) -> Option<&str> {
    absolute_path
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
}

fn ntfs_walk_occurrence_limit() -> usize {
    std::env::var(NTFS_WALK_MAX_OCCURRENCES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|limit| *limit > 0)
        .map(|limit| limit.min(NTFS_WALK_HARD_MAX_OCCURRENCES))
        .unwrap_or(NTFS_WALK_DEFAULT_MAX_OCCURRENCES)
}

fn insert_directory_entry(
    entries: &mut HashSet<NtfsDirectoryEntryIdentity>,
    child_id: u64,
    child_sequence: u16,
    entry_name: Arc<str>,
) -> bool {
    entries.insert((child_id, child_sequence, entry_name))
}

impl FileCommon for MFTRecord {
    fn id(&self) -> u64 {
        self.id
    }

    fn size(&self) -> u64 {
        self.unnamed_data_size().unwrap_or(0)
    }
    fn is_dir(&self) -> bool {
        self.is_dir()
    }

    fn entry_kind(&self) -> FileKind {
        ntfs_reparse_kind(&self.attributes).unwrap_or_else(|| {
            if self.is_dir() {
                FileKind::Directory
            } else {
                FileKind::Regular
            }
        })
    }

    fn to_string(&self) -> String {
        ToString::to_string(self)
    }

    fn to_json(&self) -> Value {
        self.to_json()
    }
}

impl DirectoryCommon for DirectoryEntry {
    fn file_id(&self) -> u64 {
        self.file_id
    }
    fn name(&self) -> &str {
        &self.name
    }
    /// Return the string representation of a File
    fn to_string(&self) -> String {
        format!("{}/{} - {}", self.file_id, self.flags, self.name)
    }
    /// Return the json representation of a File
    fn to_json(&self) -> Value {
        self.to_json()
    }
}

#[inline]
fn filetime_to_unix_secs(ft: u64) -> u64 {
    // FILETIME is 100ns since 1601-01-01; Unix is seconds since 1970-01-01
    // 11_644_473_600 = seconds between 1601-01-01 and 1970-01-01
    (ft / 10_000_000).saturating_sub(11_644_473_600)
}

impl<T: Read + Seek> Filesystem for NTFS<T> {
    type FileType = MFTRecord;
    type DirectoryType = DirectoryEntry;

    fn filesystem_type(&self) -> String {
        "NT File System".to_string()
    }

    fn path_separator(&self) -> String {
        "\\".to_string()
    }

    fn record_count(&mut self) -> u64 {
        self.mft_records_count().unwrap_or(0)
    }

    fn block_size(&self) -> u64 {
        self.pbs.cluster_size() as u64
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.pbs.to_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.pbs.to_string())
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        self.get_file_id(file_id)
    }

    fn resolve_child(
        &mut self,
        parent: &Self::FileType,
        entry: &Self::DirectoryType,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        if entry.parent_ref != parent.id || entry.parent_seq != parent.header.sequence_number {
            return Err(format!(
                "NTFS directory entry {:?} has parent MFT #{} sequence {}, expected MFT #{} sequence {}",
                entry.name,
                entry.parent_ref,
                entry.parent_seq,
                parent.id,
                parent.header.sequence_number
            )
            .into());
        }

        let child = self.get_file_id(entry.file_id)?;
        if child.header.sequence_number != entry.file_sequence {
            return Err(format!(
                "stale NTFS directory entry {:?}: MFT #{} has sequence {}, index expects {}",
                entry.name, entry.file_id, child.header.sequence_number, entry.file_sequence
            )
            .into());
        }
        Ok(child)
    }

    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(0, file.id, u64::from(file.header.sequence_number))
    }

    fn read_file_content(&mut self, record: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file(record)
    }

    fn read_file_prefix(
        &mut self,
        record: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_prefix(record, length)
    }

    fn get_root_file_id(&self) -> u64 {
        5
    }

    fn read_file_slice(
        &mut self,
        record: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_slice(record, offset, length)
    }

    fn list_dir(
        &mut self,
        record: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_dir(record.id())
    }

    /// Walk every distinct NTFS directory-entry occurrence.
    ///
    /// A file reference number identifies a record, not a path. The generic
    /// walker de-duplicates globally by that number, which loses additional
    /// names for legitimate NTFS hard links. This override instead keys an
    /// occurrence by its complete parent path, record number, sequence, and
    /// entry name. An ancestor chain prevents corrupt directory cycles, while
    /// explicit depth and occurrence limits bound hostile directory graphs.
    fn walk_fs(&mut self, callback: &mut dyn FnMut(WalkEvent)) -> Result<(), Box<dyn Error>> {
        struct PendingOccurrence {
            record_id: u64,
            expected_sequence: Option<u16>,
            path: Arc<str>,
            ancestor_directories: Arc<Vec<u64>>,
            depth: usize,
        }

        let separator = self.path_separator();
        let root_id = self.get_root_file_id();
        let occurrence_limit = ntfs_walk_occurrence_limit();
        // Iterative depth-first traversal keeps only the current frontier in
        // memory. A breadth-first queue can retain millions of complete path
        // strings before the indexer has a chance to process them.
        let mut stack = vec![PendingOccurrence {
            record_id: root_id,
            expected_sequence: None,
            path: Arc::from(separator.as_str()),
            ancestor_directories: Arc::new(Vec::new()),
            depth: 0,
        }];
        let mut queued_occurrences = 1usize;
        let mut skipped_cycles = 0usize;
        let mut skipped_stale_entries = 0usize;
        let mut skipped_invalid_parent_entries = 0usize;

        while let Some(pending) = stack.pop() {
            let record = match self.get_file(pending.record_id) {
                Ok(record) => record,
                Err(error) => {
                    let message = format!(
                        "NTFS walk could not read {} (MFT #{}): {error}",
                        pending.path, pending.record_id
                    );
                    callback(WalkEvent::Status(message.clone()));
                    return Err(message.into());
                }
            };
            if let Some(expected_sequence) = pending.expected_sequence
                && record.header.sequence_number != expected_sequence
            {
                skipped_stale_entries = skipped_stale_entries.saturating_add(1);
                if skipped_stale_entries <= NTFS_WALK_MAX_DIAGNOSTIC_EVENTS {
                    callback(WalkEvent::Status(format!(
                        "Skipping stale NTFS directory entry {}: MFT #{} has sequence {}, index expects {}",
                        pending.path,
                        pending.record_id,
                        record.header.sequence_number,
                        expected_sequence
                    )));
                }
                continue;
            }
            let is_dir = record.is_dir();

            if is_dir && pending.ancestor_directories.contains(&pending.record_id) {
                skipped_cycles = skipped_cycles.saturating_add(1);
                continue;
            }

            callback(WalkEvent::File(self.record_to_file(
                &record,
                pending.record_id,
                pending.path.as_ref(),
            )));

            if !is_dir {
                continue;
            }

            let entries = match Filesystem::list_dir(self, &record) {
                Ok(entries) => entries,
                Err(error) => {
                    let message = format!(
                        "NTFS walk could not list {} (MFT #{}): {error}",
                        pending.path, pending.record_id
                    );
                    callback(WalkEvent::Status(message.clone()));
                    return Err(message.into());
                }
            };
            if entries.is_empty() {
                continue;
            }
            if pending.depth >= NTFS_WALK_MAX_DEPTH {
                let message = format!(
                    "NTFS walk aborted at depth limit {NTFS_WALK_MAX_DEPTH} while expanding {} (MFT #{})",
                    pending.path, pending.record_id
                );
                callback(WalkEvent::Status(message.clone()));
                return Err(message.into());
            }

            let mut child_ancestors = pending.ancestor_directories.as_ref().clone();
            child_ancestors.push(pending.record_id);
            let child_ancestors = Arc::new(child_ancestors);
            // `pending.path` scopes this set to one concrete parent occurrence,
            // so the identity is equivalent to (parent path, child reference,
            // entry name) without retaining every full path for the whole walk.
            let mut directory_entries = HashSet::<NtfsDirectoryEntryIdentity>::new();
            let mut children = Vec::new();

            for entry in entries {
                if entry.parent_ref != pending.record_id
                    || entry.parent_seq != record.header.sequence_number
                {
                    skipped_invalid_parent_entries =
                        skipped_invalid_parent_entries.saturating_add(1);
                    if skipped_invalid_parent_entries <= NTFS_WALK_MAX_DIAGNOSTIC_EVENTS {
                        callback(WalkEvent::Status(format!(
                            "Skipping NTFS index entry {:?} under {}: parent reference is MFT #{} sequence {}, expected MFT #{} sequence {}",
                            entry.name,
                            pending.path,
                            entry.parent_ref,
                            entry.parent_seq,
                            pending.record_id,
                            record.header.sequence_number
                        )));
                    }
                    continue;
                }

                let child_id = entry.file_id();
                let entry_name = Arc::<str>::from(entry.name());
                if !insert_directory_entry(
                    &mut directory_entries,
                    child_id,
                    entry.file_sequence,
                    Arc::clone(&entry_name),
                ) {
                    continue;
                }
                if queued_occurrences >= occurrence_limit {
                    let message = format!(
                        "NTFS walk aborted after {occurrence_limit} directory-entry occurrences; set {NTFS_WALK_MAX_OCCURRENCES_ENV} to raise the limit up to {NTFS_WALK_HARD_MAX_OCCURRENCES}"
                    );
                    callback(WalkEvent::Status(message.clone()));
                    return Err(message.into());
                }

                let child_path = if pending.path.as_ref() == separator {
                    format!("{separator}{entry_name}")
                } else {
                    format!("{}{separator}{entry_name}", pending.path)
                };
                children.push(PendingOccurrence {
                    record_id: child_id,
                    expected_sequence: Some(entry.file_sequence),
                    path: Arc::from(child_path),
                    ancestor_directories: Arc::clone(&child_ancestors),
                    depth: pending.depth + 1,
                });
                queued_occurrences += 1;
            }
            // Preserve the directory listing's order despite the LIFO stack.
            stack.extend(children.into_iter().rev());
        }

        if skipped_cycles > 0 {
            callback(WalkEvent::Status(format!(
                "NTFS walk skipped {skipped_cycles} cyclic directory reference(s)"
            )));
        }
        if skipped_stale_entries > NTFS_WALK_MAX_DIAGNOSTIC_EVENTS {
            callback(WalkEvent::Status(format!(
                "NTFS walk skipped {skipped_stale_entries} stale directory entries; individual warnings were limited to {NTFS_WALK_MAX_DIAGNOSTIC_EVENTS}"
            )));
        }
        if skipped_invalid_parent_entries > NTFS_WALK_MAX_DIAGNOSTIC_EVENTS {
            callback(WalkEvent::Status(format!(
                "NTFS walk skipped {skipped_invalid_parent_entries} entries with invalid parent references; individual warnings were limited to {NTFS_WALK_MAX_DIAGNOSTIC_EVENTS}"
            )));
        }

        Ok(())
    }

    // Record to File object implementation for NTFS
    fn record_to_file(&self, record: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        let name = walked_entry_name(absolute_path)
            .map(str::to_owned)
            .or_else(|| record.primary_name())
            .unwrap_or_else(|| format!("(MFT #{} – unnamed)", file_id));

        // Let's prefer $STANDARD_INFORMATION, fall back to first $FILE_NAME.
        let (c_ft, mft_ft, a_ft) = record
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Resident { header, value, .. }
                    if header.attr_type == AttributeType::StandardInformation =>
                {
                    StandardInformation::from_bytes(value)
                        .map(|si| (si.created, si.mft_modified, si.accessed))
                }
                _ => None,
            })
            .or_else(|| {
                let walked_name = walked_entry_name(absolute_path);
                record
                    .file_names()
                    .into_iter()
                    .find(|file_name| walked_name == Some(file_name.name.as_str()))
                    .or_else(|| record.preferred_file_name())
                    .map(|file_name| {
                        (
                            file_name.created,
                            file_name.mft_modified,
                            file_name.accessed,
                        )
                    })
            })
            .unwrap_or((0, 0, 0)); // if totally missing, leave zeros and map to None below

        let created = (c_ft != 0).then(|| filetime_to_unix_secs(c_ft));
        let modified = (mft_ft != 0).then(|| filetime_to_unix_secs(mft_ft));
        let accessed = (a_ft != 0).then(|| filetime_to_unix_secs(a_ft));

        let mft_ts = if mft_ft == 0 {
            "-".to_string()
        } else {
            exhume_ntfs::mft::filetime_to_local_datetime(mft_ft)
        };

        let ftype = match record.entry_kind() {
            FileKind::Directory => "Directory",
            FileKind::Regular => "File",
            FileKind::Symlink => "Symlink",
            FileKind::Special => "Special",
        }
        .to_string();

        let mut display = format!(
            "{id:<6} - {ftype:<10} - {size:>10} - {mft_ts} - {abs_path}",
            id = file_id,
            ftype = ftype,
            size = record.size(),
            mft_ts = mft_ts,
            abs_path = absolute_path
        );

        for fnm in record.file_names() {
            display.push_str(&format!("\n  - {}", fnm.name));
        }
        for ads in record.alternate_data_streams() {
            display.push_str(&format!("\n  - ads:{}", ads.name));
        }

        let metadata = record.to_json();

        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_owned(),
            name,
            created,
            modified,
            accessed,
            permissions: None,
            owner: None,
            group: None,
            ftype,
            size: record.size(),
            display: Some(display),
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{insert_directory_entry, ntfs_reparse_kind, walked_entry_name};
    use crate::filesystem::FileKind;
    use exhume_ntfs::mft::{Attribute, AttributeHeaderCommon, AttributeType, ResidentHeader};
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn selected_ntfs_directory_entry_controls_the_file_name() {
        assert_eq!(
            walked_entry_name(r"\Users\ECTEG\Documents"),
            Some("Documents")
        );
        assert_eq!(walked_entry_name(r"\DOCUME~1"), Some("DOCUME~1"));
        assert_eq!(walked_entry_name(r"\"), None);
    }

    #[test]
    fn directory_entry_identity_keeps_hard_links_and_distinguishes_sequences() {
        let mut first_parent = HashSet::new();

        assert!(insert_directory_entry(
            &mut first_parent,
            42,
            7,
            Arc::from("report.docx")
        ));
        assert!(!insert_directory_entry(
            &mut first_parent,
            42,
            7,
            Arc::from("report.docx")
        ));
        assert!(insert_directory_entry(
            &mut first_parent,
            42,
            8,
            Arc::from("report.docx")
        ));
        assert!(insert_directory_entry(
            &mut first_parent,
            42,
            7,
            Arc::from("report-link.docx")
        ));

        // A fresh set represents a distinct complete parent path, so the same
        // hard-link identity remains discoverable under that other path.
        let mut second_parent = HashSet::new();
        assert!(insert_directory_entry(
            &mut second_parent,
            42,
            7,
            Arc::from("report.docx")
        ));

        assert_eq!(first_parent.len(), 3);
        assert_eq!(second_parent.len(), 1);
    }

    fn resident_reparse(tag: u32) -> Attribute {
        Attribute::Resident {
            header: AttributeHeaderCommon {
                attr_type: AttributeType::ReparsePoint,
                length: 0,
                non_resident: false,
                name_length: 0,
                name_offset: 0,
                flags: 0,
                id: 0,
                name: None,
            },
            resident: ResidentHeader {
                value_length: 4,
                value_offset: 0,
                resident_flags: 0,
            },
            value: tag.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn reparse_points_are_never_exported_as_regular_files() {
        assert_eq!(
            ntfs_reparse_kind(&[resident_reparse(0xA000_000C)]),
            Some(FileKind::Symlink)
        );
        assert_eq!(
            ntfs_reparse_kind(&[resident_reparse(0xA000_0003)]),
            Some(FileKind::Symlink)
        );
        assert_eq!(
            ntfs_reparse_kind(&[resident_reparse(0x8000_001B)]),
            Some(FileKind::Special)
        );
    }
}
