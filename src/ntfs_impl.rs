use crate::filesystem::{DirectoryCommon, FileCommon, FileIdentity, FileKind};
use crate::filesystem::{File, Filesystem};
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

    fn walk_roots(
        &mut self,
        context: &mut crate::walk::WalkContext<'_>,
    ) -> crate::walk::WalkResult<Vec<crate::walk::WalkRoot>> {
        context.restrict_limits(NTFS_WALK_MAX_DEPTH, ntfs_walk_occurrence_limit() as u64);
        Ok(vec![crate::walk::WalkRoot {
            identifier: 5,
            path: "\\".to_owned(),
        }])
    }

    fn walk_root(
        &mut self,
        identifier: u64,
        context: &mut crate::walk::WalkContext<'_>,
    ) -> crate::walk::WalkResult<Option<Self::FileType>> {
        let raw = self
            .get_file_id_raw(identifier)
            .map_err(|error| context.source_error(error))?;
        if raw.header.flags & 1 == 0 || raw.header.base_file_record != 0 {
            return Err(context.source_error("NTFS root is not an allocated base record"));
        }
        self.hydrate_attribute_list(raw)
            .map(Some)
            .map_err(|error| context.source_error(error))
    }

    fn walk_child(
        &mut self,
        parent: &Self::FileType,
        entry: &Self::DirectoryType,
        context: &mut crate::walk::WalkContext<'_>,
    ) -> crate::walk::WalkResult<Option<Self::FileType>> {
        use crate::walk::*;
        let raw = match self.get_file_id_raw(entry.file_id) {
            Ok(record) => record,
            Err(error) => {
                let mut issue = WalkIssue::new(
                    context.path(),
                    WalkStage::RecordRead,
                    WalkIssueCode::RecordReadFailed,
                    WalkAction::SkipEntry,
                    error.to_string(),
                );
                issue.record_id = Some(entry.file_id);
                issue.expected_generation = Some(u64::from(entry.file_sequence));
                context.issue(issue)?;
                return Ok(None);
            }
        };
        let identity = FileIdentity::new(0, raw.id, u64::from(raw.header.sequence_number));
        let invalid =
            if entry.parent_ref != parent.id || entry.parent_seq != parent.header.sequence_number {
                Some((
                    WalkIssueCode::InvalidParentReference,
                    "directory key has an invalid parent reference".to_owned(),
                ))
            } else if entry.file_sequence != raw.header.sequence_number {
                Some((
                    WalkIssueCode::StaleReference,
                    format!(
                        "MFT #{} has sequence {}, directory expects {}",
                        raw.id, raw.header.sequence_number, entry.file_sequence
                    ),
                ))
            } else if raw.header.flags & 1 == 0 {
                Some((
                    WalkIssueCode::InactiveRecord,
                    format!("MFT #{} is not in use", raw.id),
                ))
            } else if raw.header.base_file_record != 0 {
                Some((
                    WalkIssueCode::ExtensionRecordReference,
                    format!(
                        "Directory entry targets extension MFT #{} instead of a base record",
                        raw.id
                    ),
                ))
            } else {
                None
            };
        if let Some((code, message)) = invalid {
            let mut issue = WalkIssue::new(
                context.path(),
                WalkStage::IdentityValidation,
                code,
                WalkAction::SkipEntry,
                message,
            );
            issue.record_id = Some(raw.id);
            issue.identity = Some(identity);
            issue.expected_generation = Some(u64::from(entry.file_sequence));
            context.issue(issue)?;
            return Ok(None);
        }
        let is_dir = raw.is_dir();
        match self.hydrate_attribute_list(raw) {
            Ok(record) => Ok(Some(record)),
            Err(error) => {
                let mut issue = WalkIssue::new(
                    context.path(),
                    WalkStage::AttributeList,
                    WalkIssueCode::AttributeListInvalid,
                    if is_dir {
                        WalkAction::SkipSubtree
                    } else {
                        WalkAction::SkipEntry
                    },
                    error.to_string(),
                );
                issue.record_id = Some(entry.file_id);
                issue.identity = Some(identity);
                issue.expected_generation = Some(u64::from(entry.file_sequence));
                context.issue(issue)?;
                Ok(None)
            }
        }
    }

    fn walk_directory(
        &mut self,
        record: &Self::FileType,
        context: &mut crate::walk::WalkContext<'_>,
    ) -> crate::walk::WalkResult<Vec<Self::DirectoryType>> {
        use crate::walk::*;
        use exhume_ntfs::DirectoryIssueKind;
        let mut delivery_error = None;
        let result = self.list_dir_with_diagnostics(record.id, &mut |diagnostic| {
            let code = match diagnostic.kind {
                DirectoryIssueKind::InvalidIndexRoot => WalkIssueCode::InvalidIndexRoot,
                DirectoryIssueKind::InvalidIndexBlock => WalkIssueCode::InvalidIndexBlock,
                DirectoryIssueKind::TruncatedIndexBlock => WalkIssueCode::TruncatedIndexBlock,
                DirectoryIssueKind::IndexBlockReadFailed => WalkIssueCode::IndexBlockReadFailed,
                DirectoryIssueKind::InvalidParentReference => WalkIssueCode::InvalidParentReference,
            };
            let mut issue = WalkIssue::new(
                context.path(),
                WalkStage::DirectoryIndex,
                code,
                if matches!(diagnostic.kind, DirectoryIssueKind::InvalidParentReference) {
                    WalkAction::SkipEntry
                } else {
                    WalkAction::SkipIndexBlock
                },
                diagnostic.message,
            );
            issue.record_id = diagnostic.child_record.or(Some(record.id));
            issue.identity = diagnostic
                .child_record
                .is_none()
                .then_some(FileIdentity::new(
                    0,
                    record.id,
                    u64::from(record.header.sequence_number),
                ));
            issue.index_block = diagnostic.index_block;
            if let Err(error) = context.issue(issue) {
                delivery_error = Some(error);
                return Err("walk diagnostic delivery failed".into());
            }
            Ok(())
        });
        if let Some(error) = delivery_error {
            return Err(error);
        }
        match result {
            Ok(mut entries) => {
                let mut seen = HashSet::new();
                entries.retain(|entry| {
                    insert_directory_entry(
                        &mut seen,
                        entry.file_id,
                        entry.file_sequence,
                        Arc::from(entry.name()),
                    )
                });
                Ok(entries)
            }
            Err(error) if context.is_root() => Err(context.source_error(error)),
            Err(error) => {
                context.read_failure(
                    WalkStage::DirectoryRead,
                    WalkIssueCode::DirectoryReadFailed,
                    WalkAction::SkipSubtree,
                    error,
                )?;
                Ok(Vec::new())
            }
        }
    }

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
