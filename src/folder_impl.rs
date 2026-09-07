use crate::filesystem::{
    DirectoryCommon, DirectoryEntryLimitError, File, FileCommon, FileIdentity, FileKind, Filesystem,
};
use serde_json::{Value, json};
use std::error::Error;
use std::fs::{self, File as StdFile, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostFileIdentity {
    device: u64,
    file_id: u64,
}

#[cfg(unix)]
fn inspect_path(path: &Path) -> Result<(Metadata, HostFileIdentity), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    let identity = HostFileIdentity {
        device: metadata.dev(),
        file_id: metadata.ino(),
    };
    Ok((metadata, identity))
}

#[cfg(windows)]
fn inspect_path(path: &Path) -> Result<(Metadata, HostFileIdentity), Box<dyn Error>> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    // Query the directory entry itself with no data access. Opening reparse
    // points rather than their targets keeps FolderFS inside the evidence root.
    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let opened = options.open(path)?;
    inspect_open_file(&opened)
}

#[cfg(unix)]
fn inspect_open_file(file: &StdFile) -> Result<(Metadata, HostFileIdentity), Box<dyn Error>> {
    let metadata = file.metadata()?;
    let identity = HostFileIdentity {
        device: metadata.dev(),
        file_id: metadata.ino(),
    };
    Ok((metadata, identity))
}

#[cfg(windows)]
fn inspect_open_file(file: &StdFile) -> Result<(Metadata, HostFileIdentity), Box<dyn Error>> {
    let metadata = file.metadata()?;
    let information = winapi_util::file::information(file)?;
    let identity = HostFileIdentity {
        device: information.volume_serial_number(),
        file_id: information.file_index(),
    };
    Ok((metadata, identity))
}

#[cfg(unix)]
fn open_regular_no_follow(path: &Path) -> Result<StdFile, Box<dyn Error>> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

#[cfg(windows)]
fn open_regular_no_follow(path: &Path) -> Result<StdFile, Box<dyn Error>> {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(unix)]
fn host_ownership_and_permissions(metadata: &Metadata) -> (u32, u32, u32) {
    (metadata.mode(), metadata.uid(), metadata.gid())
}

#[cfg(windows)]
fn host_ownership_and_permissions(_metadata: &Metadata) -> (u32, u32, u32) {
    // Windows access is governed by ACLs, which cannot be represented by the
    // POSIX mode/UID/GID fields exposed by the current normalized File model.
    (0, 0, 0)
}

#[cfg(unix)]
fn normalized_permissions(file: &FolderFile) -> Option<String> {
    Some(format!("{:o}", file.permissions))
}

#[cfg(windows)]
fn normalized_permissions(_file: &FolderFile) -> Option<String> {
    None
}

#[cfg(unix)]
fn normalized_owner(file: &FolderFile) -> Option<String> {
    Some(file.uid.to_string())
}

#[cfg(windows)]
fn normalized_owner(_file: &FolderFile) -> Option<String> {
    None
}

#[cfg(unix)]
fn normalized_group(file: &FolderFile) -> Option<String> {
    Some(file.gid.to_string())
}

#[cfg(windows)]
fn normalized_group(_file: &FolderFile) -> Option<String> {
    None
}

#[derive(Debug, Clone)]
pub struct FolderFile {
    pub id: u64,
    pub device: u64,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub kind: FileKind,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
}

impl FileCommon for FolderFile {
    fn id(&self) -> u64 {
        self.id
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn entry_kind(&self) -> FileKind {
        self.kind
    }
    fn to_string(&self) -> String {
        format!(
            "FolderFile {{ id: {}, path: {:?}, size: {}, is_dir: {} }}",
            self.id, self.path, self.size, self.is_dir
        )
    }
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "device": self.device,
            "path": self.path,
            "size": self.size,
            "is_dir": self.is_dir,
            "kind": self.kind,
            "created": self.created,
            "modified": self.modified,
            "accessed": self.accessed,
            "permissions": self.permissions,
            "uid": self.uid,
            "gid": self.gid
        })
    }
}

#[derive(Debug, Clone)]
pub struct FolderDirectory {
    pub file_id: u64,
    pub device: u64,
    pub name: String,
    pub path: PathBuf,
}

impl DirectoryCommon for FolderDirectory {
    fn file_id(&self) -> u64 {
        self.file_id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string(&self) -> String {
        format!(
            "FolderDirectory {{ file_id: {}, name: {} }}",
            self.file_id, self.name
        )
    }
    fn to_json(&self) -> Value {
        json!({
            "file_id": self.file_id,
            "device": self.device,
            "name": self.name
        })
    }
}

use std::collections::HashMap;

pub struct FolderFS {
    pub root_path: PathBuf,
    pub path_cache: HashMap<u64, PathBuf>,
}

impl FolderFS {
    pub fn new(root_path: PathBuf) -> Self {
        let mut fs = Self {
            root_path: root_path.clone(),
            path_cache: HashMap::new(),
        };
        // Prime the cache with the root
        if let Ok((_, identity)) = inspect_path(&root_path) {
            fs.path_cache.insert(identity.file_id, root_path);
        }
        fs
    }

    fn canonical_root(&self) -> Result<PathBuf, Box<dyn Error>> {
        let root = fs::canonicalize(&self.root_path).map_err(|error| {
            format!(
                "could not resolve FolderFS root {}: {error}",
                self.root_path.display()
            )
        })?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(format!("FolderFS root is not a directory: {}", root.display()).into());
        }
        Ok(root)
    }

    fn ensure_parent_contained(&self, path: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let root = self.canonical_root()?;
        if path == self.root_path || path == root {
            return Ok(root);
        }
        let parent = path
            .parent()
            .ok_or_else(|| format!("FolderFS path has no parent: {}", path.display()))?;
        let canonical_parent = fs::canonicalize(parent).map_err(|error| {
            format!(
                "could not resolve parent of FolderFS path {}: {error}",
                path.display()
            )
        })?;
        if !canonical_parent.starts_with(&root) {
            return Err(format!(
                "FolderFS path resolves outside its root: {}",
                path.display()
            )
            .into());
        }
        Ok(root)
    }

    fn kind_from_metadata(metadata: &Metadata) -> FileKind {
        if metadata.file_type().is_symlink() {
            FileKind::Symlink
        } else if metadata.is_dir() {
            FileKind::Directory
        } else if metadata.is_file() {
            FileKind::Regular
        } else {
            FileKind::Special
        }
    }

    fn get_file_from_path(
        &self,
        path: &Path,
        expected_id: u64,
    ) -> Result<FolderFile, Box<dyn Error>> {
        self.ensure_parent_contained(path)?;
        let (metadata, identity) = inspect_path(path)?;
        if expected_id != 0 && expected_id != identity.file_id {
            return Err(format!(
                "FolderFS path {} has file ID {}, expected {}",
                path.display(),
                identity.file_id,
                expected_id
            )
            .into());
        }

        let created = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let accessed = metadata
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let (permissions, uid, gid) = host_ownership_and_permissions(&metadata);

        Ok(FolderFile {
            id: identity.file_id,
            device: identity.device,
            path: path.to_path_buf(),
            size: metadata.len(),
            is_dir: metadata.is_dir(),
            kind: Self::kind_from_metadata(&metadata),
            created,
            modified,
            accessed,
            permissions,
            uid,
            gid,
        })
    }

    fn verify_record(&self, file: &FolderFile) -> Result<Metadata, Box<dyn Error>> {
        let root = self.ensure_parent_contained(&file.path)?;
        let (metadata, identity) = inspect_path(&file.path)?;
        let kind = Self::kind_from_metadata(&metadata);
        if identity.device != file.device || identity.file_id != file.id || kind != file.kind {
            return Err(format!(
                "FolderFS occurrence changed at {} (expected device/file ID/kind {}/{}/{:?}, found {}/{}/{:?})",
                file.path.display(),
                file.device,
                file.id,
                file.kind,
                identity.device,
                identity.file_id,
                kind
            )
            .into());
        }
        if kind == FileKind::Directory {
            let canonical = fs::canonicalize(&file.path)?;
            if !canonical.starts_with(root) {
                return Err(format!(
                    "FolderFS directory resolves outside its root: {}",
                    file.path.display()
                )
                .into());
            }
        }
        Ok(metadata)
    }

    fn open_verified_regular(&self, file: &FolderFile) -> Result<StdFile, Box<dyn Error>> {
        if file.kind != FileKind::Regular {
            return Err(format!(
                "FolderFS record is not a regular file: {}",
                file.path.display()
            )
            .into());
        }
        self.ensure_parent_contained(&file.path)?;
        let opened = open_regular_no_follow(&file.path)?;
        let (metadata, identity) = inspect_open_file(&opened)?;
        if !metadata.is_file() || identity.device != file.device || identity.file_id != file.id {
            return Err(format!(
                "FolderFS regular-file occurrence changed at {}",
                file.path.display()
            )
            .into());
        }
        Ok(opened)
    }

    fn list_directory_entries(
        &mut self,
        file: &FolderFile,
        maximum: Option<usize>,
    ) -> Result<Vec<FolderDirectory>, Box<dyn Error>> {
        if file.kind != FileKind::Directory {
            return Err(format!(
                "FolderFS record is not a directory: {}",
                file.path.display()
            )
            .into());
        }
        self.verify_record(file)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&file.path)? {
            if let Some(maximum) = maximum
                && entries.len() >= maximum
            {
                return Err(Box::new(DirectoryEntryLimitError { maximum }));
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            let (_, identity) = inspect_path(&path)?;
            self.path_cache.insert(identity.file_id, path.clone());
            entries.push(FolderDirectory {
                file_id: identity.file_id,
                device: identity.device,
                name,
                path,
            });
        }
        Ok(entries)
    }
}

impl Filesystem for FolderFS {
    type FileType = FolderFile;
    type DirectoryType = FolderDirectory;

    fn filesystem_type(&self) -> String {
        "Folder".to_string()
    }

    fn path_separator(&self) -> String {
        std::path::MAIN_SEPARATOR.to_string()
    }

    fn record_count(&mut self) -> u64 {
        0 // Not easily countable without full traversal
    }

    fn block_size(&self) -> u64 {
        4096 // Default assumption
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(json!({
            "root_path": self.root_path
        }))
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(format!("Folder FS Root: {:?}", self.root_path))
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        let path = self.path_cache.get(&file_id).ok_or_else(|| {
            format!("File ID {} not found in path cache. FolderFS requires traversal to populate cache.", file_id)
        })?;

        // We need to clone path to use it, or just use it.
        // get_file_from_path takes &Path.
        self.get_file_from_path(path, file_id)
    }

    fn resolve_child(
        &mut self,
        parent: &Self::FileType,
        entry: &Self::DirectoryType,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        if parent.kind != FileKind::Directory {
            return Err("FolderFS child parent is not a directory".into());
        }
        self.verify_record(parent)?;
        if entry.path.parent() != Some(parent.path.as_path()) {
            return Err(format!(
                "FolderFS child path {} does not belong to parent {}",
                entry.path.display(),
                parent.path.display()
            )
            .into());
        }
        let child = self.get_file_from_path(&entry.path, entry.file_id)?;
        if child.device != entry.device {
            return Err(format!(
                "FolderFS child {} changed device from {} to {}",
                entry.path.display(),
                entry.device,
                child.device
            )
            .into());
        }
        Ok(child)
    }

    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(file.device, file.id, 0)
    }

    fn protected_host_root(&self) -> Option<&Path> {
        Some(&self.root_path)
    }

    fn get_file_by_path(
        &mut self,
        path: &str,
        file_id: u64,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        let canonical_root = self.canonical_root()?;

        let relative = Path::new(path.trim_start_matches(std::path::MAIN_SEPARATOR));
        for component in relative.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir => {
                    return Err(format!(
                        "FolderFS path escapes through a parent component: {path:?}"
                    )
                    .into());
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(
                        format!("FolderFS path is not relative to its root: {path:?}").into(),
                    );
                }
            }
        }

        let candidate = canonical_root.join(relative);
        let canonical_parent = if candidate == canonical_root {
            canonical_root.clone()
        } else {
            fs::canonicalize(candidate.parent().ok_or("FolderFS path has no parent")?).map_err(
                |error| {
                    format!(
                        "could not resolve parent of FolderFS path {}: {error}",
                        candidate.display()
                    )
                },
            )?
        };
        if !canonical_parent.starts_with(&canonical_root) {
            return Err(format!(
                "FolderFS path resolves outside its root: {}",
                candidate.display()
            )
            .into());
        }

        // Inspect, but deliberately do not canonicalize, the final component.
        // A final symlink is a valid evidence entry and must not be followed.
        let (_, identity) = inspect_path(&candidate).map_err(|error| {
            format!(
                "could not inspect FolderFS path {}: {error}",
                candidate.display()
            )
        })?;
        if file_id != 0 && file_id != identity.file_id {
            return Err(format!(
                "FolderFS path {} has file ID {}, expected {}",
                candidate.display(),
                identity.file_id,
                file_id
            )
            .into());
        }
        self.path_cache.insert(identity.file_id, candidate.clone());
        self.get_file_from_path(&candidate, identity.file_id)
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = self.open_verified_regular(file)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = self.open_verified_regular(file)?;
        let mut buffer = vec![0; length];
        let n = f.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = self.open_verified_regular(file)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buffer = vec![0; length];
        let n = f.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn list_dir(
        &mut self,
        file: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_directory_entries(file, None)
    }

    fn list_dir_limited(
        &mut self,
        file: &Self::FileType,
        maximum: usize,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_directory_entries(file, Some(maximum))
    }

    fn get_root_file_id(&self) -> u64 {
        inspect_path(&self.root_path)
            .map(|(_, identity)| identity.file_id)
            .unwrap_or(0)
    }

    fn record_to_file(&self, file: &Self::FileType, _file_id: u64, absolute_path: &str) -> File {
        // `file` is `FolderFile` which already has metadata.
        // `absolute_path` is passed from the walker.

        File {
            id: None, // Database ID not yet assigned
            identifier: file.id,
            absolute_path: absolute_path.to_string(),
            name: file
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            ftype: match file.kind {
                FileKind::Directory => "Directory",
                FileKind::Regular => "File",
                FileKind::Symlink => "Symlink",
                FileKind::Special => "Special",
            }
            .to_string(),
            size: file.size,
            created: file.created,
            modified: file.modified,
            accessed: file.accessed,
            permissions: normalized_permissions(file),
            owner: normalized_owner(file),
            group: normalized_group(file),
            display: None,
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata: json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_filesystem_resolves_and_reads_a_child_with_stable_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let child_path = temporary.path().join("evidence.bin");
        fs::write(&child_path, b"forensic bytes").unwrap();

        let mut filesystem = FolderFS::new(temporary.path().to_path_buf());
        let root_id = filesystem.get_root_file_id();
        assert_ne!(root_id, 0);

        let root = filesystem.get_file(root_id).unwrap();
        let entries = filesystem.list_dir(&root).unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.name == "evidence.bin")
            .unwrap();
        let child = filesystem.resolve_child(&root, entry).unwrap();

        assert_eq!(child.id, entry.file_id);
        assert_eq!(child.device, entry.device);
        assert_eq!(
            filesystem.read_file_content(&child).unwrap(),
            b"forensic bytes"
        );

        let normalized = filesystem.record_to_file(&child, child.id, "/evidence.bin");
        assert_eq!(normalized.name, "evidence.bin");
        assert_eq!(normalized.size, 14);
        #[cfg(unix)]
        assert!(normalized.permissions.is_some());
        #[cfg(windows)]
        {
            assert!(normalized.permissions.is_none());
            assert!(normalized.owner.is_none());
            assert!(normalized.group.is_none());
        }
    }
}
