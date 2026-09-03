use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::error::Error;
use std::fmt;
use std::fs::File as StdFile;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

const CACHE_SIZE: usize = 64 * 1024; // 64 KiB cache;

/// Normalized kind of an on-disk filesystem entry.
///
/// Exporters must use this value rather than the presentation-oriented
/// [`File::ftype`] string, whose spelling predates this common abstraction and
/// varies between filesystem implementations.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Special,
}

/// Sanitized view actually used to expose filesystem bytes. This records an
/// applied transform, never credentials or merely supplied key material.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemSourceView {
    Native,
    BitlockerDecrypted,
}

impl FilesystemSourceView {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::BitlockerDecrypted => "bitlocker_decrypted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntryLimitError {
    pub maximum: usize,
}

impl fmt::Display for DirectoryEntryLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "directory contains more than {} exportable entries",
            self.maximum
        )
    }
}

impl Error for DirectoryEntryLimitError {}

/// Stable identity used for directory-cycle detection and hard-link
/// provenance. `namespace` distinguishes volumes/devices, while `generation`
/// protects filesystems such as NTFS from stale reused record numbers.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub namespace: u64,
    pub identifier: u64,
    pub generation: u64,
}

impl FileIdentity {
    pub const fn new(namespace: u64, identifier: u64, generation: u64) -> Self {
        Self {
            namespace,
            identifier,
            generation,
        }
    }
}

/// A trait for common file record functionality.
pub trait FileCommon {
    /// Return the unique file identifier
    fn id(&self) -> u64;
    /// Returns the size of the record.
    fn size(&self) -> u64;
    /// Returns true if the record represents a directory.
    fn is_dir(&self) -> bool;
    /// Return the normalized kind of the entry.
    ///
    /// The default preserves compatibility for third-party filesystem
    /// implementations. Implementors should override it when they can
    /// distinguish symbolic links or special entries.
    fn entry_kind(&self) -> FileKind {
        if self.is_dir() {
            FileKind::Directory
        } else {
            FileKind::Regular
        }
    }
    /// Return the string representation of a File
    fn to_string(&self) -> String;
    /// Return the json representation of a File
    fn to_json(&self) -> Value;
}

/// A trait for common directory entry functionality.
pub trait DirectoryCommon {
    /// Returns the file identifier associated with this directory entry.
    fn file_id(&self) -> u64;
    /// Returns the name of the directory.
    fn name(&self) -> &str;
    /// Return the string representation of a File
    fn to_string(&self) -> String;
    /// Return the json representation of a File
    fn to_json(&self) -> Value;
}

// A cross-filesystem Exhume File abstraction
#[derive(Serialize, Deserialize, Debug, Clone, FromRow)]
pub struct File {
    pub id: Option<i64>,       // Application-specific unique ID
    pub identifier: u64,       // FS-specific unique ID (inode, MFT record, etc.)
    pub absolute_path: String, // Full path from root
    pub name: String,          // File name
    pub ftype: String,         // File type (file, dir, symlink, etc.)
    pub size: u64,             // Size in bytes
    // We are normalizing all timestamps in UNIX Time for all filesystems
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    pub permissions: Option<String>, // Permissions in some normalized form
    pub owner: Option<String>,       // Owner user name or SID/UID
    pub group: Option<String>,       // Group name or GID (Unix)
    pub display: Option<String>,     // Custom filesystem-specific stdout formatting string
    pub sig_name: Option<String>, // Identified signature name (e.g. "Executable and Linkable Format")
    pub sig_mime: Option<String>, // Identified MIME type (comma separated)
    pub sig_exts: Option<String>, // Identified extensions (comma separated)
    pub metadata: Value,          // Filesystem-specific extra metadata
}

/// Dispatched events during `walk_fs`.
#[allow(clippy::large_enum_variant)]
pub enum WalkEvent {
    /// A regular file or directory was discovered.
    File(File),
    /// An intermediate status message for long-running operations.
    Status(String),
}

/// The Filesystem trait
pub trait Filesystem {
    type FileType: FileCommon;
    type DirectoryType: DirectoryCommon;

    fn filesystem_type(&self) -> String;
    /// Return the sanitized source view that was actually opened.
    fn source_view(&self) -> FilesystemSourceView {
        FilesystemSourceView::Native
    }
    fn path_separator(&self) -> String;
    fn record_count(&mut self) -> u64;
    fn block_size(&self) -> u64;
    fn get_metadata(&self) -> Result<Value, Box<dyn Error>>;
    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>>;
    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>>;
    /// Resolve a concrete directory-entry occurrence beneath `parent`.
    ///
    /// The hook carries context that a bare identifier cannot represent on
    /// multi-volume or host-folder filesystems. The default remains suitable
    /// for traditional inode-based filesystems.
    fn resolve_child(
        &mut self,
        _parent: &Self::FileType,
        entry: &Self::DirectoryType,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        self.get_file(entry.file_id())
    }

    /// Identifier to publish for a concrete child occurrence.
    fn entry_identifier(&self, _parent: &Self::FileType, entry: &Self::DirectoryType) -> u64 {
        entry.file_id()
    }

    /// Stable identity for cycle detection and hard-link provenance.
    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(0, file.id(), 0)
    }

    /// Canonical public identifier for an already-resolved record.
    fn file_identifier(&self, file: &Self::FileType) -> u64 {
        file.id()
    }

    /// Host root that must remain read-only while exporting Folder evidence.
    fn protected_host_root(&self) -> Option<&Path> {
        None
    }
    fn get_file_by_path(
        &mut self,
        path: &str,
        _file_id: u64,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        let separator = self.path_separator();
        let components: Vec<&str> = path
            .split(separator.as_str())
            .filter(|component| !component.is_empty())
            .collect();
        let root_id = self.get_root_file_id();
        let mut current = self.get_file(root_id)?;
        for component in &components {
            let entries = self.list_dir(&current)?;
            let entry = entries
                .into_iter()
                .find(|e| e.name() == *component)
                .ok_or_else(|| format!("path component not found: {:?}", component))?;
            current = self.resolve_child(&current, &entry)?;
        }
        Ok(current)
    }
    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>>;
    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>>;
    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>>;

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>>;
    /// Bounded directory listing used by exporters. Backends should override
    /// this to stop decoding/collecting once `maximum` is exceeded.
    fn list_dir_limited(
        &mut self,
        file: &Self::FileType,
        maximum: usize,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        let entries = self.list_dir(file)?;
        if entries.len() > maximum {
            Err(Box::new(DirectoryEntryLimitError { maximum }))
        } else {
            Ok(entries)
        }
    }
    fn record_to_file(&self, file: &Self::FileType, file_id: u64, absolute_path: &str) -> File;
    fn get_root_file_id(&self) -> u64;

    /// Walk the filesystem and call the callback for each file found.
    /// This default implementation uses Breadth-First Search via `get_file` and `list_dir`.
    fn walk_fs(&mut self, callback: &mut dyn FnMut(WalkEvent)) -> Result<(), Box<dyn Error>> {
        use std::collections::{HashSet, VecDeque};
        let mut seen: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, String)> = VecDeque::new();

        let root_id = self.get_root_file_id();
        queue.push_back((root_id, self.path_separator()));

        while let Some((record_id, path)) = queue.pop_front() {
            if !seen.insert(record_id) {
                continue;
            }

            let record = match self.get_file(record_id) {
                Ok(r) => r,
                Err(_) => continue,
            };

            let file_obj = self.record_to_file(&record, record_id, &path);
            let is_dir = record.is_dir();

            callback(WalkEvent::File(file_obj));

            if is_dir && let Ok(entries) = self.list_dir(&record) {
                for entry in entries {
                    let child_id = entry.file_id();
                    let child_path = if path == self.path_separator() {
                        format!("{}{}", self.path_separator(), entry.name())
                    } else {
                        format!("{}{}{}", path, self.path_separator(), entry.name())
                    };
                    queue.push_back((child_id, child_path));
                }
            }
        }

        Ok(())
    }

    /// Return all files in the filesystem
    fn enumerate_all_files(&mut self) -> Result<Vec<File>, Box<dyn Error>> {
        let mut files = Vec::new();
        self.walk_fs(&mut |event| {
            if let WalkEvent::File(f) = event {
                files.push(f);
            }
        })?;
        Ok(files)
    }

    fn dump_to_fs(&mut self, file: &Self::FileType) {
        info!(
            "Dumping file {} content into 'file_{}.bin'",
            file.id(),
            file.id()
        );

        match &self.read_file_content(file) {
            Ok(data) => {
                let filename = format!("file_{}.bin", file.id());
                match StdFile::create(&filename) {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(data) {
                            error!("Error writing file '{}': {}", filename, e);
                        } else {
                            info!(
                                "Successfully wrote {} bytes into '{}'",
                                data.len(),
                                filename
                            );
                        }
                    }
                    Err(e) => error!("Could not create dump file '{}': {}", filename, e),
                }
            }
            Err(e) => {
                error!("Cannot read content for inode {}: {}", file.id(), e);
            }
        }
    }

    fn dump_to_std(&mut self, file: &Self::FileType) {
        info!("Displaying record {} content", file.id());

        match &self.read_file_content(file) {
            Ok(data) => {
                println!("{}", String::from_utf8_lossy(data));
            }
            Err(e) => {
                error!("Cannot read content for inode {}: {}", file.id(), e);
            }
        }
    }
}

/// Single-thread Read+Seek adapter backed by Filesystem::read_file_slice().
pub struct FsFileReadSeek<'a, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    fs: &'a mut F,
    file: F::FileType,
    len: u64,
    pos: u64,

    // Simple read-ahead cache
    cache: Vec<u8>,
    cache_start: u64,
}

impl<'a, F> FsFileReadSeek<'a, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    /// Create an adapter from an already fetched filesystem file record.
    pub fn new(fs: &'a mut F, file: F::FileType) -> Self {
        let len = file.size();
        Self {
            fs,
            file,
            len,
            pos: 0,
            cache: Vec::new(),
            cache_start: 0,
        }
    }

    /// Fetch file by id (filesystem identifier) and create adapter.
    pub fn from_id(fs: &'a mut F, file_id: u64) -> Result<Self, Box<dyn Error>> {
        let file = fs.get_file(file_id)?;
        Ok(Self::new(fs, file))
    }

    #[inline]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn position(&self) -> u64 {
        self.pos
    }

    fn refill_cache(&mut self, at: u64) -> io::Result<()> {
        if at >= self.len {
            self.cache.clear();
            self.cache_start = at;
            return Ok(());
        }

        let want = (self.len - at).min(CACHE_SIZE as u64) as usize;
        let data = self
            .fs
            .read_file_slice(&self.file, at, want)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.cache_start = at;
        self.cache = data;
        Ok(())
    }
}

impl<'a, F> Read for FsFileReadSeek<'a, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= self.len {
            return Ok(0);
        }

        let cache_end = self.cache_start.saturating_add(self.cache.len() as u64);
        if self.cache.is_empty() || !(self.cache_start <= self.pos && self.pos < cache_end) {
            self.refill_cache(self.pos)?;
        }

        if self.cache.is_empty() {
            return Ok(0);
        }

        let cache_off = (self.pos - self.cache_start) as usize;
        let available = self.cache.len().saturating_sub(cache_off);
        if available == 0 {
            return Ok(0);
        }

        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.cache[cache_off..cache_off + to_copy]);

        self.pos += to_copy as u64;
        Ok(to_copy)
    }
}

impl<'a, F> Seek for FsFileReadSeek<'a, F>
where
    F: Filesystem,
    F::FileType: FileCommon,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos_i128: i128 = match pos {
            SeekFrom::Start(off) => off as i128,
            SeekFrom::Current(delta) => self.pos as i128 + delta as i128,
            SeekFrom::End(delta) => self.len as i128 + delta as i128,
        };

        if new_pos_i128 < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }

        let new_pos = new_pos_i128 as u64;
        if new_pos > self.len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek past end"));
        }

        self.pos = new_pos;
        Ok(self.pos)
    }
}
