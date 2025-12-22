use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::error::Error;
use std::fs::File as StdFile;
use std::io::{self, Read, Seek, SeekFrom, Write};

const CACHE_SIZE: usize = 64 * 1024; // 64 KiB cache;

/// A trait for common file record functionality.
pub trait FileCommon {
    /// Return the unique file identifier
    fn id(&self) -> u64;
    /// Returns the size of the record.
    fn size(&self) -> u64;
    /// Returns true if the record represents a directory.
    fn is_dir(&self) -> bool;
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
    pub metadata: Value,             // Filesystem-specific extra metadata
}

/// The Filesystem trait
pub trait Filesystem {
    type FileType: FileCommon;
    type DirectoryType: DirectoryCommon;

    fn filesystem_type(&self) -> String;
    fn path_separator(&self) -> String;
    fn record_count(&mut self) -> u64;
    fn block_size(&self) -> u64;
    fn get_metadata(&self) -> Result<Value, Box<dyn Error>>;
    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>>;
    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>>;
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
    fn record_to_file(&self, file: &Self::FileType, file_id: u64, absolute_path: &str) -> File;
    fn get_root_file_id(&self) -> u64;
    fn enumerate(&mut self) -> Result<(), Box<dyn Error>>;
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
                        if let Err(e) = f.write_all(&data) {
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
                println!("{}", String::from_utf8_lossy(&data));
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
        let data = self.fs.read_file_slice(&self.file, at, want).unwrap();
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
