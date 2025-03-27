use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;

#[derive(Serialize, Deserialize)]
pub struct FsInfo {
    pub filesystem_type: String,
    pub block_size: u64,
    pub metadata: Value,
}

/// A trait for common inode functionality.
pub trait InodeCommon {
    /// Returns the size of the file.
    fn size(&self) -> u64;
    /// Returns true if the inode represents a directory.
    fn is_dir(&self) -> bool;
    /// Returns true if the inode represents a regular file.
    fn is_regular_file(&self) -> bool;
    /// Returns true if the inode represents a symlink.
    fn is_symlink(&self) -> bool;
    /// Returns the user ID of the owner.
    fn uid(&self) -> u32;
    /// Returns the group ID of the owner.
    fn gid(&self) -> u32;
}

/// A trait for common directory entry functionality.
pub trait DirEntryCommon {
    /// Returns the inode number associated with this directory entry.
    fn inode(&self) -> u32;
    /// Returns the name of the directory entry.
    fn name(&self) -> &str;
}

/// A local representation of a Linux File metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxFile {
    pub evidence_id: Option<i64>,
    pub absolute_path: String,
    pub filename: String,
    pub parent_directory: String,
    pub inode_number: u32,
    pub file_type: String, // e.g., "dir", "file", "symlink", "other"
    pub size_bytes: u64,
    pub owner_uid: u32,
    pub group_gid: u32,
    pub permissions_mode: u32,
    pub hard_link_count: u16,
    pub access_time: String,
    pub modification_time: String,
    pub change_time: String,
    pub creation_time: String,
    pub extended_attributes: Value,
    pub symlink_target: Option<String>,
    pub mount_point: String,
    pub filesystem_type: String,
}

impl LinuxFile {
    /// Sets time-related fields from Unix epoch seconds.
    pub fn set_times(&mut self, atime: i64, mtime: i64, ctime: i64, crtime: i64) {
        self.access_time = Utc
            .timestamp_opt(atime, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.modification_time = Utc
            .timestamp_opt(mtime, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.change_time = Utc
            .timestamp_opt(ctime, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        self.creation_time = Utc
            .timestamp_opt(crtime, 0)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
    }
}

/// The Filesystem trait now requires that its associated types implement the common traits.
pub trait Filesystem {
    type InodeType: InodeCommon;
    type DirEntryType: DirEntryCommon;

    fn filesystem_type(&self) -> String;
    fn block_size(&self) -> u64;
    fn read_superblock(&self) -> Result<Value, Box<dyn Error>>;
    fn read_inode(&mut self, inode_num: u64) -> Result<Self::InodeType, Box<dyn Error>>;
    fn read_file_content(&mut self, inode: &Self::InodeType) -> Result<Vec<u8>, Box<dyn Error>>;
    fn list_dir(
        &mut self,
        inode: &Self::InodeType,
    ) -> Result<Vec<Self::DirEntryType>, Box<dyn Error>>;
    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn inode_to_linuxfile(
        &self,
        inode: &Self::InodeType,
        inode_num: u64,
        absolute_path: &str,
    ) -> LinuxFile;
}
