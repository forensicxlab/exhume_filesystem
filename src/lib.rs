use chrono::{TimeZone, Utc};
use exhume_extfs::ExtFS;
use exhume_extfs::direntry::DirEntry;
use exhume_extfs::inode::Inode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

/// A local copy of the LinuxFile metadata structure. (This is similar to the original LinuxFile,
/// but now it is owned by the ldfi crate rather than pulled from elsewhere.)
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
    /// Permissions stored as a decimal number (e.g., 420 for octal 0644)
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
    /// Helper function to set time-related fields from raw Unix epoch seconds.
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

/// A trait defining basic operations that any filesystem should support.
/// You can expand or modify this trait as needed for your forensic needs.
pub trait Filesystem {
    /// The type that represents an inode within this filesystem.
    type InodeType;

    /// The type that represents a directory entry within this filesystem.
    type DirEntryType;

    /// Perform any necessary setup/opening operations. Often, new() or from_reader()
    /// is sufficient, so this could be a no-op depending on your FS design.
    fn open_fs(&mut self) -> Result<(), Box<dyn Error>>;

    /// Return some identification string, e.g. "FAT", "NTFS", "ext4", etc.
    fn filesystem_type(&self) -> String;

    /// Return the block size (in bytes). Many forensics tasks need this detail.
    fn block_size(&self) -> u64;

    /// Return a JSON object (or any structured data) summarizing
    /// the filesystem’s superblock (or equivalent) metadata.
    fn read_superblock(&self) -> Result<Value, Box<dyn Error>>;

    /// Return the InodeType object for a given inode number.
    fn read_inode(&mut self, inode_num: u64) -> Result<Self::InodeType, Box<dyn Error>>;

    /// Read the content of a file/directory from an inode into a byte array.
    /// Typically, you only call this if the inode is a regular file or symlink,
    /// but it can also return raw bytes for directories or other objects.
    fn read_file_content(&mut self, inode: &Self::InodeType) -> Result<Vec<u8>, Box<dyn Error>>;

    /// List the directory entries of an inode if it is a directory.
    fn list_dir(
        &mut self,
        inode: &Self::InodeType,
    ) -> Result<Vec<Self::DirEntryType>, Box<dyn Error>>;

    /// Convenience method: look up a file by path (from the filesystem’s root),
    /// read its contents, and return as a Vec<u8>.
    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>>;

    /// Convert filesystem-specific inode data into a LinuxFile metadata object.
    /// Use this to fill standard fields (mode, uid, size, times, etc.) so the indexer
    /// can remain filesystem-agnostic.
    ///
    /// - inode_num: the numeric ID of the inode being converted
    /// - absolute_path: the path (from the filesystem root) for this file
    ///
    /// Return a fully populated LinuxFile (with times, user, group, file type, etc.)
    /// where possible. For fields not applicable or unknown, fill default/empty values.
    fn inode_to_linuxfile(
        &self,
        inode: &Self::InodeType,
        inode_num: u64,
        absolute_path: &str,
    ) -> LinuxFile;
}
// Define a trait that exposes the required methods.
pub trait FsDirEntry {
    fn inode(&self) -> u32;
    fn name(&self) -> &str;
}

// -------------- ExtFS Implements the Filesystem Trait -------------- //

// Implement the trait for your specific DirEntry.
impl FsDirEntry for exhume_extfs::direntry::DirEntry {
    fn inode(&self) -> u32 {
        self.inode
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl<T: Read + Seek> Filesystem for ExtFS<T> {
    type InodeType = Inode;
    type DirEntryType = DirEntry;

    fn open_fs(&mut self) -> Result<(), Box<dyn Error>> {
        // ExtFS::new() has already read the superblock, so likely nothing else to do.
        Ok(())
    }

    fn filesystem_type(&self) -> String {
        // Could refine if you detect ext2 vs ext3 vs ext4, etc.
        "ext".to_string()
    }

    fn block_size(&self) -> u64 {
        self.superblock.block_size()
    }

    fn read_superblock(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.superblock.to_json())
    }

    fn read_inode(&mut self, inode_num: u64) -> Result<Self::InodeType, Box<dyn Error>> {
        self.get_inode(inode_num)
    }

    fn read_file_content(&mut self, inode: &Self::InodeType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode(inode)
    }

    fn list_dir(
        &mut self,
        inode: &Self::InodeType,
    ) -> Result<Vec<Self::DirEntryType>, Box<dyn Error>> {
        self.list_dir(inode)
    }

    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_by_path(path)
    }

    fn inode_to_linuxfile(
        &self,
        inode: &Self::InodeType,
        inode_num: u64,
        absolute_path: &str,
    ) -> LinuxFile {
        let mut file_type = String::from("other");
        if inode.is_dir() {
            file_type = String::from("dir");
        } else if inode.is_regular_file() {
            file_type = String::from("file");
        } else if inode.is_symlink() {
            file_type = String::from("symlink");
        }
        let size_bytes = inode.size() as u64;
        let uid = inode.uid() as u32;
        let gid = inode.gid() as u32;
        let permissions = inode.i_mode;
        let links_count = inode.i_links_count;

        // Many ext4 inodes do not store explicit creation time. We’ll approximate or store 0 if unknown.
        // If your Inode struct stores more detail, extract them here.
        let atime = inode.i_atime as i64;
        let mtime = inode.i_mtime as i64;
        let ctime = 0i64;
        let crtime = inode.i_crtime as i64; // placeholder unless we have dedicated creation time

        // Build the LinuxFile.
        let mut lf = LinuxFile {
            evidence_id: None,
            absolute_path: absolute_path.to_string(),
            filename: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            parent_directory: {
                let p = Path::new(absolute_path).parent();
                match p {
                    Some(pp) if pp.to_string_lossy().is_empty() => "/".to_string(),
                    Some(pp) => {
                        let s = pp.to_string_lossy().to_string();
                        if s.is_empty() { "/".to_string() } else { s }
                    }
                    None => "/".to_string(),
                }
            },
            inode_number: inode_num as u32,
            file_type: file_type.clone(),
            size_bytes,
            owner_uid: uid,
            group_gid: gid,
            permissions_mode: permissions as u32 & 0o7777, // keep just the lower 12 bits
            hard_link_count: links_count,
            access_time: "".to_string(),
            modification_time: "".to_string(),
            change_time: "".to_string(),
            creation_time: "".to_string(),
            extended_attributes: serde_json::Value::Null,
            symlink_target: None, // If you wish, you could parse a short symlink content
            mount_point: "".to_string(),
            filesystem_type: self.filesystem_type(),
        };

        // Set the times as RFC3339 strings.
        lf.set_times(atime, mtime, ctime, crtime);

        lf
    }
}
