use crate::filesystem::{DirEntryCommon, InodeCommon};
use crate::filesystem::{Filesystem, LinuxFile};
use chrono::{TimeZone, Utc};
use exhume_extfs::ExtFS;
use exhume_extfs::direntry::DirEntry;
use exhume_extfs::inode::Inode;
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

impl InodeCommon for Inode {
    fn size(&self) -> u64 {
        self.size()
    }
    fn is_dir(&self) -> bool {
        self.is_dir()
    }
    fn is_regular_file(&self) -> bool {
        self.is_regular_file()
    }
    fn is_symlink(&self) -> bool {
        self.is_symlink()
    }
    fn uid(&self) -> u32 {
        self.uid()
    }
    fn gid(&self) -> u32 {
        self.gid()
    }
}

impl DirEntryCommon for DirEntry {
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

    fn filesystem_type(&self) -> String {
        "Extended File System".to_string()
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
