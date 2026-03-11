use crate::filesystem::{DirectoryCommon, FileCommon};
use crate::filesystem::{File, Filesystem};
use exhume_extfs::ExtFS;
use exhume_extfs::direntry::DirEntry;
use exhume_extfs::inode::Inode;
use serde_json::Value;

use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

impl FileCommon for Inode {
    fn id(&self) -> u64 {
        self.i_num
    }

    fn size(&self) -> u64 {
        self.size()
    }
    fn is_dir(&self) -> bool {
        self.is_dir()
    }

    fn to_string(&self) -> String {
        ToString::to_string(self)
    }

    fn to_json(&self) -> Value {
        self.to_json()
    }
}

pub fn format_unix_permissions(inode: &Inode) -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}{}",
        if inode.is_dir() {
            'd'
        } else if inode.is_symlink() {
            'l'
        } else {
            '-'
        },
        if inode.mode() & 0o400 != 0 { 'r' } else { '-' },
        if inode.mode() & 0o200 != 0 { 'w' } else { '-' },
        if inode.mode() & 0o100 != 0 { 'x' } else { '-' },
        if inode.mode() & 0o040 != 0 { 'r' } else { '-' },
        if inode.mode() & 0o020 != 0 { 'w' } else { '-' },
        if inode.mode() & 0o010 != 0 { 'x' } else { '-' },
        if inode.mode() & 0o004 != 0 { 'r' } else { '-' },
        if inode.mode() & 0o002 != 0 { 'w' } else { '-' },
        if inode.mode() & 0o001 != 0 { 'x' } else { '-' }
    )
}

impl DirectoryCommon for DirEntry {
    fn file_id(&self) -> u64 {
        self.inode as u64
    }
    fn name(&self) -> &str {
        &self.name
    }
    /// Return the string representation of a File
    fn to_string(&self) -> String {
        ToString::to_string(self)
    }
    /// Return the json representation of a File
    fn to_json(&self) -> Value {
        self.to_json()
    }
}

impl<T: Read + Seek> Filesystem for ExtFS<T> {
    type FileType = Inode;
    type DirectoryType = DirEntry;

    fn filesystem_type(&self) -> String {
        "Extended File System".to_string()
    }

    fn record_count(&mut self) -> u64 {
        self.superblock.s_inodes_count
    }

    fn path_separator(&self) -> String {
        "/".to_string()
    }

    fn block_size(&self) -> u64 {
        self.superblock.block_size()
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.superblock.to_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.superblock.to_string())
    }

    fn get_file(&mut self, inode_num: u64) -> Result<Self::FileType, Box<dyn Error>> {
        self.get_inode(inode_num)
    }

    fn read_file_content(&mut self, inode: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode(inode)
    }

    fn read_file_prefix(
        &mut self,
        inode: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode_prefix(inode, length)
    }

    fn get_root_file_id(&self) -> u64 {
        2
    }

    fn read_file_slice(
        &mut self,
        inode: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode_slice(inode, offset, length)
    }

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_dir(inode)
    }

    // Record to File object implementation for ExtFS
    fn record_to_file(&self, inode: &Self::FileType, inode_num: u64, absolute_path: &str) -> File {
        let mut file_type = String::from("other");
        if inode.is_dir() {
            file_type = String::from("dir");
        } else if inode.is_regular_file() {
            file_type = String::from("file");
        } else if inode.is_symlink() {
            file_type = String::from("symlink");
        }

        File {
            id: None,
            identifier: inode_num,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            created: Some(inode.i_crtime as u64),
            modified: Some(inode.i_mtime as u64),
            accessed: Some(inode.i_atime as u64),
            permissions: Some(format_unix_permissions(inode)),
            owner: Some(format!("{}", inode.uid())),
            group: Some(format!("{}", inode.gid())),
            ftype: file_type.clone(),
            size: inode.size(),
            display: Some(format!(
                "[{}] - {} {} {} {} {:>5} {} {}",
                inode_num,
                format_unix_permissions(inode),
                inode.i_links_count,
                inode.uid(),
                inode.gid(),
                inode.size(),
                inode.i_mtime_h,
                absolute_path
            )),
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata: inode.to_json(),
        }
    }
}
