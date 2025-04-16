use crate::filesystem::{DirectoryCommon, FileCommon};
use crate::filesystem::{File, Filesystem};
//use chrono::{TimeZone, Utc};
use exhume_extfs::ExtFS;
use exhume_extfs::direntry::DirEntry;
use exhume_extfs::inode::Inode;
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

impl FileCommon for Inode {
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

impl DirectoryCommon for DirEntry {
    fn file_id(&self) -> u32 {
        self.inode
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl<T: Read + Seek> Filesystem for ExtFS<T> {
    type FileType = Inode;
    type DirectoryType = DirEntry;

    fn filesystem_type(&self) -> String {
        "Extended File System".to_string()
    }

    fn block_size(&self) -> u64 {
        self.superblock.block_size()
    }

    fn read_superblock(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.superblock.to_json())
    }

    fn read_inode(&mut self, inode_num: u64) -> Result<Self::FileType, Box<dyn Error>> {
        self.get_inode(inode_num)
    }

    fn read_file_content(&mut self, inode: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_inode(inode)
    }

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_dir(inode)
    }

    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_by_path(path)
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
            identifier: inode_num,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            ftype: file_type.clone(),
            size: inode.size(),
            metadata: inode.to_json(),
        }
    }
}
