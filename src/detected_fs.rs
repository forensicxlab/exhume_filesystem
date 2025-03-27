use crate::filesystem::{Filesystem, LinuxFile};
use exhume_body::{Body, BodySlice};
use exhume_extfs::ExtFS;
use std::error::Error;
use std::io::{Read, Seek};

pub enum DetectedFs<T: Read + Seek> {
    Ext(ExtFS<T>),
}

impl<T: Read + Seek> Filesystem for DetectedFs<T> {
    type InodeType = <ExtFS<T> as Filesystem>::InodeType;
    type DirEntryType = <ExtFS<T> as Filesystem>::DirEntryType;

    fn filesystem_type(&self) -> String {
        match self {
            DetectedFs::Ext(fs) => fs.filesystem_type(),
            // DetectedFs::Xfs(fs) => fs.filesystem_type(),
        }
    }

    fn block_size(&self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.block_size(),
            // DetectedFs::Xfs(fs) => fs.block_size(),
        }
    }

    fn read_superblock(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.read_superblock(),
            // DetectedFs::Xfs(fs) => fs.read_superblock(),
        }
    }

    fn read_inode(&mut self, inode_num: u64) -> Result<Self::InodeType, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_inode(inode_num),
            // DetectedFs::Xfs(fs) => fs.read_inode(inode_num),
        }
    }

    fn read_file_content(&mut self, inode: &Self::InodeType) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.read_file_content(inode),
            // DetectedFs::Xfs(fs) => fs.read_file_content(inode),
        }
    }

    fn list_dir(
        &mut self,
        inode: &Self::InodeType,
    ) -> Result<Vec<Self::DirEntryType>, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.list_dir(inode),
            // DetectedFs::Xfs(fs) => fs.list_dir(inode),
        }
    }

    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.read_file_by_path(path),
            // DetectedFs::Xfs(fs) => fs.read_file_by_path(path),
        }
    }

    fn inode_to_linuxfile(
        &self,
        inode: &Self::InodeType,
        inode_num: u64,
        absolute_path: &str,
    ) -> LinuxFile {
        match self {
            DetectedFs::Ext(fs) => fs.inode_to_linuxfile(inode, inode_num, absolute_path),
            // DetectedFs::Xfs(fs) => fs.inode_to_linuxfile(inode, inode_num, absolute_path),
        }
    }
}

pub fn detect_filesystem(
    body: &mut Body,
    offset: u64,
    partition_size: u64,
) -> Result<DetectedFs<BodySlice>, Box<dyn Error>> {
    // Create a BodySlice from the disk image.
    let partition = BodySlice::new(body, offset, partition_size)
        .map_err(|e| format!("Could not create BodySlice: {}", e))?;

    // Try to initialize an ExtFS instance.
    if let Ok(ext_fs) = ExtFS::new(partition) {
        return Ok(DetectedFs::Ext(ext_fs));
    }

    // If you support additional filesystems, try them here...
    // For example:
    // if let Ok(lvm_fs) = Lvm2::open(partition) {
    //     return Ok(DetectedFs::Lvm(lvm_fs));
    // }

    Err(format!("No supported filesystem detected at offset {}", offset).into())
}
