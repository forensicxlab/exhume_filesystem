use crate::filesystem::{DirectoryCommon, File, FileCommon, Filesystem};
use exhume_body::{Body, BodySlice};
use exhume_extfs::ExtFS;
use exhume_ntfs::NTFS;
use log::info;
use serde_json::Value;
use std::error::Error;

use std::io::{Read, Seek};

pub enum DetectedFs<T: Read + Seek> {
    Ext(ExtFS<T>),
    Ntfs(NTFS<T>),
}

pub enum DetectedFile {
    Ext(exhume_extfs::inode::Inode),
    Ntfs(exhume_ntfs::mft::MFTRecord),
}

pub enum DetectedDir {
    Ext(exhume_extfs::direntry::DirEntry),
    Ntfs(exhume_ntfs::mft::DirectoryEntry),
}

impl FileCommon for DetectedFile {
    fn id(&self) -> u64 {
        match self {
            DetectedFile::Ext(inode) => inode.id(),
            DetectedFile::Ntfs(record) => record.id(),
        }
    }

    fn size(&self) -> u64 {
        match self {
            DetectedFile::Ext(inode) => inode.size(),
            DetectedFile::Ntfs(record) => record.size(),
        }
    }

    fn is_dir(&self) -> bool {
        match self {
            DetectedFile::Ext(inode) => inode.is_dir(),
            DetectedFile::Ntfs(record) => record.is_dir(),
        }
    }

    fn to_string(&self) -> String {
        match self {
            DetectedFile::Ext(inode) => inode.to_string(),
            DetectedFile::Ntfs(record) => record.to_string(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            DetectedFile::Ext(inode) => inode.to_json(),
            DetectedFile::Ntfs(record) => record.to_json(),
        }
    }
}

impl DirectoryCommon for DetectedDir {
    fn file_id(&self) -> u64 {
        match self {
            DetectedDir::Ext(d) => d.file_id(),
            DetectedDir::Ntfs(d) => d.file_id(),
        }
    }

    fn name(&self) -> &str {
        match self {
            DetectedDir::Ext(d) => d.name(),
            DetectedDir::Ntfs(d) => d.name(),
        }
    }

    fn to_string(&self) -> String {
        match self {
            DetectedDir::Ext(d) => d.to_string(),
            DetectedDir::Ntfs(d) => d.to_string(),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            DetectedDir::Ext(d) => d.to_json(),
            DetectedDir::Ntfs(d) => d.to_json(),
        }
    }
}

impl<T: Read + Seek> Filesystem for DetectedFs<T> {
    type FileType = DetectedFile;
    type DirectoryType = DetectedDir;

    fn filesystem_type(&self) -> String {
        match self {
            DetectedFs::Ext(fs) => fs.filesystem_type(),
            DetectedFs::Ntfs(fs) => fs.filesystem_type(),
        }
    }

    fn record_count(&mut self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.record_count(),
            DetectedFs::Ntfs(fs) => fs.record_count(),
        }
    }

    fn block_size(&self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.block_size(),
            DetectedFs::Ntfs(fs) => fs.block_size(),
        }
    }

    fn get_metadata(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_metadata(),
            DetectedFs::Ntfs(fs) => fs.get_metadata(),
        }
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_metadata_pretty(),
            DetectedFs::Ntfs(fs) => fs.get_metadata_pretty(),
        }
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_file(file_id).map(DetectedFile::Ext),
            DetectedFs::Ntfs(fs) => fs.get_file(file_id).map(DetectedFile::Ntfs),
        }
    }

    fn read_file_content(&mut self, record: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        match (self, record) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => fs.read_file_content(inode),
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => fs.read_file_content(rec),
            _ => Err("filesystem / record variant mismatch".into()),
        }
    }

    fn list_dir(
        &mut self,
        file: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        match (self, file) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => fs
                .list_dir(inode)
                .map(|v| v.into_iter().map(DetectedDir::Ext).collect()),
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => fs
                .list_dir(rec.id())
                .map(|v| v.into_iter().map(DetectedDir::Ntfs).collect()),
            _ => Err("filesystem / record variant mismatch".into()),
        }
    }

    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.enumerate(),
            DetectedFs::Ntfs(fs) => fs.enumerate(),
        }
    }

    fn record_to_file(&self, record: &Self::FileType, inode_num: u64, absolute_path: &str) -> File {
        match (self, record) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => {
                fs.record_to_file(inode, inode_num, absolute_path)
            }
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => {
                fs.record_to_file(rec, inode_num, absolute_path)
            }
            _ => unreachable!("filesystem / record variant mismatch"),
        }
    }
}

// detected_fs.rs

pub fn detect_filesystem(
    body: &Body,
    offset: u64,
    partition_size: u64,
) -> Result<DetectedFs<BodySlice>, Box<dyn std::error::Error>> {
    let partition = BodySlice::new(body, offset, partition_size)
        .map_err(|e| format!("Could not create BodySlice: {e}"))?;

    if let Ok(ext_fs) = ExtFS::new(partition) {
        info!("Detected an Extended filesystem.");
        return Ok(DetectedFs::Ext(ext_fs));
    }

    let partition = BodySlice::new(body, offset, partition_size)
        .map_err(|e| format!("Could not create BodySlice: {e}"))?;

    if let Ok(ntfs) = NTFS::new(partition) {
        info!("Detected an NT filesystem.");
        return Ok(DetectedFs::Ntfs(ntfs));
    }

    Err(format!("No supported filesystem detected at offset {offset}").into())
}
