use crate::apfs_impl::ApfsFs;
use crate::filesystem::{DirectoryCommon, File, FileCommon, Filesystem};
use exhume_apfs::APFS;
use exhume_body::{Body, BodySlice};
use exhume_exfat::ExFatFS;
use exhume_extfs::ExtFS;
use exhume_ntfs::NTFS;
use log::info;
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Seek};

pub enum DetectedFs<T: Read + Seek> {
    Ext(ExtFS<T>),
    Ntfs(NTFS<T>),
    Exfat(ExFatFS<T>),
    Apfs(ApfsFs<T>),
}

pub enum DetectedFile {
    Ext(exhume_extfs::inode::Inode),
    Ntfs(exhume_ntfs::mft::MFTRecord),
    Exfat(exhume_exfat::exinode::ExInode),
    Apfs(crate::apfs_impl::ApfsFileRecord),
}

pub enum DetectedDir {
    Ext(exhume_extfs::direntry::DirEntry),
    Ntfs(exhume_ntfs::mft::DirectoryEntry),
    Exfat(exhume_exfat::compat::CompatDirEntry),
    Apfs(crate::apfs_impl::ApfsDirectoryEntry),
}

impl FileCommon for DetectedFile {
    fn id(&self) -> u64 {
        match self {
            DetectedFile::Ext(inode) => inode.id(),
            DetectedFile::Ntfs(record) => record.id(),
            DetectedFile::Exfat(inode) => inode.id(),
            DetectedFile::Apfs(inode) => inode.id(),
        }
    }
    fn size(&self) -> u64 {
        match self {
            DetectedFile::Ext(inode) => inode.size(),
            DetectedFile::Ntfs(record) => record.size(),
            DetectedFile::Exfat(inode) => inode.size(),
            DetectedFile::Apfs(inode) => inode.size(),
        }
    }
    fn is_dir(&self) -> bool {
        match self {
            DetectedFile::Ext(inode) => inode.is_dir(),
            DetectedFile::Ntfs(record) => record.is_dir(),
            DetectedFile::Exfat(inode) => inode.is_dir(),
            DetectedFile::Apfs(inode) => inode.is_dir(),
        }
    }
    fn to_string(&self) -> String {
        match self {
            DetectedFile::Ext(inode) => inode.to_string(),
            DetectedFile::Ntfs(record) => record.to_string(),
            DetectedFile::Exfat(inode) => inode.to_string(),
            DetectedFile::Apfs(inode) => inode.to_string(),
        }
    }
    fn to_json(&self) -> Value {
        match self {
            DetectedFile::Ext(inode) => inode.to_json(),
            DetectedFile::Ntfs(record) => record.to_json(),
            DetectedFile::Exfat(inode) => inode.to_json(),
            DetectedFile::Apfs(inode) => inode.to_json(),
        }
    }
}

impl DirectoryCommon for DetectedDir {
    fn file_id(&self) -> u64 {
        match self {
            DetectedDir::Ext(d) => d.file_id(),
            DetectedDir::Ntfs(d) => d.file_id(),
            DetectedDir::Exfat(d) => d.file_id(),
            DetectedDir::Apfs(d) => d.file_id(),
        }
    }
    fn name(&self) -> &str {
        match self {
            DetectedDir::Ext(d) => d.name(),
            DetectedDir::Ntfs(d) => d.name(),
            DetectedDir::Exfat(d) => d.name(),
            DetectedDir::Apfs(d) => d.name(),
        }
    }
    fn to_string(&self) -> String {
        match self {
            DetectedDir::Ext(d) => d.to_string(),
            DetectedDir::Ntfs(d) => d.to_string(),
            DetectedDir::Exfat(d) => d.to_string(),
            DetectedDir::Apfs(d) => d.to_string(),
        }
    }
    fn to_json(&self) -> Value {
        match self {
            DetectedDir::Ext(d) => d.to_json(),
            DetectedDir::Ntfs(d) => d.to_json(),
            DetectedDir::Exfat(d) => d.to_json(),
            DetectedDir::Apfs(d) => d.to_json(),
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
            DetectedFs::Exfat(fs) => fs.filesystem_type(),
            DetectedFs::Apfs(fs) => fs.filesystem_type(),
        }
    }
    fn path_separator(&self) -> String {
        match self {
            DetectedFs::Ext(fs) => fs.path_separator(),
            DetectedFs::Ntfs(fs) => fs.path_separator(),
            DetectedFs::Exfat(fs) => fs.path_separator(),
            DetectedFs::Apfs(fs) => fs.path_separator(),
        }
    }
    fn record_count(&mut self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.record_count(),
            DetectedFs::Ntfs(fs) => fs.record_count(),
            DetectedFs::Exfat(fs) => fs.record_count(),
            DetectedFs::Apfs(fs) => fs.record_count(),
        }
    }
    fn block_size(&self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.block_size(),
            DetectedFs::Ntfs(fs) => fs.block_size(),
            DetectedFs::Exfat(fs) => fs.block_size(),
            DetectedFs::Apfs(fs) => fs.block_size(),
        }
    }
    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_metadata(),
            DetectedFs::Ntfs(fs) => fs.get_metadata(),
            DetectedFs::Exfat(fs) => fs.get_metadata(),
            DetectedFs::Apfs(fs) => fs.get_metadata(),
        }
    }
    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_metadata_pretty(),
            DetectedFs::Ntfs(fs) => fs.get_metadata_pretty(),
            DetectedFs::Exfat(fs) => fs.get_metadata_pretty(),
            DetectedFs::Apfs(fs) => fs.get_metadata_pretty(),
        }
    }
    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.get_file(file_id).map(DetectedFile::Ext),
            DetectedFs::Ntfs(fs) => fs.get_file(file_id).map(DetectedFile::Ntfs),
            DetectedFs::Exfat(fs) => fs.get_file(file_id).map(DetectedFile::Exfat),
            DetectedFs::Apfs(fs) => fs.get_file(file_id).map(DetectedFile::Apfs),
        }
    }
    fn read_file_content(&mut self, record: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        match (self, record) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => fs.read_file_content(inode),
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => fs.read_file_content(rec),
            (DetectedFs::Exfat(fs), DetectedFile::Exfat(inode)) => fs.read_file_content(inode),
            (DetectedFs::Apfs(fs), DetectedFile::Apfs(inode)) => fs.read_file_content(inode),
            _ => Err("filesystem / record variant mismatch".into()),
        }
    }
    fn read_file_prefix(
        &mut self,
        record: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        match (self, record) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => fs.read_file_prefix(inode, length),
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => fs.read_file_prefix(rec, length),
            (DetectedFs::Exfat(fs), DetectedFile::Exfat(inode)) => {
                fs.read_file_prefix(inode, length)
            }
            (DetectedFs::Apfs(fs), DetectedFile::Apfs(inode)) => fs.read_file_prefix(inode, length),
            _ => Err("filesystem / record variant mismatch".into()),
        }
    }
    fn read_file_slice(
        &mut self,
        record: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        match (self, record) {
            (DetectedFs::Ext(fs), DetectedFile::Ext(inode)) => {
                fs.read_file_slice(inode, offset, length)
            }
            (DetectedFs::Ntfs(fs), DetectedFile::Ntfs(rec)) => {
                fs.read_file_slice(rec, offset, length)
            }
            (DetectedFs::Exfat(fs), DetectedFile::Exfat(inode)) => {
                fs.read_file_slice(inode, offset, length)
            }
            (DetectedFs::Apfs(fs), DetectedFile::Apfs(inode)) => {
                fs.read_file_slice(inode, offset, length)
            }
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
            (DetectedFs::Exfat(fs), DetectedFile::Exfat(inode)) => Filesystem::list_dir(fs, inode)
                .map(|v| v.into_iter().map(DetectedDir::Exfat).collect()),
            (DetectedFs::Apfs(fs), DetectedFile::Apfs(inode)) => Filesystem::list_dir(fs, inode)
                .map(|v| v.into_iter().map(DetectedDir::Apfs).collect()),
            _ => Err("filesystem / record variant mismatch".into()),
        }
    }
    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        match self {
            DetectedFs::Ext(fs) => fs.enumerate(),
            DetectedFs::Ntfs(fs) => fs.enumerate(),
            DetectedFs::Exfat(fs) => fs.enumerate(),
            DetectedFs::Apfs(fs) => fs.enumerate(),
        }
    }
    fn get_root_file_id(&self) -> u64 {
        match self {
            DetectedFs::Ext(fs) => fs.get_root_file_id(),
            DetectedFs::Ntfs(fs) => fs.get_root_file_id(),
            DetectedFs::Exfat(fs) => fs.get_root_file_id(),
            DetectedFs::Apfs(fs) => fs.get_root_file_id(),
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
            (DetectedFs::Exfat(fs), DetectedFile::Exfat(inode)) => {
                fs.record_to_file(inode, inode_num, absolute_path)
            }
            (DetectedFs::Apfs(fs), DetectedFile::Apfs(inode)) => {
                fs.record_to_file(inode, inode_num, absolute_path)
            }
            _ => unreachable!("filesystem / record variant mismatch"),
        }
    }
}

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
    if let Ok(apfs) = APFS::new(partition)
        && let Ok(apfs_fs) = ApfsFs::new(apfs)
    {
        info!("Detected an APFS filesystem/container.");
        return Ok(DetectedFs::Apfs(apfs_fs));
    }

    let partition = BodySlice::new(body, offset, partition_size)
        .map_err(|e| format!("Could not create BodySlice: {e}"))?;
    if let Ok(exfat) = ExFatFS::new(partition) {
        info!("Detected an exFAT filesystem.");
        return Ok(DetectedFs::Exfat(exfat));
    }

    let partition = BodySlice::new(body, offset, partition_size)
        .map_err(|e| format!("Could not create BodySlice: {e}"))?;
    if let Ok(ntfs) = NTFS::new(partition) {
        info!("Detected an NT filesystem.");
        return Ok(DetectedFs::Ntfs(ntfs));
    }

    Err(format!("No supported filesystem detected at offset {offset}").into())
}
