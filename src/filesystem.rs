use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::fs::File as StdFile;
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct FsInfo {
    pub filesystem_type: String,
    pub block_size: u64,
    pub metadata: Value,
}

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
    fn file_id(&self) -> u32;
    /// Returns the name of the directory.
    fn name(&self) -> &str;
    /// Return the string representation of a File
    fn to_string(&self) -> String;
    /// Return the json representation of a File
    fn to_json(&self) -> Value;
}

// A cross-filesystem Exhume File abstraction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct File {
    pub identifier: u64, // All files have an identifier (eg. inode for Linux, record number for NTFS,...)
    pub absolute_path: String, // All files have an absolute path
    pub name: String,    // All files have a name
    pub ftype: String,   // All files have a type
    pub size: u64,
    pub metadata: Value, // All files have their own specific attributes/metadata
}

impl fmt::Display for File {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("test")?;
        Ok(())
    }
}

/// The Filesystem trait
pub trait Filesystem {
    type FileType: FileCommon;
    type DirectoryType: DirectoryCommon;

    fn filesystem_type(&self) -> String;
    fn block_size(&self) -> u64;
    fn read_metadata(&self) -> Result<Value, Box<dyn Error>>;
    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>>;
    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>>;
    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>>;
    fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn record_to_file(&self, file: &Self::FileType, inode_num: u64, absolute_path: &str) -> File;
    fn dump(&mut self, file: &Self::FileType) {
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
}
