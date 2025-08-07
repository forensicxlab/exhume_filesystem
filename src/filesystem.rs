use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use std::error::Error;
use std::fs::File as StdFile;
use std::io::Write;

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
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
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
