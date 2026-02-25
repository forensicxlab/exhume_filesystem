use crate::filesystem::{DirectoryCommon, File, FileCommon, Filesystem};
use serde_json::{json, Value};
use std::error::Error;
use std::fs::{self, File as StdFile};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct FolderFile {
    pub id: u64,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    pub permissions: u32,
    pub uid: u32,
    pub gid: u32,
}

impl FileCommon for FolderFile {
    fn id(&self) -> u64 {
        self.id
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn to_string(&self) -> String {
        format!(
            "FolderFile {{ id: {}, path: {:?}, size: {}, is_dir: {} }}",
            self.id, self.path, self.size, self.is_dir
        )
    }
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "path": self.path,
            "size": self.size,
            "is_dir": self.is_dir,
            "created": self.created,
            "modified": self.modified,
            "accessed": self.accessed,
            "permissions": self.permissions,
            "uid": self.uid,
            "gid": self.gid
        })
    }
}

#[derive(Debug, Clone)]
pub struct FolderDirectory {
    pub file_id: u64,
    pub name: String,
}

impl DirectoryCommon for FolderDirectory {
    fn file_id(&self) -> u64 {
        self.file_id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string(&self) -> String {
        format!("FolderDirectory {{ file_id: {}, name: {} }}", self.file_id, self.name)
    }
    fn to_json(&self) -> Value {
        json!({
            "file_id": self.file_id,
            "name": self.name
        })
    }
}

use std::collections::{HashMap, VecDeque};

pub struct FolderFS {
    pub root_path: PathBuf,
    pub path_cache: HashMap<u64, PathBuf>,
}

impl FolderFS {
    pub fn new(root_path: PathBuf) -> Self {
        let mut fs = Self {
            root_path: root_path.clone(),
            path_cache: HashMap::new(),
        };
        // Prime the cache with the root
        if let Ok(meta) = fs::metadata(&root_path) {
            fs.path_cache.insert(meta.ino(), root_path);
        }
        fs
    }

    fn get_file_from_path(&self, path: &Path, id: u64) -> Result<FolderFile, Box<dyn Error>> {
        let metadata = fs::symlink_metadata(path)?;
        
        let created = metadata.created().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
        let modified = metadata.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
        let accessed = metadata.accessed().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());

        Ok(FolderFile {
            id,
            path: path.to_path_buf(),
            size: metadata.len(),
            is_dir: metadata.is_dir(),
            created,
            modified,
            accessed,
            permissions: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    }
}

impl Filesystem for FolderFS {
    type FileType = FolderFile;
    type DirectoryType = FolderDirectory;

    fn filesystem_type(&self) -> String {
        "Folder".to_string()
    }

    fn path_separator(&self) -> String {
        std::path::MAIN_SEPARATOR.to_string()
    }

    fn record_count(&mut self) -> u64 {
        0 // Not easily countable without full traversal
    }

    fn block_size(&self) -> u64 {
        4096 // Default assumption
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(json!({
            "root_path": self.root_path
        }))
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(format!("Folder FS Root: {:?}", self.root_path))
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        let path = self.path_cache.get(&file_id).ok_or_else(|| {
            format!("File ID {} not found in path cache. FolderFS requires traversal to populate cache.", file_id)
        })?;
        
        // We need to clone path to use it, or just use it. 
        // get_file_from_path takes &Path.
        self.get_file_from_path(path, file_id)
    }

    fn get_file_by_path(&mut self, path: &str, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        // The path from system_files is likely "absolute" relative to the FS root (e.g. "/implant.exe").
        // We need to map this to the host filesystem path by joining with root_path.
        let relative_path = path.trim_start_matches(|c| c == '/' || c == '\\');
        let full_path = self.root_path.join(relative_path);

        if full_path.exists() {
            self.get_file_from_path(&full_path, file_id)
        } else {
             // Fallback: try the path as-is just in case it was already a host path
            let mixed_path = PathBuf::from(path);
             if mixed_path.exists() {
                 return self.get_file_from_path(&mixed_path, file_id);
             }

            Err(format!("File not found at path: {} (host: {})", path, full_path.display()).into())
        }
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = StdFile::open(&file.path)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = StdFile::open(&file.path)?;
        let mut buffer = vec![0; length];
        let n = f.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = StdFile::open(&file.path)?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buffer = vec![0; length];
        let n = f.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn list_dir(
        &mut self,
        file: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&file.path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let ino = metadata.ino();
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            
            // Populate cache
            self.path_cache.insert(ino, path);
            
            entries.push(FolderDirectory {
                file_id: ino,
                name,
            });
        }
        Ok(entries)
    }
    
    fn get_root_file_id(&self) -> u64 {
        fs::metadata(&self.root_path).map(|m| m.ino()).unwrap_or(0)
    }

    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        let mut queue = VecDeque::new();
        queue.push_back(self.root_path.clone());

        // Ensure root is in cache
        if let Ok(meta) = fs::metadata(&self.root_path) {
            self.path_cache.insert(meta.ino(), self.root_path.clone());
        }

        while let Some(path) = queue.pop_front() {
            if let Ok(entries) = fs::read_dir(&path) {
                for entry in entries {
                    if let Ok(entry) = entry {
                        let entry_path = entry.path();
                        if let Ok(meta) = entry.metadata() {
                            self.path_cache.insert(meta.ino(), entry_path.clone());
                            if meta.is_dir() {
                                queue.push_back(entry_path);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn record_to_file(&self, file: &Self::FileType, _file_id: u64, absolute_path: &str) -> File {
        // `file` is `FolderFile` which already has metadata.
        // `absolute_path` is passed from the walker.
        
        File {
            id: None, // Database ID not yet assigned
            identifier: file.id,
            absolute_path: absolute_path.to_string(),
            name: file.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            ftype: if file.is_dir { "Directory".to_string() } else { "File".to_string() },
            size: file.size,
            created: file.created,
            modified: file.modified,
            accessed: file.accessed,
            permissions: Some(format!("{:o}", file.permissions)),
            owner: Some(file.uid.to_string()),
            group: Some(file.gid.to_string()),
            metadata: json!({}),
        }
    }
}


