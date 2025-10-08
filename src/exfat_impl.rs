use crate::filesystem::{DirectoryCommon, File, FileCommon, Filesystem};
use exhume_exfat::compat::CompatDirEntry;
use exhume_exfat::exinode::ExInode;
use exhume_exfat::{BootSector, ExFatFS};
use serde_json::Value;

use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

/// Minimal attribute string (read-only, hidden, system, dir, archive)
fn exfat_attr_string(attrs: u16, is_dir: bool) -> String {
    let mut s = String::new();
    if (attrs & 0x0001) != 0 {
        s.push('R');
    } // READ_ONLY
    if (attrs & 0x0002) != 0 {
        s.push('H');
    } // HIDDEN
    if (attrs & 0x0004) != 0 {
        s.push('S');
    } // SYSTEM
    if is_dir {
        s.push('D');
    }
    if (attrs & 0x0020) != 0 {
        s.push('A');
    } // ARCHIVE
    s
}

/// Synthesize a stable “fake” inode number for the root directory.
/// exFAT doesn’t store a directory entry for root, so we fix a sentinel low part.
fn root_inode_num(bpb: &BootSector) -> u64 {
    ((bpb.root_dir_first_cluster as u64) << 32) | 0xffff_ffff
}

/// Build a synthetic ExInode for the root directory so we can use the same API.
fn make_root_inode(bpb: &BootSector) -> ExInode {
    ExInode {
        i_num: root_inode_num(bpb),
        attributes: 0x0010, // directory
        first_cluster: bpb.root_dir_first_cluster,
        size: 0,
        name: "/".to_string(),
    }
}

impl FileCommon for ExInode {
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
        self.to_string()
    }
    fn to_json(&self) -> Value {
        self.to_json()
    }
}

impl DirectoryCommon for CompatDirEntry {
    fn file_id(&self) -> u64 {
        self.inode
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string(&self) -> String {
        self.to_string()
    }
    fn to_json(&self) -> Value {
        self.to_json()
    }
}

impl<T: Read + Seek> Filesystem for ExFatFS<T> {
    type FileType = ExInode;
    type DirectoryType = CompatDirEntry;

    fn filesystem_type(&self) -> String {
        "exFAT".to_string()
    }

    fn path_separator(&self) -> String {
        "/".to_string()
    }

    /// There isn't a fixed “record count” in exFAT; return 0 (unknown).
    fn record_count(&mut self) -> u64 {
        0
    }

    fn block_size(&self) -> u64 {
        self.bpb.bytes_per_cluster()
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.super_info_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.bpb.to_string())
    }

    /// Get a file by its fake inode number. We handle our synthetic root specially.
    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        if file_id == root_inode_num(&self.bpb) {
            return Ok(make_root_inode(&self.bpb));
        }
        Ok(self.get_inode(file_id)?)
    }

    fn read_file_content(&mut self, inode: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        if inode.is_dir() {
            return Err("exFAT: requested content for a directory".into());
        }
        Ok(self.read_inode(inode)?)
    }

    fn read_file_prefix(
        &mut self,
        inode: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut data = self.read_file_content(inode)?;
        if data.len() > length {
            data.truncate(length);
        }
        Ok(data)
    }

    fn read_file_slice(
        &mut self,
        inode: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let data = self.read_file_content(inode)?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Vec::new());
        }
        let end = off.saturating_add(length).min(data.len());
        Ok(data[off..end].to_vec())
    }

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        if !inode.is_dir() {
            return Err("not a directory".into());
        }
        Ok(self.list_dir_inode(inode)?)
    }

    fn record_to_file(&self, inode: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        let is_dir = inode.is_dir();
        let ftype = if is_dir { "dir" } else { "file" }.to_string();

        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(n) => n.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            created: None,
            modified: None,
            accessed: None,
            permissions: Some(exfat_attr_string(inode.attributes, is_dir)),
            owner: None,
            group: None,
            ftype,
            size: inode.size(),
            metadata: inode.to_json(),
        }
    }

    fn get_root_file_id(&self) -> u64 {
        root_inode_num(&self.bpb)
    }

    /// BFS enumeration starting at the synthetic root. Prints a terse line per record.
    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        let root_id = self.get_root_file_id();
        queue.push_back((root_id, "/".to_string()));

        while let Some((inode_num, path)) = queue.pop_front() {
            if !visited.insert(inode_num) {
                continue;
            }

            let inode = match self.get_file(inode_num) {
                Ok(i) => i,
                Err(_) => continue,
            };

            let file_obj = self.record_to_file(&inode, inode_num, &path);
            let ty = if inode.is_dir() { "DIR" } else { "FILE" };
            println!(
                "{:016x} - {:>4} - {:>10} - {}",
                inode_num,
                ty,
                inode.size(),
                file_obj.absolute_path
            );

            if inode.is_dir() {
                let entries = Filesystem::list_dir(self, &inode)?;
                for entry in entries {
                    let child_inode_num = entry.file_id();
                    let name = entry.name();
                    let child_path = if path == "/" {
                        format!("/{}", name)
                    } else {
                        format!("{}/{}", path, name)
                    };
                    queue.push_back((child_inode_num, child_path));
                }
            }
        }

        Ok(())
    }
}
