use crate::filesystem::{DirectoryCommon, FileCommon};
use crate::filesystem::{File, Filesystem};
use exhume_extfs::ExtFS;
use exhume_extfs::direntry::DirEntry;
use exhume_extfs::inode::Inode;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};

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
        self.to_string()
    }

    fn to_json(&self) -> Value {
        self.to_json()
    }
}

impl DirectoryCommon for DirEntry {
    fn file_id(&self) -> u32 {
        self.inode
    }
    fn name(&self) -> &str {
        &self.name
    }
    /// Return the string representation of a File
    fn to_string(&self) -> String {
        self.to_string()
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

    fn record_count(&self) -> u64 {
        self.superblock.s_inodes_count
    }

    fn block_size(&self) -> u64 {
        self.superblock.block_size()
    }

    fn read_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.superblock.to_json())
    }

    fn get_file(&mut self, inode_num: u64) -> Result<Self::FileType, Box<dyn Error>> {
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

    /// Builds a list of all files (and directories) in the filesystem
    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        let mut result: Vec<File> = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let root_file_record = 2;
        queue.push_back((root_file_record, "/".to_owned()));

        while let Some((inode_num, path)) = queue.pop_front() {
            if !visited.insert(inode_num) {
                continue;
            }

            let inode = self.get_file(inode_num).expect("Could not get Inode.");
            let file_obj = self.record_to_file(&inode, inode_num, &path);

            let perm_str = format!(
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
            );

            println!(
                "{} {} {} {} {:>5} {} {}",
                perm_str,
                inode.i_links_count,
                inode.uid(),
                inode.gid(),
                inode.size(),
                inode.i_mtime_h,
                file_obj.absolute_path
            );

            result.push(file_obj.clone());

            if inode.is_dir() {
                let entries = self.list_dir(&inode)?;
                for entry in entries {
                    let child_inode_num = entry.file_id() as u64;
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
