//! ZFS adapter: maps `exhume_zfs` onto the common `Filesystem` traits.
//!
//! A pool holds several datasets, each with its own object numbers, so the
//! public identifier packs the dataset slot (position in the sorted dataset
//! table, 1-based) in the upper 16 bits and the object number in the lower 48.
//! Slot 0 is a virtual root that lists the top-level datasets; a dataset's root
//! directory also lists its child datasets, like a mount with the default
//! mountpoints shows them.

use crate::filesystem::{DirectoryCommon, File, FileCommon, FileIdentity, FileKind, Filesystem};
use exhume_zfs::fs::{Entry, Node, ZfsFS, unpack_id};
use serde_json::{Value, json};
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

/// A resolved object together with the slot of its dataset.
#[derive(Debug, Clone)]
pub struct ZfsFileRecord {
    pub node: Node,
}

impl ZfsFileRecord {
    fn kind_name(&self) -> &'static str {
        let a = &self.node.attrs;
        if a.is_dir() {
            "dir"
        } else if a.is_reg() {
            "file"
        } else if a.is_symlink() {
            "symlink"
        } else {
            "other"
        }
    }
}

impl FileCommon for ZfsFileRecord {
    fn id(&self) -> u64 {
        self.node.id()
    }
    fn size(&self) -> u64 {
        self.node.attrs.size
    }
    fn is_dir(&self) -> bool {
        self.node.attrs.is_dir()
    }
    fn entry_kind(&self) -> FileKind {
        let a = &self.node.attrs;
        if a.is_dir() {
            FileKind::Directory
        } else if a.is_reg() {
            FileKind::Regular
        } else if a.is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Special
        }
    }
    fn to_string(&self) -> String {
        let a = &self.node.attrs;
        let mut out = format!(
            "Identifier: {}\nDataset slot: {}\nObject: {}\nType: {}\nMode: {} ({:o})\nSize: {}\nLinks: {}\nUID: {}\nGID: {}\nParent object: {}\nGeneration: {}\nAccessed: {}\nModified: {}\nChanged: {}\nCreated: {}",
            self.node.id(),
            self.node.slot,
            self.node.object,
            self.kind_name(),
            a.permissions(),
            a.mode & 0o7777,
            a.size,
            a.links,
            a.uid,
            a.gid,
            a.parent,
            a.generation,
            a.atime.0,
            a.mtime.0,
            a.ctime.0,
            a.crtime.0,
        );
        if let Some(target) = &a.symlink {
            out.push_str(&format!("\nSymlink target: {target}"));
        }
        out
    }
    fn to_json(&self) -> Value {
        let a = &self.node.attrs;
        json!({
            "identifier": self.node.id(),
            "dataset_slot": self.node.slot,
            "object": self.node.object,
            "type": self.kind_name(),
            "mode": a.mode,
            "permissions": a.permissions(),
            "size": a.size,
            "links": a.links,
            "uid": a.uid,
            "gid": a.gid,
            "parent": a.parent,
            "generation": a.generation,
            "atime": {"sec": a.atime.0, "nsec": a.atime.1},
            "mtime": {"sec": a.mtime.0, "nsec": a.mtime.1},
            "ctime": {"sec": a.ctime.0, "nsec": a.ctime.1},
            "crtime": {"sec": a.crtime.0, "nsec": a.crtime.1},
            "symlink": a.symlink,
        })
    }
}

/// A directory entry whose target is already a packed identifier (a dataset
/// entry targets the root directory of that dataset).
#[derive(Debug, Clone)]
pub struct ZfsDirectoryEntry {
    pub entry: Entry,
}

impl DirectoryCommon for ZfsDirectoryEntry {
    fn file_id(&self) -> u64 {
        self.entry.target_id
    }
    fn name(&self) -> &str {
        &self.entry.name
    }
    fn to_string(&self) -> String {
        format!(
            "[{}] {}{}",
            self.entry.target_id,
            self.entry.name,
            if self.entry.is_dataset {
                " (dataset)"
            } else {
                ""
            }
        )
    }
    fn to_json(&self) -> Value {
        json!({
            "identifier": self.entry.target_id,
            "name": self.entry.name,
            "kind": self.entry.kind,
            "dataset": self.entry.is_dataset,
        })
    }
}

/// Unix seconds of a ZFS timestamp, `None` when the field was never set.
fn timestamp(ts: (u64, u64)) -> Option<u64> {
    if ts == (0, 0) { None } else { Some(ts.0) }
}

pub struct ZfsFs<T: Read + Seek> {
    pub zfs: ZfsFS<T>,
}

impl<T: Read + Seek> ZfsFs<T> {
    pub fn new(zfs: ZfsFS<T>) -> Self {
        ZfsFs { zfs }
    }

    fn dataset_name(&self, slot: usize) -> Option<&str> {
        if slot == 0 {
            return None;
        }
        self.zfs.datasets.get(slot - 1).map(|d| d.name.as_str())
    }
}

impl<T: Read + Seek> Filesystem for ZfsFs<T> {
    type FileType = ZfsFileRecord;
    type DirectoryType = ZfsDirectoryEntry;

    fn filesystem_type(&self) -> String {
        "ZFS".to_string()
    }

    fn path_separator(&self) -> String {
        "/".to_string()
    }

    /// Number of objects across the readable datasets (from each objset root).
    fn record_count(&mut self) -> u64 {
        self.zfs.object_count()
    }

    fn block_size(&self) -> u64 {
        self.zfs.block_size()
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.zfs.metadata_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.zfs.metadata_pretty())
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        Ok(ZfsFileRecord {
            node: self.zfs.get_node(file_id)?,
        })
    }

    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(
            file.node.slot as u64,
            file.node.object,
            file.node.attrs.generation,
        )
    }

    fn get_file_by_path(
        &mut self,
        path: &str,
        _file_id: u64,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        Ok(ZfsFileRecord {
            node: self.zfs.resolve_path(path)?,
        })
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.zfs.read_all(&file.node)?)
    }

    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.zfs.read_slice(&file.node, 0, length)?)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.zfs.read_slice(&file.node, offset, length)?)
    }

    fn list_dir(
        &mut self,
        file: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        Ok(self
            .zfs
            .list_dir(&file.node)?
            .into_iter()
            .map(|entry| ZfsDirectoryEntry { entry })
            .collect())
    }

    fn record_to_file(&self, record: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        let a = &record.node.attrs;
        let mut metadata = record.to_json();
        if let Value::Object(map) = &mut metadata {
            let (slot, _) = unpack_id(file_id);
            map.insert("dataset".into(), json!(self.dataset_name(slot)));
        }
        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            created: timestamp(a.crtime),
            modified: timestamp(a.mtime),
            accessed: timestamp(a.atime),
            permissions: Some(a.permissions()),
            owner: Some(format!("{}", a.uid)),
            group: Some(format!("{}", a.gid)),
            ftype: record.kind_name().to_string(),
            size: a.size,
            display: Some(format!(
                "[{}] - {} {} {} {} {:>5} {} {}",
                file_id,
                a.permissions(),
                a.links,
                a.uid,
                a.gid,
                a.size,
                a.mtime.0,
                absolute_path
            )),
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata,
        }
    }

    fn get_root_file_id(&self) -> u64 {
        self.zfs.root_id()
    }
}
