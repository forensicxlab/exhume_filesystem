//! Btrfs adapter: maps `exhume_btrfs` onto the common `Filesystem` traits.
//!
//! Btrfs inode numbers are only unique inside a subvolume, so the public
//! identifier packs the subvolume slot (position in the subvolume table, 0 for
//! the top level) in the upper 16 bits and the inode number in the lower 48.
//! Subvolumes and snapshots appear as directories at the place they are
//! mounted in the top-level tree, like a `subvolid=5` mount shows them.

use crate::filesystem::{DirectoryCommon, File, FileCommon, FileIdentity, FileKind, Filesystem};
use exhume_btrfs::dir::DirEntry;
use exhume_btrfs::inode::Inode;
use exhume_btrfs::key::FIRST_FREE_OBJECTID;
use exhume_btrfs::{BtrfsFS, pack_id, unpack_id};
use serde_json::{Value, json};
use std::error::Error;
use std::io::{Read, Seek};
use std::path::Path;

/// An inode together with the slot of its subvolume.
#[derive(Debug, Clone)]
pub struct BtrfsFileRecord {
    pub slot: usize,
    pub inode: Inode,
}

impl BtrfsFileRecord {
    pub fn packed_id(&self) -> u64 {
        pack_id(self.slot, self.inode.ino).unwrap_or(self.inode.ino)
    }
}

impl FileCommon for BtrfsFileRecord {
    fn id(&self) -> u64 {
        self.packed_id()
    }
    fn size(&self) -> u64 {
        self.inode.size()
    }
    fn is_dir(&self) -> bool {
        self.inode.is_dir()
    }
    fn entry_kind(&self) -> FileKind {
        if self.inode.is_dir() {
            FileKind::Directory
        } else if self.inode.is_regular_file() {
            FileKind::Regular
        } else if self.inode.is_symlink() {
            FileKind::Symlink
        } else {
            FileKind::Special
        }
    }
    fn to_string(&self) -> String {
        format!("{}\nIdentifier: {}", self.inode, self.packed_id())
    }
    fn to_json(&self) -> Value {
        let mut value = self.inode.to_json();
        if let Value::Object(map) = &mut value {
            map.insert("identifier".into(), json!(self.packed_id()));
            map.insert("subvolume_slot".into(), json!(self.slot));
        }
        value
    }
}

/// A directory entry with its target already resolved to a packed identifier
/// (a subvolume entry targets the root directory of the child tree).
#[derive(Debug, Clone)]
pub struct BtrfsDirectoryEntry {
    pub entry: DirEntry,
    pub target_id: u64,
}

impl DirectoryCommon for BtrfsDirectoryEntry {
    fn file_id(&self) -> u64 {
        self.target_id
    }
    fn name(&self) -> &str {
        &self.entry.name
    }
    fn to_string(&self) -> String {
        format!("[{}] {}", self.target_id, self.entry)
    }
    fn to_json(&self) -> Value {
        let mut value = self.entry.to_json();
        if let Value::Object(map) = &mut value {
            map.insert("identifier".into(), json!(self.target_id));
        }
        value
    }
}

/// Unix seconds of a Btrfs timestamp, `None` when the field was never set
/// (inodes created by old kernels have no otime).
fn timestamp(ts: &exhume_btrfs::inode::Timespec) -> Option<u64> {
    if ts.sec == 0 && ts.nsec == 0 {
        None
    } else {
        Some(ts.unix_seconds())
    }
}

pub struct BtrfsFs<T: Read + Seek> {
    pub btrfs: BtrfsFS<T>,
    record_count_cache: Option<u64>,
}

impl<T: Read + Seek> BtrfsFs<T> {
    pub fn new(btrfs: BtrfsFS<T>) -> Self {
        BtrfsFs {
            btrfs,
            record_count_cache: None,
        }
    }

    fn wrap(&self, inode: Inode) -> Result<BtrfsFileRecord, Box<dyn Error>> {
        let slot = self
            .btrfs
            .subvolume_slot(inode.tree_id)
            .ok_or_else(|| format!("subvolume {} is not in the subvolume table", inode.tree_id))?;
        if pack_id(slot, inode.ino).is_none() {
            return Err(format!(
                "inode {} of subvolume {} cannot be represented in a packed identifier",
                inode.ino, inode.tree_id
            )
            .into());
        }
        Ok(BtrfsFileRecord { slot, inode })
    }

    fn wrap_entry(&self, entry: DirEntry) -> Option<BtrfsDirectoryEntry> {
        let (tree, ino) = entry.target()?;
        let ino = if entry.is_subvolume() {
            self.btrfs
                .subvolume(tree)
                .map(|s| s.root_dirid)
                .unwrap_or(FIRST_FREE_OBJECTID)
        } else {
            ino
        };
        let slot = self.btrfs.subvolume_slot(tree)?;
        Some(BtrfsDirectoryEntry {
            entry,
            target_id: pack_id(slot, ino)?,
        })
    }
}

impl<T: Read + Seek> Filesystem for BtrfsFs<T> {
    type FileType = BtrfsFileRecord;
    type DirectoryType = BtrfsDirectoryEntry;

    fn filesystem_type(&self) -> String {
        "Btrfs".to_string()
    }

    fn path_separator(&self) -> String {
        "/".to_string()
    }

    /// Number of inode items across the readable subvolumes (computed once).
    fn record_count(&mut self) -> u64 {
        if let Some(count) = self.record_count_cache {
            return count;
        }
        use exhume_btrfs::key::{INODE_ITEM_KEY, Key};
        let mut count = 0u64;
        let ids: Vec<u64> = self
            .btrfs
            .subvolumes()
            .iter()
            .filter(|s| s.readable)
            .map(|s| s.id)
            .collect();
        for id in ids {
            if let Some(root) = self.btrfs.tree_root(id) {
                let _ = self
                    .btrfs
                    .walk_range(root, Key::MIN, Key::MAX, &mut |key, _| {
                        if key.ty == INODE_ITEM_KEY {
                            count += 1;
                        }
                        true
                    });
            }
        }
        self.record_count_cache = Some(count);
        count
    }

    fn block_size(&self) -> u64 {
        self.btrfs.block_size()
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.btrfs.metadata_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.btrfs.metadata_pretty())
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        let (slot, _) = unpack_id(file_id);
        let inode = self.btrfs.get_inode_packed(file_id)?;
        Ok(BtrfsFileRecord { slot, inode })
    }

    fn resolve_child(
        &mut self,
        _parent: &Self::FileType,
        entry: &Self::DirectoryType,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        let inode = self.btrfs.resolve_entry(&entry.entry)?;
        self.wrap(inode)
    }

    fn entry_identifier(&self, _parent: &Self::FileType, entry: &Self::DirectoryType) -> u64 {
        entry.target_id
    }

    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(file.inode.tree_id, file.inode.ino, 0)
    }

    fn file_identifier(&self, file: &Self::FileType) -> u64 {
        file.packed_id()
    }

    fn get_file_by_path(
        &mut self,
        path: &str,
        _file_id: u64,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        let inode = self.btrfs.resolve_path(path)?;
        self.wrap(inode)
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.btrfs.read_inode(&file.inode)
    }

    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.btrfs.read_inode_prefix(&file.inode, length)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.btrfs.read_inode_slice(&file.inode, offset, length)
    }

    fn list_dir(
        &mut self,
        file: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        let entries = self.btrfs.list_dir(&file.inode)?;
        Ok(entries
            .into_iter()
            .filter_map(|entry| {
                let wrapped = self.wrap_entry(entry.clone());
                if wrapped.is_none() {
                    if entry.is_subvolume() && !entry.reachable {
                        // Stale subvolume entry copied into a snapshot: the kernel
                        // shows an empty directory, we skip it (see exhume_btrfs).
                        log::info!(
                            "btrfs: skipping stale subvolume entry {:?} (subvolume {}) in subvolume {} inode {}",
                            entry.name,
                            entry.location.objectid,
                            entry.parent_tree,
                            entry.parent_ino
                        );
                    } else {
                        log::warn!(
                            "btrfs: skipping entry {:?} of subvolume {} inode {}: unresolvable target {}",
                            entry.name,
                            entry.parent_tree,
                            entry.parent_ino,
                            entry.location
                        );
                    }
                }
                wrapped
            })
            .collect())
    }

    fn record_to_file(&self, record: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        let inode = &record.inode;
        let ftype = match inode.kind_name() {
            "dir" => "dir",
            "file" => "file",
            "symlink" => "symlink",
            _ => "other",
        }
        .to_string();
        let mut metadata = record.to_json();
        if let Value::Object(map) = &mut metadata
            && let Some(s) = self.btrfs.subvolume(inode.tree_id)
        {
            map.insert("subvolume_id".into(), json!(s.id));
            map.insert("subvolume_path".into(), json!(s.path));
            map.insert("subvolume_kind".into(), json!(s.kind_name()));
        }
        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            created: timestamp(&inode.item.otime),
            modified: timestamp(&inode.item.mtime),
            accessed: timestamp(&inode.item.atime),
            permissions: Some(inode.permissions()),
            owner: Some(format!("{}", inode.uid())),
            group: Some(format!("{}", inode.gid())),
            ftype,
            size: inode.size(),
            display: Some(format!(
                "[{}] - {} {} {} {} {:>5} {} {}",
                file_id,
                inode.permissions(),
                inode.nlink(),
                inode.uid(),
                inode.gid(),
                inode.size(),
                inode.mtime_h,
                absolute_path
            )),
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata,
        }
    }

    fn get_root_file_id(&self) -> u64 {
        let root_dirid = self
            .btrfs
            .subvolume(exhume_btrfs::key::FS_TREE_OBJECTID)
            .map(|s| s.root_dirid)
            .unwrap_or(FIRST_FREE_OBJECTID);
        pack_id(0, root_dirid).unwrap_or(root_dirid)
    }
}
