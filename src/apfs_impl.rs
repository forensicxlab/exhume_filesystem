use crate::decmpfs::{self, Algorithm, DecodeLimits, Storage as DecmpfsStorage};
use crate::filesystem::{DirectoryCommon, File, FileCommon, FileIdentity, FileKind, Filesystem};
use exhume_apfs::{
    APFS, ApfsVolumeSuperblock, DirEntry, FsTree, INODE_HAS_UNCOMPRESSED_SIZE, InodeVal,
    XattrRecord, XattrStorage, apfs_kind, is_dir_mode,
};
use log::warn;
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;
const PACKED_INODE_MASK: u64 = 0x00ff_ffff_ffff_ffff;

#[derive(Debug, Clone)]
pub struct ApfsFileRecord {
    pub fs_index: u32,
    pub inode_id: u64,
    pub inode: InodeVal,
    /// Extended attributes owned by this inode. Stream-backed values remain
    /// lazy and are resolved only when explicitly read.
    pub xattrs: Vec<XattrRecord>,
}

#[derive(Debug, Clone)]
pub struct ApfsDirectoryEntry {
    pub fs_index: u32,
    pub inode_id: u64,
    pub name: String,
    pub raw_id: u64,
    pub flags: u16,
    pub date_added: u64,
}

pub struct ApfsFs<T: Read + Seek> {
    pub apfs: APFS<T>,
    pub volume: ApfsVolumeSuperblock,
    pub root_inode_id: u64,
    pub valid_volumes: Vec<(ApfsVolumeSuperblock, u64)>, // (volume, root_inode_id)
    cached_trees: std::collections::HashMap<u32, FsTree>,
}

impl<T: Read + Seek> ApfsFs<T> {
    pub fn new(mut apfs: APFS<T>) -> Result<Self, Box<dyn Error>> {
        if apfs.volumes.is_empty() {
            return Err("No APFS volumes discovered".into());
        }

        let mut vols = apfs.volumes.clone();
        vols.sort_by_key(|v| v.fs_index);

        // Prefer fs_index 0 if valid, then fallback to first valid volume.
        let mut candidates = Vec::new();
        if let Some(v0) = vols.iter().find(|v| v.fs_index == 0) {
            candidates.push(v0.clone());
        }
        for v in vols {
            if !candidates
                .iter()
                .any(|c: &ApfsVolumeSuperblock| c.fs_index == v.fs_index)
            {
                candidates.push(v);
            }
        }

        let mut valid_volumes = Vec::<(ApfsVolumeSuperblock, u64)>::new();
        for vol in candidates {
            let fst = match apfs.open_fstree_for_volume(&vol) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(root_inode_id) = fst.detect_root_inode_id(&mut apfs)? else {
                continue;
            };
            valid_volumes.push((vol, root_inode_id));
        }

        if valid_volumes.is_empty() {
            return Err("Could not open any APFS volume with a valid filesystem tree".into());
        }

        let selected = valid_volumes
            .iter()
            .find(|(v, _)| v.fs_index == 0)
            .cloned()
            .unwrap_or_else(|| valid_volumes[0].clone());

        Ok(Self {
            apfs,
            volume: selected.0,
            root_inode_id: selected.1,
            valid_volumes,
            cached_trees: std::collections::HashMap::new(),
        })
    }

    fn ensure_fstree(&mut self, fs_index: u32) -> Result<(), Box<dyn Error>> {
        if self.cached_trees.contains_key(&fs_index) {
            return Ok(());
        }
        let vol = self
            .volume_by_index(fs_index)
            .ok_or_else(|| format!("Volume with fs_index {} not found", fs_index))?;
        let tree = self.apfs.open_fstree_for_volume(&vol)?;
        self.cached_trees.insert(fs_index, tree);
        Ok(())
    }

    fn volume_by_index(&self, fs_index: u32) -> Option<ApfsVolumeSuperblock> {
        self.valid_volumes
            .iter()
            .find(|(v, _)| v.fs_index == fs_index)
            .map(|(v, _)| v.clone())
    }

    fn load_xattrs(
        &mut self,
        fs_index: u32,
        inode_id: u64,
        private_id: u64,
    ) -> Result<Vec<XattrRecord>, Box<dyn Error>> {
        self.ensure_fstree(fs_index)?;
        let fst = self.cached_trees.get(&fs_index).unwrap();
        let mut records = fst.xattrs_for_inode(&mut self.apfs, inode_id)?;
        if records.is_empty() && private_id != 0 && private_id != inode_id {
            records = fst.xattrs_for_inode(&mut self.apfs, private_id)?;
        }
        Ok(records)
    }

    /// Returns the parsed APFS extended-attribute descriptors for a file.
    pub fn list_xattrs<'a>(&self, file: &'a ApfsFileRecord) -> &'a [XattrRecord] {
        &file.xattrs
    }

    /// Reads one APFS extended attribute, resolving stream-backed values.
    pub fn read_xattr(
        &mut self,
        file: &ApfsFileRecord,
        name: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let Some(record) = file.xattrs.iter().find(|record| record.name == name) else {
            return Ok(None);
        };
        self.ensure_fstree(file.fs_index)?;
        let fst = self.cached_trees.get(&file.fs_index).unwrap();
        Ok(Some(fst.read_xattr_record(&mut self.apfs, record)?))
    }
}

impl FileCommon for ApfsFileRecord {
    fn id(&self) -> u64 {
        self.inode_id
    }

    fn size(&self) -> u64 {
        if self.inode.internal_flags & INODE_HAS_UNCOMPRESSED_SIZE != 0 {
            self.inode.uncompressed_size
        } else {
            self.inode
                .dstream
                .as_ref()
                .map(|d| d.size)
                .unwrap_or(self.inode.uncompressed_size)
        }
    }

    fn is_dir(&self) -> bool {
        is_dir_mode(self.inode.mode)
    }

    fn entry_kind(&self) -> FileKind {
        match self.inode.mode & 0o170000 {
            0o040000 => FileKind::Directory,
            0o100000 => FileKind::Regular,
            0o120000 => FileKind::Symlink,
            _ => FileKind::Special,
        }
    }

    fn to_string(&self) -> String {
        self.inode.metadata_table(self.inode_id)
    }

    fn to_json(&self) -> Value {
        json!({
            "fs_index": self.fs_index,
            "inode_id": self.inode_id,
            "mode": self.inode.mode,
            "size": self.size(),
            "inode": self.inode,
            "xattrs": self.xattrs.iter().map(xattr_metadata_json).collect::<Vec<_>>(),
        })
    }
}

fn xattr_metadata_json(record: &XattrRecord) -> Value {
    let storage = match &record.storage {
        XattrStorage::Embedded { data } => json!({
            "kind": "embedded",
            "size": data.len(),
            "preview": xattr_preview(data),
        }),
        XattrStorage::DataStream {
            xattr_obj_id,
            dstream,
        } => json!({
            "kind": "data_stream",
            "object_id": xattr_obj_id,
            "size": dstream.size,
            "allocated_size": dstream.alloced_size,
            "crypto_id": dstream.default_crypto_id,
        }),
        XattrStorage::Unknown { data } => json!({
            "kind": "unknown",
            "size": data.len(),
            "preview": xattr_preview(data),
        }),
    };

    let decmpfs = if record.name == "com.apple.decmpfs" {
        record.embedded_data().and_then(|data| {
            decmpfs::parse_header(data, DecodeLimits::default())
                .ok()
                .map(|header| {
                    let algorithm = match header.compression.algorithm {
                        Algorithm::Uncompressed => "uncompressed",
                        Algorithm::Zlib => "zlib",
                        Algorithm::Lzvn => "lzvn",
                        Algorithm::Lzfse => "lzfse",
                    };
                    let storage = match header.compression.storage {
                        DecmpfsStorage::Inline => "inline",
                        DecmpfsStorage::ResourceFork => "resource_fork",
                    };
                    json!({
                        "compression_type": header.compression.raw_type,
                        "algorithm": algorithm,
                        "storage": storage,
                        "uncompressed_size": header.uncompressed_size,
                    })
                })
        })
    } else {
        None
    };

    json!({
        "name": record.name,
        "flags": format!("0x{:04x}", record.flags),
        "declared_data_len": record.declared_data_len,
        "storage": storage,
        "decmpfs": decmpfs,
    })
}

fn xattr_preview(data: &[u8]) -> Value {
    const PREVIEW_BYTES: usize = 256;
    let preview = &data[..data.len().min(PREVIEW_BYTES)];
    match std::str::from_utf8(preview) {
        Ok(text)
            if text
                .chars()
                .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t')) =>
        {
            json!({
                "encoding": "utf8",
                "value": text,
                "truncated": preview.len() < data.len(),
            })
        }
        _ => json!({
            "encoding": "hex",
            "value": hex::encode(preview),
            "truncated": preview.len() < data.len(),
        }),
    }
}

impl ApfsFileRecord {
    /// Returns the "effective" size by also considering extent coverage.
    /// This is more robust on variants where the inode fixed header size is missing.
    fn effective_size<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut APFS<T>,
        fst: &exhume_apfs::FsTree,
    ) -> u64 {
        let declared = self.size();
        if declared > 0 {
            return declared;
        }

        let mut ext = fst.file_extents(apfs, self.inode_id).unwrap_or_default();
        if ext.is_empty() && self.inode.private_id != 0 {
            ext = fst
                .file_extents(apfs, self.inode.private_id)
                .unwrap_or_default();
        }
        let mut max_end = 0u64;
        for e in &ext {
            max_end = max_end.max(e.logical_addr.saturating_add(e.length_bytes));
        }
        max_end
    }
}

impl DirectoryCommon for ApfsDirectoryEntry {
    fn file_id(&self) -> u64 {
        self.inode_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn to_string(&self) -> String {
        format!(
            "{}:{} - {} (raw_id={} flags=0x{:04x})",
            self.fs_index, self.inode_id, self.name, self.raw_id, self.flags
        )
    }

    fn to_json(&self) -> Value {
        json!({
            "fs_index": self.fs_index,
            "inode_id": self.inode_id,
            "name": self.name,
            "raw_id": self.raw_id,
            "flags": format!("0x{:04x}", self.flags),
            "date_added": self.date_added,
        })
    }
}

impl<T: Read + Seek> Filesystem for ApfsFs<T> {
    type FileType = ApfsFileRecord;
    type DirectoryType = ApfsDirectoryEntry;

    fn filesystem_type(&self) -> String {
        "Apple File System".to_string()
    }

    fn path_separator(&self) -> String {
        "/".to_string()
    }

    fn record_count(&mut self) -> u64 {
        0
    }

    fn block_size(&self) -> u64 {
        self.apfs.block_size_u64()
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(json!({
            "container": {
                "block_size": self.apfs.nx.block_size,
                "block_count": self.apfs.nx.block_count,
                "uuid": self.apfs.nx.uuid_string(),
                "next_xid": self.apfs.nx.next_xid,
                "xp_desc_base": self.apfs.nx.xp_desc_base,
                "xp_desc_blocks": self.apfs.nx.xp_desc_blocks,
                "xp_data_base": self.apfs.nx.xp_data_base,
                "xp_data_blocks": self.apfs.nx.xp_data_blocks,
            },
            "selected_volume": self.volume,
            "root_inode_id": self.root_inode_id,
            "volumes": self.apfs.volumes,
        }))
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(format!(
            "APFS Container\nblock_size={} block_count={} uuid={}\nSelected volume: fs_index={} oid={} xid={} root_tree_oid={} root_inode={}",
            self.apfs.nx.block_size,
            self.apfs.nx.block_count,
            self.apfs.nx.uuid_string(),
            self.volume.fs_index,
            self.volume.o.oid,
            self.volume.o.xid,
            self.volume.root_tree_oid,
            self.root_inode_id
        ))
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        let (fs_index, inode_query, _volume) =
            if let Some((fs_idx, inode_id)) = unpack_identifier(file_id) {
                if let Some(vol) = self.volume_by_index(fs_idx) {
                    (fs_idx, inode_id, vol)
                } else {
                    (self.volume.fs_index, file_id, self.volume.clone())
                }
            } else {
                (self.volume.fs_index, file_id, self.volume.clone())
            };

        self.ensure_fstree(fs_index)?;
        let inode = {
            let fst = self.cached_trees.get(&fs_index).unwrap();
            fst.inode_by_id(&mut self.apfs, inode_query)?
        };
        if let Some(inode) = inode {
            let xattrs = self.load_xattrs(fs_index, inode_query, inode.private_id)?;
            return Ok(ApfsFileRecord {
                fs_index,
                inode_id: inode_query,
                inode,
                xattrs,
            });
        }
        let resolved = {
            let fst = self.cached_trees.get(&fs_index).unwrap();
            if let Some(inode_id) = fst.inode_id_by_private_id(&mut self.apfs, inode_query)? {
                fst.inode_by_id(&mut self.apfs, inode_id)?
                    .map(|inode| (inode_id, inode))
            } else {
                None
            }
        };
        if let Some((inode_id, inode)) = resolved {
            let xattrs = self.load_xattrs(fs_index, inode_id, inode.private_id)?;
            return Ok(ApfsFileRecord {
                fs_index,
                inode_id,
                inode,
                xattrs,
            });
        }
        Err(format!(
            "inode not found for id={} (fs_index={})",
            inode_query, fs_index
        )
        .into())
    }

    fn resolve_child(
        &mut self,
        parent: &Self::FileType,
        entry: &Self::DirectoryType,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        if entry.fs_index != parent.fs_index {
            return Err(format!(
                "APFS directory entry volume {} does not match parent volume {}",
                entry.fs_index, parent.fs_index
            )
            .into());
        }
        self.get_file(pack_identifier(entry.fs_index, entry.inode_id))
    }

    fn entry_identifier(&self, _parent: &Self::FileType, entry: &Self::DirectoryType) -> u64 {
        pack_identifier(entry.fs_index, entry.inode_id)
    }

    fn file_identity(&self, file: &Self::FileType) -> FileIdentity {
        FileIdentity::new(u64::from(file.fs_index), file.inode_id, 0)
    }

    fn file_identifier(&self, file: &Self::FileType) -> u64 {
        pack_identifier(file.fs_index, file.inode_id)
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(decoded) = self.read_decompressed_file(file)? {
            return Ok(decoded);
        }
        self.ensure_fstree(file.fs_index)?;
        let size = {
            let fst = self.cached_trees.get(&file.fs_index).unwrap();
            file.effective_size(&mut self.apfs, fst)
        };
        if size > MAX_READ_BYTES {
            return Err(format!(
                "refusing to allocate {} bytes (cap={} bytes)",
                size, MAX_READ_BYTES
            )
            .into());
        }
        let len = usize::try_from(size).map_err(|_| "file size does not fit usize")?;
        self.read_file_slice_with_size(file, 0, len, size)
    }

    fn read_file_prefix(
        &mut self,
        file: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if let Some(decoded) = self.read_decompressed_file(file)? {
            return Ok(decoded[..decoded.len().min(length)].to_vec());
        }
        self.ensure_fstree(file.fs_index)?;
        let size = {
            let fst = self.cached_trees.get(&file.fs_index).unwrap();
            file.effective_size(&mut self.apfs, fst)
        };
        let to_read = length.min(size as usize);
        self.read_file_slice_with_size(file, 0, to_read, size)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if let Some(decoded) = self.read_decompressed_file(file)? {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(decoded.len());
            let end = start.saturating_add(length).min(decoded.len());
            return Ok(decoded[start..end].to_vec());
        }
        self.ensure_fstree(file.fs_index)?;
        let size = {
            let fst = self.cached_trees.get(&file.fs_index).unwrap();
            file.effective_size(&mut self.apfs, fst)
        };
        self.read_file_slice_with_size(file, offset, length, size)
    }

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        if !inode.is_dir() {
            return Err("not a directory".into());
        }
        self.ensure_fstree(inode.fs_index)?;
        let fst = self.cached_trees.get(&inode.fs_index).unwrap();
        let entries: Vec<DirEntry> = fst.dir_children(&mut self.apfs, inode.inode_id)?;
        Ok(entries
            .into_iter()
            .filter_map(|e| {
                e.inode_id.map(|inode_id| ApfsDirectoryEntry {
                    fs_index: inode.fs_index,
                    inode_id,
                    name: e.name,
                    raw_id: e.raw_id,
                    flags: e.flags,
                    date_added: e.date_added,
                })
            })
            .collect())
    }

    fn record_to_file(&self, file: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_string(),
            name: match Path::new(absolute_path).file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => absolute_path.to_string(),
            },
            ftype: apfs_kind(file.inode.mode).to_string(),
            size: file.size(),
            created: Some(file.inode.create_time / 1_000_000_000),
            modified: Some(file.inode.mod_time / 1_000_000_000),
            accessed: Some(file.inode.access_time / 1_000_000_000),
            permissions: Some(apfs_mode_to_string(file.inode.mode)),
            owner: Some(format!("{}", file.inode.owner)),
            group: Some(format!("{}", file.inode.group)),
            display: Some(format!(
                "[{}] - {} {} {} {} {} {}",
                file_id,
                apfs_mode_to_string(file.inode.mode),
                exhume_apfs::fmt_apfs_ns_utc(file.inode.mod_time),
                file.inode.owner,
                file.inode.group,
                file.size(),
                absolute_path
            )),
            sig_name: None,
            sig_mime: None,
            sig_exts: None,
            metadata: file.to_json(),
        }
    }

    fn get_root_file_id(&self) -> u64 {
        self.root_inode_id
    }

    fn get_file_by_path(
        &mut self,
        path: &str,
        _file_id: u64,
    ) -> Result<Self::FileType, Box<dyn Error>> {
        let mut components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        if components.is_empty() {
            return Err("empty path".into());
        }

        // First component is "volume_N" → extract fs_index
        let vol_component = components.remove(0);
        let fs_index: u32 = if let Some(n) = vol_component.strip_prefix("volume_") {
            n.parse()
                .map_err(|_| format!("invalid volume component: {}", vol_component))?
        } else {
            return Err(format!("expected volume_N prefix, got: {}", vol_component).into());
        };

        let root_inode_id = self
            .valid_volumes
            .iter()
            .find(|(v, _)| v.fs_index == fs_index)
            .map(|(_, id)| *id)
            .ok_or_else(|| format!("no valid volume with fs_index={}", fs_index))?;

        self.ensure_fstree(fs_index)?;

        let root_inode = {
            let fst = self.cached_trees.get(&fs_index).unwrap();
            fst.inode_by_id(&mut self.apfs, root_inode_id)?
                .ok_or_else(|| format!("root inode {} not found", root_inode_id))?
        };

        let root_xattrs = self.load_xattrs(fs_index, root_inode_id, root_inode.private_id)?;
        let mut current = ApfsFileRecord {
            fs_index,
            inode_id: root_inode_id,
            inode: root_inode,
            xattrs: root_xattrs,
        };

        for component in components {
            let entries = self.list_dir(&current)?;
            let entry = entries
                .into_iter()
                .find(|e| e.name() == component)
                .ok_or_else(|| format!("path component not found: {:?}", component))?;

            self.ensure_fstree(fs_index)?;
            let inode = {
                let fst = self.cached_trees.get(&fs_index).unwrap();
                fst.inode_by_id(&mut self.apfs, entry.inode_id)?
                    .ok_or_else(|| format!("inode {} not found", entry.inode_id))?
            };
            let xattrs = self.load_xattrs(fs_index, entry.inode_id, inode.private_id)?;
            current = ApfsFileRecord {
                fs_index,
                inode_id: entry.inode_id,
                inode,
                xattrs,
            };
        }

        Ok(current)
    }

    fn walk_fs(
        &mut self,
        callback: &mut dyn FnMut(crate::filesystem::WalkEvent),
    ) -> Result<(), Box<dyn Error>> {
        let vols = self.valid_volumes.clone();

        for (vol, root_inode_id) in vols {
            self.ensure_fstree(vol.fs_index)?;
            let fst = self.cached_trees.get(&vol.fs_index).unwrap();

            callback(crate::filesystem::WalkEvent::Status(format!(
                "Scanning APFS volume {} B-Tree...",
                vol.fs_index
            )));

            // Linear B-Tree scan to load all records into memory at once
            let (inodes, drecs, mut xattrs) = fst.scan_all_records_with_xattrs(
                &mut self.apfs,
                Some(&mut |count| {
                    callback(crate::filesystem::WalkEvent::Status(format!(
                        "Scanning APFS B-Tree... {} records processed",
                        count
                    )));
                }),
            )?;

            callback(crate::filesystem::WalkEvent::Status(format!(
                "Building tree for volume {}...",
                vol.fs_index
            )));
            let mut visited = HashSet::<u64>::new();
            let mut queue = VecDeque::<(u64, String)>::new();
            let vol_prefix = format!("/volume_{}", vol.fs_index);
            queue.push_back((root_inode_id, vol_prefix.clone()));

            while let Some((inode_id, path)) = queue.pop_front() {
                if !visited.insert(inode_id) {
                    continue;
                }

                let inode = match inodes.get(&inode_id) {
                    Some(v) => v.clone(),
                    None => continue,
                };

                let inode_xattrs = xattrs.remove(&inode_id).or_else(|| {
                    (inode.private_id != 0 && inode.private_id != inode_id)
                        .then(|| xattrs.remove(&inode.private_id))
                        .flatten()
                });
                let rec = ApfsFileRecord {
                    fs_index: vol.fs_index,
                    inode_id,
                    inode,
                    xattrs: inode_xattrs.unwrap_or_default(),
                };
                let packed_id = pack_identifier(vol.fs_index, inode_id);
                callback(crate::filesystem::WalkEvent::File(
                    self.record_to_file(&rec, packed_id, &path),
                ));

                if rec.is_dir()
                    && let Some(children) = drecs.get(&inode_id)
                {
                    for de in children {
                        let Some(child_inode) = de.inode_id else {
                            continue;
                        };
                        let child_path = if path == vol_prefix {
                            format!("{}/{}", vol_prefix, de.name)
                        } else {
                            format!("{}/{}", path, de.name)
                        };
                        queue.push_back((child_inode, child_path));
                    }
                }
            }
        }

        Ok(())
    }
}

impl<T: Read + Seek> ApfsFs<T> {
    /// Returns decoded AppleFSCompression content when the file carries a
    /// `com.apple.decmpfs` xattr. A file marked compressed without the xattr is
    /// an error: silently returning sparse zeroes would corrupt forensic output.
    fn read_decompressed_file(
        &mut self,
        file: &ApfsFileRecord,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let Some(decmpfs_xattr) = self.read_xattr(file, "com.apple.decmpfs")? else {
            if file.inode.is_compressed() {
                return Err(format!(
                    "APFS inode {} is marked compressed but com.apple.decmpfs is missing",
                    file.inode_id
                )
                .into());
            }
            return Ok(None);
        };

        let header =
            decmpfs::parse_header(&decmpfs_xattr, DecodeLimits::default()).map_err(|error| {
                format!(
                    "failed to parse decmpfs header for APFS inode {}: {}",
                    file.inode_id, error
                )
            })?;
        let resource_fork = if header.compression.storage == DecmpfsStorage::ResourceFork {
            self.read_xattr(file, "com.apple.ResourceFork")?
        } else {
            None
        };
        let decoded = decmpfs::decompress_decmpfs(&decmpfs_xattr, resource_fork.as_deref())
            .map_err(|error| {
                format!(
                    "failed to decode APFS-compressed inode {}: {}",
                    file.inode_id, error
                )
            })?;
        Ok(Some(decoded))
    }

    fn read_file_slice_with_size(
        &mut self,
        file: &ApfsFileRecord,
        offset: u64,
        length: usize,
        file_size: u64,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if is_dir_mode(file.inode.mode) {
            return Err("requested file content for a directory".into());
        }

        if offset >= file_size {
            return Ok(Vec::new());
        }
        let end = offset
            .saturating_add(length as u64)
            .min(file_size)
            .min(offset + MAX_READ_BYTES);
        let req_len = usize::try_from(end.saturating_sub(offset))
            .map_err(|_| "requested slice length does not fit usize")?;
        let mut out = vec![0u8; req_len];

        self.ensure_fstree(file.fs_index)?;
        let ext = {
            let fst = self.cached_trees.get(&file.fs_index).unwrap();
            let mut ext = fst
                .file_extents(&mut self.apfs, file.inode_id)
                .unwrap_or_default();
            if ext.is_empty() && file.inode.private_id != 0 {
                ext = fst
                    .file_extents(&mut self.apfs, file.inode.private_id)
                    .unwrap_or_default();
            }
            ext
        };

        let bs = self.apfs.block_size_u64();
        for e in ext {
            let ext_start = e.logical_addr;
            let ext_end = e.logical_addr.saturating_add(e.length_bytes);
            let ov_start = ext_start.max(offset);
            let ov_end = ext_end.min(end);
            if ov_end <= ov_start {
                continue;
            }

            let read_len =
                usize::try_from(ov_end - ov_start).map_err(|_| "extent overlap too large")?;
            let mut buf = vec![0u8; read_len];

            if e.phys_block_num != 0 {
                let rel_in_ext = ov_start - ext_start;
                let phys_byte = e
                    .phys_block_num
                    .checked_mul(bs)
                    .and_then(|x| x.checked_add(rel_in_ext))
                    .ok_or("physical offset overflow")?;
                match self.apfs.body.seek(SeekFrom::Start(phys_byte)) {
                    Ok(_) => self.apfs.body.read_exact(&mut buf)?,
                    Err(io_err) if io_err.kind() == io::ErrorKind::InvalidInput => {
                        warn!(
                            "inode {}: extent phys_block={} maps to byte {} outside image slice; treating as sparse",
                            file.inode_id, e.phys_block_num, phys_byte
                        );
                    }
                    Err(io_err) => return Err(Box::new(io_err)),
                }
            }

            let dst_off =
                usize::try_from(ov_start - offset).map_err(|_| "destination offset too large")?;
            out[dst_off..dst_off + read_len].copy_from_slice(&buf);
        }

        Ok(out)
    }
}

fn apfs_mode_to_string(mode: u16) -> String {
    let mut out = String::with_capacity(10);
    out.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o100000 => '-',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    });
    for &(bit, ch) in &[
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ] {
        out.push(if (mode & bit) != 0 { ch } else { '-' });
    }
    if (mode & 0o4000) != 0 {
        out.replace_range(3..4, if (mode & 0o100) != 0 { "s" } else { "S" });
    }
    if (mode & 0o2000) != 0 {
        out.replace_range(6..7, if (mode & 0o010) != 0 { "s" } else { "S" });
    }
    if (mode & 0o1000) != 0 {
        out.replace_range(9..10, if (mode & 0o001) != 0 { "t" } else { "T" });
    }
    out
}

fn pack_identifier(fs_index: u32, inode_id: u64) -> u64 {
    ((fs_index as u64) << 56) | (inode_id & PACKED_INODE_MASK)
}

fn unpack_identifier(file_id: u64) -> Option<(u32, u64)> {
    let fs_index = (file_id >> 56) as u32;
    let inode_id = file_id & PACKED_INODE_MASK;
    if fs_index > 0 && inode_id > 0 {
        Some((fs_index, inode_id))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_identifier_preserves_non_default_volume_namespace() {
        let packed = pack_identifier(3, 42);
        assert_ne!(packed, 42);
        assert_eq!(unpack_identifier(packed), Some((3, 42)));
    }

    fn inode_with_sizes(uncompressed_size: u64, stream_size: u64) -> InodeVal {
        InodeVal {
            parent_id: 2,
            private_id: 3,
            create_time: 0,
            mod_time: 0,
            change_time: 0,
            access_time: 0,
            internal_flags: INODE_HAS_UNCOMPRESSED_SIZE,
            nchildren_or_nlink: 1,
            default_protection_class: 0,
            write_gen_counter: 0,
            bsd_flags: exhume_apfs::BSD_UF_COMPRESSED,
            owner: 0,
            group: 0,
            mode: 0o100644,
            uncompressed_size,
            dstream: Some(exhume_apfs::JDStream {
                size: stream_size,
                alloced_size: stream_size,
                default_crypto_id: 0,
                total_bytes_written: stream_size,
                total_bytes_read: 0,
            }),
            xfields: Vec::new(),
        }
    }

    #[test]
    fn compressed_record_reports_uncompressed_size() {
        let record = ApfsFileRecord {
            fs_index: 0,
            inode_id: 3,
            inode: inode_with_sizes(643, 445),
            xattrs: Vec::new(),
        };
        assert_eq!(record.size(), 643);
    }

    #[test]
    fn xattr_metadata_identifies_decmpfs_header() {
        let mut data = Vec::new();
        data.extend_from_slice(&decmpfs::MAGIC.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&643u64.to_le_bytes());
        let metadata = xattr_metadata_json(&XattrRecord {
            owner_id: 3,
            name: "com.apple.decmpfs".to_string(),
            flags: exhume_apfs::XATTR_DATA_EMBEDDED,
            declared_data_len: data.len() as u16,
            storage: XattrStorage::Embedded { data },
        });

        assert_eq!(metadata["decmpfs"]["compression_type"], 8);
        assert_eq!(metadata["decmpfs"]["algorithm"], "lzvn");
        assert_eq!(metadata["decmpfs"]["storage"], "resource_fork");
        assert_eq!(metadata["decmpfs"]["uncompressed_size"], 643);
    }
}
