use crate::filesystem::{DirectoryCommon, File, FileCommon, Filesystem};
use exhume_apfs::{APFS, ApfsVolumeSuperblock, DirEntry, InodeVal, FsTree, is_dir_mode, apfs_kind, fmt_apfs_ns_utc};
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;
const PACKED_INODE_MASK: u64 = 0x00ff_ffff_ffff_ffff;

#[derive(Debug, Clone)]
pub struct ApfsFileRecord {
    pub fs_index: u32,
    pub inode_id: u64,
    pub inode: InodeVal,
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

    fn get_fstree(&mut self, fs_index: u32) -> Result<FsTree, Box<dyn Error>> {
        if let Some(tree) = self.cached_trees.get(&fs_index) {
            return Ok(tree.clone());
        }
        let vol = self.volume_by_index(fs_index).ok_or_else(|| format!("Volume with fs_index {} not found", fs_index))?;
        let tree = self.apfs.open_fstree_for_volume(&vol)?;
        self.cached_trees.insert(fs_index, tree.clone());
        Ok(tree)
    }


    fn volume_by_index(&self, fs_index: u32) -> Option<ApfsVolumeSuperblock> {
        self.valid_volumes
            .iter()
            .find(|(v, _)| v.fs_index == fs_index)
            .map(|(v, _)| v.clone())
    }

    pub fn enumerate_all_files(&mut self) -> Result<Vec<File>, Box<dyn Error>> {
        let mut out = Vec::<File>::new();
        self.walk_fs(|f| out.push(f))?;
        Ok(out)
    }

    fn walk_fs<F>(&mut self, mut callback: F) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(File),
    {
        let vols = self.valid_volumes.clone();

        for (vol, root_inode_id) in vols {
            let mut visited = HashSet::<u64>::new();
            let mut queue = VecDeque::<(u64, String)>::new();
            let vol_prefix = format!("/volume_{}", vol.fs_index);
            queue.push_back((root_inode_id, vol_prefix.clone()));

            while let Some((inode_id, path)) = queue.pop_front() {
                if !visited.insert(inode_id) {
                    continue;
                }
                let fst = self.get_fstree(vol.fs_index)?;
                let inode = match fst.inode_by_id(&mut self.apfs, inode_id)? {
                    Some(v) => v,
                    None => continue,
                };
                let rec = ApfsFileRecord {
                    fs_index: vol.fs_index,
                    inode_id,
                    inode,
                };
                let packed_id = pack_identifier(vol.fs_index, inode_id);
                callback(self.record_to_file(&rec, packed_id, &path));

                if rec.is_dir() {
                    let children = match fst.dir_children(&mut self.apfs, inode_id) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
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

impl FileCommon for ApfsFileRecord {
    fn id(&self) -> u64 {
        self.inode_id
    }

    fn size(&self) -> u64 {
        self.inode
            .dstream
            .as_ref()
            .map(|d| d.size)
            .unwrap_or(self.inode.uncompressed_size)
    }

    fn is_dir(&self) -> bool {
        is_dir_mode(self.inode.mode)
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
        })
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
        if max_end > declared {
            max_end
        } else {
            declared
        }
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

        let fst = self.get_fstree(fs_index)?;
        if let Some(inode) = fst.inode_by_id(&mut self.apfs, inode_query)? {
            return Ok(ApfsFileRecord {
                fs_index,
                inode_id: inode_query,
                inode,
            });
        }
        if let Some(inode_id) = fst.inode_id_by_private_id(&mut self.apfs, inode_query)?
            && let Some(inode) = fst.inode_by_id(&mut self.apfs, inode_id)?
        {
            return Ok(ApfsFileRecord {
                fs_index,
                inode_id,
                inode,
            });
        }
        Err(format!(
            "inode not found for id={} (fs_index={})",
            inode_query, fs_index
        )
        .into())
    }

    fn read_file_content(&mut self, file: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        let fst = self.get_fstree(file.fs_index)?;
        let size = file.effective_size(&mut self.apfs, &fst);
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
        let fst = self.get_fstree(file.fs_index)?;
        let size = file.effective_size(&mut self.apfs, &fst);
        let to_read = length.min(size as usize);
        self.read_file_slice_with_size(file, 0, to_read, size)
    }

    fn read_file_slice(
        &mut self,
        file: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let fst = self.get_fstree(file.fs_index)?;
        let size = file.effective_size(&mut self.apfs, &fst);
        self.read_file_slice_with_size(file, offset, length, size)
    }

    fn list_dir(
        &mut self,
        inode: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        if !inode.is_dir() {
            return Err("not a directory".into());
        }
        let fst = self.get_fstree(inode.fs_index)?;
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
            metadata: file.to_json(),
        }
    }

    fn get_root_file_id(&self) -> u64 {
        self.root_inode_id
    }

    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        self.walk_fs(|file| {
            println!(
                "[{}] - {} {} {} {} {} {}",
                file.identifier,
                file.permissions
                    .clone()
                    .unwrap_or_else(|| "??????????".to_string()),
                fmt_apfs_ns_utc((file.modified.unwrap_or(0) as u64) * 1_000_000_000),
                file.owner.clone().unwrap_or_else(|| "-".to_string()),
                file.group.clone().unwrap_or_else(|| "-".to_string()),
                file.size,
                file.absolute_path
            );
        })
    }
}

impl<T: Read + Seek> ApfsFs<T> {
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

        let fst = self.get_fstree(file.fs_index)?;
        let mut ext = fst
            .file_extents(&mut self.apfs, file.inode_id)
            .unwrap_or_default();
        if ext.is_empty() && file.inode.private_id != 0 {
            ext = fst
                .file_extents(&mut self.apfs, file.inode.private_id)
                .unwrap_or_default();
        }

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
            let rel_in_ext = ov_start - ext_start;
            let phys_byte = e
                .phys_block_num
                .checked_mul(bs)
                .and_then(|x| x.checked_add(rel_in_ext))
                .ok_or("physical offset overflow")?;
            let mut buf = vec![0u8; read_len];
            self.apfs.body.seek(SeekFrom::Start(phys_byte))?;
            self.apfs.body.read_exact(&mut buf)?;

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
