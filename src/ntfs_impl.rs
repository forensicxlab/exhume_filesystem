use crate::filesystem::{DirectoryCommon, FileCommon};
use crate::filesystem::{File, Filesystem};
use exhume_ntfs::NTFS;
use exhume_ntfs::mft::{
    Attribute, AttributeType, DirectoryEntry, MFTRecord, StandardInformation,
    filetime_to_local_datetime,
};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Seek};

impl FileCommon for MFTRecord {
    fn id(&self) -> u64 {
        self.id
    }

    fn size(&self) -> u64 {
        let mut size = 0;
        for attr in &self.attributes {
            match attr {
                Attribute::Resident {
                    header, resident, ..
                } if header.attr_type == AttributeType::Data && header.name_length == 0 => {
                    size = resident.value_length as u64;
                }
                Attribute::NonResident {
                    header,
                    non_resident,
                    ..
                } if header.attr_type == AttributeType::Data && header.name_length == 0 => {
                    size = non_resident.real_size;
                }
                _ => {}
            }
        }
        size
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

impl DirectoryCommon for DirectoryEntry {
    fn file_id(&self) -> u64 {
        self.file_id
    }
    fn name(&self) -> &str {
        &self.name
    }
    /// Return the string representation of a File
    fn to_string(&self) -> String {
        format!("{}/{} - {}", self.file_id, self.flags, self.name)
    }
    /// Return the json representation of a File
    fn to_json(&self) -> Value {
        self.to_json()
    }
}

#[inline]
fn filetime_to_unix_secs(ft: u64) -> u64 {
    // FILETIME is 100ns since 1601-01-01; Unix is seconds since 1970-01-01
    // 11_644_473_600 = seconds between 1601-01-01 and 1970-01-01
    (ft / 10_000_000).saturating_sub(11_644_473_600)
}

impl<T: Read + Seek> Filesystem for NTFS<T> {
    type FileType = MFTRecord;
    type DirectoryType = DirectoryEntry;

    fn filesystem_type(&self) -> String {
        "NT File System".to_string()
    }

    fn path_separator(&self) -> String {
        "\\".to_string()
    }

    fn record_count(&mut self) -> u64 {
        self.mft_records_count().unwrap_or(0)
    }

    fn block_size(&self) -> u64 {
        self.pbs.cluster_size() as u64
    }

    fn get_metadata(&self) -> Result<Value, Box<dyn Error>> {
        Ok(self.pbs.to_json())
    }

    fn get_metadata_pretty(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.pbs.to_string())
    }

    fn get_file(&mut self, file_id: u64) -> Result<Self::FileType, Box<dyn Error>> {
        self.get_file_id(file_id)
    }

    fn read_file_content(&mut self, record: &Self::FileType) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file(record)
    }

    fn read_file_prefix(
        &mut self,
        record: &Self::FileType,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_prefix(record, length)
    }

    fn get_root_file_id(&self) -> u64 {
        return 5;
    }

    fn read_file_slice(
        &mut self,
        record: &Self::FileType,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.read_file_slice(record, offset, length)
    }

    fn list_dir(
        &mut self,
        record: &Self::FileType,
    ) -> Result<Vec<Self::DirectoryType>, Box<dyn Error>> {
        self.list_dir(record.id())
    }

    // Record to File object implementation for NTFS
    fn record_to_file(&self, record: &Self::FileType, file_id: u64, absolute_path: &str) -> File {
        let name = record
            .primary_name()
            .unwrap_or_else(|| format!("(MFT #{} – unnamed)", file_id));

        // Let's prefer $STANDARD_INFORMATION, fall back to first $FILE_NAME.
        let (c_ft, mft_ft, a_ft) = record
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Resident { header, value, .. }
                    if header.attr_type == AttributeType::StandardInformation =>
                {
                    StandardInformation::from_bytes(value)
                        .map(|si| (si.created, si.mft_modified, si.accessed))
                }
                _ => None,
            })
            .or_else(|| {
                record
                    .file_names()
                    .into_iter()
                    .next()
                    .map(|fnm| (fnm.created, fnm.mft_modified, fnm.accessed))
            })
            .unwrap_or((0, 0, 0)); // if totally missing, leave zeros and map to None below

        let created = (c_ft != 0).then(|| filetime_to_unix_secs(c_ft));
        let modified = (mft_ft != 0).then(|| filetime_to_unix_secs(mft_ft));
        let accessed = (a_ft != 0).then(|| filetime_to_unix_secs(a_ft));

        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_owned(),
            name,
            created,
            modified,
            accessed,
            permissions: None,
            owner: None,
            group: None,
            ftype: if record.is_dir() { "Directory" } else { "File" }.into(),
            size: record.size(),
            metadata: record.to_json(),
        }
    }
    /// Builds a list of all files (and directories) in the filesystem
    fn enumerate(&mut self) -> Result<(), Box<dyn Error>> {
        use log::{debug, info};

        let total = self.record_count();
        info!("NTFS: walking {} MFT records…", total);

        let mut cache: HashMap<u64, MFTRecord> = HashMap::new();

        for id in 0..total {
            let rec = match self.get_file(id) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if rec.header.flags & 0x0001 == 0 {
                // unallocated
                continue;
            }

            let mut parts = Vec::<String>::new();
            let mut cur = rec.clone();
            let mut cur_id = id;
            for _ in 0..512 {
                let nm = cur
                    .primary_name()
                    .unwrap_or_else(|| format!("MFT_{}", cur_id));
                parts.push(nm);
                match cur.parent_file_id() {
                    Some(pid) if pid != cur_id => {
                        cur_id = pid;
                        if let Some(p) = cache.get(&pid) {
                            cur = p.clone();
                        } else {
                            match self.get_file(pid) {
                                Ok(p) => {
                                    cur = p.clone();
                                    cache.insert(pid, p);
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    _ => break,
                }
            }
            parts.reverse();
            let abs_path = format!(r"\{}", parts.join(r"\"));

            let names: Vec<String> = rec.file_names().into_iter().map(|f| f.name).collect();

            let ads: Vec<String> = rec
                .alternate_data_streams()
                .into_iter()
                .map(|d| d.name)
                .collect();

            // 1st $STANDARD_INFORMATION has the authoritative timestamps
            let mft_ts = rec
                .attributes
                .iter()
                .find_map(|a| match a {
                    Attribute::Resident { header, value, .. }
                        if header.attr_type == AttributeType::StandardInformation =>
                    {
                        StandardInformation::from_bytes(value).map(|si| si.mft_modified)
                    }
                    _ => None,
                })
                .map(|ft| filetime_to_local_datetime(ft))
                .unwrap_or_else(|| "-".to_string());

            let ftype = if rec.is_dir() { "DIR" } else { "FILE" };
            let size = rec.size();

            println!("{id:<6} - {ftype:<4} - {size:>10} - {mft_ts} - {abs_path}");

            for n in names {
                println!("  - {n}");
            }
            for s in ads {
                println!("  - ads:{s}");
            }
        }

        debug!("NTFS enumeration finished.");
        Ok(())
    }
}
