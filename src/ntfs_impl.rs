use crate::filesystem::{DirectoryCommon, FileCommon};
use crate::filesystem::{File, Filesystem};
use exhume_ntfs::NTFS;
use exhume_ntfs::mft::{Attribute, AttributeType, DirectoryEntry, MFTRecord, StandardInformation};
use std::collections::HashMap;
use std::error::Error;

use serde_json::Value;
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

impl<T: Read + Seek> Filesystem for NTFS<T> {
    type FileType = MFTRecord;
    type DirectoryType = DirectoryEntry;

    fn filesystem_type(&self) -> String {
        "NT File System".to_string()
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
            .unwrap_or_else(|| format!("(MFT #{} – unnamed)", file_id));

        File {
            id: None,
            identifier: file_id,
            absolute_path: absolute_path.to_owned(),
            name,
            created: None,
            modified: None,
            accessed: None,
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
                        StandardInformation::from_bytes(value)
                    }
                    _ => None,
                })
                .map(|si| si.mft_modified)
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
