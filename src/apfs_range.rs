//! Bounded payload reads for APFS streams and AppleFSCompression.
use super::*;
use exhume_apfs::FileExtent;

pub(super) enum Source {
    Embedded(Vec<u8>),
    Stream { size: u64, extents: Vec<FileExtent> },
}
impl Source {
    pub(super) fn size(&self) -> u64 {
        match self {
            Self::Embedded(data) => data.len() as u64,
            Self::Stream { size, .. } => *size,
        }
    }
    pub(super) fn read<T: Read + Seek>(
        &self,
        body: &mut T,
        block_size: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let length = self.size().saturating_sub(offset).min(length as u64) as usize;
        if length == 0 {
            return Ok(Vec::new());
        }
        if let Self::Embedded(data) = self {
            return Ok(data[offset as usize..offset as usize + length].to_vec());
        }
        let Self::Stream { extents, .. } = self else {
            unreachable!()
        };
        let mut output = vec![0; length];
        let end = offset + length as u64;
        // Metadata is cached and sorted once; avoid walking all earlier extents.
        let first =
            extents.partition_point(|e| e.logical_addr.saturating_add(e.length_bytes) <= offset);
        for extent in &extents[first..] {
            if extent.logical_addr >= end {
                break;
            }
            if extent.crypto_id != 0 {
                return Err("encrypted APFS extent is unsupported".into());
            }
            let start = extent.logical_addr.max(offset);
            let stop = extent
                .logical_addr
                .checked_add(extent.length_bytes)
                .ok_or("extent overflow")?
                .min(end);
            if stop <= start || extent.phys_block_num == 0 {
                continue;
            }
            let physical = extent
                .phys_block_num
                .checked_mul(block_size)
                .and_then(|at| at.checked_add(start - extent.logical_addr))
                .ok_or("physical extent overflow")?;
            body.seek(SeekFrom::Start(physical))?;
            body.read_exact(&mut output[(start - offset) as usize..(stop - offset) as usize])?;
        }
        Ok(output)
    }
    pub(super) fn stream(size: u64, mut extents: Vec<FileExtent>) -> Result<Self, Box<dyn Error>> {
        extents.sort_unstable_by_key(|e| e.logical_addr);
        let mut previous_end = 0;
        for extent in &extents {
            if extent.logical_addr < previous_end {
                return Err("overlapping APFS stream extents".into());
            }
            previous_end = extent
                .logical_addr
                .checked_add(extent.length_bytes)
                .ok_or("APFS extent overflow")?;
        }
        Ok(Self::Stream { size, extents })
    }
}

pub(super) enum CompressedFile {
    Inline(Vec<u8>),
    Resource {
        compression: decmpfs::Compression,
        size: u64,
        source: Source,
        ranges: Vec<(u64, usize)>,
        cache: Option<(usize, Vec<u8>)>,
    },
}
impl CompressedFile {
    fn read<T: Read + Seek>(
        &mut self,
        body: &mut T,
        block_size: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Self::Inline(data) => {
                let start = offset.min(data.len() as u64) as usize;
                Ok(data[start..start.saturating_add(length).min(data.len())].to_vec())
            }
            Self::Resource {
                compression,
                size,
                source,
                ranges,
                cache,
            } => {
                let length = size.saturating_sub(offset).min(length as u64) as usize;
                let mut output = Vec::with_capacity(length);
                while output.len() < length {
                    let at = offset + output.len() as u64;
                    let index = (at / decmpfs::CHUNK_SIZE as u64) as usize;
                    if cache.as_ref().is_none_or(|(cached, _)| *cached != index) {
                        let (start, count) = ranges[index];
                        let bytes = source.read(body, block_size, start, count)?;
                        let expected = (*size - index as u64 * decmpfs::CHUNK_SIZE as u64)
                            .min(decmpfs::CHUNK_SIZE as u64)
                            as usize;
                        *cache = Some((
                            index,
                            decmpfs::decode_chunk(*compression, &bytes, expected)?,
                        ));
                    }
                    let data = &cache.as_ref().unwrap().1;
                    let start = (at % decmpfs::CHUNK_SIZE as u64) as usize;
                    let count = (length - output.len()).min(data.len() - start);
                    output.extend_from_slice(&data[start..start + count]);
                }
                Ok(output)
            }
        }
    }
}

impl<T: Read + Seek> ApfsFs<T> {
    fn xattr_source(
        &mut self,
        file: &ApfsFileRecord,
        name: &str,
    ) -> Result<Option<Source>, Box<dyn Error>> {
        let Some(record) = file.xattrs.iter().find(|r| r.name == name) else {
            return Ok(None);
        };
        match &record.storage {
            XattrStorage::Embedded { data } => Ok(Some(Source::Embedded(data.clone()))),
            XattrStorage::Unknown { .. } => Err("unsupported APFS xattr storage".into()),
            XattrStorage::DataStream {
                xattr_obj_id,
                dstream,
            } => {
                self.ensure_fstree(file.fs_index)?;
                let extents = self
                    .cached_trees
                    .get(&file.fs_index)
                    .unwrap()
                    .file_extents(&mut self.apfs, *xattr_obj_id)?;
                Ok(Some(Source::stream(dstream.size, extents)?))
            }
        }
    }
    pub(super) fn read_decompressed_range(
        &mut self,
        file: &ApfsFileRecord,
        offset: u64,
        length: usize,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        const INLINE_LIMIT: usize = 8 * 1024 * 1024;
        let key = (file.fs_index, file.inode_id);
        if self
            .compressed_cache
            .as_ref()
            .is_none_or(|(id, _)| *id != key)
        {
            self.compressed_cache = None;
            let Some(source) = self.xattr_source(file, "com.apple.decmpfs")? else {
                if file.inode.is_compressed() {
                    return Err("compressed APFS file has no decmpfs attribute".into());
                }
                return Ok(None);
            };
            let bs = self.apfs.block_size_u64();
            let header_bytes = source.read(&mut self.apfs.body, bs, 0, decmpfs::HEADER_LEN)?;
            let header = decmpfs::parse_header(
                &header_bytes,
                DecodeLimits {
                    max_uncompressed_size: u64::MAX,
                    ..DecodeLimits::default()
                },
            )?;
            let decoded = if header.compression.storage == DecmpfsStorage::Inline {
                if source.size() > INLINE_LIMIT as u64
                    || header.uncompressed_size > INLINE_LIMIT as u64
                {
                    return Err(
                        "inline APFS compression exceeds the 8 MiB bounded-reader limit".into(),
                    );
                }
                let bytes = source.read(&mut self.apfs.body, bs, 0, source.size() as usize)?;
                CompressedFile::Inline(decmpfs::decompress_decmpfs(&bytes, None)?)
            } else {
                let fork = self
                    .xattr_source(file, "com.apple.ResourceFork")?
                    .ok_or("missing APFS resource fork")?;
                let ranges = decmpfs::resource_ranges(
                    header.compression,
                    header.uncompressed_size,
                    fork.size(),
                    |at, count| {
                        fork.read(&mut self.apfs.body, bs, at, count)
                            .map_err(|e| e.to_string())
                    },
                )?;
                CompressedFile::Resource {
                    compression: header.compression,
                    size: header.uncompressed_size,
                    source: fork,
                    ranges,
                    cache: None,
                }
            };
            self.compressed_cache = Some((key, decoded));
        }
        let bs = self.apfs.block_size_u64();
        self.compressed_cache
            .as_mut()
            .unwrap()
            .1
            .read(&mut self.apfs.body, bs, offset, length)
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn stream_range_spans_extents_sparse_holes_and_reports_short_reads() {
        let extents = vec![
            FileExtent {
                logical_addr: 0,
                phys_block_num: 1,
                length_bytes: 4,
                crypto_id: 0,
            },
            FileExtent {
                logical_addr: 6,
                phys_block_num: 3,
                length_bytes: 4,
                crypto_id: 0,
            },
        ];
        let source = Source::stream(10, extents).unwrap();
        let mut body = Cursor::new(b"----abcd----efgh".to_vec());
        assert_eq!(source.read(&mut body, 4, 2, 7).unwrap(), b"cd\0\0efg");
        body.get_mut().truncate(14);
        assert!(source.read(&mut body, 4, 6, 4).is_err());
        let encrypted = Source::stream(
            4,
            vec![FileExtent {
                logical_addr: 0,
                phys_block_num: 1,
                length_bytes: 4,
                crypto_id: 7,
            }],
        )
        .unwrap();
        assert!(encrypted.read(&mut body, 4, 0, 1).is_err());
    }
    #[test]
    fn resource_ranges_cross_chunks_without_loading_whole_fork_and_cache_reuses_chunk() {
        let chunks = [vec![b'a'; decmpfs::CHUNK_SIZE], vec![b'b'; 23]];
        let size = chunks.iter().map(Vec::len).sum::<usize>();
        let first = 12usize;
        let second = first + chunks[0].len();
        let end = second + chunks[1].len();
        let mut bytes = Vec::new();
        for offset in [first, second, end] {
            bytes.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        for chunk in chunks {
            bytes.extend_from_slice(&chunk);
        }
        let compression = decmpfs::classify(10).unwrap();
        let mut requests = Vec::new();
        let ranges = decmpfs::resource_ranges(
            compression,
            size as u64,
            bytes.len() as u64,
            |at, length| {
                requests.push((at, length));
                Ok(bytes[at as usize..at as usize + length].to_vec())
            },
        )
        .unwrap();
        assert_eq!(requests, [(0, 12)]);
        let mut file = CompressedFile::Resource {
            compression,
            size: size as u64,
            source: Source::Embedded(bytes),
            ranges,
            cache: None,
        };
        let mut body = Cursor::new(Vec::new());
        assert_eq!(
            file.read(&mut body, 1, decmpfs::CHUNK_SIZE as u64 - 3, 8)
                .unwrap(),
            b"aaabbbbb"
        );
        let CompressedFile::Resource { cache, .. } = &file else {
            unreachable!()
        };
        assert_eq!(cache.as_ref().unwrap().0, 1);
        assert_eq!(cache.as_ref().unwrap().1.len(), 23);
        assert_eq!(file.read(&mut body, 1, size as u64 - 2, 8).unwrap(), b"bb");
    }
    #[test]
    fn malformed_tables_and_overlapping_extents_are_errors() {
        let compression = decmpfs::classify(10).unwrap();
        let table = [8u32.to_le_bytes(), 7u32.to_le_bytes()].concat();
        assert!(decmpfs::resource_ranges(compression, 1, 7, |_, _| Ok(table.clone())).is_err());
        assert!(
            Source::stream(
                10,
                vec![
                    FileExtent {
                        logical_addr: 0,
                        phys_block_num: 1,
                        length_bytes: 8,
                        crypto_id: 0
                    },
                    FileExtent {
                        logical_addr: 7,
                        phys_block_num: 2,
                        length_bytes: 2,
                        crypto_id: 0
                    }
                ]
            )
            .is_err()
        );
    }
}
