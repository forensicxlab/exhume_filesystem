//! AppleFSCompression (`decmpfs`) decoder used by HFS+ and APFS.
//!
//! A compressed file carries a `com.apple.decmpfs` extended attribute. Its
//! fixed 16-byte, little-endian header contains the magic, compression type,
//! and original size. Odd compression types keep their payload inline after
//! the header; even types keep independently compressed 64 KiB chunks in the
//! `com.apple.ResourceFork` extended attribute.
//!
//! The constants and layouts here follow Apple's XNU `decmpfs_disk_header`
//! (`bsd/sys/decmpfs.h` and `bsd/kern/decmpfs.c`) plus the resource-fork
//! layouts implemented by The Sleuth Kit and libfshfs. Apple has not published
//! a standalone resource-fork compression specification.
//!
//! This decoder is deliberately strict for forensic use: malformed input or a
//! decoded-size mismatch returns an error, never a partial result. Allocation,
//! resource-fork, and chunk-count limits are checked before decoding.

use flate2::read::ZlibDecoder;
use lzfse_rust::LzfseRingDecoder;
use std::error::Error;
use std::fmt;
use std::io::Read;

/// Length of the fixed `decmpfs_disk_header`.
pub const HEADER_LEN: usize = 16;

/// `decmpfs` magic as a native integer after little-endian decoding.
///
/// On-disk bytes are `66 70 6d 63` (`fpmc`); XNU defines the numeric value as
/// `0x636d7066` (`cmpf` when written most-significant byte first).
pub const MAGIC: u32 = 0x636d_7066;

/// Original size represented by one resource-fork chunk.
pub const CHUNK_SIZE: usize = 65_536;

const ZLIB_STORED_MARKER: u8 = 0xff;
const LZVN_STORED_MARKER: u8 = 0x06;
const LZFSE_STORED_MARKER: u8 = 0xff;
const PLAIN_STORED_MARKER: u8 = 0xcc;

const ZLIB_RSRC_TABLE_OFFSET: usize = 0x104;
const ZLIB_RSRC_ENTRIES_OFFSET: usize = 0x108;

/// Maximums applied before allocating or walking attacker-controlled tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum decoded file size.
    pub max_uncompressed_size: u64,
    /// Maximum accepted `com.apple.ResourceFork` byte length.
    pub max_resource_fork_size: usize,
    /// Maximum number of resource-fork chunks.
    pub max_chunks: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            // Matches the existing APFS whole-file read ceiling.
            max_uncompressed_size: 512 * 1024 * 1024,
            max_resource_fork_size: 512 * 1024 * 1024,
            max_chunks: 8_192,
        }
    }
}

/// Where the compressed bytes are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Inline,
    ResourceFork,
}

/// Codec selected by the `compression_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Uncompressed,
    Zlib,
    Lzvn,
    Lzfse,
}

/// Decoded meaning of a supported `compression_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compression {
    pub raw_type: u32,
    pub algorithm: Algorithm,
    pub storage: Storage,
}

/// Parsed view of the `com.apple.decmpfs` extended attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecmpfsHeader<'a> {
    pub compression: Compression,
    pub uncompressed_size: u64,
    /// Bytes following the 16-byte header. Empty for normal resource-fork
    /// variants; retained so callers can report unexpected trailing bytes.
    pub inline_payload: &'a [u8],
}

/// Named failure modes for untrusted on-disk data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecmpfsError {
    TruncatedHeader {
        actual: usize,
    },
    BadMagic {
        found: u32,
    },
    UnsupportedCompressionType(u32),
    DatalessCompressionType(u32),
    MissingResourceFork {
        compression_type: u32,
    },
    LimitExceeded {
        field: &'static str,
        value: u64,
        maximum: u64,
    },
    Truncated {
        context: &'static str,
        offset: usize,
        needed: usize,
        available: usize,
    },
    InvalidResourceFork(String),
    Codec {
        algorithm: Algorithm,
        message: String,
    },
    SizeMismatch {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for DecmpfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => write!(
                f,
                "truncated decmpfs header: expected {HEADER_LEN} bytes, found {actual}"
            ),
            Self::BadMagic { found } => {
                write!(f, "invalid decmpfs magic 0x{found:08x}")
            }
            Self::UnsupportedCompressionType(kind) => {
                write!(f, "unsupported decmpfs compression type {kind}")
            }
            Self::DatalessCompressionType(kind) => write!(
                f,
                "decmpfs type 0x{kind:08x} is a dataless placeholder with no local payload"
            ),
            Self::MissingResourceFork { compression_type } => write!(
                f,
                "decmpfs compression type {compression_type} requires com.apple.ResourceFork"
            ),
            Self::LimitExceeded {
                field,
                value,
                maximum,
            } => write!(f, "decmpfs {field} {value} exceeds limit {maximum}"),
            Self::Truncated {
                context,
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated {context} at offset 0x{offset:x}: need {needed} bytes, have {available}"
            ),
            Self::InvalidResourceFork(message) => {
                write!(f, "invalid decmpfs resource fork: {message}")
            }
            Self::Codec { algorithm, message } => {
                write!(f, "{algorithm:?} decmpfs decode failed: {message}")
            }
            Self::SizeMismatch { expected, actual } => write!(
                f,
                "decmpfs decoded-size mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for DecmpfsError {}

pub type Result<T> = std::result::Result<T, DecmpfsError>;

/// Map XNU/forensic-community compression type values to codec and storage.
pub fn classify(raw_type: u32) -> Result<Compression> {
    let (algorithm, storage) = match raw_type {
        1 | 9 => (Algorithm::Uncompressed, Storage::Inline),
        3 => (Algorithm::Zlib, Storage::Inline),
        4 => (Algorithm::Zlib, Storage::ResourceFork),
        7 => (Algorithm::Lzvn, Storage::Inline),
        8 => (Algorithm::Lzvn, Storage::ResourceFork),
        10 => (Algorithm::Uncompressed, Storage::ResourceFork),
        11 => (Algorithm::Lzfse, Storage::Inline),
        12 => (Algorithm::Lzfse, Storage::ResourceFork),
        // XNU's dataless types identify cloud/network placeholders, not
        // locally compressed content.
        0x8000_0001 | 0x8000_0002 => {
            return Err(DecmpfsError::DatalessCompressionType(raw_type));
        }
        _ => return Err(DecmpfsError::UnsupportedCompressionType(raw_type)),
    };
    Ok(Compression {
        raw_type,
        algorithm,
        storage,
    })
}

/// Parse and validate the fixed header, including the decoded-size limit.
pub fn parse_header(data: &[u8], limits: DecodeLimits) -> Result<DecmpfsHeader<'_>> {
    if data.len() < HEADER_LEN {
        return Err(DecmpfsError::TruncatedHeader { actual: data.len() });
    }
    let magic = le_u32(data, 0, "decmpfs header")?;
    if magic != MAGIC {
        return Err(DecmpfsError::BadMagic { found: magic });
    }
    let raw_type = le_u32(data, 4, "decmpfs header")?;
    let uncompressed_size = le_u64(data, 8, "decmpfs header")?;
    if uncompressed_size > limits.max_uncompressed_size {
        return Err(DecmpfsError::LimitExceeded {
            field: "uncompressed size",
            value: uncompressed_size,
            maximum: limits.max_uncompressed_size,
        });
    }
    Ok(DecmpfsHeader {
        compression: classify(raw_type)?,
        uncompressed_size,
        inline_payload: &data[HEADER_LEN..],
    })
}

/// Decode using [`DecodeLimits::default`].
pub fn decompress_decmpfs(decmpfs_xattr: &[u8], resource_fork: Option<&[u8]>) -> Result<Vec<u8>> {
    decompress_decmpfs_with_limits(decmpfs_xattr, resource_fork, DecodeLimits::default())
}

/// Decode a complete file from its `com.apple.decmpfs` xattr and optional
/// `com.apple.ResourceFork` xattr.
///
/// The returned vector is only produced after exact decoded-size validation.
pub fn decompress_decmpfs_with_limits(
    decmpfs_xattr: &[u8],
    resource_fork: Option<&[u8]>,
    limits: DecodeLimits,
) -> Result<Vec<u8>> {
    let header = parse_header(decmpfs_xattr, limits)?;
    let expected =
        usize::try_from(header.uncompressed_size).map_err(|_| DecmpfsError::LimitExceeded {
            field: "uncompressed size",
            value: header.uncompressed_size,
            maximum: usize::MAX as u64,
        })?;

    let decoded = match header.compression.storage {
        Storage::Inline => decode_inline(
            header.compression.algorithm,
            header.inline_payload,
            expected,
        )?,
        Storage::ResourceFork => {
            let fork = resource_fork.ok_or(DecmpfsError::MissingResourceFork {
                compression_type: header.compression.raw_type,
            })?;
            if fork.len() > limits.max_resource_fork_size {
                return Err(DecmpfsError::LimitExceeded {
                    field: "resource-fork size",
                    value: fork.len() as u64,
                    maximum: limits.max_resource_fork_size as u64,
                });
            }
            decode_resource_fork(header.compression, fork, expected, limits)?
        }
    };

    ensure_size(decoded, expected)
}

fn decode_inline(algorithm: Algorithm, payload: &[u8], expected: usize) -> Result<Vec<u8>> {
    // Types 1/9 are raw, but current macOS can still prefix their inline data
    // with the 0xcc stored marker used by raw resource chunks. Only strip it
    // when the remaining byte count exactly matches the declared output size;
    // an ordinary raw file may legitimately begin with 0xcc.
    let payload = if algorithm == Algorithm::Uncompressed
        && payload.first().copied() == Some(PLAIN_STORED_MARKER)
        && payload.len() == expected.saturating_add(1)
    {
        &payload[1..]
    } else {
        payload
    };
    // Compressed inline variants use the same stored-data markers as their
    // resource chunks.
    let payload = stored_payload(algorithm, payload, false);
    match payload {
        StoredPayload::Verbatim(bytes) => copy_exact(bytes, expected),
        StoredPayload::Encoded(bytes) => decode_codec(algorithm, bytes, expected),
    }
}

fn decode_resource_fork(
    compression: Compression,
    fork: &[u8],
    expected: usize,
    limits: DecodeLimits,
) -> Result<Vec<u8>> {
    if expected == 0 {
        return Ok(Vec::new());
    }
    let chunk_count = expected
        .checked_add(CHUNK_SIZE - 1)
        .ok_or_else(|| DecmpfsError::InvalidResourceFork("chunk-count overflow".to_string()))?
        / CHUNK_SIZE;
    if chunk_count > limits.max_chunks {
        return Err(DecmpfsError::LimitExceeded {
            field: "chunk count",
            value: chunk_count as u64,
            maximum: limits.max_chunks as u64,
        });
    }

    let ranges = if compression.raw_type == 4 {
        fixed_zlib_ranges(fork, chunk_count)?
    } else {
        absolute_ranges(fork, chunk_count)?
    };

    let mut output = Vec::new();
    output
        .try_reserve_exact(expected)
        .map_err(|error| DecmpfsError::Codec {
            algorithm: compression.algorithm,
            message: format!("cannot reserve {expected} output bytes: {error}"),
        })?;

    for (index, (start, end)) in ranges.into_iter().enumerate() {
        let remaining = expected - output.len();
        let expected_chunk = remaining.min(CHUNK_SIZE);
        let bytes = &fork[start..end];
        let chunk = match stored_payload(compression.algorithm, bytes, true) {
            StoredPayload::Verbatim(bytes) => copy_exact(bytes, expected_chunk)?,
            StoredPayload::Encoded(bytes) => {
                decode_codec(compression.algorithm, bytes, expected_chunk).map_err(|error| {
                    DecmpfsError::Codec {
                        algorithm: compression.algorithm,
                        message: format!("resource chunk {index}: {error}"),
                    }
                })?
            }
        };
        output.extend_from_slice(&chunk);
    }
    ensure_size(output, expected)
}

enum StoredPayload<'a> {
    Verbatim(&'a [u8]),
    Encoded(&'a [u8]),
}

/// Compression frameworks prefix incompressible data with an algorithm-specific
/// marker. Types 1/9 are inherently verbatim and need no marker.
fn stored_payload(algorithm: Algorithm, bytes: &[u8], resource_chunk: bool) -> StoredPayload<'_> {
    if algorithm == Algorithm::Uncompressed {
        return if resource_chunk && bytes.first().copied() == Some(PLAIN_STORED_MARKER) {
            StoredPayload::Verbatim(&bytes[1..])
        } else {
            StoredPayload::Verbatim(bytes)
        };
    }
    let marker = match algorithm {
        Algorithm::Zlib => ZLIB_STORED_MARKER,
        Algorithm::Lzvn => LZVN_STORED_MARKER,
        Algorithm::Lzfse => LZFSE_STORED_MARKER,
        Algorithm::Uncompressed => unreachable!(),
    };
    if bytes.first().copied() == Some(marker) {
        StoredPayload::Verbatim(&bytes[1..])
    } else {
        StoredPayload::Encoded(bytes)
    }
}

fn decode_codec(algorithm: Algorithm, bytes: &[u8], expected: usize) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Uncompressed => copy_exact(bytes, expected),
        Algorithm::Zlib => decode_zlib(bytes, expected),
        Algorithm::Lzvn => {
            let decoded = lzvn::decode(bytes, expected).map_err(|error| DecmpfsError::Codec {
                algorithm,
                message: error.to_string(),
            })?;
            ensure_size(decoded, expected)
        }
        Algorithm::Lzfse => {
            // The streaming reader lets us impose a hard expected+1 output
            // ceiling. The slice-to-Vec decoder trusts sizes inside the stream
            // and could otherwise allocate beyond our forensic read limit.
            let mut decoder = LzfseRingDecoder::default();
            let mut reader = decoder.reader(bytes);
            let decoded = read_bounded(&mut reader, expected, algorithm)?;
            ensure_size(decoded, expected)
        }
    }
}

fn decode_zlib(bytes: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(bytes);
    let decoded = read_bounded(&mut decoder, expected, Algorithm::Zlib)?;
    ensure_size(decoded, expected)
}

/// Drain at most `expected + 1` bytes into a pre-sized buffer. Reading the
/// sentinel byte detects an oversized stream without allowing `read_to_end`
/// to grow a `Vec` according to attacker-controlled codec metadata.
fn read_bounded(reader: &mut dyn Read, expected: usize, algorithm: Algorithm) -> Result<Vec<u8>> {
    let maximum = expected.checked_add(1).ok_or(DecmpfsError::LimitExceeded {
        field: "codec output size",
        value: expected as u64,
        maximum: usize::MAX as u64,
    })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(maximum)
        .map_err(|error| DecmpfsError::Codec {
            algorithm,
            message: format!("cannot reserve {maximum} bounded output bytes: {error}"),
        })?;
    output.resize(maximum, 0);

    let mut written = 0usize;
    while written < maximum {
        match reader.read(&mut output[written..]) {
            Ok(0) => break,
            Ok(count) => written += count,
            Err(error) => {
                return Err(DecmpfsError::Codec {
                    algorithm,
                    message: error.to_string(),
                });
            }
        }
    }
    output.truncate(written);
    Ok(output)
}

/// Type 4 uses the classic resource-manager layout: count at `0x104`, then
/// `[relative_offset, length]` entries. Relative offsets are based at `0x104`.
fn fixed_zlib_ranges(fork: &[u8], expected_chunks: usize) -> Result<Vec<(usize, usize)>> {
    let stored_count = le_u32(fork, ZLIB_RSRC_TABLE_OFFSET, "type-4 chunk count")? as usize;
    if stored_count != expected_chunks {
        return Err(DecmpfsError::InvalidResourceFork(format!(
            "type-4 chunk count {stored_count} disagrees with expected {expected_chunks}"
        )));
    }
    let table_bytes = stored_count
        .checked_mul(8)
        .and_then(|n| ZLIB_RSRC_ENTRIES_OFFSET.checked_add(n))
        .ok_or_else(|| DecmpfsError::InvalidResourceFork("type-4 table overflow".to_string()))?;
    require(fork, 0, table_bytes, "type-4 chunk table")?;

    let mut ranges = Vec::with_capacity(stored_count);
    let mut previous_end = table_bytes;
    for index in 0..stored_count {
        let entry = ZLIB_RSRC_ENTRIES_OFFSET + index * 8;
        let relative = le_u32(fork, entry, "type-4 chunk entry")? as usize;
        let length = le_u32(fork, entry + 4, "type-4 chunk entry")? as usize;
        let start = ZLIB_RSRC_TABLE_OFFSET
            .checked_add(relative)
            .ok_or_else(|| {
                DecmpfsError::InvalidResourceFork(format!("type-4 chunk {index} offset overflow"))
            })?;
        let end = start.checked_add(length).ok_or_else(|| {
            DecmpfsError::InvalidResourceFork(format!("type-4 chunk {index} length overflow"))
        })?;
        if length == 0 || start < table_bytes || start < previous_end || end > fork.len() {
            return Err(DecmpfsError::InvalidResourceFork(format!(
                "invalid type-4 chunk {index} range 0x{start:x}..0x{end:x}"
            )));
        }
        ranges.push((start, end));
        previous_end = end;
    }
    Ok(ranges)
}

/// Types 8/10/12 use `chunk_count + 1` absolute little-endian offsets at byte
/// zero. Adjacent offsets delimit each chunk.
fn absolute_ranges(fork: &[u8], chunk_count: usize) -> Result<Vec<(usize, usize)>> {
    let offset_count = chunk_count
        .checked_add(1)
        .ok_or_else(|| DecmpfsError::InvalidResourceFork("offset-count overflow".to_string()))?;
    let table_len = offset_count
        .checked_mul(4)
        .ok_or_else(|| DecmpfsError::InvalidResourceFork("offset-table overflow".to_string()))?;
    require(fork, 0, table_len, "absolute chunk table")?;

    let mut offsets = Vec::with_capacity(offset_count);
    for index in 0..offset_count {
        offsets.push(le_u32(fork, index * 4, "absolute chunk offset")? as usize);
    }
    if offsets[0] < table_len {
        return Err(DecmpfsError::InvalidResourceFork(format!(
            "first absolute chunk offset 0x{:x} overlaps table ending at 0x{table_len:x}",
            offsets[0]
        )));
    }
    if offsets[offset_count - 1] != fork.len() {
        return Err(DecmpfsError::InvalidResourceFork(format!(
            "final absolute chunk offset 0x{:x} does not equal resource-fork size 0x{:x}",
            offsets[offset_count - 1],
            fork.len()
        )));
    }

    let mut ranges = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let start = offsets[index];
        let end = offsets[index + 1];
        if start >= end || end > fork.len() {
            return Err(DecmpfsError::InvalidResourceFork(format!(
                "invalid absolute chunk {index} range 0x{start:x}..0x{end:x}"
            )));
        }
        ranges.push((start, end));
    }
    Ok(ranges)
}

fn ensure_size(bytes: Vec<u8>, expected: usize) -> Result<Vec<u8>> {
    if bytes.len() != expected {
        return Err(DecmpfsError::SizeMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn copy_exact(bytes: &[u8], expected: usize) -> Result<Vec<u8>> {
    if bytes.len() != expected {
        return Err(DecmpfsError::SizeMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes.to_vec())
}

fn require(data: &[u8], offset: usize, needed: usize, context: &'static str) -> Result<()> {
    let end = offset
        .checked_add(needed)
        .ok_or_else(|| DecmpfsError::InvalidResourceFork("offset overflow".to_string()))?;
    if end > data.len() {
        return Err(DecmpfsError::Truncated {
            context,
            offset,
            needed,
            available: data.len().saturating_sub(offset),
        });
    }
    Ok(())
}

fn le_u32(data: &[u8], offset: usize, context: &'static str) -> Result<u32> {
    require(data, offset, 4, context)?;
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn le_u64(data: &[u8], offset: usize, context: &'static str) -> Result<u64> {
    require(data, offset, 8, context)?;
    Ok(u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression as ZlibLevel;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn header(kind: u32, uncompressed_size: usize, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
        bytes.extend_from_slice(&MAGIC.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&(uncompressed_size as u64).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), ZlibLevel::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn absolute_fork(chunks: &[&[u8]]) -> Vec<u8> {
        let table_len = (chunks.len() + 1) * 4;
        let mut offsets = Vec::with_capacity(chunks.len() + 1);
        let mut next = table_len;
        offsets.push(next);
        for chunk in chunks {
            next += chunk.len();
            offsets.push(next);
        }
        let mut fork = Vec::with_capacity(next);
        for offset in offsets {
            fork.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        for chunk in chunks {
            fork.extend_from_slice(chunk);
        }
        fork
    }

    fn fixed_zlib_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
        let table_end = ZLIB_RSRC_ENTRIES_OFFSET + chunks.len() * 8;
        let mut fork = vec![0u8; table_end];
        fork[ZLIB_RSRC_TABLE_OFFSET..ZLIB_RSRC_TABLE_OFFSET + 4]
            .copy_from_slice(&(chunks.len() as u32).to_le_bytes());
        let mut start = table_end;
        for (index, chunk) in chunks.iter().enumerate() {
            let entry = ZLIB_RSRC_ENTRIES_OFFSET + index * 8;
            let relative = start - ZLIB_RSRC_TABLE_OFFSET;
            fork[entry..entry + 4].copy_from_slice(&(relative as u32).to_le_bytes());
            fork[entry + 4..entry + 8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            fork.extend_from_slice(chunk);
            start += chunk.len();
        }
        // Real type-4 forks carry a 50-byte resource-map trailer; range entries
        // deliberately exclude it.
        fork.extend_from_slice(&[0u8; 50]);
        fork
    }

    #[test]
    fn parses_header_and_classifies_supported_types() {
        let bytes = header(7, 5, b"payload");
        let parsed = parse_header(&bytes, DecodeLimits::default()).unwrap();
        assert_eq!(parsed.compression.algorithm, Algorithm::Lzvn);
        assert_eq!(parsed.compression.storage, Storage::Inline);
        assert_eq!(parsed.uncompressed_size, 5);
        assert_eq!(parsed.inline_payload, b"payload");

        assert_eq!(classify(1).unwrap().algorithm, Algorithm::Uncompressed);
        assert_eq!(classify(9).unwrap().storage, Storage::Inline);
        assert_eq!(classify(10).unwrap().storage, Storage::ResourceFork);
        assert!(matches!(
            classify(0x8000_0001),
            Err(DecmpfsError::DatalessCompressionType(_))
        ));
    }

    #[test]
    fn rejects_bad_or_oversized_headers() {
        assert!(matches!(
            parse_header(b"short", DecodeLimits::default()),
            Err(DecmpfsError::TruncatedHeader { .. })
        ));
        let mut bad = header(1, 0, b"");
        bad[0] = 0;
        assert!(matches!(
            parse_header(&bad, DecodeLimits::default()),
            Err(DecmpfsError::BadMagic { .. })
        ));
        let limits = DecodeLimits {
            max_uncompressed_size: 3,
            ..DecodeLimits::default()
        };
        assert!(matches!(
            parse_header(&header(1, 4, b"test"), limits),
            Err(DecmpfsError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn decodes_inline_uncompressed_variants() {
        for kind in [1, 9] {
            assert_eq!(
                decompress_decmpfs(&header(kind, 5, b"hello"), None).unwrap(),
                b"hello"
            );
        }
        // A leading 0xcc is ordinary data when it is part of the declared
        // output size, but is a stored marker when it is one extra byte.
        assert_eq!(
            decompress_decmpfs(&header(1, 2, &[0xcc, b'x']), None).unwrap(),
            [0xcc, b'x']
        );
        assert_eq!(
            decompress_decmpfs(&header(9, 1, &[0xcc, b'\n']), None).unwrap(),
            [b'\n']
        );
    }

    #[test]
    fn decodes_inline_zlib_and_stored_marker() {
        assert_eq!(
            decompress_decmpfs(&header(3, 5, &zlib(b"hello")), None).unwrap(),
            b"hello"
        );
        assert_eq!(
            decompress_decmpfs(&header(3, 5, b"\xffhello"), None).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decodes_inline_lzvn_and_stored_marker() {
        // Large-literal opcode, five literals, then the LZVN EOS opcode plus
        // its seven padding bytes.
        let stream = [
            0xe5, b'h', b'e', b'l', b'l', b'o', 0x06, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            decompress_decmpfs(&header(7, 5, &stream), None).unwrap(),
            b"hello"
        );
        assert_eq!(
            decompress_decmpfs(&header(7, 5, b"\x06hello"), None).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decodes_inline_lzfse_and_stored_marker() {
        // Reference lzfse_rust fixture: one uncompressed `bvx-` block and EOS.
        let stream = [
            0x62, 0x76, 0x78, 0x2d, 0x04, 0, 0, 0, b't', b'e', b's', b't', 0x62, 0x76, 0x78, 0x24,
        ];
        assert_eq!(
            decompress_decmpfs(&header(11, 4, &stream), None).unwrap(),
            b"test"
        );
        assert_eq!(
            decompress_decmpfs(&header(11, 4, b"\xfftest"), None).unwrap(),
            b"test"
        );
    }

    #[test]
    fn decodes_type4_fixed_zlib_resource_fork() {
        let fork = fixed_zlib_fork(&[zlib(b"hello")]);
        assert_eq!(
            decompress_decmpfs(&header(4, 5, b""), Some(&fork)).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn decodes_absolute_resource_variants() {
        let lzvn = [
            0xe5, b'h', b'e', b'l', b'l', b'o', 0x06, 0, 0, 0, 0, 0, 0, 0,
        ];
        let fork = absolute_fork(&[&lzvn]);
        assert_eq!(
            decompress_decmpfs(&header(8, 5, b""), Some(&fork)).unwrap(),
            b"hello"
        );

        let plain = b"\xccplain";
        let fork = absolute_fork(&[plain]);
        assert_eq!(
            decompress_decmpfs(&header(10, 5, b""), Some(&fork)).unwrap(),
            b"plain"
        );

        let lzfse = [
            0x62, 0x76, 0x78, 0x2d, 0x04, 0, 0, 0, b't', b'e', b's', b't', 0x62, 0x76, 0x78, 0x24,
        ];
        let fork = absolute_fork(&[&lzfse]);
        assert_eq!(
            decompress_decmpfs(&header(12, 4, b""), Some(&fork)).unwrap(),
            b"test"
        );
    }

    #[test]
    fn decodes_multiple_absolute_chunks() {
        let first = vec![b'x'; CHUNK_SIZE];
        let mut stored_first = vec![PLAIN_STORED_MARKER];
        stored_first.extend_from_slice(&first);
        let stored_last = [PLAIN_STORED_MARKER, b'e', b'n', b'd'];
        let fork = absolute_fork(&[&stored_first, &stored_last]);
        let decoded = decompress_decmpfs(&header(10, CHUNK_SIZE + 3, b""), Some(&fork)).unwrap();
        assert_eq!(decoded.len(), CHUNK_SIZE + 3);
        assert_eq!(&decoded[..CHUNK_SIZE], first);
        assert_eq!(&decoded[CHUNK_SIZE..], b"end");
    }

    #[test]
    fn rejects_missing_or_malformed_resource_forks() {
        assert!(matches!(
            decompress_decmpfs(&header(8, 5, b""), None),
            Err(DecmpfsError::MissingResourceFork { .. })
        ));

        let mut fork = absolute_fork(&[b"\xcchello"]);
        // Force the first offset to overlap the table.
        fork[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            decompress_decmpfs(&header(10, 5, b""), Some(&fork)),
            Err(DecmpfsError::InvalidResourceFork(_))
        ));
    }

    #[test]
    fn never_returns_partial_output_on_size_mismatch() {
        assert!(matches!(
            decompress_decmpfs(&header(1, 6, b"short"), None),
            Err(DecmpfsError::SizeMismatch {
                expected: 6,
                actual: 5
            })
        ));
        assert!(matches!(
            decompress_decmpfs(&header(3, 6, &zlib(b"short")), None),
            Err(DecmpfsError::SizeMismatch {
                expected: 6,
                actual: 5
            })
        ));
    }
}
