//! BitLocker transform adapter for the generic volume pipeline.
//!
//! BitLocker format knowledge remains in `exhume_ntfs`; this module only binds
//! its bounded reader to [`crate::volume::VolumeLayer`]. Secret material is
//! zeroized when the layer is dropped and is never included in descriptors.

use crate::volume::{BoxLayerError, BoxVolumeReader, VolumeLayer, VolumeLayerDescriptor};
use exhume_ntfs::bitlocker::{
    BitLockerEncryptionMethod, BitLockerLayout, BitLockerStream, BitLockerVolumeOptions,
    EncryptedBoundaryInterpretation,
};
use std::error::Error;
use std::fmt;
use std::io;
use zeroize::Zeroizing;

/// A metadata-driven BitLocker decryption layer.
///
/// `partition_offset_bytes` is the absolute offset of the bounded source in its
/// parent disk image. BitLocker metadata can contain absolute-disk boundaries,
/// so omitting this geometry can silently select the wrong encrypted range.
pub struct BitLockerLayer {
    fvek: Zeroizing<Vec<u8>>,
    partition_offset_bytes: u64,
    volume_len: u64,
    sector_size: u32,
}

impl BitLockerLayer {
    pub fn new(
        fvek: Vec<u8>,
        partition_offset_bytes: u64,
        volume_len: u64,
        sector_size: u32,
    ) -> Result<Self, BitLockerLayerError> {
        // Wrap the caller-owned buffer before any validation can fail so every
        // return path scrubs the supplied key material.
        let fvek = Zeroizing::new(fvek);
        if !matches!(fvek.len(), 32 | 64) {
            return Err(BitLockerLayerError::InvalidConfiguration(
                "FVEK must contain 32 bytes for AES-XTS-128 or 64 bytes for AES-XTS-256".to_owned(),
            ));
        }
        if volume_len == 0 {
            return Err(BitLockerLayerError::InvalidConfiguration(
                "BitLocker volume length must be greater than zero".to_owned(),
            ));
        }
        if sector_size == 0 || !sector_size.is_power_of_two() {
            return Err(BitLockerLayerError::InvalidConfiguration(
                "BitLocker sector size must be a non-zero power of two".to_owned(),
            ));
        }
        if partition_offset_bytes % u64::from(sector_size) != 0
            || volume_len % u64::from(sector_size) != 0
        {
            return Err(BitLockerLayerError::InvalidConfiguration(
                "BitLocker partition offset and length must be sector-aligned".to_owned(),
            ));
        }

        Ok(Self {
            fvek,
            partition_offset_bytes,
            volume_len,
            sector_size,
        })
    }

    fn open_stream(
        &self,
        source: BoxVolumeReader,
    ) -> Result<BitLockerStream<BoxVolumeReader>, BitLockerLayerError> {
        if source.volume_len() != self.volume_len {
            return Err(BitLockerLayerError::InvalidConfiguration(format!(
                "source volume length {} differs from configured BitLocker length {}",
                source.volume_len(),
                self.volume_len
            )));
        }
        if source.sector_size() != self.sector_size {
            return Err(BitLockerLayerError::InvalidConfiguration(format!(
                "source sector size {} differs from configured BitLocker sector size {}",
                source.sector_size(),
                self.sector_size
            )));
        }

        let options = BitLockerVolumeOptions::new(self.volume_len, u64::from(self.sector_size))
            .with_partition_offset_bytes(self.partition_offset_bytes);
        BitLockerStream::new_with_options(source, &self.fvek, options)
            .map_err(BitLockerLayerError::Open)
    }

    fn resolved_descriptor(&self, layout: &BitLockerLayout) -> VolumeLayerDescriptor {
        let mut descriptor = self.descriptor();
        let parameters = &mut descriptor.public_parameters;
        parameters.insert(
            "encryption_method".to_owned(),
            match layout.encryption_method() {
                BitLockerEncryptionMethod::AesXts128 => "aes-xts-128",
                BitLockerEncryptionMethod::AesXts256 => "aes-xts-256",
            }
            .to_owned(),
        );
        parameters.insert(
            "fve_block_header_version".to_owned(),
            layout.block_header_version().to_string(),
        );
        parameters.insert(
            "raw_encrypted_volume_size_bytes".to_owned(),
            layout.raw_encrypted_volume_size().to_string(),
        );
        parameters.insert(
            "encrypted_boundary_bytes".to_owned(),
            layout.encrypted_boundary().to_string(),
        );
        parameters.insert(
            "encrypted_boundary_interpretation".to_owned(),
            match layout.encrypted_boundary_interpretation() {
                EncryptedBoundaryInterpretation::NotPresent => "not-present",
                EncryptedBoundaryInterpretation::PartitionRelative => "partition-relative",
                EncryptedBoundaryInterpretation::AbsoluteDisk => "absolute-disk",
            }
            .to_owned(),
        );
        parameters.insert(
            "metadata_offsets_bytes".to_owned(),
            layout
                .metadata_offsets()
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        parameters.insert(
            "metadata_region_size_bytes".to_owned(),
            layout.metadata_region_size().to_string(),
        );
        parameters.insert(
            "metadata_payload_size_bytes".to_owned(),
            layout.metadata_payload_size().to_string(),
        );
        parameters.insert(
            "selected_metadata_copy_zero_based".to_owned(),
            layout.selected_metadata_copy().to_string(),
        );
        let relocated = layout.relocated_header();
        parameters.insert(
            "relocated_header_offset_bytes".to_owned(),
            relocated.offset().to_string(),
        );
        parameters.insert(
            "relocated_header_length_bytes".to_owned(),
            relocated.length().to_string(),
        );
        parameters.insert(
            "layout_identifier".to_owned(),
            format_guid_le(layout.layout_identifier()),
        );
        parameters.insert(
            "volume_identifier".to_owned(),
            format_guid_le(layout.volume_identifier()),
        );
        descriptor
    }
}

impl VolumeLayer for BitLockerLayer {
    fn descriptor(&self) -> VolumeLayerDescriptor {
        let mut descriptor = VolumeLayerDescriptor::new("bitlocker");
        descriptor.version = Some("fve-metadata-v1".to_owned());
        descriptor.public_parameters.insert(
            "encryption_method".to_owned(),
            "metadata-derived-aes-xts".to_owned(),
        );
        descriptor.public_parameters.insert(
            "partition_offset_bytes".to_owned(),
            self.partition_offset_bytes.to_string(),
        );
        descriptor
            .public_parameters
            .insert("volume_len".to_owned(), self.volume_len.to_string());
        descriptor
            .public_parameters
            .insert("sector_size".to_owned(), self.sector_size.to_string());
        descriptor
    }

    fn open(&self, source: BoxVolumeReader) -> Result<BoxVolumeReader, BoxLayerError> {
        let stream = self.open_stream(source)?;
        Ok(Box::new(stream))
    }

    fn open_resolved(
        &self,
        source: BoxVolumeReader,
    ) -> Result<(BoxVolumeReader, VolumeLayerDescriptor), BoxLayerError> {
        let stream = self.open_stream(source)?;
        let descriptor = self.resolved_descriptor(stream.layout());
        Ok((Box::new(stream), descriptor))
    }
}

fn format_guid_le(bytes: [u8; 16]) -> String {
    let first = u32::from_le_bytes(bytes[0..4].try_into().expect("fixed GUID field"));
    let second = u16::from_le_bytes(bytes[4..6].try_into().expect("fixed GUID field"));
    let third = u16::from_le_bytes(bytes[6..8].try_into().expect("fixed GUID field"));
    format!(
        "{first:08x}-{second:04x}-{third:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

#[derive(Debug)]
pub enum BitLockerLayerError {
    InvalidConfiguration(String),
    Open(io::Error),
}

impl fmt::Display for BitLockerLayerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => formatter.write_str(message),
            Self::Open(error) => write!(formatter, "cannot open BitLocker volume: {error}"),
        }
    }
}

impl Error for BitLockerLayerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open(error) => Some(error),
            Self::InvalidConfiguration(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exhume_body::VolumeReader;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    struct TestVolume {
        inner: Cursor<Vec<u8>>,
        sector_size: u32,
    }

    impl Read for TestVolume {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Seek for TestVolume {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.inner.seek(position)
        }
    }

    impl VolumeReader for TestVolume {
        fn volume_len(&self) -> u64 {
            self.inner.get_ref().len() as u64
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    #[test]
    fn rejects_mismatched_source_geometry_before_format_parsing() {
        let layer = BitLockerLayer::new(vec![0x5a; 32], 4096, 1024, 512).unwrap();
        let source = TestVolume {
            inner: Cursor::new(vec![0; 512]),
            sector_size: 512,
        };
        let error = match layer.open(Box::new(source)) {
            Ok(_) => panic!("mismatched source geometry must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("source volume length"));
    }

    #[test]
    fn public_descriptor_never_contains_raw_fvek() {
        let layer = BitLockerLayer::new(vec![0xab; 32], 4096, 1024, 512).unwrap();
        let encoded = serde_json::to_string(&layer.descriptor()).unwrap();
        assert!(!encoded.contains(&"ab".repeat(32)));
        assert!(!encoded.contains("key_identifier"));
    }

    #[test]
    fn formats_on_disk_guid_bytes_canonically() {
        assert_eq!(
            format_guid_le([
                0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
                0xd0, 0x01,
            ]),
            "4967d63b-2e29-4ad8-8399-f6a339e3d001"
        );
    }
}
