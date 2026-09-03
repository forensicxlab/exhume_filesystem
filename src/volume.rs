//! Composable block-volume views.
//!
//! A volume starts as a checked extent of an evidence [`Body`].  Optional
//! layers can replace that reader with another logical block view (for
//! example, a BitLocker-decrypted view) without coupling the exporter to a
//! filesystem or encryption format.

pub use exhume_body::VolumeReader;
use exhume_body::{Body, BodySlice};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

pub type BoxVolumeReader = Box<dyn VolumeReader>;
pub type BoxLayerError = Box<dyn Error + Send + Sync + 'static>;

/// A byte-accurate partition or container extent in its parent evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeExtent {
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub sector_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl VolumeExtent {
    pub fn new(
        offset_bytes: u64,
        length_bytes: u64,
        sector_size: u32,
    ) -> Result<Self, VolumeError> {
        let extent = Self {
            offset_bytes,
            length_bytes,
            sector_size,
            partition_index: None,
            partition_guid: None,
            label: None,
        };
        extent.validate()?;
        Ok(extent)
    }

    /// Construct from normalized partition geometry whose sector size is a
    /// `u64` (as used by partition-table parsers), with checked narrowing.
    pub fn from_parts(
        offset_bytes: u64,
        length_bytes: u64,
        sector_size: u64,
    ) -> Result<Self, VolumeError> {
        let sector_size = u32::try_from(sector_size).map_err(|_| {
            VolumeError::InvalidExtent(format!("sector size {sector_size} does not fit in u32"))
        })?;
        Self::new(offset_bytes, length_bytes, sector_size)
    }

    pub fn with_partition_identity(
        mut self,
        partition_index: Option<u32>,
        partition_guid: Option<String>,
        label: Option<String>,
    ) -> Self {
        self.partition_index = partition_index;
        self.partition_guid = partition_guid;
        self.label = label;
        self
    }

    pub fn end_bytes(&self) -> Result<u64, VolumeError> {
        self.offset_bytes
            .checked_add(self.length_bytes)
            .ok_or(VolumeError::InvalidExtent(
                "extent offset plus length overflows u64".to_owned(),
            ))
    }

    pub fn validate(&self) -> Result<(), VolumeError> {
        if self.length_bytes == 0 {
            return Err(VolumeError::InvalidExtent(
                "extent length must be greater than zero".to_owned(),
            ));
        }
        if self.sector_size == 0 || !self.sector_size.is_power_of_two() {
            return Err(VolumeError::InvalidExtent(
                "sector size must be a non-zero power of two".to_owned(),
            ));
        }
        let sector_size = u64::from(self.sector_size);
        if !self.offset_bytes.is_multiple_of(sector_size) {
            return Err(VolumeError::InvalidExtent(format!(
                "extent offset {} is not aligned to sector size {}",
                self.offset_bytes, self.sector_size
            )));
        }
        if !self.length_bytes.is_multiple_of(sector_size) {
            return Err(VolumeError::InvalidExtent(format!(
                "extent length {} is not aligned to sector size {}",
                self.length_bytes, self.sector_size
            )));
        }
        self.end_bytes()?;
        Ok(())
    }
}

/// Public, non-secret description of a transform in a volume pipeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeLayerDescriptor {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_parameters: BTreeMap<String, String>,
}

impl VolumeLayerDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            public_parameters: BTreeMap::new(),
        }
    }
}

/// A modular block transform. Implementations live with the format they know.
///
/// `descriptor` must never contain a password, FVEK, recovery key, or a
/// correlatable derivative of secret material. Resume identity is established
/// from public source geometry and verified logical bytes instead.
pub trait VolumeLayer: Send + Sync {
    fn descriptor(&self) -> VolumeLayerDescriptor;

    fn open(&self, source: BoxVolumeReader) -> Result<BoxVolumeReader, BoxLayerError>;

    /// Open the transform and return the descriptor resolved from the source.
    ///
    /// Most layers have a fully known descriptor before opening and can use
    /// this default. Metadata-driven formats may override it so the manifest
    /// records the validated on-disk layout rather than only configuration
    /// supplied by the caller.
    fn open_resolved(
        &self,
        source: BoxVolumeReader,
    ) -> Result<(BoxVolumeReader, VolumeLayerDescriptor), BoxLayerError> {
        let descriptor = self.descriptor();
        let reader = self.open(source)?;
        Ok((reader, descriptor))
    }
}

/// A source volume plus the ordered transformations applied to it.
pub struct VolumePipeline {
    reader: BoxVolumeReader,
    extent: Option<VolumeExtent>,
    layers: Vec<VolumeLayerDescriptor>,
}

impl VolumePipeline {
    /// Open a checked extent from a body as an untransformed physical view.
    pub fn from_body(body: &Body, extent: VolumeExtent) -> Result<Self, VolumeError> {
        extent.validate()?;
        let end = extent.end_bytes()?;
        if end > body.get_image_size() {
            return Err(VolumeError::InvalidExtent(format!(
                "extent ends at {end}, beyond image length {}",
                body.get_image_size()
            )));
        }
        if u32::from(body.get_sector_size()) != extent.sector_size {
            return Err(VolumeError::InvalidExtent(format!(
                "extent sector size {} differs from evidence sector size {}",
                extent.sector_size,
                body.get_sector_size()
            )));
        }

        let slice = BodySlice::new(body, extent.offset_bytes, extent.length_bytes)
            .map_err(VolumeError::Io)?;
        Ok(Self {
            reader: Box::new(slice),
            extent: Some(extent),
            layers: Vec::new(),
        })
    }

    /// Build a pipeline around any already-bounded reader.
    pub fn from_reader(reader: BoxVolumeReader) -> Result<Self, VolumeError> {
        validate_reader(reader.as_ref())?;
        Ok(Self {
            reader,
            extent: None,
            layers: Vec::new(),
        })
    }

    pub fn apply<L: VolumeLayer + 'static>(self, layer: L) -> Result<Self, VolumeError> {
        self.apply_boxed(Box::new(layer))
    }

    pub fn apply_boxed(self, layer: Box<dyn VolumeLayer>) -> Result<Self, VolumeError> {
        let declared_descriptor = layer.descriptor();
        if declared_descriptor.name.trim().is_empty() {
            return Err(VolumeError::InvalidLayer(
                "layer name must not be empty".to_owned(),
            ));
        }
        let (reader, descriptor) =
            layer
                .open_resolved(self.reader)
                .map_err(|source| VolumeError::Layer {
                    layer: declared_descriptor.name.clone(),
                    source,
                })?;
        if descriptor.name.trim().is_empty() {
            return Err(VolumeError::InvalidLayer(
                "resolved layer name must not be empty".to_owned(),
            ));
        }
        if descriptor.name != declared_descriptor.name {
            return Err(VolumeError::InvalidLayer(format!(
                "resolved layer name {:?} differs from declared name {:?}",
                descriptor.name, declared_descriptor.name
            )));
        }
        validate_reader(reader.as_ref())?;

        let mut layers = self.layers;
        layers.push(descriptor);
        Ok(Self {
            reader,
            extent: self.extent,
            layers,
        })
    }

    pub fn extent(&self) -> Option<&VolumeExtent> {
        self.extent.as_ref()
    }

    pub fn layers(&self) -> &[VolumeLayerDescriptor] {
        &self.layers
    }

    pub fn reader_mut(&mut self) -> &mut dyn VolumeReader {
        self.reader.as_mut()
    }

    pub fn into_reader(self) -> BoxVolumeReader {
        self.reader
    }
}

impl Read for VolumePipeline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Seek for VolumePipeline {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.reader.seek(pos)
    }
}

impl VolumeReader for VolumePipeline {
    fn volume_len(&self) -> u64 {
        self.reader.volume_len()
    }

    fn sector_size(&self) -> u32 {
        self.reader.sector_size()
    }
}

fn validate_reader(reader: &dyn VolumeReader) -> Result<(), VolumeError> {
    if reader.volume_len() == 0 {
        return Err(VolumeError::InvalidReader(
            "volume length must be greater than zero".to_owned(),
        ));
    }
    if reader.sector_size() == 0 || !reader.sector_size().is_power_of_two() {
        return Err(VolumeError::InvalidReader(
            "sector size must be a non-zero power of two".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum VolumeError {
    InvalidExtent(String),
    InvalidReader(String),
    InvalidLayer(String),
    Io(io::Error),
    Layer {
        layer: String,
        source: BoxLayerError,
    },
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExtent(message) => write!(f, "invalid volume extent: {message}"),
            Self::InvalidReader(message) => write!(f, "invalid volume reader: {message}"),
            Self::InvalidLayer(message) => write!(f, "invalid volume layer: {message}"),
            Self::Io(error) => write!(f, "volume I/O error: {error}"),
            Self::Layer { layer, source } => {
                write!(f, "volume layer '{layer}' failed: {source}")
            }
        }
    }
}

impl Error for VolumeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Layer { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for VolumeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct TestReader {
        inner: Cursor<Vec<u8>>,
        sector_size: u32,
    }

    impl Read for TestReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl Seek for TestReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    impl VolumeReader for TestReader {
        fn volume_len(&self) -> u64 {
            self.inner.get_ref().len() as u64
        }

        fn sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    struct XorLayer(u8);

    struct ResolvedDescriptorLayer;

    struct XorReader {
        source: BoxVolumeReader,
        key: u8,
    }

    impl Read for XorReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.source.read(buf)?;
            for byte in &mut buf[..read] {
                *byte ^= self.key;
            }
            Ok(read)
        }
    }

    impl Seek for XorReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.source.seek(pos)
        }
    }

    impl VolumeReader for XorReader {
        fn volume_len(&self) -> u64 {
            self.source.volume_len()
        }

        fn sector_size(&self) -> u32 {
            self.source.sector_size()
        }
    }

    impl VolumeLayer for XorLayer {
        fn descriptor(&self) -> VolumeLayerDescriptor {
            VolumeLayerDescriptor::new("test-xor")
        }

        fn open(&self, source: BoxVolumeReader) -> Result<BoxVolumeReader, BoxLayerError> {
            Ok(Box::new(XorReader {
                source,
                key: self.0,
            }))
        }
    }

    impl VolumeLayer for ResolvedDescriptorLayer {
        fn descriptor(&self) -> VolumeLayerDescriptor {
            VolumeLayerDescriptor::new("test-resolved")
        }

        fn open(&self, source: BoxVolumeReader) -> Result<BoxVolumeReader, BoxLayerError> {
            Ok(source)
        }

        fn open_resolved(
            &self,
            source: BoxVolumeReader,
        ) -> Result<(BoxVolumeReader, VolumeLayerDescriptor), BoxLayerError> {
            let mut descriptor = self.descriptor();
            descriptor
                .public_parameters
                .insert("discovered".to_owned(), "true".to_owned());
            Ok((source, descriptor))
        }
    }

    #[test]
    fn extent_rejects_unaligned_and_overflowing_ranges() {
        assert!(VolumeExtent::new(1, 512, 512).is_err());
        assert!(VolumeExtent::new(0, 513, 512).is_err());
        assert!(VolumeExtent::new(u64::MAX - 511, 512, 512).is_err());
    }

    #[test]
    fn layers_compose_without_exporter_format_knowledge() {
        let source = TestReader {
            inner: Cursor::new(vec![0x11; 512]),
            sector_size: 512,
        };
        let mut pipeline = VolumePipeline::from_reader(Box::new(source))
            .unwrap()
            .apply(XorLayer(0xff))
            .unwrap()
            .apply(XorLayer(0x0f))
            .unwrap();

        let mut output = vec![0; 512];
        pipeline.read_exact(&mut output).unwrap();
        assert!(output.iter().all(|byte| *byte == (0x11 ^ 0xff ^ 0x0f)));
        assert_eq!(pipeline.layers().len(), 2);
        assert_eq!(pipeline.volume_len(), 512);
    }

    #[test]
    fn pipeline_records_the_descriptor_resolved_while_opening() {
        let source = TestReader {
            inner: Cursor::new(vec![0; 512]),
            sector_size: 512,
        };
        let pipeline = VolumePipeline::from_reader(Box::new(source))
            .unwrap()
            .apply(ResolvedDescriptorLayer)
            .unwrap();

        assert_eq!(
            pipeline.layers()[0]
                .public_parameters
                .get("discovered")
                .map(String::as_str),
            Some("true")
        );
    }
}
