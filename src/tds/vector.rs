//! The SQL Server 2025 `vector` data type.
//!
//! A `vector` column holds a fixed number of floating point elements. With
//! [`Config::vector_support`] enabled, `float32` vectors travel in their native
//! binary form and are read and written as [`Vector`]; otherwise the server
//! exposes them as `varchar(max)` JSON arrays.
//!
//! [`Config::vector_support`]: crate::Config::vector_support

use std::{fmt, str::FromStr};

/// Size of the vector header that precedes the element bytes on the wire.
pub(crate) const VECTOR_HEADER_SIZE: usize = 8;
/// Magic number in the first header byte ("layout format").
const VECTOR_MAGIC: u8 = 0xA9;
/// Layout version in the second header byte.
const VECTOR_LAYOUT_VERSION: u8 = 0x01;
/// Bytes per `float32` element.
const FLOAT32_SIZE: usize = 4;
/// The most `float32` elements whose payload (header + elements) still fits a
/// `u16` length prefix. SQL Server itself caps `vector` at 1998 dimensions and
/// rejects larger values; this bound only keeps the encoding well-formed.
const MAX_FLOAT32_DIMENSIONS: usize = (u16::MAX as usize - VECTOR_HEADER_SIZE) / FLOAT32_SIZE;

/// The element (base) type of a `vector` column, sent as the `SCALE` byte of
/// the column's `TYPE_INFO` and in the vector header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum VectorElementType {
    /// Single-precision (4-byte) floating point, the default base type.
    Float32,
}

impl VectorElementType {
    /// The wire value of the element type.
    pub(crate) fn to_u8(self) -> u8 {
        match self {
            VectorElementType::Float32 => 0x00,
        }
    }

    /// Parses the wire value of the element type. Only `float32` (`0x00`) is
    /// negotiated by this client.
    pub(crate) fn from_u8(value: u8) -> crate::Result<Self> {
        match value {
            0x00 => Ok(VectorElementType::Float32),
            other => Err(crate::Error::Protocol(
                format!("unsupported vector element type {other:#04x}").into(),
            )),
        }
    }

    /// Bytes per element.
    pub(crate) fn size(self) -> usize {
        match self {
            VectorElementType::Float32 => FLOAT32_SIZE,
        }
    }
}

/// A `vector` value: a list of `float32` elements.
///
/// ```
/// use tiberius::vector::Vector;
///
/// let v = Vector::from(vec![0.1f32, 0.2, 0.3]);
/// assert_eq!(v.dimensions(), 3);
/// assert_eq!(v.as_slice()[1], 0.2);
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vector {
    values: Vec<f32>,
}

impl Vector {
    /// Creates a `float32` vector from its elements.
    pub fn new(values: Vec<f32>) -> Self {
        Self { values }
    }

    /// The element type of the vector.
    pub fn element_type(&self) -> VectorElementType {
        VectorElementType::Float32
    }

    /// The number of elements.
    pub fn dimensions(&self) -> usize {
        self.values.len()
    }

    /// The elements of the vector.
    pub fn as_slice(&self) -> &[f32] {
        &self.values
    }

    /// Takes the elements out of the vector.
    pub fn into_vec(self) -> Vec<f32> {
        self.values
    }

    /// The size in bytes of the encoded value (header plus elements).
    pub(crate) fn encoded_len(&self) -> usize {
        VECTOR_HEADER_SIZE + self.values.len() * FLOAT32_SIZE
    }

    /// Encodes the value in the TDS vector layout:
    ///
    /// | bytes | field                        |
    /// |-------|------------------------------|
    /// | 1     | layout format, `0xA9`        |
    /// | 1     | layout version, `0x01`       |
    /// | 2     | number of elements (LE)      |
    /// | 1     | element type (`0` = float32) |
    /// | 3     | reserved, zero               |
    /// | n * 4 | elements, little-endian      |
    pub(crate) fn encode_payload(&self) -> crate::Result<Vec<u8>> {
        let dims = self.values.len();

        if dims == 0 || dims > MAX_FLOAT32_DIMENSIONS {
            return Err(crate::Error::Conversion(
                format!(
                    "a vector must have between 1 and {MAX_FLOAT32_DIMENSIONS} elements, got {dims}"
                )
                .into(),
            ));
        }

        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(VECTOR_MAGIC);
        out.push(VECTOR_LAYOUT_VERSION);
        out.extend_from_slice(&(dims as u16).to_le_bytes());
        out.push(self.element_type().to_u8());
        out.extend_from_slice(&[0u8; 3]);

        for value in &self.values {
            out.extend_from_slice(&value.to_le_bytes());
        }

        Ok(out)
    }

    /// Decodes a value in the TDS vector layout (see [`Self::encode_payload`]),
    /// validating the header against the payload length.
    pub(crate) fn decode_payload(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < VECTOR_HEADER_SIZE {
            return Err(crate::Error::Protocol(
                format!(
                    "vector value of {} bytes is shorter than its header",
                    bytes.len()
                )
                .into(),
            ));
        }

        if bytes[0] != VECTOR_MAGIC || bytes[1] != VECTOR_LAYOUT_VERSION {
            return Err(crate::Error::Protocol(
                format!(
                    "invalid vector header: layout {:#04x}, version {:#04x}",
                    bytes[0], bytes[1]
                )
                .into(),
            ));
        }

        let dims = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let element_type = VectorElementType::from_u8(bytes[4])?;
        let expected = VECTOR_HEADER_SIZE + dims * element_type.size();

        if bytes.len() != expected {
            return Err(crate::Error::Protocol(
                format!(
                    "vector value of {} bytes does not match its header ({dims} elements, {expected} bytes)",
                    bytes.len()
                )
                .into(),
            ));
        }

        let values = bytes[VECTOR_HEADER_SIZE..]
            .as_chunks::<FLOAT32_SIZE>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes(*c))
            .collect();

        Ok(Self { values })
    }

    /// The JSON-array text form, e.g. `[0.1,0.2,0.3]`, which SQL Server
    /// converts implicitly to `vector`. Used when native vector support was
    /// not negotiated.
    pub(crate) fn to_json_text(&self) -> String {
        self.to_string()
    }
}

/// Formats the vector as a JSON array, e.g. `[0.1,0.2,0.3]`.
impl fmt::Display for Vector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{value}")?;
        }
        f.write_str("]")
    }
}

/// Parses the JSON-array text form of a vector, e.g. `[0.1, 0.2]` or the
/// `[1.0000000e-001,2.0000000e-001]` that SQL Server produces when native
/// vector support is not negotiated.
impl FromStr for Vector {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || crate::Error::Conversion(format!("invalid vector text: {s:?}").into());

        let inner = s
            .trim()
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or_else(invalid)?
            .trim();

        if inner.is_empty() {
            return Err(invalid());
        }

        let values = inner
            .split(',')
            .map(|part| part.trim().parse::<f32>().map_err(|_| invalid()))
            .collect::<Result<Vec<_>, _>>()?;

        if values.iter().any(|v| !v.is_finite()) {
            return Err(invalid());
        }

        Ok(Self { values })
    }
}

impl From<Vec<f32>> for Vector {
    fn from(values: Vec<f32>) -> Self {
        Self::new(values)
    }
}

impl From<&[f32]> for Vector {
    fn from(values: &[f32]) -> Self {
        Self::new(values.to_vec())
    }
}

impl From<Vector> for Vec<f32> {
    fn from(vector: Vector) -> Self {
        vector.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_header_and_little_endian_elements() {
        let bytes = Vector::from(vec![1.0f32, -2.5]).encode_payload().unwrap();

        let mut expected = vec![0xA9, 0x01, 2, 0, 0x00, 0, 0, 0];
        expected.extend_from_slice(&1.0f32.to_le_bytes());
        expected.extend_from_slice(&(-2.5f32).to_le_bytes());

        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), Vector::from(vec![1.0f32, -2.5]).encoded_len());
    }

    #[test]
    fn round_trips() {
        let v = Vector::from(vec![0.1f32, 0.2, 0.3, f32::MIN_POSITIVE]);
        let decoded = Vector::decode_payload(&v.encode_payload().unwrap()).unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn rejects_empty_and_oversized_vectors() {
        assert!(Vector::new(vec![]).encode_payload().is_err());
        assert!(Vector::new(vec![0.0; MAX_FLOAT32_DIMENSIONS])
            .encode_payload()
            .is_ok());
        assert!(Vector::new(vec![0.0; MAX_FLOAT32_DIMENSIONS + 1])
            .encode_payload()
            .is_err());
    }

    #[test]
    fn rejects_bad_magic_version_and_element_type() {
        let good = Vector::from(vec![1.0f32]).encode_payload().unwrap();

        let mut bad = good.clone();
        bad[0] = 0x00;
        assert!(Vector::decode_payload(&bad).is_err());

        let mut bad = good.clone();
        bad[1] = 0x02;
        assert!(Vector::decode_payload(&bad).is_err());

        let mut bad = good;
        bad[4] = 0x01; // float16 is not negotiated
        assert!(Vector::decode_payload(&bad).is_err());
    }

    #[test]
    fn rejects_length_mismatch_and_short_input() {
        let good = Vector::from(vec![1.0f32, 2.0]).encode_payload().unwrap();
        assert!(Vector::decode_payload(&good[..good.len() - 1]).is_err());
        assert!(Vector::decode_payload(&good[..4]).is_err());

        let mut longer = good;
        longer.extend_from_slice(&[0, 0, 0, 0]);
        assert!(Vector::decode_payload(&longer).is_err());
    }

    #[test]
    fn parses_server_and_plain_json_text() {
        let v: Vector = "[1.0000000e-001,2.0000000e-001,3.0000001e-001]"
            .parse()
            .unwrap();
        assert_eq!(v.as_slice(), &[0.1f32, 0.2, 0.3]);

        let v: Vector = " [ 1, -2.5 ,3e2 ] ".parse().unwrap();
        assert_eq!(v.as_slice(), &[1.0f32, -2.5, 300.0]);

        for bad in ["", "[]", "1,2", "[1,]", "[a]", "[NaN]", "[inf]"] {
            assert!(bad.parse::<Vector>().is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn display_round_trips_through_from_str() {
        let v = Vector::from(vec![0.1f32, -2.0, 1e-7, 123456.79]);
        let parsed: Vector = v.to_string().parse().unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn json_text() {
        assert_eq!(
            Vector::from(vec![0.1f32, -2.0, 3.5]).to_json_text(),
            "[0.1,-2,3.5]"
        );
    }
}
