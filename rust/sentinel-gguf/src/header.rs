// header.rs — GGUF binary header parser
//
// GGUF format (v3):
//   Bytes 0..4    : magic "GGUF"
//   Bytes 4..8    : version (u32 LE)
//   Bytes 8..16   : tensor_count (u64 LE)
//   Bytes 16..24  : kv_count (u64 LE)
//   Then kv_count KV pairs, each:
//     - key_len (u64 LE) + key bytes
//     - value_type (u32 LE)
//     - value data (type-dependent)

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Data too short: need at least 24 bytes, got {0}")]
    TooShort(usize),

    #[error("Invalid magic: expected 'GGUF', got {0:?}")]
    BadMagic([u8; 4]),

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),

    #[error("Truncated KV pair at offset {0}")]
    TruncatedKV(usize),
}

/// GGUF value types (from spec)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GgufType {
    Uint8    = 0,
    Int8     = 1,
    Uint16   = 2,
    Int16    = 3,
    Uint32   = 4,
    Int32    = 5,
    Float32  = 6,
    Bool     = 7,
    String   = 8,
    Array    = 9,
    Uint64   = 10,
    Int64    = 11,
    Float64  = 12,
    Unknown,
}

impl From<u32> for GgufType {
    fn from(v: u32) -> Self {
        match v {
            0  => GgufType::Uint8,
            1  => GgufType::Int8,
            2  => GgufType::Uint16,
            3  => GgufType::Int16,
            4  => GgufType::Uint32,
            5  => GgufType::Int32,
            6  => GgufType::Float32,
            7  => GgufType::Bool,
            8  => GgufType::String,
            9  => GgufType::Array,
            10 => GgufType::Uint64,
            11 => GgufType::Int64,
            12 => GgufType::Float64,
            _  => GgufType::Unknown,
        }
    }
}

/// A parsed KV entry from the GGUF header.
#[derive(Debug, Clone)]
pub struct KVEntry {
    pub key: String,
    pub value_type: GgufType,
    /// String representation of the value (for string type) or raw hex.
    pub value_str: String,
    /// Byte length of the raw value.
    pub value_len: usize,
    /// Offset in the original data where the KV starts.
    pub offset: usize,
}

/// Parsed GGUF header.
#[derive(Debug, Clone)]
pub struct GgufHeader {
    pub version: u32,
    pub tensor_count: u64,
    pub kv_count: u64,
    pub kv_entries: Vec<KVEntry>,
    pub data_len: usize,
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Parse a GGUF header from raw bytes.
pub fn parse(data: &[u8]) -> Result<GgufHeader, ParseError> {
    if data.len() < 24 {
        return Err(ParseError::TooShort(data.len()));
    }

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[0..4]);
    if &magic != b"GGUF" {
        return Err(ParseError::BadMagic(magic));
    }

    let version = read_u32_le(data, 4).unwrap();
    if version == 0 || version > 3 {
        return Err(ParseError::UnsupportedVersion(version));
    }

    let tensor_count = read_u64_le(data, 8).unwrap();
    let kv_count = read_u64_le(data, 16).unwrap();

    // Parse KV pairs (up to 10_000 to avoid DoS)
    let max_kv = kv_count.min(10_000) as usize;
    let mut entries = Vec::with_capacity(max_kv);
    let mut offset = 24usize;

    for _ in 0..max_kv {
        if offset + 8 > data.len() {
            break;
        }
        let kv_start = offset;

        // Read key
        let key_len = read_u64_le(data, offset).unwrap_or(0) as usize;
        offset += 8;
        if offset + key_len > data.len() {
            break;
        }
        let key = String::from_utf8_lossy(&data[offset..offset + key_len]).to_string();
        offset += key_len;

        // Read value type
        if offset + 4 > data.len() {
            break;
        }
        let vtype_raw = read_u32_le(data, offset).unwrap_or(0xFF);
        let vtype = GgufType::from(vtype_raw);
        offset += 4;

        // Read value based on type
        let (value_str, value_len) = match vtype {
            GgufType::String => {
                if offset + 8 > data.len() {
                    break;
                }
                let slen = read_u64_le(data, offset).unwrap_or(0) as usize;
                offset += 8;
                let slen = slen.min(data.len().saturating_sub(offset));
                let s = String::from_utf8_lossy(&data[offset..offset + slen]).to_string();
                offset += slen;
                (s, slen)
            }
            GgufType::Uint32 | GgufType::Int32 | GgufType::Float32 => {
                if offset + 4 > data.len() {
                    break;
                }
                let val = read_u32_le(data, offset).unwrap_or(0);
                offset += 4;
                (format!("{val}"), 4)
            }
            GgufType::Uint64 | GgufType::Int64 | GgufType::Float64 => {
                if offset + 8 > data.len() {
                    break;
                }
                let val = read_u64_le(data, offset).unwrap_or(0);
                offset += 8;
                (format!("{val}"), 8)
            }
            GgufType::Bool | GgufType::Uint8 | GgufType::Int8 => {
                if offset >= data.len() {
                    break;
                }
                let val = data[offset];
                offset += 1;
                (format!("{val}"), 1)
            }
            GgufType::Uint16 | GgufType::Int16 => {
                if offset + 2 > data.len() {
                    break;
                }
                let val = u16::from_le_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                (format!("{val}"), 2)
            }
            _ => {
                // Array or unknown — skip remaining bytes for this entry
                let remain = data.len().saturating_sub(offset).min(64);
                let hex: String = data[offset..offset + remain]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                offset += remain;
                (format!("(raw:{hex})"), remain)
            }
        };

        entries.push(KVEntry {
            key,
            value_type: vtype,
            value_str,
            value_len,
            offset: kv_start,
        });
    }

    Ok(GgufHeader {
        version,
        tensor_count,
        kv_count,
        kv_entries: entries,
        data_len: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_gguf(version: u32, tensor_count: u64, kv_count: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GGUF");
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&tensor_count.to_le_bytes());
        buf.extend_from_slice(&kv_count.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_minimal_header() {
        let data = make_minimal_gguf(3, 10, 0);
        let hdr = parse(&data).unwrap();
        assert_eq!(hdr.version, 3);
        assert_eq!(hdr.tensor_count, 10);
        assert_eq!(hdr.kv_count, 0);
    }

    #[test]
    fn test_bad_magic() {
        let data = b"XXXX\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(parse(data).is_err());
    }

    #[test]
    fn test_too_short() {
        assert!(parse(b"GGUF").is_err());
    }

    #[test]
    fn test_unsupported_version() {
        let data = make_minimal_gguf(0, 0, 0);
        assert!(parse(&data).is_err());
        let data = make_minimal_gguf(255, 0, 0);
        assert!(parse(&data).is_err());
    }

    #[test]
    fn test_parse_string_kv() {
        let mut data = make_minimal_gguf(3, 0, 1);
        // Key: "general.name" (12 bytes)
        let key = b"general.name";
        data.extend_from_slice(&(key.len() as u64).to_le_bytes());
        data.extend_from_slice(key);
        // Type: string (8)
        data.extend_from_slice(&8u32.to_le_bytes());
        // Value: "test_model" (10 bytes)
        let val = b"test_model";
        data.extend_from_slice(&(val.len() as u64).to_le_bytes());
        data.extend_from_slice(val);

        let hdr = parse(&data).unwrap();
        assert_eq!(hdr.kv_entries.len(), 1);
        assert_eq!(hdr.kv_entries[0].key, "general.name");
        assert_eq!(hdr.kv_entries[0].value_str, "test_model");
    }
}
