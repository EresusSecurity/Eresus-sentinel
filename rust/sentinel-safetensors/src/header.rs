// Parse the safetensors binary format.
//
// Layout:
//   [0..8]  — little-endian u64: header byte length (N)
//   [8..8+N] — UTF-8 JSON string
//
// The JSON maps tensor names to {dtype, shape, data_offsets} dicts,
// plus an optional "__metadata__" key with arbitrary string values.

use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("file too short ({0} bytes, need ≥ 8)")]
    TooShort(usize),
    #[error("header length field claims {0} bytes but only {1} available")]
    HeaderOverflow(u64, usize),
    #[error("header is not valid UTF-8")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("header is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Header = HashMap<String, serde_json::Value>;

pub fn parse(data: &[u8]) -> Result<Header, ParseError> {
    if data.len() < 8 {
        return Err(ParseError::TooShort(data.len()));
    }

    let hdr_len = u64::from_le_bytes(data[..8].try_into().unwrap());

    let available = data.len() - 8;
    if hdr_len as usize > available {
        return Err(ParseError::HeaderOverflow(hdr_len, available));
    }

    let json_bytes = &data[8..8 + hdr_len as usize];
    let json_str   = std::str::from_utf8(json_bytes)?;
    let header: Header = serde_json::from_str(json_str)?;
    Ok(header)
}
