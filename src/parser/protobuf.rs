//! # `parser::protobuf`
//!
//! **Purpose**: Dynamic Protobuf descriptor import and binary-to-JSON decoding.
//! **Public API**: `ProtobufSchema`, `ProtobufError`, `import_descriptor_file`,
//!   `import_descriptor_set`, `protobuf_to_json`
//! **Dependencies**: `prost-reflect`, `serde_json`, `std`, `thiserror`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 135 / 200

#[cfg(test)]
mod tests;

use std::{fs, path::Path};

use prost_reflect::{DescriptorPool, DynamicMessage};

/// Imported dynamic Protobuf schema.
#[derive(Debug, Clone)]
pub struct ProtobufSchema {
    pool: DescriptorPool,
    message_types: Vec<String>,
}

/// Protobuf descriptor import or decode error.
#[derive(Debug, thiserror::Error)]
pub enum ProtobufError {
    /// Descriptor file could not be read.
    #[error("failed to read protobuf descriptor file '{path}': {source}")]
    DescriptorRead {
        path: String,
        source: std::io::Error,
    },
    /// Descriptor set bytes could not be decoded or resolved.
    #[error("invalid protobuf descriptor set: {0}")]
    InvalidDescriptor(#[from] prost_reflect::DescriptorError),
    /// Requested message type is missing from the imported schema.
    #[error("protobuf message type not found: {message_type}")]
    UnknownMessageType { message_type: String },
    /// Skip value exceeds available payload bytes.
    #[error("protobuf skip {skip} exceeds payload length {len}")]
    SkipOutOfBounds { skip: usize, len: usize },
    /// Binary protobuf data could not be decoded as the requested message type.
    #[error("invalid protobuf message: {0}")]
    Decode(#[from] prost_reflect::prost::DecodeError),
    /// Decoded message could not be serialized to JSON.
    #[error("protobuf JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Imports a binary `FileDescriptorSet` from disk.
///
/// # Arguments
/// * `path` — Path to a Protobuf-encoded `google.protobuf.FileDescriptorSet` file.
///
/// # Returns
/// Imported schema with a dynamic descriptor pool and available message types.
///
/// # Errors
/// Returns [`ProtobufError`] when the file cannot be read or descriptor bytes are invalid.
pub fn import_descriptor_file(path: impl AsRef<Path>) -> Result<ProtobufSchema, ProtobufError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| ProtobufError::DescriptorRead {
        path: path.display().to_string(),
        source,
    })?;
    import_descriptor_set(&bytes)
}

/// Imports a binary `FileDescriptorSet`.
///
/// # Arguments
/// * `descriptor_set` — Protobuf-encoded `google.protobuf.FileDescriptorSet` bytes.
///
/// # Returns
/// Imported schema with a dynamic descriptor pool and available message types.
///
/// # Errors
/// Returns [`ProtobufError`] when descriptor bytes are invalid or cannot be resolved.
pub fn import_descriptor_set(descriptor_set: &[u8]) -> Result<ProtobufSchema, ProtobufError> {
    let pool = DescriptorPool::decode(descriptor_set)?;
    let mut message_types = pool
        .all_messages()
        .map(|message| message.full_name().to_owned())
        .collect::<Vec<_>>();
    message_types.sort();
    Ok(ProtobufSchema {
        pool,
        message_types,
    })
}

/// Decodes one binary protobuf message into canonical JSON.
///
/// # Arguments
/// * `schema` — Imported descriptor schema.
/// * `data` — Captured protobuf payload bytes.
/// * `skip` — Number of leading bytes to skip before decoding.
/// * `message_type` — Fully qualified protobuf message name.
///
/// # Returns
/// Canonical protobuf JSON string for the decoded message.
///
/// # Errors
/// Returns [`ProtobufError`] when the message type is unknown, skip is out of bounds,
/// binary data is invalid, or JSON serialization fails.
pub fn protobuf_to_json(
    schema: &ProtobufSchema,
    data: &[u8],
    skip: usize,
    message_type: &str,
) -> Result<String, ProtobufError> {
    let descriptor = schema
        .pool
        .get_message_by_name(message_type)
        .ok_or_else(|| ProtobufError::UnknownMessageType {
            message_type: message_type.to_owned(),
        })?;
    let payload = data.get(skip..).ok_or(ProtobufError::SkipOutOfBounds {
        skip,
        len: data.len(),
    })?;
    let message = DynamicMessage::decode(descriptor, payload)?;
    Ok(serde_json::to_string(&message)?)
}

impl ProtobufSchema {
    /// Returns all available fully qualified message type names.
    ///
    /// # Returns
    /// Message names sorted lexicographically for stable UI display.
    pub fn message_types(&self) -> &[String] {
        &self.message_types
    }
}
