//! # `parser::protobuf::tests`
//!
//! **Purpose**: Unit tests for dynamic Protobuf descriptor import and JSON decoding.
//! **Public API**: test module only
//! **Dependencies**: `parser::protobuf`, `prost`, `prost-types`, `serde_json`, `tempfile`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 118 / 200

use std::fs;

use prost::Message as _;
use prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
};
use serde_json::json;

use super::{import_descriptor_file, import_descriptor_set, protobuf_to_json, ProtobufError};

#[test]
fn descriptor_import_lists_message_types() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");

    assert_eq!(schema.message_types(), &["demo.Sample".to_owned()]);
}

#[test]
fn descriptor_file_import_lists_message_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sample.descriptor");
    fs::write(&path, descriptor_set_bytes()).expect("write descriptor");

    let schema = import_descriptor_file(&path).expect("descriptor file");

    assert_eq!(schema.message_types(), &["demo.Sample".to_owned()]);
}

#[test]
fn descriptor_file_import_reports_missing_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("missing.descriptor");

    let err = import_descriptor_file(&path).expect_err("missing descriptor");

    assert!(matches!(err, ProtobufError::DescriptorRead { .. }));
}

#[test]
fn protobuf_to_json_decodes_message_after_skip() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");
    let payload = [b"xx".as_slice(), sample_message_bytes().as_slice()].concat();

    let json_text = protobuf_to_json(&schema, &payload, 2, "demo.Sample").expect("decode");
    let json_value: serde_json::Value = serde_json::from_str(&json_text).expect("json");

    assert_eq!(json_value, json!({ "id": 150, "name": "bob" }));
}

#[test]
fn protobuf_to_json_rejects_unknown_message_type() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");
    let err = protobuf_to_json(&schema, &sample_message_bytes(), 0, "demo.Missing")
        .expect_err("missing message");

    assert!(matches!(err, ProtobufError::UnknownMessageType { .. }));
}

#[test]
fn protobuf_to_json_rejects_skip_past_input() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");
    let err =
        protobuf_to_json(&schema, &sample_message_bytes(), 99, "demo.Sample").expect_err("skip");

    assert!(matches!(err, ProtobufError::SkipOutOfBounds { .. }));
}

fn descriptor_set_bytes() -> Vec<u8> {
    FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("sample.proto".to_owned()),
            package: Some("demo".to_owned()),
            message_type: vec![sample_descriptor()],
            syntax: Some("proto3".to_owned()),
            ..Default::default()
        }],
    }
    .encode_to_vec()
}

fn sample_descriptor() -> DescriptorProto {
    DescriptorProto {
        name: Some("Sample".to_owned()),
        field: vec![
            FieldDescriptorProto {
                name: Some("id".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                json_name: Some("id".to_owned()),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("name".to_owned()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                json_name: Some("name".to_owned()),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

fn sample_message_bytes() -> Vec<u8> {
    vec![0x08, 0x96, 0x01, 0x12, 0x03, b'b', b'o', b'b']
}
