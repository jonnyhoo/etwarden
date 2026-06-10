//! # `search::tests::protobuf`
//!
//! **Purpose**: Unit tests for Protobuf JSON-backed payload search.
//! **Public API**: test module only
//! **Dependencies**: `parser::protobuf`, `prost`, `prost-types`, `search`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 137 / 200

use prost::Message as _;
use prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
};

use super::{
    search_protobuf_all, search_protobuf_payload, CapturedPayload, ProtobufSearchConfig,
    ProtobufSearchError, SearchType,
};
use crate::parser::protobuf::{import_descriptor_set, ProtobufError};

#[test]
fn protobuf_payload_search_finds_decoded_json_text() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");
    let payload = [b"xx".as_slice(), sample_message_bytes("bob").as_slice()].concat();

    let results = search_protobuf_payload(&payload, config(&schema), "bob", SearchType::Utf8, true)
        .expect("search");

    assert_eq!(results[0].offset, 18);
    assert_eq!(results[0].length, 3);
    assert_eq!(results[0].context, br#"{"id":150,"name":"bob"}"#);
}

#[test]
fn protobuf_all_search_preserves_request_ids() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");
    let bob = [b"xx".as_slice(), sample_message_bytes("bob").as_slice()].concat();
    let alice = [b"xx".as_slice(), sample_message_bytes("alice").as_slice()].concat();
    let second_bob = [b"xx".as_slice(), sample_message_bytes("bob").as_slice()].concat();
    let payloads = [
        CapturedPayload {
            request_id: 7,
            payload: &bob,
        },
        CapturedPayload {
            request_id: 9,
            payload: &alice,
        },
        CapturedPayload {
            request_id: 11,
            payload: &second_bob,
        },
    ];

    let results = search_protobuf_all(&payloads, config(&schema), "bob", SearchType::Utf8, true)
        .expect("search");

    assert_eq!(
        results
            .iter()
            .map(|hit| (hit.request_id, hit.length))
            .collect::<Vec<_>>(),
        vec![(7, 3), (11, 3)]
    );
}

#[test]
fn protobuf_payload_search_propagates_decode_errors() {
    let schema = import_descriptor_set(&descriptor_set_bytes()).expect("descriptor");

    let err = search_protobuf_payload(b"xx\xff", config(&schema), "bob", SearchType::Utf8, true)
        .expect_err("decode");

    assert!(matches!(
        err,
        ProtobufSearchError::Protobuf(ProtobufError::Decode(_))
    ));
}

fn config(schema: &crate::parser::protobuf::ProtobufSchema) -> ProtobufSearchConfig<'_> {
    ProtobufSearchConfig {
        schema,
        skip: 2,
        message_type: "demo.Sample",
    }
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

fn sample_message_bytes(name: &str) -> Vec<u8> {
    let mut bytes = vec![
        0x08,
        0x96,
        0x01,
        0x12,
        u8::try_from(name.len()).expect("name fits"),
    ];
    bytes.extend_from_slice(name.as_bytes());
    bytes
}
