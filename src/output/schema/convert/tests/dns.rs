use super::test_timestamp;
use crate::{
    output::schema::{convert::*, OutputLine},
    parser::types::NetEvent,
};

#[test]
fn dns_query_line_uses_hostname_field() {
    let event = NetEvent::DnsQuery {
        timestamp: test_timestamp(),
        pid: 1234,
        domain: "example.com".into(),
        query_type: 1,
        query_type_name: "A".into(),
    };
    let line = event_to_line(&event);
    let OutputLine::DnsEvent(line) = line else {
        unreachable!()
    };
    assert_eq!(line.hostname, "example.com");
    assert_eq!(line.event, "dns_query");
    assert_eq!(line.status, None);
}

#[test]
fn dns_response_line_keeps_status_and_ips() {
    let event = NetEvent::DnsResponse {
        timestamp: test_timestamp(),
        pid: 1234,
        domain: "example.com".into(),
        query_type: 1,
        query_type_name: "A".into(),
        status: 0,
        status_name: "NOERROR".into(),
        result_ips: vec!["93.184.216.34".into()],
        truncated: false,
    };
    let line = event_to_line(&event);
    let OutputLine::DnsEvent(line) = line else {
        unreachable!()
    };
    assert_eq!(line.hostname, "example.com");
    assert_eq!(line.status, Some(0));
    assert_eq!(line.result_ips, vec!["93.184.216.34"]);
    assert!(!line.truncated);
}

#[test]
fn dns_response_line_keeps_truncated_flag() {
    let event = NetEvent::DnsResponse {
        timestamp: test_timestamp(),
        pid: 1234,
        domain: "example.com".into(),
        query_type: 1,
        query_type_name: "A".into(),
        status: 0,
        status_name: "NOERROR".into(),
        result_ips: Vec::new(),
        truncated: true,
    };
    let line = event_to_line(&event);
    let OutputLine::DnsEvent(line) = line else {
        unreachable!()
    };
    assert!(line.truncated);
}
