//! # `output::json`
//!
//! **Purpose**: NDJSON emitter — writes one JSON line per `NetEvent` to stdout.
//! **Public API**: `struct JsonEmitter`
//! **Dependencies**: `output::schema`, `parser::types`, `error`, `process::tree`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 120 / 200

use std::{io::Write, sync::Arc};

use crate::{
    error::EtwardenError,
    output::{schema::event_to_line_with_process_info, Emitter},
    parser::types::NetEvent,
    process::ProcessTreeCache,
};

/// Writes `NetEvent` as NDJSON lines to a `Write` sink.
///
/// Optionally enriches output with process-tree resolution via
/// an injected [`ProcessTreeCache`].
pub struct JsonEmitter<W: Write> {
    writer: W,
    process_cache: Option<Arc<ProcessTreeCache>>,
}

impl<W: Write> JsonEmitter<W> {
    /// Creates a new `JsonEmitter` writing to the given sink.
    ///
    /// # Arguments
    /// * `writer` — Any type implementing `std::io::Write`.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            process_cache: None,
        }
    }

    /// Attaches a process name cache for enrichment.
    #[must_use]
    pub fn with_process_cache(mut self, cache: Arc<ProcessTreeCache>) -> Self {
        self.process_cache = Some(cache);
        self
    }

    /// Consumes the emitter and returns the inner writer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write + Send> Emitter for JsonEmitter<W> {
    fn emit(&mut self, event: &NetEvent) -> std::result::Result<(), EtwardenError> {
        let process_info = self
            .process_cache
            .as_ref()
            .and_then(|cache| cache.get_info(event.pid()));
        let line = event_to_line_with_process_info(event, process_info, None);
        let json = serde_json::to_string(&line)
            .map_err(|e| EtwardenError::OutputWrite(format!("serialize: {e}")))?;
        self.writer
            .write_all(json.as_bytes())
            .map_err(|e| EtwardenError::OutputWrite(format!("write: {e}")))?;
        self.writer
            .write_all(b"\n")
            .map_err(|e| EtwardenError::OutputWrite(format!("newline: {e}")))?;
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), EtwardenError> {
        self.writer
            .flush()
            .map_err(|e| EtwardenError::OutputWrite(format!("flush: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::parser::types::Protocol;

    fn test_timestamp() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .map(|dt| dt.with_timezone(&Utc))
            .expect("valid timestamp")
    }

    #[test]
    fn emit_connect_writes_ndjson_line() {
        let mut buf = Vec::new();
        let mut emitter = JsonEmitter::new(&mut buf);
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        emitter.emit(&event).expect("emit");
        let output = String::from_utf8(buf).expect("utf8");
        assert!(output.contains("\"event\":\"connect\""), "actual: {output}");
        assert!(output.ends_with('\n'), "should end with newline");
    }

    #[test]
    fn emit_multiple_events() {
        let mut buf = Vec::new();
        let mut emitter = JsonEmitter::new(&mut buf);
        let event1 = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let event2 = NetEvent::Disconnect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "192.168.1.1:50234".into(),
            dst: "93.184.216.34:443".into(),
            bytes_out: 512,
            bytes_in: 2048,
        };
        emitter.emit(&event1).expect("emit1");
        emitter.emit(&event2).expect("emit2");
        let output = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("connect"));
        assert!(lines[1].contains("disconnect"));
    }

    #[test]
    fn flush_succeeds() {
        let mut buf = Vec::new();
        let mut emitter = JsonEmitter::new(&mut buf);
        emitter.flush().expect("flush");
    }

    #[test]
    fn into_inner_returns_writer() {
        let buf = Vec::new();
        let emitter = JsonEmitter::new(buf);
        let inner = emitter.into_inner();
        assert!(inner.is_empty());
    }

    #[test]
    fn emit_with_process_cache_includes_name() {
        let mut buf = Vec::new();
        let cache = Arc::new(ProcessTreeCache::new());
        let mut emitter = JsonEmitter::new(&mut buf).with_process_cache(cache);

        let my_pid = std::process::id();
        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: my_pid,
            proto: Protocol::Tcp,
            src: "127.0.0.1:49152".into(),
            dst: "127.0.0.1:8080".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        emitter.emit(&event).expect("emit");
        let output = String::from_utf8(buf).expect("utf8");
        assert!(
            output.contains("\"process_name\""),
            "should contain process_name: {output}"
        );
        assert!(
            output.contains("\"tree_path\""),
            "should contain tree_path: {output}"
        );
    }

    #[test]
    fn emit_without_cache_omits_name() {
        let mut buf = Vec::new();
        let mut emitter = JsonEmitter::new(&mut buf);

        let event = NetEvent::Connect {
            timestamp: test_timestamp(),
            pid: 1234,
            proto: Protocol::Tcp,
            src: "127.0.0.1:49152".into(),
            dst: "127.0.0.1:8080".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        emitter.emit(&event).expect("emit");
        let output = String::from_utf8(buf).expect("utf8");
        assert!(
            !output.contains("\"process_name\""),
            "should NOT contain process_name: {output}"
        );
    }
}
