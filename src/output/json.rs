//! # `output::json`
//!
//! **Purpose**: NDJSON emitter — writes one JSON line per `NetEvent` to stdout.
//! **Public API**: `struct JsonEmitter`
//! **Dependencies**: `output::schema`, `parser::types`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 98 / 200

use std::io::Write;

use crate::{
    error::EtwardenError,
    output::{schema::event_to_line, Emitter},
    parser::types::NetEvent,
};

/// Writes `NetEvent` as NDJSON lines to a `Write` sink.
pub struct JsonEmitter<W: Write> {
    writer: W,
}

impl<W: Write> JsonEmitter<W> {
    /// Creates a new `JsonEmitter` writing to the given sink.
    ///
    /// # Arguments
    /// * `writer` — Any type implementing `std::io::Write`.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Consumes the emitter and returns the inner writer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write + Send> Emitter for JsonEmitter<W> {
    fn emit(&mut self, event: &NetEvent) -> std::result::Result<(), EtwardenError> {
        let line = event_to_line(event);
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
}
