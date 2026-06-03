//! # `capture::session`
//!
//! **Purpose**: Wraps `ferrisetw` `UserTrace` for ETW session lifecycle.
//! **Public API**: `struct EtwSession`, `struct RunningSession`
//! **Dependencies**: `ferrisetw`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 80 / 100

use ferrisetw::{provider::Provider, trace::UserTrace};

use crate::error::{EtwardenError, Result};

// ---------------------------------------------------------------------------
// EtwSession — builder for an ETW trace session
// ---------------------------------------------------------------------------

/// Builder for an ETW real-time trace session.
///
/// Collects providers before starting the session.
pub struct EtwSession {
    trace_builder: ferrisetw::trace::TraceBuilder<UserTrace>,
    providers: Vec<Provider>,
}

impl EtwSession {
    /// Creates a new session builder with a random trace name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace_builder: UserTrace::new(),
            providers: Vec::new(),
        }
    }

    /// Creates a new session builder with a specific trace name.
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            trace_builder: UserTrace::new().named(name.to_string()),
            providers: Vec::new(),
        }
    }

    /// Adds a pre-built `Provider` to the session.
    pub fn add_provider(&mut self, provider: Provider) {
        self.providers.push(provider);
    }

    /// Starts the ETW trace session, consuming the builder.
    ///
    /// # Errors
    /// Returns [`EtwardenError::EtwSession`] if the trace fails to start.
    pub fn start(self) -> Result<RunningSession> {
        let mut builder = self.trace_builder;
        for provider in self.providers {
            builder = builder.enable(provider);
        }

        let (user_trace, _trace_handle) = builder
            .start()
            .map_err(|e| EtwardenError::EtwSession(format!("failed to start ETW trace: {e:?}")))?;

        Ok(RunningSession {
            trace: Some(user_trace),
        })
    }
}

impl Default for EtwSession {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RunningSession — owns a started ETW trace
// ---------------------------------------------------------------------------

/// A running ETW trace session. Stops on drop.
pub struct RunningSession {
    trace: Option<UserTrace>,
}

impl RunningSession {
    /// Stops the trace session explicitly.
    ///
    /// # Errors
    /// Returns [`EtwardenError::EtwSession`] if stopping fails.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(trace) = self.trace.take() {
            trace
                .stop()
                .map_err(|e| EtwardenError::EtwSession(format!("failed to stop trace: {e:?}")))?;
        }
        Ok(())
    }
}

impl Drop for RunningSession {
    fn drop(&mut self) {
        // Best-effort stop on drop — UserTrace also stops on drop.
        if let Some(trace) = self.trace.take() {
            drop(trace);
        }
    }
}
