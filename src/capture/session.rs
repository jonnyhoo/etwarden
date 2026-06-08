//! # `capture::session`
//!
//! **Purpose**: Wraps `ferrisetw` `UserTrace` and `KernelTrace` for ETW session lifecycle.
//! **Public API**: `struct EtwSession`, `struct RunningSession`
//! **Dependencies**: `ferrisetw`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 80 / 100

use ferrisetw::{
    provider::Provider,
    trace::{KernelTrace, UserTrace},
};

use crate::error::{EtwardenError, Result};

// ---------------------------------------------------------------------------
// EtwSession — builder for a user-mode ETW trace session
// ---------------------------------------------------------------------------

/// Builder for a user-mode ETW real-time trace session.
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

        let user_trace = builder
            .start_and_process()
            .map_err(|e| EtwardenError::EtwSession(format!("failed to start user trace: {e:?}")))?;

        crate::output::diagnostic::warn(format_args!("ETW user trace started successfully"));

        Ok(RunningSession {
            kernel_trace: None,
            user_trace: Some(user_trace),
        })
    }
}

impl Default for EtwSession {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EtwKernelSession — builder for a kernel ETW trace session
// ---------------------------------------------------------------------------

/// Builder for a kernel ETW real-time trace session.
///
/// Kernel trace sessions set `EnableFlags` from providers' `kernel_flags`,
/// which is required for classic kernel providers like TCPIP.
pub struct EtwKernelSession {
    trace_builder: ferrisetw::trace::TraceBuilder<KernelTrace>,
    providers: Vec<Provider>,
}

impl EtwKernelSession {
    /// Creates a new kernel session builder with a random trace name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trace_builder: KernelTrace::new(),
            providers: Vec::new(),
        }
    }

    /// Adds a pre-built `Provider` to the kernel session.
    pub fn add_provider(&mut self, provider: Provider) {
        self.providers.push(provider);
    }

    /// Starts the kernel ETW trace session, consuming the builder.
    ///
    /// # Errors
    /// Returns [`EtwardenError::EtwSession`] if the trace fails to start.
    pub fn start(self) -> Result<RunningSession> {
        let mut builder = self.trace_builder;
        for provider in self.providers {
            builder = builder.enable(provider);
        }

        let kernel_trace = builder.start_and_process().map_err(|e| {
            EtwardenError::EtwSession(format!("failed to start kernel trace: {e:?}"))
        })?;

        crate::output::diagnostic::warn(format_args!("ETW kernel trace started successfully"));

        Ok(RunningSession {
            kernel_trace: Some(kernel_trace),
            user_trace: None,
        })
    }
}

impl Default for EtwKernelSession {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RunningSession — owns running ETW traces
// ---------------------------------------------------------------------------

/// A running ETW trace session. Stops on drop.
///
/// May hold a kernel trace, a user trace, or both.
pub struct RunningSession {
    kernel_trace: Option<KernelTrace>,
    user_trace: Option<UserTrace>,
}

impl RunningSession {
    /// Creates a `RunningSession` from separate kernel and user traces.
    #[must_use]
    pub const fn new(kernel: Option<KernelTrace>, user: Option<UserTrace>) -> Self {
        Self {
            kernel_trace: kernel,
            user_trace: user,
        }
    }

    /// Takes the kernel and user traces out, leaving `None` in their place.
    /// Use this to combine traces from separate sessions.
    pub const fn take_parts(&mut self) -> (Option<KernelTrace>, Option<UserTrace>) {
        (self.kernel_trace.take(), self.user_trace.take())
    }

    /// Stops all trace sessions explicitly.
    ///
    /// # Errors
    /// Returns [`EtwardenError::EtwSession`] if stopping fails.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(trace) = self.kernel_trace.take() {
            trace.stop().map_err(|e| {
                EtwardenError::EtwSession(format!("failed to stop kernel trace: {e:?}"))
            })?;
        }
        if let Some(trace) = self.user_trace.take() {
            trace.stop().map_err(|e| {
                EtwardenError::EtwSession(format!("failed to stop user trace: {e:?}"))
            })?;
        }
        Ok(())
    }
}

impl Drop for RunningSession {
    fn drop(&mut self) {
        // Best-effort stop on drop — traces also stop on their own drop.
        self.kernel_trace.take();
        self.user_trace.take();
    }
}
