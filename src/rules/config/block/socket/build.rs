//! # `rules::config::block::socket::build`
//!
//! **Purpose**: Builders for socket block-rule config collections.
//! **Public API**: `RulesConfig` TCP/UDP block build methods
//! **Dependencies**: `rules::config::block::socket`, `rules::block::socket`, `rules::matcher`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 44 / 80

use super::SocketBlockRuleConfig;
use crate::rules::{
    block::socket::{SocketBlockRule, SocketProtocol},
    config::RulesConfig,
    matcher::MatchError,
};

impl RulesConfig {
    /// Builds configured TCP block rules.
    ///
    /// # Errors
    /// Returns `MatchError` if any configured address matcher pattern is invalid.
    pub fn build_tcp_block_rules(&self) -> Result<Vec<SocketBlockRule>, MatchError> {
        build_socket_rules(&self.block_rules.tcp, SocketProtocol::Tcp)
    }

    /// Builds configured UDP block rules.
    ///
    /// # Errors
    /// Returns `MatchError` if any configured address matcher pattern is invalid.
    pub fn build_udp_block_rules(&self) -> Result<Vec<SocketBlockRule>, MatchError> {
        build_socket_rules(&self.block_rules.udp, SocketProtocol::Udp)
    }
}

fn build_socket_rules(
    configs: &[SocketBlockRuleConfig],
    protocol: SocketProtocol,
) -> Result<Vec<SocketBlockRule>, MatchError> {
    configs
        .iter()
        .map(|config| config.build(protocol))
        .collect()
}
