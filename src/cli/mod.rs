pub mod domain;
pub mod rule;
pub mod secret;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

fn default_config_dir() -> PathBuf {
    dirs_or_default()
}

fn dirs_or_default() -> PathBuf {
    if let Some(config) = dirs::config_dir() {
        config.join("terpol")
    } else {
        PathBuf::from(".terpol")
    }
}

#[derive(Parser)]
#[command(name = "terpol", about = "Secret-injecting MITM proxy", version)]
pub struct Cli {
    /// Config directory (default: ~/.config/terpol)
    #[arg(long, global = true, default_value_os_t = default_config_dir())]
    pub config_dir: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize config, vault, and CA certificate
    Init,
    /// Start the proxy
    Run {
        /// Run as background daemon
        #[arg(long)]
        daemon: bool,
        /// Don't set system proxy (require manual HTTP_PROXY instead)
        #[arg(long)]
        no_system_proxy: bool,
    },
    /// Manage secrets in the vault
    Secret {
        #[command(subcommand)]
        action: secret::SecretAction,
    },
    /// Manage substitution rules
    Rule {
        #[command(subcommand)]
        action: rule::RuleAction,
    },
    /// Manage MITM domain allowlist
    Domain {
        #[command(subcommand)]
        action: domain::DomainAction,
    },
    /// Export CA certificate for trust store
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[derive(Subcommand)]
pub enum CaAction {
    /// Export CA certificate to stdout or a file
    Export {
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
