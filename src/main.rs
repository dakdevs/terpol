mod cli;
mod config;
mod engine;
mod proxy;
mod vault;

use clap::Parser;
use cli::{CaAction, Cli, Command};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config_dir = &cli.config_dir;

    match cli.command {
        Command::Init => {
            std::fs::create_dir_all(config_dir)?;

            // Generate CA
            proxy::tls::generate_ca(config_dir)?;
            println!("CA certificate generated at {}/ca.pem", config_dir.display());

            // Create example config if none exists
            let config_path = config_dir.join("config.yaml");
            if !config_path.exists() {
                let example = include_str!("../config.example.yaml");
                std::fs::write(&config_path, example)?;
                println!("Example config written to {}", config_path.display());
            }

            // Create vault
            let vault_path = config_dir.join("vault.enc");
            if !vault_path.exists() {
                let password = rpassword::prompt_password("Set vault master password: ")?;
                let _vault =
                    vault::encrypted_file::EncryptedFileVault::open(&vault_path, &password)?;
                println!("Vault created at {}", vault_path.display());
            }

            println!("Initialization complete.");
        }

        Command::Run { daemon: _, no_system_proxy } => {
            let config_path = config_dir.join("config.yaml");
            let cfg = config::load_config(&config_path)?;

            let vault_path = config_dir.join("vault.enc");
            let password = rpassword::prompt_password("Vault password: ")?;
            let vault_backend =
                vault::encrypted_file::EncryptedFileVault::open(&vault_path, &password)?;

            // Parse listen address for system proxy setup
            let listen_addr: std::net::SocketAddr = cfg.proxy.listen.parse()?;

            // Set system proxy (restored automatically on drop)
            let _proxy_guard = if no_system_proxy {
                None
            } else {
                match proxy::system_proxy::ProxyGuard::enable(
                    &listen_addr.ip().to_string(),
                    listen_addr.port(),
                ) {
                    Ok(guard) => {
                        println!("System proxy enabled — all apps will route through sever");
                        Some(guard)
                    }
                    Err(e) => {
                        eprintln!("Warning: could not set system proxy ({e}), use HTTP_PROXY manually");
                        None
                    }
                }
            };

            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            // Handle Ctrl+C
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                let _ = shutdown_tx.send(());
            });

            proxy::server::run_proxy(&cfg, Box::new(vault_backend), config_dir, shutdown_rx)
                .await?;

            // _proxy_guard drops here, restoring system proxy settings
        }

        Command::Secret { action } => {
            let vault_path = config_dir.join("vault.enc");
            let password = rpassword::prompt_password("Vault password: ")?;
            let mut vault_backend =
                vault::encrypted_file::EncryptedFileVault::open(&vault_path, &password)?;

            use crate::vault::VaultBackend;
            match action {
                cli::secret::SecretAction::Add { key } => {
                    let value = rpassword::prompt_password(&format!("Value for {key}: "))?;
                    vault_backend.set(&key, &value)?;
                    println!("Secret '{key}' added.");
                }
                cli::secret::SecretAction::Remove { key } => {
                    vault_backend.delete(&key)?;
                    println!("Secret '{key}' removed.");
                }
                cli::secret::SecretAction::List => {
                    let keys = vault_backend.list()?;
                    if keys.is_empty() {
                        println!("(no secrets stored)");
                    } else {
                        for key in keys {
                            println!("  {key}");
                        }
                    }
                }
            }
        }

        Command::Rule { action } => {
            let config_path = config_dir.join("config.yaml");
            let cfg = config::load_config(&config_path)?;

            match action {
                cli::rule::RuleAction::List => {
                    if cfg.rules.is_empty() {
                        println!("(no rules configured)");
                    } else {
                        for rule in &cfg.rules {
                            println!(
                                "  {} -> {} ({:?} on {})",
                                rule.name, rule.secret, rule.target, rule.domain
                            );
                        }
                    }
                }
                cli::rule::RuleAction::Remove { name } => {
                    println!(
                        "Remove rule '{}' by editing {}",
                        name,
                        config_path.display()
                    );
                }
            }
        }

        Command::Domain { action } => {
            let config_path = config_dir.join("config.yaml");
            let cfg = config::load_config(&config_path)?;

            match action {
                cli::domain::DomainAction::Add { pattern } => {
                    println!(
                        "Add '{}' to mitm.domains in {}",
                        pattern,
                        config_path.display()
                    );
                }
                cli::domain::DomainAction::List => {
                    if cfg.mitm.domains.is_empty() {
                        println!("(no MITM domains configured)");
                    } else {
                        for domain in &cfg.mitm.domains {
                            println!("  {domain}");
                        }
                    }
                }
                cli::domain::DomainAction::Remove { pattern } => {
                    println!(
                        "Remove '{}' from mitm.domains in {}",
                        pattern,
                        config_path.display()
                    );
                }
            }
        }

        Command::Ca { action } => match action {
            CaAction::Export { output } => {
                let ca_path = config_dir.join("ca.pem");
                let cert = std::fs::read_to_string(&ca_path)?;
                match output {
                    Some(path) => {
                        std::fs::write(&path, &cert)?;
                        println!("CA certificate exported to {}", path.display());
                    }
                    None => print!("{cert}"),
                }
            }
        },
    }

    Ok(())
}
