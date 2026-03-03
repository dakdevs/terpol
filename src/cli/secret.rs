use clap::Subcommand;

#[derive(Subcommand)]
pub enum SecretAction {
    /// Add a secret to the vault
    Add {
        /// Secret key name
        key: String,
    },
    /// Remove a secret from the vault
    Remove {
        /// Secret key name
        key: String,
    },
    /// List all secret key names (values are never shown)
    List,
}
