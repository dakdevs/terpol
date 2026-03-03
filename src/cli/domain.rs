use clap::Subcommand;

#[derive(Subcommand)]
pub enum DomainAction {
    /// Add a domain pattern to the MITM allowlist
    Add {
        /// Domain glob pattern (e.g., "*.example.com")
        pattern: String,
    },
    /// List all MITM domain patterns
    List,
    /// Remove a domain pattern
    Remove {
        /// Domain glob pattern
        pattern: String,
    },
}
