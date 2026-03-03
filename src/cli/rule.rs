use clap::Subcommand;

#[derive(Subcommand)]
pub enum RuleAction {
    /// List all rules
    List,
    /// Remove a rule by name
    Remove {
        /// Rule name
        name: String,
    },
}
