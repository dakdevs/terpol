pub mod types;

pub use types::*;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("validation error: {0}")]
    Validation(String),
}

pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&contents)?;
    validate(&config)?;
    Ok(config)
}

#[allow(dead_code)]
pub fn parse_config(yaml: &str) -> Result<Config, ConfigError> {
    let config: Config = serde_yaml::from_str(yaml)?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    if config.signature.prefix.is_empty() || config.signature.suffix.is_empty() {
        return Err(ConfigError::Validation(
            "signature prefix and suffix must not be empty".into(),
        ));
    }

    for rule in &config.rules {
        if rule.target == RuleTarget::Header && rule.header_name.is_none() {
            return Err(ConfigError::Validation(format!(
                "rule '{}' targets header but has no header_name",
                rule.name
            )));
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub fn watch_config(
    path: PathBuf,
    config: Arc<RwLock<Config>>,
) -> Result<RecommendedWatcher, notify::Error> {
    let config_clone = config.clone();
    let path_clone = path.clone();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    match load_config(&path_clone) {
                        Ok(new_config) => {
                            let config = config_clone.clone();
                            // Use blocking write since we're in a sync callback
                            if let Ok(mut guard) = config.try_write() {
                                *guard = new_config;
                                info!("config reloaded from {}", path_clone.display());
                            }
                        }
                        Err(e) => {
                            error!("failed to reload config: {e}");
                        }
                    }
                }
            }
            Err(e) => error!("config watcher error: {e}"),
        }
    })?;

    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_empty_prefix() {
        let yaml = r#"
signature:
  prefix: ""
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:8080"
"#;
        let err = parse_config(yaml).unwrap_err();
        assert!(
            err.to_string()
                .contains("prefix and suffix must not be empty")
        );
    }

    #[test]
    fn test_validate_rejects_header_without_name() {
        let yaml = r#"
signature:
  prefix: "%%["
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:8080"
rules:
  - name: bad-rule
    secret: KEY
    domain: example.com
    target: header
"#;
        let err = parse_config(yaml).unwrap_err();
        assert!(err.to_string().contains("has no header_name"));
    }

    #[test]
    fn test_example_config_parses() {
        let example = include_str!("../../config.example.yaml");
        let config: Config = serde_yaml::from_str(example).unwrap();
        assert_eq!(config.proxy.listen, "127.0.0.1:8080");
    }

    #[test]
    fn test_valid_config_passes() {
        let yaml = r#"
signature:
  prefix: "%%VAULT["
  suffix: "]%%"
mitm:
  domains:
    - api.stripe.com
proxy:
  listen: "127.0.0.1:8080"
rules:
  - name: good-rule
    secret: KEY
    domain: api.stripe.com
    target: header
    header_name: Authorization
"#;
        let config = parse_config(yaml).unwrap();
        assert_eq!(config.rules.len(), 1);
    }
}
