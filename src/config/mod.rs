pub mod types;

pub use types::*;

use std::path::Path;
use thiserror::Error;

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
        assert!(err.to_string().contains("prefix and suffix must not be empty"));
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
