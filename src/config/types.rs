use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub signature: SignatureConfig,
    pub mitm: MitmConfig,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignatureConfig {
    pub prefix: String,
    pub suffix: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MitmConfig {
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub secret: String,
    pub domain: String,
    #[serde(default = "default_wildcard")]
    pub method: String,
    #[serde(default = "default_wildcard")]
    pub path: String,
    pub target: RuleTarget,
    pub header_name: Option<String>,
    #[serde(default)]
    pub on_missing: OnMissing,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleTarget {
    Url,
    Header,
    Body,
    Query,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OnMissing {
    #[default]
    Block,
    Passthrough,
}

fn default_wildcard() -> String {
    "*".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_full_config() {
        let yaml = r#"
signature:
  prefix: "%%VAULT["
  suffix: "]%%"
mitm:
  domains:
    - api.stripe.com
    - "*.internal.corp"
proxy:
  listen: "127.0.0.1:8080"
rules:
  - name: stripe-key
    secret: STRIPE_API_KEY
    domain: api.stripe.com
    method: POST
    path: "/v1/*"
    target: header
    header_name: Authorization
    on_missing: block
  - name: body-token
    secret: INTERNAL_TOKEN
    domain: "*.internal.corp"
    target: body
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.signature.prefix, "%%VAULT[");
        assert_eq!(config.signature.suffix, "]%%");
        assert_eq!(config.mitm.domains.len(), 2);
        assert_eq!(config.proxy.listen, "127.0.0.1:8080");
        assert_eq!(config.rules.len(), 2);

        let rule0 = &config.rules[0];
        assert_eq!(rule0.name, "stripe-key");
        assert_eq!(rule0.target, RuleTarget::Header);
        assert_eq!(rule0.header_name.as_deref(), Some("Authorization"));
        assert_eq!(rule0.on_missing, OnMissing::Block);

        let rule1 = &config.rules[1];
        assert_eq!(rule1.method, "*");
        assert_eq!(rule1.path, "*");
        assert_eq!(rule1.on_missing, OnMissing::Block);
    }

    #[test]
    fn test_deserialize_minimal_config() {
        let yaml = r#"
signature:
  prefix: "%%["
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:9090"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.rules.is_empty());
        assert_eq!(config.proxy.listen, "127.0.0.1:9090");
    }

    #[test]
    fn test_header_rule_requires_header_name() {
        // This test documents that header_name is Option —
        // validation that header rules have header_name is done at load time, not serde.
        let yaml = r#"
signature:
  prefix: "%%["
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:8080"
rules:
  - name: test
    secret: KEY
    domain: example.com
    target: header
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.rules[0].header_name.is_none());
    }
}
