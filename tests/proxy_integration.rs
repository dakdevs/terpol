use tempfile::TempDir;
use terpol::config;
use terpol::engine::rules::RuleEngine;
use terpol::engine::scanner::replace_signatures;
use terpol::vault::{VaultBackend, encrypted_file::EncryptedFileVault};

/// Integration test: validates that the full pipeline works end-to-end.
/// Config parsing -> vault creation -> rule matching -> signature replacement.
///
/// The proxy handler integration test (start_test_proxy / test_proxy_substitutes_header)
/// will be added once src/proxy/handler.rs is implemented (Task 9).
#[test]
fn test_pipeline_end_to_end() {
    let tmp = TempDir::new().unwrap();

    // 1. Generate and load CA
    terpol::proxy::tls::generate_ca(tmp.path()).unwrap();
    let _ca = terpol::proxy::tls::load_ca(tmp.path()).unwrap();

    // 2. Create vault with a test secret
    let vault_path = tmp.path().join("vault.enc");
    let mut vault = EncryptedFileVault::open(&vault_path, "test").unwrap();
    vault.set("TEST_TOKEN", "actual-secret-value").unwrap();

    // 3. Parse config
    let yaml = r#"
signature:
  prefix: "%%VAULT["
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:0"
rules:
  - name: test-header
    secret: TEST_TOKEN
    domain: "*"
    method: "*"
    path: "*"
    target: header
    header_name: X-Auth-Token
"#;
    let cfg = config::parse_config(yaml).unwrap();

    // 4. Build rule engine and match
    let engine = RuleEngine::new(cfg.rules.clone()).unwrap();
    let matches = engine.match_rules("api.example.com", "GET", "/v1/test");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule.name, "test-header");

    // 5. Signature replacement using vault lookup
    let input = "Bearer %%VAULT[TEST_TOKEN]%%";
    let (output, missing) = replace_signatures(input, &cfg.signature, &|key| vault.get(key).ok());
    assert_eq!(output, "Bearer actual-secret-value");
    assert!(missing.is_empty());
}

#[test]
fn test_pipeline_missing_secret() {
    let tmp = TempDir::new().unwrap();

    let vault_path = tmp.path().join("vault.enc");
    let vault = EncryptedFileVault::open(&vault_path, "test").unwrap();

    let yaml = r#"
signature:
  prefix: "%%VAULT["
  suffix: "]%%"
mitm:
  domains: []
proxy:
  listen: "127.0.0.1:0"
rules: []
"#;
    let cfg = config::parse_config(yaml).unwrap();

    // Signature with a key that doesn't exist in the vault
    let input = "Token: %%VAULT[MISSING_KEY]%%";
    let (output, missing) = replace_signatures(input, &cfg.signature, &|key| vault.get(key).ok());
    // Original signature preserved when key is missing
    assert_eq!(output, "Token: %%VAULT[MISSING_KEY]%%");
    assert_eq!(missing, vec!["MISSING_KEY"]);
}
