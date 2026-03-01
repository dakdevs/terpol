# Network Latch Design

A Rust MITM forward proxy that intercepts network traffic, finds interpolation signatures, and replaces them with secrets from a pluggable vault.

## Requirements

- Forward proxy intercepting HTTP/HTTPS traffic from arbitrary apps
- Custom delimiters for interpolation signatures (e.g., `%%VAULT[SECRET_NAME]%%`)
- Selective MITM -- only decrypt HTTPS for allowlisted domains
- Pluggable vault backends, starting with encrypted local file
- CLI + config file management (YAML)
- Rule-based scoping: domain + method + path pattern + request part (URL, header, body, query)
- Leak detection logging when signatures appear in unfiltered traffic
- Configurable fail mode per rule (block or passthrough on missing vault key)
- Config hot-reload via file watcher

## Architecture

```
+----------------+     +---------------------------------------+     +----------+
|  Any App       |---->|          network-latch                 |---->|  Internet|
|  (via proxy)   |<----|                                       |<----|          |
+----------------+     |  +-----------+  +---------------+     |     +----------+
                       |  | Rule      |  | Vault         |     |
                       |  | Engine    |  | (pluggable)   |     |
                       |  +-----------+  +---------------+     |
                       |  +-----------+  +---------------+     |
                       |  | Signature |  | Leak          |     |
                       |  | Scanner   |  | Detector      |     |
                       |  +-----------+  +---------------+     |
                       +---------------------------------------+
```

### Components

1. **Proxy Core** -- hudsucker-based forward proxy. Apps route through it via HTTP_PROXY/HTTPS_PROXY.
2. **Rule Engine** -- Matches requests against rules (domain glob + method + path glob + request part). Drives the scanner.
3. **Signature Scanner** -- Finds interpolation signatures in request data and resolves them from the vault.
4. **Vault** -- Trait-based pluggable storage. Initial backend: AES-256-GCM encrypted local file, key from Argon2id.
5. **Leak Detector** -- Scans all readable traffic for stray interpolation signatures. Logs warnings.
6. **CLI** -- Subcommands for secrets, rules, domains, and proxy lifecycle.

## Config Format (YAML)

```yaml
signature:
  prefix: "%%VAULT["
  suffix: "]%%"

mitm:
  domains:
    - api.stripe.com
    - api.openai.com
    - "*.internal.corp"

proxy:
  listen: "127.0.0.1:8080"

rules:
  - name: stripe-api-key
    secret: STRIPE_API_KEY
    domain: api.stripe.com
    method: POST
    path: "/v1/*"
    target: header
    header_name: Authorization
    on_missing: block          # block (default) | passthrough

  - name: openai-bearer
    secret: OPENAI_KEY
    domain: api.openai.com
    target: header
    header_name: Authorization

  - name: internal-api-body
    secret: INTERNAL_TOKEN
    domain: "*.internal.corp"
    method: POST
    path: "/api/v2/auth"
    target: body
```

## Rule Engine

Rules match on: domain (glob), method (exact or `*`), path (glob), target (url | header | body | query).

When `target = header`, the `header_name` field specifies which header to scan. When `target = body`, the entire request body is scanned. When `target = url` or `query`, the URL/query string is scanned.

Each rule has `on_missing`: `block` returns HTTP 502 (prevents leaking raw signatures), `passthrough` forwards the request unchanged.

## Vault

### Trait

```rust
trait VaultBackend: Send + Sync {
    async fn get(&self, key: &str) -> Result<String>;
    async fn set(&mut self, key: &str, value: &str) -> Result<()>;
    async fn delete(&mut self, key: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<String>>;
}
```

### Encrypted Local File Backend

- Storage: `~/.config/network-latch/vault.enc`
- Encryption: AES-256-GCM
- Key derivation: Argon2id from master password
- Master password prompted on first run, cached in memory for session
- File format: encrypted JSON blob

## CLI

```
network-latch run                  # Start the proxy
network-latch run --daemon         # Background daemon

network-latch secret add KEY       # Prompts for value (hidden input)
network-latch secret remove KEY
network-latch secret list          # Key names only, never values

network-latch rule add             # Interactive rule creation
network-latch rule list
network-latch rule remove NAME

network-latch domain add PATTERN
network-latch domain list
network-latch domain remove PATTERN

network-latch init                 # Create config, vault, CA cert
network-latch ca export            # Export CA cert for trust store
```

## Request Processing Flow

1. Request arrives at proxy
2. HTTPS CONNECT: check domain against MITM allowlist via `should_intercept`
   - Allowed: decrypt and process as HTTP
   - Not allowed: pass-through tunnel, scan CONNECT hostname for leaks
3. HTTP/decrypted request: match against rules
   - No match: scan for leak detection, forward unchanged
   - Match: for each rule, scan target for signatures, replace from vault
   - Missing key: per-rule `on_missing` (block -> 502, passthrough -> forward)
4. Forward modified request, return response unchanged

## Error Handling

| Scenario | Behavior |
|---|---|
| Vault key not found | Per-rule: block (502) or passthrough |
| Vault locked/corrupted | Proxy refuses to start |
| No signatures in matched target | No-op, forward unchanged |
| MITM cert rejected upstream | 502 to client, log error |
| Config parse error | Proxy refuses to start with clear error |
| Config file changed | Hot-reload rules and domains via file watcher |

## Logging

- INFO: Proxy lifecycle, substitution performed (rule name, domain, key name)
- WARN: Leak detected (signature, destination)
- ERROR: Vault key not found (key name, rule name)
- DEBUG: Rule matching, timing
- Secret values are never logged.

## Selective MITM

Uses hudsucker's `should_intercept` method. Returns `true` only for domains in the MITM allowlist. All other HTTPS passes through untouched as an opaque tunnel.

## CA Certificate

Generated via `rcgen` on `network-latch init`. Stored at `~/.config/network-latch/ca.pem` and `ca-key.pem`. User exports and trusts it in their OS via `network-latch ca export`.

## Key Dependencies

| Crate | Purpose |
|---|---|
| hudsucker | MITM proxy framework |
| rcgen | CA cert generation |
| aes-gcm | Vault encryption |
| argon2 | Key derivation |
| clap | CLI |
| serde + serde_yaml | Config |
| notify | Config hot-reload |
| tracing | Logging |
| globset | Pattern matching |
| rpassword | Hidden password input |

## Project Structure

```
network-latch/
  Cargo.toml
  config.example.yaml
  src/
    main.rs              # CLI entry (clap)
    proxy/
      mod.rs             # Proxy setup and lifecycle
      handler.rs         # HttpHandler impl
      tls.rs             # CA cert management
    engine/
      mod.rs
      rules.rs           # Rule matching
      scanner.rs         # Signature scan and replace
      leak.rs            # Leak detection
    vault/
      mod.rs             # VaultBackend trait
      encrypted_file.rs  # Encrypted file backend
    config/
      mod.rs             # Loading, validation, hot-reload
      types.rs           # Config structs
    cli/
      mod.rs
      secret.rs
      rule.rs
      domain.rs
```
