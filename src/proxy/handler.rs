use crate::config::{OnMissing, RuleTarget, SignatureConfig};
use crate::engine::leak::LeakDetector;
use crate::engine::rules::RuleEngine;
use crate::engine::scanner::replace_signatures;
use crate::vault::VaultBackend;

use http::{Response, StatusCode};
use http_body_util::Full;
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use hyper::body::Bytes;
use hyper::Request;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use globset::{Glob, GlobMatcher};

#[derive(Clone)]
pub struct LatchHandler {
    pub engine: Arc<RwLock<RuleEngine>>,
    pub vault: Arc<RwLock<Box<dyn VaultBackend>>>,
    pub sig: Arc<SignatureConfig>,
    pub leak_detector: Arc<LeakDetector>,
    pub mitm_matchers: Arc<Vec<GlobMatcher>>,
}

impl LatchHandler {
    pub fn new(
        engine: RuleEngine,
        vault: Box<dyn VaultBackend>,
        sig: SignatureConfig,
        mitm_domains: &[String],
    ) -> Result<Self, globset::Error> {
        let matchers = mitm_domains
            .iter()
            .map(|d| Ok(Glob::new(d)?.compile_matcher()))
            .collect::<Result<Vec<_>, globset::Error>>()?;

        let leak_detector = LeakDetector::new(sig.clone());

        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            vault: Arc::new(RwLock::new(vault)),
            sig: Arc::new(sig),
            leak_detector: Arc::new(leak_detector),
            mitm_matchers: Arc::new(matchers),
        })
    }

    fn domain_in_mitm_list(&self, host: &str) -> bool {
        // Strip port if present
        let domain = host.split(':').next().unwrap_or(host);
        self.mitm_matchers.iter().any(|m| m.is_match(domain))
    }

    fn extract_host(req: &Request<Body>) -> Option<String> {
        // Try Host header first, then URI authority
        if let Some(host) = req.headers().get("host") {
            return host.to_str().ok().map(|s| s.to_string());
        }
        req.uri().host().map(|h| h.to_string())
    }
}

impl HttpHandler for LatchHandler {
    async fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> bool {
        let host = Self::extract_host(req).unwrap_or_default();
        let should = self.domain_in_mitm_list(&host);
        debug!(host = %host, intercept = should, "CONNECT tunnel decision");

        if !should {
            // Check the CONNECT hostname itself for leaked signatures
            let uri_str = req.uri().to_string();
            self.leak_detector
                .check(&uri_str, &format!("CONNECT to {host} (not intercepted)"));
        }

        should
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        let host = Self::extract_host(&req).unwrap_or_default();
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        let engine = self.engine.read().await;
        let matching_rules = engine.match_rules(&host, &method, &path);

        if matching_rules.is_empty() {
            // No rules match -- run leak detection on the full request
            let uri_str = req.uri().to_string();
            self.leak_detector
                .check(&uri_str, &format!("unmatched request to {host}"));
            return req.into();
        }

        let vault = self.vault.read().await;

        for compiled_rule in &matching_rules {
            let rule = &compiled_rule.rule;
            debug!(rule = %rule.name, host = %host, "rule matched");

            match rule.target {
                RuleTarget::Url => {
                    let uri_str = req.uri().to_string();
                    let (replaced, missing) = replace_signatures(&uri_str, &self.sig, &|key| {
                        vault.get(key).ok()
                    });

                    if !missing.is_empty() {
                        if rule.on_missing == OnMissing::Block {
                            error!(
                                rule = %rule.name,
                                missing = ?missing,
                                "vault key not found, blocking request"
                            );
                            return Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from(format!(
                                    "network-latch: missing vault keys: {:?}",
                                    missing
                                )))
                                .unwrap()
                                .into();
                        }
                    } else if replaced != uri_str {
                        if let Ok(new_uri) = replaced.parse() {
                            *req.uri_mut() = new_uri;
                            info!(rule = %rule.name, "substituted signature in URL");
                        }
                    }
                }

                RuleTarget::Header => {
                    let header_name = match &rule.header_name {
                        Some(name) => name.clone(),
                        None => continue,
                    };
                    if let Some(value) = req.headers().get(&header_name) {
                        let value_str = match value.to_str() {
                            Ok(s) => s.to_string(),
                            Err(_) => continue,
                        };
                        let (replaced, missing) =
                            replace_signatures(&value_str, &self.sig, &|key| vault.get(key).ok());

                        if !missing.is_empty() && rule.on_missing == OnMissing::Block {
                            error!(
                                rule = %rule.name,
                                missing = ?missing,
                                "vault key not found, blocking request"
                            );
                            return Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from(format!(
                                    "network-latch: missing vault keys: {:?}",
                                    missing
                                )))
                                .unwrap()
                                .into();
                        }

                        if replaced != value_str {
                            if let Ok(new_value) = replaced.parse() {
                                req.headers_mut().insert(
                                    http::header::HeaderName::from_bytes(header_name.as_bytes())
                                        .unwrap(),
                                    new_value,
                                );
                                info!(
                                    rule = %rule.name,
                                    header = %header_name,
                                    "substituted signature in header"
                                );
                            }
                        }
                    }
                }

                RuleTarget::Query => {
                    if let Some(query) = req.uri().query() {
                        let (replaced, missing) =
                            replace_signatures(query, &self.sig, &|key| vault.get(key).ok());

                        if !missing.is_empty() && rule.on_missing == OnMissing::Block {
                            error!(
                                rule = %rule.name,
                                missing = ?missing,
                                "vault key not found, blocking request"
                            );
                            return Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from(format!(
                                    "network-latch: missing vault keys: {:?}",
                                    missing
                                )))
                                .unwrap()
                                .into();
                        }

                        if replaced != query {
                            let new_uri = format!(
                                "{}?{}",
                                req.uri().path(),
                                replaced
                            );
                            if let Ok(new_uri) = new_uri.parse() {
                                *req.uri_mut() = new_uri;
                                info!(rule = %rule.name, "substituted signature in query");
                            }
                        }
                    }
                }

                RuleTarget::Body => {
                    // Body substitution requires consuming and rebuilding the body.
                    // We collect the body bytes, do replacement, then set a new body.
                    let (parts, body) = req.into_parts();
                    let body_bytes = match http_body_util::BodyExt::collect(body).await {
                        Ok(collected) => collected.to_bytes(),
                        Err(_) => {
                            error!(rule = %rule.name, "failed to read request body");
                            return Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from("network-latch: failed to read request body"))
                                .unwrap()
                                .into();
                        }
                    };

                    let body_str = match std::str::from_utf8(&body_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            // Binary body -- can't scan, reassemble and continue
                            req = Request::from_parts(parts, Body::from(Full::new(Bytes::copy_from_slice(&body_bytes))));
                            continue;
                        }
                    };

                    let (replaced, missing) =
                        replace_signatures(body_str, &self.sig, &|key| vault.get(key).ok());

                    if !missing.is_empty() && rule.on_missing == OnMissing::Block {
                        error!(
                            rule = %rule.name,
                            missing = ?missing,
                            "vault key not found, blocking request"
                        );
                        return Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(format!(
                                "network-latch: missing vault keys: {:?}",
                                missing
                            )))
                            .unwrap()
                            .into();
                    }

                    if replaced != body_str {
                        info!(rule = %rule.name, "substituted signature in body");
                    }

                    req = Request::from_parts(parts, Body::from(replaced));
                }
            }
        }

        req.into()
    }
}
