use crate::config::Rule;
use globset::{Glob, GlobMatcher};

pub struct CompiledRule {
    pub rule: Rule,
    domain_matcher: GlobMatcher,
    path_matcher: GlobMatcher,
}

impl CompiledRule {
    pub fn new(rule: Rule) -> Result<Self, globset::Error> {
        let domain_matcher = Glob::new(&rule.domain)?.compile_matcher();
        let path_matcher = Glob::new(&rule.path)?.compile_matcher();
        Ok(Self {
            rule,
            domain_matcher,
            path_matcher,
        })
    }

    pub fn matches(&self, domain: &str, method: &str, path: &str) -> bool {
        if !self.domain_matcher.is_match(domain) {
            return false;
        }
        if self.rule.method != "*" && !self.rule.method.eq_ignore_ascii_case(method) {
            return false;
        }
        if self.rule.path != "*" && !self.path_matcher.is_match(path) {
            return false;
        }
        true
    }
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Result<Self, globset::Error> {
        let compiled = rules
            .into_iter()
            .map(CompiledRule::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { rules: compiled })
    }

    /// Returns all rules matching the given request properties.
    pub fn match_rules(&self, domain: &str, method: &str, path: &str) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.matches(domain, method, path))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OnMissing, RuleTarget};

    fn make_rule(domain: &str, method: &str, path: &str, target: RuleTarget) -> Rule {
        Rule {
            name: "test".to_string(),
            secret: "KEY".to_string(),
            domain: domain.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            target: target.clone(),
            header_name: if target == RuleTarget::Header {
                Some("Authorization".to_string())
            } else {
                None
            },
            on_missing: OnMissing::Block,
        }
    }

    #[test]
    fn test_exact_domain_match() {
        let engine =
            RuleEngine::new(vec![make_rule("api.stripe.com", "*", "*", RuleTarget::Header)])
                .unwrap();

        let matches = engine.match_rules("api.stripe.com", "GET", "/v1/charges");
        assert_eq!(matches.len(), 1);

        let matches = engine.match_rules("other.com", "GET", "/");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_wildcard_domain() {
        let engine =
            RuleEngine::new(vec![make_rule("*.internal.corp", "*", "*", RuleTarget::Body)])
                .unwrap();

        let matches = engine.match_rules("api.internal.corp", "POST", "/");
        assert_eq!(matches.len(), 1);

        let matches = engine.match_rules("external.com", "POST", "/");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_method_filter() {
        let engine =
            RuleEngine::new(vec![make_rule("api.example.com", "POST", "*", RuleTarget::Body)])
                .unwrap();

        let matches = engine.match_rules("api.example.com", "POST", "/");
        assert_eq!(matches.len(), 1);

        let matches = engine.match_rules("api.example.com", "GET", "/");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_path_glob() {
        let engine =
            RuleEngine::new(vec![make_rule("api.stripe.com", "*", "/v1/*", RuleTarget::Header)])
                .unwrap();

        let matches = engine.match_rules("api.stripe.com", "GET", "/v1/charges");
        assert_eq!(matches.len(), 1);

        let matches = engine.match_rules("api.stripe.com", "GET", "/v2/charges");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_multiple_rules_match() {
        let engine = RuleEngine::new(vec![
            make_rule("api.example.com", "*", "*", RuleTarget::Header),
            make_rule("api.example.com", "POST", "/api/*", RuleTarget::Body),
        ])
        .unwrap();

        let matches = engine.match_rules("api.example.com", "POST", "/api/data");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_method_case_insensitive() {
        let engine =
            RuleEngine::new(vec![make_rule("x.com", "post", "*", RuleTarget::Body)]).unwrap();

        let matches = engine.match_rules("x.com", "POST", "/");
        assert_eq!(matches.len(), 1);
    }
}
