use crate::config::SignatureConfig;
use crate::engine::scanner::scan_signatures;
use tracing::warn;

pub struct LeakDetector {
    sig: SignatureConfig,
}

impl LeakDetector {
    pub fn new(sig: SignatureConfig) -> Self {
        Self { sig }
    }

    /// Scans text for interpolation signatures and logs warnings.
    /// Returns the list of leaked key names found.
    pub fn check(&self, text: &str, context: &str) -> Vec<String> {
        let keys = scan_signatures(text, &self.sig);
        for key in &keys {
            warn!(
                key = %key,
                context = %context,
                "leak detected: interpolation signature found in unfiltered traffic"
            );
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig() -> SignatureConfig {
        SignatureConfig {
            prefix: "%%VAULT[".to_string(),
            suffix: "]%%".to_string(),
        }
    }

    #[test]
    fn test_detects_leak() {
        let detector = LeakDetector::new(sig());
        let leaked = detector.check(
            "GET /api?token=%%VAULT[SECRET]%% HTTP/1.1",
            "plaintext HTTP to unknown.com",
        );
        assert_eq!(leaked, vec!["SECRET"]);
    }

    #[test]
    fn test_no_leak() {
        let detector = LeakDetector::new(sig());
        let leaked = detector.check("GET /api HTTP/1.1", "plaintext HTTP");
        assert!(leaked.is_empty());
    }
}
