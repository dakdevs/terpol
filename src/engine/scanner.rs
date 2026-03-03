use crate::config::SignatureConfig;

/// Finds all `%%VAULT[KEY]%%` patterns in the input and extracts the keys.
pub fn scan_signatures(input: &str, sig: &SignatureConfig) -> Vec<String> {
    let mut keys = Vec::new();
    let mut search_from = 0;

    while let Some(start) = input[search_from..].find(&sig.prefix) {
        let abs_start = search_from + start;
        let after_prefix = abs_start + sig.prefix.len();

        if let Some(end) = input[after_prefix..].find(&sig.suffix) {
            let key = &input[after_prefix..after_prefix + end];
            if !key.is_empty() {
                keys.push(key.to_string());
            }
            search_from = after_prefix + end + sig.suffix.len();
        } else {
            break;
        }
    }

    keys
}

/// Replaces all signatures in input with values from the provided lookup function.
/// Returns the replaced text and a list of keys that were not found.
pub fn replace_signatures(
    input: &str,
    sig: &SignatureConfig,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> (String, Vec<String>) {
    let mut output = String::with_capacity(input.len());
    let mut missing = Vec::new();
    let mut search_from = 0;

    while let Some(start) = input[search_from..].find(&sig.prefix) {
        let abs_start = search_from + start;
        // Append text before the signature
        output.push_str(&input[search_from..abs_start]);

        let after_prefix = abs_start + sig.prefix.len();

        if let Some(end) = input[after_prefix..].find(&sig.suffix) {
            let key = &input[after_prefix..after_prefix + end];
            match lookup(key) {
                Some(value) => output.push_str(&value),
                None => {
                    // Leave the original signature in place
                    output.push_str(&input[abs_start..after_prefix + end + sig.suffix.len()]);
                    missing.push(key.to_string());
                }
            }
            search_from = after_prefix + end + sig.suffix.len();
        } else {
            // No closing suffix -- append the rest as-is
            output.push_str(&input[abs_start..]);
            search_from = input.len();
            break;
        }
    }

    // Append any remaining text after the last signature
    output.push_str(&input[search_from..]);

    (output, missing)
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
    fn test_scan_finds_keys() {
        let input = "Bearer %%VAULT[API_KEY]%% and %%VAULT[OTHER]%%";
        let keys = scan_signatures(input, &sig());
        assert_eq!(keys, vec!["API_KEY", "OTHER"]);
    }

    #[test]
    fn test_scan_no_signatures() {
        let input = "plain text with no secrets";
        let keys = scan_signatures(input, &sig());
        assert!(keys.is_empty());
    }

    #[test]
    fn test_scan_unclosed_signature() {
        let input = "Bearer %%VAULT[UNCLOSED";
        let keys = scan_signatures(input, &sig());
        assert!(keys.is_empty());
    }

    #[test]
    fn test_replace_all_found() {
        let input = "Bearer %%VAULT[TOKEN]%%";
        let lookup = |key: &str| match key {
            "TOKEN" => Some("sk-12345".to_string()),
            _ => None,
        };
        let (output, missing) = replace_signatures(input, &sig(), &lookup);
        assert_eq!(output, "Bearer sk-12345");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_replace_missing_key() {
        let input = "Key: %%VAULT[MISSING]%%";
        let lookup = |_: &str| None;
        let (output, missing) = replace_signatures(input, &sig(), &lookup);
        assert_eq!(output, "Key: %%VAULT[MISSING]%%");
        assert_eq!(missing, vec!["MISSING"]);
    }

    #[test]
    fn test_replace_multiple_mixed() {
        let input = "%%VAULT[A]%% and %%VAULT[B]%% and %%VAULT[C]%%";
        let lookup = |key: &str| match key {
            "A" => Some("1".to_string()),
            "C" => Some("3".to_string()),
            _ => None,
        };
        let (output, missing) = replace_signatures(input, &sig(), &lookup);
        assert_eq!(output, "1 and %%VAULT[B]%% and 3");
        assert_eq!(missing, vec!["B"]);
    }

    #[test]
    fn test_replace_adjacent_signatures() {
        let input = "%%VAULT[A]%%%%VAULT[B]%%";
        let lookup = |key: &str| match key {
            "A" => Some("1".to_string()),
            "B" => Some("2".to_string()),
            _ => None,
        };
        let (output, missing) = replace_signatures(input, &sig(), &lookup);
        assert_eq!(output, "12");
        assert!(missing.is_empty());
    }

    #[test]
    fn test_custom_delimiters() {
        let custom_sig = SignatureConfig {
            prefix: "${secret:".to_string(),
            suffix: "}".to_string(),
        };
        let input = "value=${secret:MY_KEY}";
        let keys = scan_signatures(input, &custom_sig);
        assert_eq!(keys, vec!["MY_KEY"]);
    }
}
