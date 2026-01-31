//! Post-flight output filtering.
//!
//! Scans LLM output for PII (email, phone, SSN, credit card) and credential
//! patterns, and returns sanitized text with findings.

use std::sync::LazyLock;

use regex::Regex;

use super::{FindingCategory, FindingSeverity, PostflightConfig};

/// A single post-flight finding.
#[derive(Debug, Clone)]
pub struct PostflightFinding {
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    pub description: String,
    /// The matched text (redacted form).
    pub matched: String,
}

/// Result of post-flight filtering.
#[derive(Debug, Clone)]
pub struct PostflightResult {
    /// The sanitized output text.
    pub sanitized: String,
    /// Findings from the scan.
    pub findings: Vec<PostflightFinding>,
    /// Whether the output should be blocked entirely.
    pub blocked: bool,
}

impl PostflightResult {
    /// Returns `true` if no findings were detected.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PII patterns
// ---------------------------------------------------------------------------

static RE_EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap()
});

static RE_SSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap());

// ---------------------------------------------------------------------------
// Credential patterns (reuses patterns from logging/redact.rs)
// ---------------------------------------------------------------------------

static RE_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(sk-[a-zA-Z0-9]{20,})").unwrap());

static RE_BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(Bearer\s+[a-zA-Z0-9._\-]{10,})").unwrap());

static RE_BASIC_AUTH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(Basic\s+[a-zA-Z0-9+/=]{10,})").unwrap());

static RE_PASSWORD_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+").unwrap());

static RE_AWS_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"AKIA[A-Z0-9]{16}").unwrap());

static RE_GITHUB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap());

/// Validate a credit card number using the Luhn algorithm.
fn luhn_check(digits: &str) -> bool {
    let digits: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Filter LLM output for PII and credential patterns.
///
/// Uses a single-pass approach: all pattern matches are collected with their
/// byte ranges, sorted, merged for overlaps, and the sanitized string is built
/// in one sweep. Custom regex patterns are pre-compiled once per call rather
/// than inside the match loop.
pub fn filter_output(text: &str, config: &PostflightConfig) -> PostflightResult {
    if !config.enabled {
        return PostflightResult {
            sanitized: text.to_string(),
            findings: Vec::new(),
            blocked: false,
        };
    }

    // Collect all matches as (start, end, redaction_label, severity, category, description).
    let mut matches: Vec<(usize, usize, &str, FindingSeverity, FindingCategory, String)> =
        Vec::new();

    if config.block_pii {
        for mat in RE_EMAIL.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[EMAIL_REDACTED]",
                FindingSeverity::Warning,
                FindingCategory::Pii,
                "Email address detected in output".to_string(),
            ));
        }
        for mat in RE_PHONE.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[PHONE_REDACTED]",
                FindingSeverity::Warning,
                FindingCategory::Pii,
                "Phone number detected in output".to_string(),
            ));
        }
        for mat in RE_SSN.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[SSN_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Pii,
                "Social Security Number detected in output".to_string(),
            ));
        }
        for mat in RE_CREDIT_CARD.find_iter(text) {
            if luhn_check(mat.as_str()) {
                matches.push((
                    mat.start(),
                    mat.end(),
                    "[CC_REDACTED]",
                    FindingSeverity::Critical,
                    FindingCategory::Pii,
                    "Credit card number detected in output (Luhn-valid)".to_string(),
                ));
            }
        }
    }

    if config.block_credentials {
        for mat in RE_API_KEY.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[KEY_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "API key pattern detected in output".to_string(),
            ));
        }
        for mat in RE_BEARER.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[TOKEN_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "Bearer token detected in output".to_string(),
            ));
        }
        for mat in RE_BASIC_AUTH.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[AUTH_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "Basic auth credential detected in output".to_string(),
            ));
        }
        for mat in RE_PASSWORD_PARAM.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[PASSWORD_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "Password parameter detected in output".to_string(),
            ));
        }
        for mat in RE_AWS_KEY.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[AWS_KEY_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "AWS access key detected in output".to_string(),
            ));
        }
        for mat in RE_GITHUB_TOKEN.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[GITHUB_TOKEN_REDACTED]",
                FindingSeverity::Critical,
                FindingCategory::Credential,
                "GitHub token detected in output".to_string(),
            ));
        }
    }

    // Pre-compile custom patterns once per call (not per-match).
    let compiled_custom: Vec<Regex> = config
        .custom_patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                tracing::warn!(
                    pattern = %p,
                    error = %e,
                    "invalid postflight custom regex pattern, skipping"
                );
                None
            }
        })
        .collect();

    for re in &compiled_custom {
        for mat in re.find_iter(text) {
            matches.push((
                mat.start(),
                mat.end(),
                "[CUSTOM_REDACTED]",
                FindingSeverity::Warning,
                FindingCategory::Credential,
                format!("Custom pattern matched: {}", re.as_str()),
            ));
        }
    }

    // Build findings from collected matches.
    let mut findings: Vec<PostflightFinding> = Vec::new();
    for &(_, _, redaction, severity, category, ref desc) in &matches {
        findings.push(PostflightFinding {
            severity,
            category,
            description: desc.clone(),
            matched: match redaction {
                "[EMAIL_REDACTED]" => "[EMAIL]",
                "[PHONE_REDACTED]" => "[PHONE]",
                "[SSN_REDACTED]" => "[SSN]",
                "[CC_REDACTED]" => "[CREDIT_CARD]",
                "[KEY_REDACTED]" => "[API_KEY]",
                "[TOKEN_REDACTED]" => "[BEARER]",
                "[AUTH_REDACTED]" => "[BASIC_AUTH]",
                "[PASSWORD_REDACTED]" => "[PASSWORD]",
                "[AWS_KEY_REDACTED]" => "[AWS_KEY]",
                "[GITHUB_TOKEN_REDACTED]" => "[GITHUB_TOKEN]",
                "[CUSTOM_REDACTED]" => "[CUSTOM]",
                _ => "[REDACTED]",
            }
            .to_string(),
        });
    }

    // Sort matches by start position, then by end (descending) for overlapping.
    matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    // Build sanitized string in a single pass, merging overlapping ranges.
    let sanitized = if matches.is_empty() {
        text.to_string()
    } else {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        // Merge overlapping ranges.
        let mut merged: Vec<(usize, usize, &str)> = Vec::new();
        for &(start, end, redaction, _, _, _) in &matches {
            if let Some(last) = merged.last_mut() {
                if start < last.1 {
                    // Overlapping — extend if needed, keep the first redaction label.
                    if end > last.1 {
                        last.1 = end;
                    }
                    continue;
                }
            }
            merged.push((start, end, redaction));
        }

        for (start, end, redaction) in merged {
            if start >= last_end {
                result.push_str(&text[last_end..start]);
                result.push_str(redaction);
                last_end = end;
            }
        }
        result.push_str(&text[last_end..]);
        result
    };

    let blocked = findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Critical);

    PostflightResult {
        sanitized,
        findings,
        blocked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PostflightConfig {
        PostflightConfig::default()
    }

    // ==================== Clean Output ====================

    #[test]
    fn test_clean_output() {
        let result = filter_output("The weather is sunny today.", &default_config());
        assert!(result.is_clean());
        assert!(!result.blocked);
        assert_eq!(result.sanitized, "The weather is sunny today.");
    }

    // ==================== PII Detection ====================

    #[test]
    fn test_email_detected() {
        let result = filter_output("Contact john@example.com for details.", &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[EMAIL_REDACTED]"));
        assert!(!result.sanitized.contains("john@example.com"));
    }

    #[test]
    fn test_phone_detected() {
        let result = filter_output("Call 555-123-4567 for support.", &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[PHONE_REDACTED]"));
    }

    #[test]
    fn test_ssn_detected() {
        let result = filter_output("SSN: 123-45-6789", &default_config());
        assert!(!result.is_clean());
        assert!(result.blocked);
        assert!(result.sanitized.contains("[SSN_REDACTED]"));
    }

    #[test]
    fn test_credit_card_luhn_valid() {
        // Valid Luhn: 4111 1111 1111 1111
        let result = filter_output("Card: 4111 1111 1111 1111", &default_config());
        assert!(!result.is_clean());
        assert!(result.blocked);
        assert!(result.sanitized.contains("[CC_REDACTED]"));
    }

    #[test]
    fn test_credit_card_luhn_invalid() {
        // Invalid Luhn: 1234 5678 9012 3456
        let result = filter_output("Card: 1234 5678 9012 3456", &default_config());
        // Should not be flagged since Luhn fails
        let cc_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.description.contains("Credit card"))
            .collect();
        assert!(cc_findings.is_empty());
    }

    // ==================== Credential Detection ====================

    #[test]
    fn test_api_key_detected() {
        let result = filter_output(
            "Use key: sk-abc123def456ghi789jkl012mno345",
            &default_config(),
        );
        assert!(!result.is_clean());
        assert!(result.blocked);
        assert!(result.sanitized.contains("[KEY_REDACTED]"));
    }

    #[test]
    fn test_bearer_token_detected() {
        let result = filter_output(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
            &default_config(),
        );
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[TOKEN_REDACTED]"));
    }

    #[test]
    fn test_basic_auth_detected() {
        let result = filter_output("Auth: Basic dXNlcjpwYXNzd29yZA==", &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[AUTH_REDACTED]"));
    }

    #[test]
    fn test_password_param_detected() {
        let result = filter_output("password=mysecretvalue123", &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[PASSWORD_REDACTED]"));
    }

    #[test]
    fn test_aws_key_detected() {
        let result = filter_output("AWS key: AKIAIOSFODNN7EXAMPLE", &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[AWS_KEY_REDACTED]"));
    }

    #[test]
    fn test_github_token_detected() {
        let long_suffix = "A".repeat(36);
        let text = format!("Token: ghp_{long_suffix}");
        let result = filter_output(&text, &default_config());
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[GITHUB_TOKEN_REDACTED]"));
    }

    // ==================== Config Toggles ====================

    #[test]
    fn test_disabled_config() {
        let config = PostflightConfig {
            enabled: false,
            ..Default::default()
        };
        let result = filter_output("SSN: 123-45-6789", &config);
        assert!(result.is_clean());
        assert!(!result.blocked);
    }

    #[test]
    fn test_pii_disabled() {
        let config = PostflightConfig {
            block_pii: false,
            ..Default::default()
        };
        let result = filter_output("Email: john@example.com", &config);
        let pii_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::Pii)
            .collect();
        assert!(pii_findings.is_empty());
    }

    #[test]
    fn test_credentials_disabled() {
        let config = PostflightConfig {
            block_credentials: false,
            ..Default::default()
        };
        let result = filter_output("Key: sk-abc123def456ghi789jkl012mno345", &config);
        let cred_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.category == FindingCategory::Credential)
            .collect();
        assert!(cred_findings.is_empty());
    }

    // ==================== Custom Patterns ====================

    #[test]
    fn test_custom_pattern() {
        let config = PostflightConfig {
            custom_patterns: vec![r"internal_id_\d+".to_string()],
            ..Default::default()
        };
        let result = filter_output("Found internal_id_12345 in database.", &config);
        assert!(!result.is_clean());
        assert!(result.sanitized.contains("[CUSTOM_REDACTED]"));
    }

    #[test]
    fn test_invalid_custom_pattern_ignored() {
        let config = PostflightConfig {
            custom_patterns: vec![r"[invalid".to_string()],
            ..Default::default()
        };
        // Should not panic
        let result = filter_output("some text", &config);
        assert!(result.is_clean());
    }

    // ==================== Luhn Algorithm ====================

    #[test]
    fn test_luhn_valid_numbers() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // Mastercard test
        assert!(luhn_check("340000000000009")); // Amex test (15 digits)
    }

    #[test]
    fn test_luhn_invalid_numbers() {
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("1111111111111111"));
    }

    #[test]
    fn test_luhn_too_short() {
        assert!(!luhn_check("1234"));
    }

    // ==================== Multiple Findings ====================

    #[test]
    fn test_multiple_pii_types() {
        let result = filter_output(
            "Contact john@example.com or call 555-123-4567. SSN: 123-45-6789",
            &default_config(),
        );
        assert!(result.blocked); // SSN is critical
        assert!(result.findings.len() >= 3);
    }

    #[test]
    fn test_empty_text() {
        let result = filter_output("", &default_config());
        assert!(result.is_clean());
        assert_eq!(result.sanitized, "");
    }
}
