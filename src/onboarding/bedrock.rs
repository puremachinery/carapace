use std::time::Duration;

use crate::agent::bedrock::{sign_aws_v4_request, AwsCredentials};
use crate::onboarding::setup::SetupCheck;

/// AWS regions known to support Bedrock at time of writing.
///
/// This list is used only for an advisory check (Skip, not Fail) so unlisted
/// regions do not block setup. Refresh periodically from:
/// https://docs.aws.amazon.com/general/latest/gr/bedrock.html
const BEDROCK_REGIONS: &[&str] = &[
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-west-2",
];

/// Where a credential value was found.
#[derive(Clone)]
pub struct CredentialSource {
    pub value: String,
    pub source: &'static str,
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSource")
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .finish()
    }
}

/// Detected Bedrock credential sources from the environment.
#[derive(Debug, Clone, Default)]
pub struct BedrockCredentialSources {
    pub region: Option<CredentialSource>,
    pub access_key: Option<CredentialSource>,
    pub secret_key: Option<CredentialSource>,
    pub session_token: Option<CredentialSource>,
}

/// Detect Bedrock credential sources from environment variables.
pub fn detect_credential_sources() -> BedrockCredentialSources {
    let mut sources = BedrockCredentialSources::default();

    if let Some(v) = crate::config::read_config_env("AWS_REGION") {
        if !v.is_empty() {
            sources.region = Some(CredentialSource {
                value: v,
                source: "AWS_REGION",
            });
        }
    }
    if sources.region.is_none() {
        if let Some(v) = crate::config::read_config_env("AWS_DEFAULT_REGION") {
            if !v.is_empty() {
                sources.region = Some(CredentialSource {
                    value: v,
                    source: "AWS_DEFAULT_REGION",
                });
            }
        }
    }

    if let Some(v) = crate::config::read_config_env("AWS_ACCESS_KEY_ID") {
        if !v.is_empty() {
            sources.access_key = Some(CredentialSource {
                value: v,
                source: "AWS_ACCESS_KEY_ID",
            });
        }
    }

    if let Some(v) = crate::config::read_config_env("AWS_SECRET_ACCESS_KEY") {
        if !v.is_empty() {
            sources.secret_key = Some(CredentialSource {
                value: v,
                source: "AWS_SECRET_ACCESS_KEY",
            });
        }
    }

    if let Some(v) = crate::config::read_config_env("AWS_SESSION_TOKEN") {
        if !v.is_empty() {
            sources.session_token = Some(CredentialSource {
                value: v,
                source: "AWS_SESSION_TOKEN",
            });
        }
    }

    sources
}

/// Validate that a region is known to support Bedrock.
pub fn validate_region(region: &str) -> SetupCheck {
    if BEDROCK_REGIONS.contains(&region) {
        SetupCheck::validation_pass(
            "Bedrock region",
            format!("Region `{region}` supports Bedrock"),
            None,
        )
    } else {
        SetupCheck::validation_skip(
            "Bedrock region",
            format!(
                "Region `{region}` is not in the known Bedrock region list; \
                 it may work if recently launched"
            ),
            Some(format!(
                "Known Bedrock regions: {}. \
                 If `{region}` was recently added, this is safe to ignore.",
                BEDROCK_REGIONS.join(", ")
            )),
            None,
        )
    }
}

/// Validate Bedrock credentials by calling the ListFoundationModels API.
///
/// Returns a credential-validation check and, on success, the raw JSON body
/// for downstream model-access checks.
pub async fn validate_bedrock_credentials(
    region: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> (SetupCheck, Option<serde_json::Value>) {
    let host = format!("bedrock.{region}.amazonaws.com");
    let uri_path = "/foundation-models";
    let datetime = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let creds = AwsCredentials {
        region,
        access_key_id: access_key,
        secret_access_key: secret_key,
        session_token,
    };
    let headers = sign_aws_v4_request(&creds, &host, "GET", uri_path, b"", &datetime);

    let url = format!("https://{host}{uri_path}");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                SetupCheck::validation_fail(
                    "Bedrock credentials",
                    format!("Failed to build HTTP client: {e}"),
                    "This is unexpected. Check your system TLS/network configuration.".to_string(),
                    None,
                ),
                None,
            );
        }
    };

    let mut request = client.get(&url);
    for (name, value) in &headers {
        request = request.header(name.as_str(), value.as_str());
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            let remediation = if e.is_timeout() {
                format!(
                    "Request to {host} timed out. Verify the region is correct \
                     and your network can reach AWS endpoints."
                )
            } else if e.is_connect() {
                format!(
                    "Could not connect to {host}. Verify the region is correct \
                     and check your network/proxy configuration."
                )
            } else {
                format!(
                    "Request failed: {e}. Check network connectivity and \
                     verify the region `{region}` is correct."
                )
            };
            return (
                SetupCheck::validation_fail(
                    "Bedrock credentials",
                    format!("{e}"),
                    remediation,
                    None,
                ),
                None,
            );
        }
    };

    let status = response.status();
    if status.is_success() {
        match response.json::<serde_json::Value>().await {
            Ok(body) => (
                SetupCheck::validation_pass(
                    "Bedrock credentials",
                    format!("AWS credentials are valid and authorized for Bedrock in `{region}`"),
                    None,
                ),
                Some(body),
            ),
            Err(e) => (
                SetupCheck::validation_skip(
                    "Bedrock credentials",
                    format!(
                        "AWS credentials are valid (HTTP 200) but response parsing failed: {e}"
                    ),
                    Some("Run `cara verify` after setup to confirm model access.".to_string()),
                    None,
                ),
                None,
            ),
        }
    } else {
        let body_text = response.text().await.unwrap_or_default();
        // AccessDeniedException means credentials are valid but lack
        // bedrock:ListFoundationModels. The runtime path only needs
        // bedrock:InvokeModel, so this is not a setup failure.
        if status.as_u16() == 403 && body_text.contains("AccessDeniedException") {
            return (
                SetupCheck::validation_skip(
                    "Bedrock credentials",
                    "AWS credentials are valid but lack `bedrock:ListFoundationModels` \
                     permission; cannot verify model access during setup"
                        .to_string(),
                    Some(
                        "Run `cara verify` after setup to confirm the runtime model path works. \
                         To enable full setup validation, attach `AmazonBedrockReadOnly` to \
                         your IAM user/role."
                            .to_string(),
                    ),
                    None,
                ),
                None,
            );
        }
        let (detail, remediation) = classify_api_error(status.as_u16(), &body_text, region);
        (
            SetupCheck::validation_fail("Bedrock credentials", detail, remediation, None),
            None,
        )
    }
}

/// Check whether a specific model is accessible in the ListFoundationModels response.
pub fn check_model_access(model_id: &str, foundation_models: &serde_json::Value) -> SetupCheck {
    let bare_model = crate::agent::bedrock::strip_bedrock_prefix(model_id);

    let models = match foundation_models.get("modelSummaries") {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => {
            return SetupCheck::validation_skip(
                "Model access",
                "Could not parse model list from ListFoundationModels response".to_string(),
                Some("Run `cara verify` after setup to confirm model access.".to_string()),
                None,
            );
        }
    };

    for model in models {
        let id = model.get("modelId").and_then(|v| v.as_str()).unwrap_or("");
        if id == bare_model {
            let status = model
                .get("modelLifecycle")
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            if status != "ACTIVE" {
                return SetupCheck::validation_fail(
                    "Model access",
                    format!("Model `{bare_model}` found but lifecycle status is `{status}`"),
                    "The model is not active or is not yet available. \
                     Check the AWS console for model status in your region."
                        .to_string(),
                    None,
                );
            }

            let supports_on_demand = model
                .get("inferenceTypesSupported")
                .and_then(|v| v.as_array())
                .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("ON_DEMAND")));

            if !supports_on_demand {
                return SetupCheck::validation_fail(
                    "Model access",
                    format!(
                        "Model `{bare_model}` is active but does not support on-demand inference"
                    ),
                    "This model requires provisioned throughput. Choose a model \
                     that supports on-demand inference, or provision throughput \
                     in the AWS console."
                        .to_string(),
                    None,
                );
            }

            return SetupCheck::validation_pass(
                "Model access",
                format!("Model `{bare_model}` is active and supports on-demand inference"),
                None,
            );
        }
    }

    SetupCheck::validation_fail(
        "Model access",
        format!(
            "Model `{bare_model}` not found in the ListFoundationModels response for this region"
        ),
        format!(
            "Verify that `{bare_model}` is available in your region and that \
             you have requested access in the AWS console \
             (Bedrock → Model access → Request access)."
        ),
        None,
    )
}

fn classify_api_error(status: u16, body: &str, region: &str) -> (String, String) {
    match status {
        403 => {
            if body.contains("SignatureDoesNotMatch") {
                (
                    "AWS signature mismatch (HTTP 403).".to_string(),
                    "Your secret access key is likely incorrect. \
                     Double-check the key or regenerate it in the IAM console."
                        .to_string(),
                )
            } else if body.contains("InvalidClientTokenId")
                || body.contains("UnrecognizedClientException")
            {
                (
                    "AWS access key not recognized (HTTP 403).".to_string(),
                    "Your access key ID is invalid or has been deactivated. \
                     Verify it in the IAM console."
                        .to_string(),
                )
            // AccessDeniedException is intercepted in validate_bedrock_credentials
            // before classify_api_error is called, so it does not need a branch here.
            } else if body.contains("ExpiredTokenException") || body.contains("ExpiredToken") {
                (
                    "AWS session token expired (HTTP 403).".to_string(),
                    "Your temporary credentials have expired. \
                     Refresh them with `aws sts get-session-token` or \
                     re-assume your role."
                        .to_string(),
                )
            } else {
                (
                    "AWS authentication failed (HTTP 403).".to_string(),
                    "Verify your access key, secret key, and session token (if using \
                     temporary credentials). Run `aws sts get-caller-identity` \
                     to test your credentials outside of Carapace."
                        .to_string(),
                )
            }
        }
        401 => (
            "AWS authentication failed (HTTP 401).".to_string(),
            "Verify your access key ID and secret access key. \
             Run `aws sts get-caller-identity` to test outside of Carapace."
                .to_string(),
        ),
        404 => (
            format!("Bedrock endpoint not found in region `{region}` (HTTP 404)."),
            format!(
                "Bedrock may not be available in `{region}`. \
                 Try a region like `us-east-1` or `us-west-2`."
            ),
        ),
        _ => (
            format!("Bedrock API returned HTTP {status}."),
            "Unexpected error. Verify your credentials and region. \
             Run `aws sts get-caller-identity` to test credentials outside of Carapace."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env::ScopedEnv;
    use serde_json::json;

    #[test]
    fn detect_sources_finds_env_vars() {
        let mut env = ScopedEnv::new();
        env.set("AWS_REGION", "us-west-2")
            .set("AWS_ACCESS_KEY_ID", "AKIATEST")
            .set("AWS_SECRET_ACCESS_KEY", "secret123")
            .set("AWS_SESSION_TOKEN", "token456");

        let sources = detect_credential_sources();
        assert_eq!(sources.region.as_ref().unwrap().value, "us-west-2");
        assert_eq!(sources.region.as_ref().unwrap().source, "AWS_REGION");
        assert_eq!(
            sources.access_key.as_ref().unwrap().source,
            "AWS_ACCESS_KEY_ID"
        );
        assert_eq!(
            sources.secret_key.as_ref().unwrap().source,
            "AWS_SECRET_ACCESS_KEY"
        );
        assert_eq!(
            sources.session_token.as_ref().unwrap().source,
            "AWS_SESSION_TOKEN"
        );
    }

    #[test]
    fn detect_sources_falls_back_to_default_region() {
        let mut env = ScopedEnv::new();
        env.unset("AWS_REGION")
            .set("AWS_DEFAULT_REGION", "eu-west-1")
            .unset("AWS_ACCESS_KEY_ID")
            .unset("AWS_SECRET_ACCESS_KEY")
            .unset("AWS_SESSION_TOKEN");

        let sources = detect_credential_sources();
        assert_eq!(sources.region.as_ref().unwrap().value, "eu-west-1");
        assert_eq!(
            sources.region.as_ref().unwrap().source,
            "AWS_DEFAULT_REGION"
        );
        assert!(sources.access_key.is_none());
    }

    #[test]
    fn detect_sources_empty_when_unset() {
        let mut env = ScopedEnv::new();
        env.unset("AWS_REGION")
            .unset("AWS_DEFAULT_REGION")
            .unset("AWS_ACCESS_KEY_ID")
            .unset("AWS_SECRET_ACCESS_KEY")
            .unset("AWS_SESSION_TOKEN");

        let sources = detect_credential_sources();
        assert!(sources.region.is_none());
        assert!(sources.access_key.is_none());
        assert!(sources.secret_key.is_none());
        assert!(sources.session_token.is_none());
        drop(env);
    }

    #[test]
    fn validate_region_known() {
        let check = validate_region("us-east-1");
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Pass
        );
    }

    #[test]
    fn validate_region_unknown() {
        let check = validate_region("mars-west-1");
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Skip
        );
    }

    #[test]
    fn check_model_access_active_missing_inference_types() {
        let body = json!({
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                    "modelLifecycle": { "status": "ACTIVE" }
                }
            ]
        });
        let check = check_model_access("bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Fail
        );
    }

    #[test]
    fn check_model_access_found_non_active_lifecycle_status() {
        let body = json!({
            "modelSummaries": [
                {
                    "modelId": "anthropic.claude-v2",
                    "modelLifecycle": { "status": "NOT_ACTIVE" }
                }
            ]
        });
        let check = check_model_access("anthropic.claude-v2", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Fail
        );
    }

    #[test]
    fn check_model_access_not_found() {
        let body = json!({ "modelSummaries": [] });
        let check = check_model_access("bedrock:nonexistent-model", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Fail
        );
    }

    #[test]
    fn check_model_access_malformed_response() {
        let body = json!({});
        let check = check_model_access("some-model", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Skip
        );
    }

    #[test]
    fn classify_error_signature_mismatch() {
        let (detail, _) = classify_api_error(403, "SignatureDoesNotMatch", "us-east-1");
        assert!(detail.contains("signature mismatch"));
    }

    #[test]
    fn classify_error_invalid_key() {
        let (detail, _) = classify_api_error(403, "UnrecognizedClientException", "us-east-1");
        assert!(detail.contains("not recognized"));
    }

    #[test]
    fn classify_error_access_denied_falls_through() {
        // AccessDeniedException is intercepted in validate_bedrock_credentials
        // before classify_api_error is called. If it somehow reaches here,
        // it falls through to the generic 403 branch.
        let (detail, _) = classify_api_error(403, "AccessDeniedException", "us-east-1");
        assert!(detail.contains("403"));
    }

    #[test]
    fn classify_error_expired_token() {
        let (detail, _) = classify_api_error(403, "ExpiredTokenException", "us-east-1");
        assert!(detail.contains("expired"));
    }

    #[test]
    fn classify_error_region_404() {
        let (detail, _) = classify_api_error(404, "", "mars-west-1");
        assert!(detail.contains("mars-west-1"));
    }

    #[test]
    fn classify_error_401() {
        let (detail, _) = classify_api_error(401, "", "us-east-1");
        assert!(detail.contains("401"));
    }

    #[test]
    fn classify_error_unknown_status() {
        let (detail, _) = classify_api_error(503, "", "us-east-1");
        assert!(detail.contains("503"));
    }

    #[test]
    fn check_model_access_active_on_demand() {
        let body = json!({
            "modelSummaries": [{
                "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                "modelLifecycle": { "status": "ACTIVE" },
                "inferenceTypesSupported": ["ON_DEMAND"]
            }]
        });
        let check = check_model_access("bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Pass
        );
    }

    #[test]
    fn check_model_access_active_provisioned_only() {
        let body = json!({
            "modelSummaries": [{
                "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                "modelLifecycle": { "status": "ACTIVE" },
                "inferenceTypesSupported": ["PROVISIONED"]
            }]
        });
        let check = check_model_access("bedrock:anthropic.claude-3-5-sonnet-20240620-v1:0", &body);
        assert_eq!(
            check.status,
            crate::onboarding::setup::SetupCheckStatus::Fail
        );
    }
}
