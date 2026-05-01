//! Golden trace test runner
//!
//! Validates WS and HTTP responses against golden traces for schema + field presence.
//! These tests verify:
//! 1. Golden trace files are valid JSON with expected structure
//! 2. All required fields are present in trace definitions
//! 3. Schema definitions are consistent
//!
//! Integration tests (against a running gateway) are separate and gated behind
//! a feature flag since they require a live server.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

/// WebSocket handshake trace structure
#[derive(Debug, Deserialize)]
struct WsHandshakeTrace {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    description: String,
    source_files: Vec<String>,
    protocol_version: u32,
    scenarios: Vec<WsScenario>,
    connect_params_schema: Value,
    hello_ok_schema: Value,
}

#[derive(Debug, Deserialize)]
struct WsScenario {
    name: String,
    description: String,
    #[serde(default)]
    steps: Vec<WsStep>,
}

#[derive(Debug, Deserialize)]
struct WsStep {
    action: String,
}

/// WebSocket messages trace structure
#[derive(Debug, Deserialize)]
struct WsMessagesTrace {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    description: String,
    source_files: Vec<String>,
    frame_types: HashMap<String, Value>,
    methods: Value,
}

/// WebSocket events trace structure
#[derive(Debug, Deserialize)]
struct WsEventsTrace {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    description: String,
    source_files: Vec<String>,
    event_list: Vec<String>,
    events: HashMap<String, EventDefinition>,
}

#[derive(Debug, Deserialize)]
struct EventDefinition {
    description: String,
}

/// WebSocket errors trace structure
#[derive(Debug, Deserialize)]
struct WsErrorsTrace {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    description: String,
    source_files: Vec<String>,
    error_codes: ErrorCodesSection,
    close_codes: CloseCodesSection,
}

#[derive(Debug, Deserialize)]
struct ErrorCodesSection {
    #[serde(default)]
    source: Option<String>,
    codes: HashMap<String, ErrorCodeDef>,
}

#[derive(Debug, Deserialize)]
struct CloseCodesSection {
    codes: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ErrorCodeDef {
    description: String,
    retryable: bool,
}

/// HTTP endpoint trace structure
#[derive(Debug, Deserialize)]
struct HttpEndpointTrace {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    description: String,
    source_files: Vec<String>,
}

// ============================================================================
// Test utilities
// ============================================================================

fn golden_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden")
}

/// Validate that a JSON value contains all expected fields
fn validate_has_fields(value: &Value, fields: &[&str], context: &str) {
    if let Value::Object(map) = value {
        for field in fields {
            assert!(
                map.contains_key(*field),
                "{}: missing required field '{}'",
                context,
                field
            );
        }
    } else {
        panic!("{}: expected object, got {:?}", context, value);
    }
}

/// Validate that a schema object has required JSON Schema fields
fn validate_schema_structure(schema: &Value, context: &str) {
    if let Value::Object(map) = schema {
        // Schema should have 'type' or be a reference
        let has_type = map.contains_key("type");
        let has_ref = map.contains_key("$ref");
        let has_const = map.contains_key("const");
        let has_enum = map.contains_key("enum");
        let has_oneof = map.contains_key("oneOf");
        let has_anyof = map.contains_key("anyOf");
        let has_properties = map.contains_key("properties");

        assert!(
            has_type
                || has_ref
                || has_const
                || has_enum
                || has_oneof
                || has_anyof
                || has_properties,
            "{}: schema should have type, $ref, const, enum, oneOf, anyOf, or properties",
            context
        );
    }
}

// ============================================================================
// WebSocket golden trace tests
// ============================================================================

#[test]
fn test_ws_handshake_trace_valid() {
    let path = format!("{}/ws/handshake.json", golden_dir());
    let content = fs::read_to_string(&path).expect("Failed to read handshake.json");

    let trace: WsHandshakeTrace =
        serde_json::from_str(&content).expect("Failed to parse handshake.json");

    // Validate required fields
    assert_eq!(trace.schema.as_deref(), Some("golden-trace-v1"));
    assert!(
        !trace.description.is_empty(),
        "description should not be empty"
    );
    assert!(
        !trace.source_files.is_empty(),
        "source_files should not be empty"
    );
    assert_eq!(trace.protocol_version, 3, "protocol version should be 3");
    assert!(!trace.scenarios.is_empty(), "scenarios should not be empty");

    // Validate scenarios have required structure
    for scenario in &trace.scenarios {
        assert!(
            !scenario.name.is_empty(),
            "scenario name should not be empty"
        );
        assert!(
            !scenario.description.is_empty(),
            "scenario description should not be empty"
        );
        assert!(
            !scenario.steps.is_empty(),
            "scenario '{}' should have steps",
            scenario.name
        );

        // Validate each step has an action
        for (i, step) in scenario.steps.iter().enumerate() {
            assert!(
                !step.action.is_empty(),
                "scenario '{}' step {} should have action",
                scenario.name,
                i
            );
        }
    }

    // Validate schemas are proper JSON Schema structures
    validate_schema_structure(&trace.connect_params_schema, "connect_params_schema");
    validate_schema_structure(&trace.hello_ok_schema, "hello_ok_schema");

    // Validate connect_params_schema has expected fields
    validate_has_fields(
        &trace.connect_params_schema,
        &["type", "required", "properties"],
        "connect_params_schema",
    );

    // Validate hello_ok_schema has expected fields
    validate_has_fields(
        &trace.hello_ok_schema,
        &["type", "required", "properties"],
        "hello_ok_schema",
    );
}

#[test]
fn test_ws_handshake_scenarios_cover_key_flows() {
    let path = format!("{}/ws/handshake.json", golden_dir());
    let content = fs::read_to_string(&path).expect("Failed to read handshake.json");
    let trace: WsHandshakeTrace = serde_json::from_str(&content).unwrap();

    let scenario_names: Vec<&str> = trace.scenarios.iter().map(|s| s.name.as_str()).collect();

    // Verify key scenarios are present
    let required_scenarios = [
        "connect_challenge_on_open",
        "connect_success_local_with_token",
        "protocol_mismatch",
        "invalid_first_request",
    ];

    for required in required_scenarios {
        assert!(
            scenario_names.contains(&required),
            "Missing required scenario: {}",
            required
        );
    }
}

#[test]
fn test_ws_messages_trace_valid() {
    let path = format!("{}/ws/messages.json", golden_dir());
    let content = fs::read_to_string(&path).expect("Failed to read messages.json");

    let trace: WsMessagesTrace =
        serde_json::from_str(&content).expect("Failed to parse messages.json");

    assert_eq!(trace.schema.as_deref(), Some("golden-trace-v1"));
    assert!(
        !trace.description.is_empty(),
        "description should not be empty"
    );
    assert!(!trace.source_files.is_empty());
    assert!(
        !trace.frame_types.is_empty(),
        "frame_types should not be empty"
    );
    assert!(trace.methods.is_object(), "methods should be an object");

    // Validate frame types include req, res, event
    assert!(
        trace.frame_types.contains_key("request"),
        "missing request frame type"
    );
    assert!(
        trace.frame_types.contains_key("response"),
        "missing response frame type"
    );
    assert!(
        trace.frame_types.contains_key("event"),
        "missing event frame type"
    );
}

#[test]
fn test_ws_events_trace_valid() {
    let path = format!("{}/ws/events.json", golden_dir());
    let content = fs::read_to_string(&path).expect("Failed to read events.json");

    let trace: WsEventsTrace = serde_json::from_str(&content).expect("Failed to parse events.json");

    assert_eq!(trace.schema.as_deref(), Some("golden-trace-v1"));
    assert!(
        !trace.description.is_empty(),
        "description should not be empty"
    );
    assert!(!trace.source_files.is_empty());
    assert!(!trace.events.is_empty(), "events should not be empty");
    assert!(
        !trace.event_list.is_empty(),
        "event_list should not be empty"
    );

    // Validate key events are present in event_list
    let required_events = ["connect.challenge", "tick", "presence", "agent"];

    for required in required_events {
        assert!(
            trace.event_list.contains(&required.to_string()),
            "Missing required event in event_list: {}",
            required
        );
        assert!(
            trace.events.contains_key(required),
            "Missing required event definition: {}",
            required
        );
    }

    // Validate each event definition has description
    for (name, event) in &trace.events {
        assert!(
            !event.description.is_empty(),
            "event '{}' description should not be empty",
            name
        );
    }
}

#[test]
fn test_ws_errors_trace_valid() {
    let path = format!("{}/ws/errors.json", golden_dir());
    let content = fs::read_to_string(&path).expect("Failed to read errors.json");

    let trace: WsErrorsTrace = serde_json::from_str(&content).expect("Failed to parse errors.json");

    assert_eq!(trace.schema.as_deref(), Some("golden-trace-v1"));
    assert!(
        !trace.description.is_empty(),
        "description should not be empty"
    );
    assert!(!trace.source_files.is_empty());
    assert!(
        trace
            .error_codes
            .source
            .as_deref()
            .is_some_and(|s| !s.is_empty()),
        "error_codes.source should not be empty"
    );
    assert!(
        !trace.error_codes.codes.is_empty(),
        "error_codes.codes should not be empty"
    );
    assert!(
        !trace.close_codes.codes.is_empty(),
        "close_codes.codes should not be empty"
    );

    // Validate required error codes
    let required_error_codes = [
        "invalid_request",
        "not_paired",
        "unavailable",
        "rate_limited",
    ];
    for code in required_error_codes {
        assert!(
            trace.error_codes.codes.contains_key(code),
            "Missing required error code: {}",
            code
        );
    }

    // Validate required close codes
    let required_close_codes = ["1000", "1002", "1008"];
    for code in required_close_codes {
        assert!(
            trace.close_codes.codes.contains_key(code),
            "Missing required close code: {}",
            code
        );
    }

    // Validate error code definitions have required fields
    for (code, def) in &trace.error_codes.codes {
        assert!(
            !def.description.is_empty(),
            "error code '{}' should have description",
            code
        );
        let retryable_codes = ["unavailable", "rate_limited"];
        if retryable_codes.contains(&code.as_str()) {
            assert!(def.retryable, "error code '{}' should be retryable", code);
        } else {
            assert!(
                !def.retryable,
                "error code '{}' should not be retryable",
                code
            );
        }
    }
}

// ============================================================================
// HTTP golden trace tests
// ============================================================================

fn validate_http_trace(filename: &str) {
    let path = format!("{}/http/{}", golden_dir(), filename);
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", filename, e));

    let trace: HttpEndpointTrace = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", filename, e));

    assert_eq!(
        trace.schema.as_deref(),
        Some("golden-trace-v1"),
        "{}: should have $schema",
        filename
    );
    assert!(
        !trace.description.is_empty(),
        "{}: description should not be empty",
        filename
    );
    assert!(
        !trace.source_files.is_empty(),
        "{}: source_files should not be empty",
        filename
    );
}

#[test]
fn test_http_connect_trace_valid() {
    validate_http_trace("connect.json");
}

#[test]
fn test_http_hooks_wake_trace_valid() {
    validate_http_trace("hooks-wake.json");
}

#[test]
fn test_http_hooks_agent_trace_valid() {
    validate_http_trace("hooks-agent.json");

    // Additional validation for hooks-agent
    let path = format!("{}/http/hooks-agent.json", golden_dir());
    let content = fs::read_to_string(&path).unwrap();
    let trace: Value = serde_json::from_str(&content).unwrap();

    // Validate request_schema exists and has required fields
    let request_schema = trace
        .get("request_schema")
        .expect("hooks-agent.json should have request_schema");
    validate_has_fields(
        request_schema,
        &["type", "required", "properties"],
        "request_schema",
    );

    // Validate scenarios exist
    let scenarios = trace
        .get("scenarios")
        .expect("hooks-agent.json should have scenarios");
    assert!(scenarios.is_array(), "scenarios should be an array");
    assert!(
        !scenarios.as_array().unwrap().is_empty(),
        "scenarios should not be empty"
    );
}

#[test]
fn test_http_hooks_mappings_trace_valid() {
    validate_http_trace("hooks-mappings.json");
}

#[test]
fn test_http_openai_chat_completions_trace_valid() {
    validate_http_trace("openai-chat-completions.json");
}

#[test]
fn test_http_openresponses_trace_valid() {
    validate_http_trace("openresponses.json");
}

#[test]
fn test_http_tools_invoke_trace_valid() {
    validate_http_trace("tools-invoke.json");
}

#[test]
fn test_http_control_ui_trace_valid() {
    validate_http_trace("control-ui.json");
}

#[test]
fn test_http_a2ui_trace_valid() {
    validate_http_trace("a2ui.json");
}

#[test]
fn test_http_channel_webhooks_trace_valid() {
    validate_http_trace("channel-webhooks.json");
}

// ============================================================================
// Schema validation utilities for integration tests
// ============================================================================

/// Validates that an actual JSON response matches expected schema structure.
/// This is used for integration testing against a running gateway.
#[derive(Debug)]
pub struct SchemaValidator {
    expected: Value,
}

impl SchemaValidator {
    pub fn new(expected: Value) -> Self {
        Self { expected }
    }

    /// Validate that actual response has all required fields from expected schema
    pub fn validate(&self, actual: &Value) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        self.validate_recursive(&self.expected, actual, "", &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_recursive(
        &self,
        expected: &Value,
        actual: &Value,
        path: &str,
        errors: &mut Vec<String>,
    ) {
        match (expected, actual) {
            (Value::Object(exp_map), Value::Object(act_map)) => {
                // Check all expected keys exist in actual
                for (key, exp_val) in exp_map {
                    let new_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };

                    // Skip placeholder values ({{...}})
                    if let Value::String(s) = exp_val {
                        if s.starts_with("{{") && s.ends_with("}}") {
                            // Placeholder - just check key exists
                            if !act_map.contains_key(key) {
                                errors.push(format!("Missing field: {}", new_path));
                            }
                            continue;
                        }
                    }

                    match act_map.get(key) {
                        Some(act_val) => {
                            self.validate_recursive(exp_val, act_val, &new_path, errors);
                        }
                        None => {
                            // Check if field is optional (has "optional" in notes or is nullable)
                            if !key.starts_with("optional") {
                                errors.push(format!("Missing field: {}", new_path));
                            }
                        }
                    }
                }
            }
            (Value::Array(exp_arr), Value::Array(act_arr)) => {
                // For arrays, validate structure of first element if expected has template
                if !exp_arr.is_empty() && !act_arr.is_empty() {
                    let new_path = format!("{}[0]", path);
                    self.validate_recursive(&exp_arr[0], &act_arr[0], &new_path, errors);
                }
            }
            (Value::String(exp_str), actual) => {
                // Placeholder values match anything
                if exp_str.starts_with("{{") && exp_str.ends_with("}}") {
                    return;
                }
                // Const values must match exactly
                if exp_str == "const" {
                    return; // Skip const markers
                }
                // Type checking
                if !matches_type(exp_str, actual) {
                    errors.push(format!(
                        "Type mismatch at {}: expected {}, got {:?}",
                        path, exp_str, actual
                    ));
                }
            }
            _ => {
                // Other scalar types are accepted by shape.
            }
        }
    }
}

fn matches_type(expected_type: &str, actual: &Value) -> bool {
    match expected_type {
        "string" => actual.is_string(),
        "integer" | "number" => actual.is_number(),
        "boolean" => actual.is_boolean(),
        "object" => actual.is_object(),
        "array" => actual.is_array(),
        "null" => actual.is_null(),
        _ => true, // Unknown types pass
    }
}

#[test]
fn test_schema_validator_basic() {
    let expected = serde_json::json!({
        "type": "res",
        "id": "{{request_id}}",
        "ok": true,
        "payload": {
            "type": "hello-ok"
        }
    });

    let actual = serde_json::json!({
        "type": "res",
        "id": "connect-1",
        "ok": true,
        "payload": {
            "type": "hello-ok",
            "protocol": 3
        }
    });

    let validator = SchemaValidator::new(expected);
    assert!(validator.validate(&actual).is_ok());
}

#[test]
fn test_schema_validator_missing_field() {
    let expected = serde_json::json!({
        "type": "res",
        "id": "{{request_id}}",
        "ok": true,
        "payload": {
            "type": "hello-ok"
        }
    });

    let actual = serde_json::json!({
        "type": "res",
        "id": "connect-1",
        "ok": true
        // missing payload
    });

    let validator = SchemaValidator::new(expected);
    let result = validator.validate(&actual);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("payload")));
}

// ============================================================================
// All traces validation
// ============================================================================

#[test]
fn test_all_golden_traces_are_valid_json() {
    let ws_dir = format!("{}/ws", golden_dir());
    let http_dir = format!("{}/http", golden_dir());

    for dir in [ws_dir, http_dir] {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    let content = fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", path, e));
                    let _: Value = serde_json::from_str(&content)
                        .unwrap_or_else(|e| panic!("Invalid JSON in {:?}: {}", path, e));
                }
            }
        }
    }
}

#[test]
fn test_all_traces_have_schema_marker() {
    let ws_dir = format!("{}/ws", golden_dir());
    let http_dir = format!("{}/http", golden_dir());

    for dir in [ws_dir, http_dir] {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    let content = fs::read_to_string(&path).unwrap();
                    let value: Value = serde_json::from_str(&content).unwrap();

                    assert!(
                        value.get("$schema").is_some(),
                        "{:?} should have $schema field",
                        path
                    );
                }
            }
        }
    }
}

#[test]
fn test_all_traces_have_source_files() {
    let ws_dir = format!("{}/ws", golden_dir());
    let http_dir = format!("{}/http", golden_dir());

    for dir in [ws_dir, http_dir] {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    let content = fs::read_to_string(&path).unwrap();
                    let value: Value = serde_json::from_str(&content).unwrap();

                    let source_files = value.get("source_files");
                    assert!(
                        source_files.is_some(),
                        "{:?} should have source_files field",
                        path
                    );

                    let arr = source_files.unwrap().as_array();
                    assert!(
                        arr.is_some() && !arr.unwrap().is_empty(),
                        "{:?} source_files should be non-empty array",
                        path
                    );
                }
            }
        }
    }
}
