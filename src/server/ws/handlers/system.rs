//! System handlers.

use serde_json::{json, Value};

use super::super::*;

/// Default TTL for presence entries (5 minutes)
pub(super) const PRESENCE_TTL_MS: u64 = 5 * 60 * 1000;

/// Maximum number of presence entries (Node uses 200)
pub(super) const MAX_PRESENCE_ENTRIES: usize = 200;

/// Parsed presence fields extracted from text
#[derive(Default, Debug)]
pub(super) struct ParsedPresence {
    pub host: Option<String>,
    pub ip: Option<String>,
    pub instance_id: Option<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
    pub platform: Option<String>,
    pub device_family: Option<String>,
    pub model_identifier: Option<String>,
    pub last_input_seconds: Option<u64>,
    pub reason: Option<String>,
    /// First segment of text for fallback key derivation
    pub text_slice: Option<String>,
}

/// Parse presence fields from text string.
/// Node's parsePresence format: "Node: host (ip) · app 1.2.3 · last input 30s ago · mode gateway · reason heartbeat"
/// or without prefix: "host (ip) · app 1.2.3 · ..."
/// Segments are separated by " · " (space-dot-space).
pub(super) fn parse_presence(text: &str) -> ParsedPresence {
    let text_slice = Some(if text.len() > 64 {
        // Find the last character that ends at or before 64 bytes
        let truncate_at = text
            .char_indices()
            .take_while(|(i, c)| i + c.len_utf8() <= 64)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        text[..truncate_at].to_string()
    } else {
        text.to_string()
    });

    let mut parsed = ParsedPresence {
        text_slice,
        ..Default::default()
    };

    // Split by " · " separator (Node format)
    let segments: Vec<&str> = text.split(" · ").collect();

    // First segment is "Node: host (ip)" or "host (ip)" or just "host"
    if let Some(first) = segments.first() {
        let first = first.trim();
        // Strip "Node: " prefix if present (Node's parser expects this)
        let first = first.strip_prefix("Node: ").unwrap_or(first);

        if let Some(paren_start) = first.find('(') {
            // "host (ip)" format
            let host_part = first[..paren_start].trim();
            if !host_part.is_empty() {
                parsed.host = Some(host_part.to_string());
            }
            if let Some(paren_end) = first[paren_start..].find(')') {
                let ip_part = &first[paren_start + 1..paren_start + paren_end];
                // Basic IPv4 validation
                if ip_part
                    .split('.')
                    .filter_map(|s| s.parse::<u8>().ok())
                    .count()
                    == 4
                {
                    parsed.ip = Some(ip_part.to_string());
                }
            }
        } else if !first.is_empty() {
            // Just host, no IP
            parsed.host = Some(first.to_string());
        }
    }

    // Parse remaining segments
    for segment in segments.iter().skip(1) {
        let segment = segment.trim();

        // "app 1.2.3" or "version 1.2.3"
        if let Some(ver) = segment.strip_prefix("app ") {
            parsed.version = Some(ver.trim().to_string());
        } else if let Some(ver) = segment.strip_prefix("version ") {
            parsed.version = Some(ver.trim().to_string());
        }
        // "last input 30s ago" or "last input 5m ago"
        else if let Some(rest) = segment.strip_prefix("last input ") {
            let rest = rest.trim();
            // Parse "30s ago" or "5m ago" or just "30s" or "5m"
            let time_part = rest.strip_suffix(" ago").unwrap_or(rest);
            if let Some(secs) = time_part.strip_suffix('s') {
                if let Ok(s) = secs.trim().parse::<u64>() {
                    parsed.last_input_seconds = Some(s);
                }
            } else if let Some(mins) = time_part.strip_suffix('m') {
                if let Ok(m) = mins.trim().parse::<u64>() {
                    parsed.last_input_seconds = Some(m * 60);
                }
            } else if let Ok(s) = time_part.trim().parse::<u64>() {
                // Just a number, assume seconds
                parsed.last_input_seconds = Some(s);
            }
        }
        // "mode gateway" or "mode client"
        else if let Some(mode) = segment.strip_prefix("mode ") {
            parsed.mode = Some(mode.trim().to_string());
        }
        // "reason heartbeat" or "reason connect"
        else if let Some(reason) = segment.strip_prefix("reason ") {
            parsed.reason = Some(reason.trim().to_string());
        }
        // "platform darwin" or "platform linux"
        else if let Some(platform) = segment.strip_prefix("platform ") {
            parsed.platform = Some(platform.trim().to_string());
        }
        // "instance abc123"
        else if let Some(instance) = segment.strip_prefix("instance ") {
            parsed.instance_id = Some(instance.trim().to_string());
        }
    }

    parsed
}

/// Handle last-heartbeat - returns heartbeat info
/// Per Node semantics: returns getLastHeartbeatEvent() which is the last heartbeat event object or null
pub(super) fn handle_last_heartbeat(state: &WsServerState) -> Result<Value, ErrorShape> {
    let snapshot = state.heartbeat_snapshot();
    if let Some(ts) = snapshot.last_heartbeat_ms {
        Ok(json!({ "ts": ts }))
    } else {
        Ok(Value::Null)
    }
}

pub(super) fn handle_set_heartbeats(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let enabled = params
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let interval_ms = params
        .and_then(|v| v.get("intervalMs").or_else(|| v.get("interval")))
        .and_then(|v| v.as_i64())
        .map(|v| v.max(0) as u64)
        .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_MS);

    let snapshot = state.set_heartbeat_settings(enabled, interval_ms);

    Ok(json!({
        "ok": true,
        "enabled": snapshot.enabled,
        "intervalMs": snapshot.interval_ms
    }))
}

pub(super) fn handle_wake(
    state: &WsServerState,
    params: Option<&Value>,
) -> Result<Value, ErrorShape> {
    let target = params
        .and_then(|v| v.get("target"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let text = match target.as_deref() {
        Some(t) if !t.is_empty() => format!("wake {}", t),
        _ => "wake".to_string(),
    };

    state.enqueue_system_event(SystemEvent {
        ts: now_ms(),
        text,
        host: None,
        ip: None,
        device_id: None,
        instance_id: None,
        reason: Some("wake".to_string()),
    });

    Ok(json!({
        "ok": true,
        "target": target
    }))
}

/// Return system info and runtime metadata.
pub(super) fn handle_system_info(state: &WsServerState) -> Result<Value, ErrorShape> {
    let sessions = state
        .session_store
        .list_sessions(crate::sessions::SessionFilter::new())
        .unwrap_or_default();
    let heartbeat = state.heartbeat_snapshot();

    Ok(json!({
        "ts": now_ms(),
        "uptimeMs": state.start_time.elapsed().as_millis() as u64,
        "version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "name": "carapace",
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH
        },
        "configPath": config::get_config_path().display().to_string(),
        "stateDir": resolve_state_dir().display().to_string(),
        "channels": {
            "total": state.channel_registry.len(),
            "connected": state
                .channel_registry
                .count_by_status(crate::channels::ChannelStatus::Connected)
        },
        "sessions": {
            "count": sessions.len()
        },
        "presenceCount": state.presence.lock().len(),
        "heartbeat": {
            "enabled": heartbeat.enabled,
            "intervalMs": heartbeat.interval_ms,
            "lastTs": heartbeat.last_heartbeat_ms
        }
    }))
}

pub(super) fn handle_send(
    state: &WsServerState,
    params: Option<&Value>,
    _conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let to = params
        .and_then(|v| v.get("to"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "to is required", None))?;
    let message = params
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "message is required", None))?;
    let idempotency_key = params
        .and_then(|v| v.get("idempotencyKey"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "idempotencyKey is required", None))?;
    let channel = params
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("default");

    let metadata = messages::outbound::MessageMetadata {
        recipient_id: Some(to.to_string()),
        ..Default::default()
    };

    let outbound = messages::outbound::OutboundMessage::new(
        channel,
        messages::outbound::MessageContent::text(message),
    )
    .with_metadata(metadata);
    let ctx = messages::outbound::OutboundContext::new().with_trace_id(idempotency_key);

    let queued = state
        .message_pipeline
        .queue_with_idempotency(outbound.clone(), ctx, Some(idempotency_key))
        .map_err(|e| error_shape(ERROR_UNAVAILABLE, &format!("queue failed: {}", e), None))?;

    // Node returns {runId, messageId, channel} plus optional delivery result fields
    // (conversationId, toJid, pollId). Delivery happens asynchronously so we
    // populate these from the queued result metadata when available.
    let delivery_result = queued.delivery_result.as_ref();

    let mut response = json!({
        "runId": idempotency_key,
        "messageId": queued.message_id.0,
        "channel": outbound.channel_id
    });

    if let Some(result) = delivery_result {
        if let Some(ref conversation_id) = result.conversation_id {
            response["conversationId"] = json!(conversation_id);
        }
        if let Some(ref to_jid) = result.to_jid {
            response["toJid"] = json!(to_jid);
        }
        if let Some(ref poll_id) = result.poll_id {
            response["pollId"] = json!(poll_id);
        }
    }

    Ok(response)
}

/// Handle system-presence - returns list of connected clients (read-only, no params)
/// Per Node semantics: returns the presence array directly, not wrapped in {ok, presence}
/// Also applies TTL pruning and returns entries sorted by ts descending.
pub(super) fn handle_system_presence(state: &WsServerState) -> Result<Value, ErrorShape> {
    let now = now_ms();
    let cutoff = now.saturating_sub(PRESENCE_TTL_MS);

    // Prune expired entries and collect valid ones
    let mut presence = state.presence.lock();

    // Remove expired entries
    presence.retain(|_, entry| entry.ts >= cutoff);

    // Collect and sort by ts descending
    let mut entries: Vec<_> = presence
        .values()
        .map(|entry| (entry.ts, serde_json::to_value(entry).unwrap_or(json!({}))))
        .collect();

    // Sort by ts descending (newest first)
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    // Limit to MAX_PRESENCE_ENTRIES (Node uses 200)
    let result: Vec<Value> = entries
        .into_iter()
        .take(MAX_PRESENCE_ENTRIES)
        .map(|(_, v)| v)
        .collect();

    Ok(json!(result))
}

/// Derive presence key from params per Node semantics.
/// Node's key precedence: deviceId > instanceId > parsed.instanceId > parsed.host > parsed.ip > parsed.text slice > hostname
/// Node normalizes keys to lowercase.
fn derive_presence_key(
    device_id: &Option<String>,
    instance_id: &Option<String>,
    parsed: &ParsedPresence,
    fallback: &str,
) -> String {
    let key = device_id
        .as_ref()
        .or(instance_id.as_ref())
        .or(parsed.instance_id.as_ref())
        .or(parsed.host.as_ref())
        .or(parsed.ip.as_ref())
        .or(parsed.text_slice.as_ref())
        .cloned()
        .unwrap_or_else(|| fallback.to_string());
    // Node normalizes presence keys to lowercase
    key.to_lowercase()
}

/// Handle system-event - triggers a system event and updates presence (admin-only)
///
/// Per Node semantics, accepts all PresenceEntry fields:
/// - text (required): The event text/message (also parsed via parsePresence for fields)
/// - instanceId, host, ip, mode, version (optional): Client info
/// - deviceId, deviceFamily, modelIdentifier (optional): Device info
/// - lastInputSeconds (optional): Idle time
/// - reason (optional): Event reason (connect/disconnect)
/// - tags (optional): Tags array
/// - roles, scopes (optional): Authorization info
///
/// Presence is keyed by deviceId > instanceId > host (not conn_id) for Node parity.
/// Also enqueues the event to system event history.
/// Resolved presence parameters extracted from explicit params and parsed text.
struct PresenceParams {
    instance_id: Option<String>,
    host: Option<String>,
    ip: Option<String>,
    mode: Option<String>,
    version: Option<String>,
    platform: Option<String>,
    device_id: Option<String>,
    device_family: Option<String>,
    model_identifier: Option<String>,
    reason: Option<String>,
    tags: Option<Vec<String>>,
    roles: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    last_input_seconds: Option<u64>,
}

/// Parse presence event parameters from explicit params and parsed text, with fallbacks.
fn extract_presence_params(
    params: Option<&Value>,
    parsed: &ParsedPresence,
    conn: &ConnectionContext,
) -> PresenceParams {
    let instance_id = params
        .and_then(|v| v.get("instanceId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.instance_id.clone());
    let host = params
        .and_then(|v| v.get("host"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.host.clone());
    let ip = params
        .and_then(|v| v.get("ip"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.ip.clone());
    let mode = params
        .and_then(|v| v.get("mode"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.mode.clone());
    let version = params
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.version.clone());
    let platform = params
        .and_then(|v| v.get("platform"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.platform.clone());
    let device_id = params
        .and_then(|v| v.get("deviceId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| conn.device_id.clone());
    let device_family = params
        .and_then(|v| v.get("deviceFamily"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.device_family.clone());
    let model_identifier = params
        .and_then(|v| v.get("modelIdentifier"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.model_identifier.clone());
    let reason = params
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| parsed.reason.clone());
    let tags = params
        .and_then(|v| v.get("tags"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });
    let roles = params
        .and_then(|v| v.get("roles"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });
    let scopes = params
        .and_then(|v| v.get("scopes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });
    let last_input_seconds = params
        .and_then(|v| v.get("lastInputSeconds"))
        .and_then(|v| v.as_u64())
        .or(parsed.last_input_seconds);

    PresenceParams {
        instance_id,
        host,
        ip,
        mode,
        version,
        platform,
        device_id,
        device_family,
        model_identifier,
        reason,
        tags,
        roles,
        scopes,
        last_input_seconds,
    }
}

/// Update the presence registry with the given parameters.
fn update_presence_registry(
    state: &WsServerState,
    conn: &ConnectionContext,
    presence_key: &str,
    text: &str,
    ts: u64,
    p: &PresenceParams,
) {
    use super::super::PresenceEntry;
    let mut presence = state.presence.lock();
    let entry = presence
        .entry(presence_key.to_string())
        .or_insert_with(|| PresenceEntry {
            conn_id: conn.conn_id.clone(),
            client_id: Some(conn.client.id.clone()),
            ts,
            host: None,
            ip: None,
            version: None,
            platform: None,
            device_family: None,
            model_identifier: None,
            mode: None,
            reason: None,
            tags: None,
            device_id: None,
            roles: None,
            scopes: None,
            instance_id: None,
            text: None,
            last_input_seconds: None,
        });

    // Update fields if provided (explicit params or parsed from text)
    if p.instance_id.is_some() {
        entry.instance_id = p.instance_id.clone();
    }
    if p.host.is_some() {
        entry.host = p.host.clone();
    }
    if p.ip.is_some() {
        entry.ip = p.ip.clone();
    }
    if p.mode.is_some() {
        entry.mode = p.mode.clone();
    }
    if p.version.is_some() {
        entry.version = p.version.clone();
    }
    if p.platform.is_some() {
        entry.platform = p.platform.clone();
    }
    if p.device_id.is_some() {
        entry.device_id = p.device_id.clone();
    }
    if p.device_family.is_some() {
        entry.device_family = p.device_family.clone();
    }
    if p.model_identifier.is_some() {
        entry.model_identifier = p.model_identifier.clone();
    }
    if p.reason.is_some() {
        entry.reason = p.reason.clone();
    }
    if p.tags.is_some() {
        entry.tags = p.tags.clone();
    }
    if p.roles.is_some() {
        entry.roles = p.roles.clone();
    }
    if p.scopes.is_some() {
        entry.scopes = p.scopes.clone();
    }
    // Always update text (required param)
    entry.text = Some(text.to_string());
    if p.last_input_seconds.is_some() {
        entry.last_input_seconds = p.last_input_seconds;
    }
    entry.ts = ts;

    // Enforce MAX_PRESENCE_ENTRIES limit (Node uses 200)
    // Remove oldest entries when over limit
    if presence.len() > MAX_PRESENCE_ENTRIES {
        let mut entries: Vec<_> = presence.iter().map(|(k, v)| (k.clone(), v.ts)).collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1)); // Sort by ts ascending (oldest first)
        let to_remove = presence.len() - MAX_PRESENCE_ENTRIES;
        for (key, _) in entries.into_iter().take(to_remove) {
            presence.remove(&key);
        }
    }
}

pub(super) fn handle_system_event(
    params: Option<&Value>,
    state: &WsServerState,
    conn: &ConnectionContext,
) -> Result<Value, ErrorShape> {
    let text = params
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_shape(ERROR_INVALID_REQUEST, "text is required", None))?;

    // Reject whitespace-only text (Node trims and rejects empty)
    if text.trim().is_empty() {
        return Err(error_shape(
            ERROR_INVALID_REQUEST,
            "text cannot be empty or whitespace-only",
            None,
        ));
    }

    // Parse presence fields from text (Node's parsePresence)
    let parsed = parse_presence(text);

    // Extract explicit params, falling back to parsed values
    let p = extract_presence_params(params, &parsed, conn);

    let ts = now_ms();

    // Derive presence key per Node semantics: deviceId > instanceId > parsed.instanceId > parsed.host > parsed.ip > text_slice > conn_id
    let presence_key = derive_presence_key(&p.device_id, &p.instance_id, &parsed, &conn.conn_id);

    // Update presence keyed by device/instance/host (not conn_id)
    update_presence_registry(state, conn, &presence_key, text, ts, &p);

    // Enqueue system event to history (per Node's enqueueSystemEvent)
    {
        use super::super::SystemEvent;
        state.enqueue_system_event(SystemEvent {
            ts,
            text: text.to_string(),
            host: p.host.clone(),
            ip: p.ip.clone(),
            device_id: p.device_id.clone(),
            instance_id: p.instance_id.clone(),
            reason: p.reason.clone(),
        });
    }

    // Broadcast presence change event to all connected clients
    let state_version = {
        let mut versions = state.state_versions.lock();
        versions.increment_presence();
        versions.current()
    };
    state.broadcast_presence_event(state_version);

    // Node returns just {ok: true} for system-event
    Ok(json!({
        "ok": true
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_presence_node_format() {
        // Node format: "host (ip) · app 1.2.3 · last input 30s ago · mode gateway · reason heartbeat"
        let text = "myhost.local (192.168.1.100) · app 1.2.3 · last input 30s ago · mode gateway · reason heartbeat";
        let parsed = parse_presence(text);

        assert_eq!(parsed.host, Some("myhost.local".to_string()));
        assert_eq!(parsed.ip, Some("192.168.1.100".to_string()));
        assert_eq!(parsed.version, Some("1.2.3".to_string()));
        assert_eq!(parsed.last_input_seconds, Some(30));
        assert_eq!(parsed.mode, Some("gateway".to_string()));
        assert_eq!(parsed.reason, Some("heartbeat".to_string()));
    }

    #[test]
    fn test_parse_presence_with_node_prefix() {
        // Node format with "Node: " prefix
        let text = "Node: myhost.local (192.168.1.100) · app 1.2.3 · mode gateway";
        let parsed = parse_presence(text);

        // Should strip "Node: " prefix
        assert_eq!(parsed.host, Some("myhost.local".to_string()));
        assert_eq!(parsed.ip, Some("192.168.1.100".to_string()));
        assert_eq!(parsed.version, Some("1.2.3".to_string()));
        assert_eq!(parsed.mode, Some("gateway".to_string()));
    }

    #[test]
    fn test_parse_presence_text_slice_truncated() {
        // text_slice should be full text truncated to 64 chars
        let long_text = "a".repeat(100);
        let parsed = parse_presence(&long_text);
        assert_eq!(parsed.text_slice.as_ref().map(|s| s.len()), Some(64));
    }

    #[test]
    fn test_parse_presence_text_slice_utf8_safe() {
        // Test that truncation doesn't panic on multi-byte UTF-8 characters
        // The emoji "😀" is 4 bytes. Create a string that would split mid-character
        // if we used naive byte slicing.

        // 62 ASCII chars + 1 emoji (4 bytes) = 66 bytes, but 63 chars
        // Naive [..64] would try to slice in the middle of the emoji and panic
        let text = format!("{}{}", "a".repeat(62), "😀");
        assert_eq!(text.len(), 66); // 62 + 4 bytes

        // This should NOT panic
        let parsed = parse_presence(&text);

        // Should truncate before the emoji since it doesn't fit in 64 bytes
        let text_slice = parsed.text_slice.unwrap();
        assert!(text_slice.len() <= 64);
        assert!(text_slice.is_char_boundary(text_slice.len()));

        // Test with emoji at the start (edge case)
        let emoji_text = format!("😀{}", "a".repeat(100));
        let parsed2 = parse_presence(&emoji_text);
        let text_slice2 = parsed2.text_slice.unwrap();
        assert!(text_slice2.len() <= 64);
        assert!(text_slice2.is_char_boundary(text_slice2.len()));

        // Test with all multi-byte characters (Japanese)
        let japanese = "あいうえおかきくけこさしすせそたちつてと"; // 20 chars, 60 bytes
        let long_japanese = format!("{}{}", japanese, japanese); // 40 chars, 120 bytes
        let parsed3 = parse_presence(&long_japanese);
        let text_slice3 = parsed3.text_slice.unwrap();
        assert!(text_slice3.len() <= 64);
        assert!(text_slice3.is_char_boundary(text_slice3.len()));
    }

    #[test]
    fn test_parse_presence_minutes() {
        let text = "host · last input 5m ago";
        let parsed = parse_presence(text);
        assert_eq!(parsed.last_input_seconds, Some(300)); // 5 * 60
    }

    #[test]
    fn test_parse_presence_host_only() {
        let text = "myhost.local";
        let parsed = parse_presence(text);
        assert_eq!(parsed.host, Some("myhost.local".to_string()));
        assert_eq!(parsed.text_slice, Some("myhost.local".to_string()));
    }

    #[test]
    fn test_parse_presence_host_and_ip() {
        let text = "myhost (10.0.0.1)";
        let parsed = parse_presence(text);
        assert_eq!(parsed.host, Some("myhost".to_string()));
        assert_eq!(parsed.ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_presence_instance_segment() {
        let text = "host · instance abc123";
        let parsed = parse_presence(text);
        assert_eq!(parsed.instance_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_parse_presence_platform_segment() {
        let text = "host · platform darwin";
        let parsed = parse_presence(text);
        assert_eq!(parsed.platform, Some("darwin".to_string()));
    }

    #[test]
    fn test_parse_presence_version_segment() {
        let text = "host · version 2.0.0";
        let parsed = parse_presence(text);
        assert_eq!(parsed.version, Some("2.0.0".to_string()));
    }

    #[test]
    fn test_derive_presence_key_device_id_first() {
        let parsed = ParsedPresence::default();
        let key = derive_presence_key(
            &Some("device-123".to_string()),
            &Some("instance-456".to_string()),
            &parsed,
            "fallback",
        );
        assert_eq!(key, "device-123");
    }

    #[test]
    fn test_derive_presence_key_instance_id_second() {
        let parsed = ParsedPresence::default();
        let key = derive_presence_key(
            &None,
            &Some("instance-456".to_string()),
            &parsed,
            "fallback",
        );
        assert_eq!(key, "instance-456");
    }

    #[test]
    fn test_derive_presence_key_parsed_instance() {
        let parsed = ParsedPresence {
            instance_id: Some("parsed-instance".to_string()),
            ..Default::default()
        };
        let key = derive_presence_key(&None, &None, &parsed, "fallback");
        assert_eq!(key, "parsed-instance");
    }

    #[test]
    fn test_derive_presence_key_parsed_host() {
        let parsed = ParsedPresence {
            host: Some("parsed-host".to_string()),
            ..Default::default()
        };
        let key = derive_presence_key(&None, &None, &parsed, "fallback");
        assert_eq!(key, "parsed-host");
    }

    #[test]
    fn test_derive_presence_key_parsed_ip() {
        let parsed = ParsedPresence {
            ip: Some("192.168.1.1".to_string()),
            ..Default::default()
        };
        let key = derive_presence_key(&None, &None, &parsed, "fallback");
        assert_eq!(key, "192.168.1.1");
    }

    #[test]
    fn test_derive_presence_key_text_slice() {
        let parsed = ParsedPresence {
            text_slice: Some("text-slice".to_string()),
            ..Default::default()
        };
        let key = derive_presence_key(&None, &None, &parsed, "fallback");
        assert_eq!(key, "text-slice");
    }

    #[test]
    fn test_derive_presence_key_fallback() {
        let parsed = ParsedPresence::default();
        let key = derive_presence_key(&None, &None, &parsed, "fallback-conn-id");
        assert_eq!(key, "fallback-conn-id");
    }

    #[test]
    fn test_derive_presence_key_lowercase_normalization() {
        // Node normalizes presence keys to lowercase
        let parsed = ParsedPresence::default();
        let key = derive_presence_key(
            &Some("Device-ABC-123".to_string()),
            &None,
            &parsed,
            "fallback",
        );
        assert_eq!(key, "device-abc-123");

        let parsed_upper = ParsedPresence {
            host: Some("MyHost.Local".to_string()),
            ..Default::default()
        };
        let key2 = derive_presence_key(&None, &None, &parsed_upper, "fallback");
        assert_eq!(key2, "myhost.local");
    }

    fn make_test_conn() -> ConnectionContext {
        ConnectionContext {
            conn_id: "test-conn".to_string(),
            role: "admin".to_string(),
            scopes: vec![],
            client: ClientInfo {
                id: "test-client".to_string(),
                version: "1.0".to_string(),
                platform: "test".to_string(),
                mode: "test".to_string(),
                display_name: None,
                device_family: None,
                model_identifier: None,
                instance_id: None,
            },
            device_id: None,
        }
    }

    #[test]
    fn test_handle_send_returns_base_fields() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "to": "user123",
            "message": "hello",
            "idempotencyKey": "key-001",
            "channel": "default"
        });

        let result = handle_send(&state, Some(&params), &conn).unwrap();

        assert_eq!(result["runId"], "key-001");
        assert!(result["messageId"].is_string());
        assert_eq!(result["channel"], "default");
    }

    #[test]
    fn test_handle_send_omits_delivery_fields_when_none() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "to": "user456",
            "message": "test message",
            "idempotencyKey": "key-002"
        });

        let result = handle_send(&state, Some(&params), &conn).unwrap();

        // When delivery hasn't happened, these fields should not be present
        assert!(result.get("conversationId").is_none());
        assert!(result.get("toJid").is_none());
        assert!(result.get("pollId").is_none());
    }

    #[test]
    fn test_handle_send_requires_to() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "message": "hello",
            "idempotencyKey": "key-003"
        });

        let result = handle_send(&state, Some(&params), &conn);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_send_requires_message() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "to": "user123",
            "idempotencyKey": "key-004"
        });

        let result = handle_send(&state, Some(&params), &conn);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_send_requires_idempotency_key() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "to": "user123",
            "message": "hello"
        });

        let result = handle_send(&state, Some(&params), &conn);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_send_defaults_to_default_channel() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();
        let params = json!({
            "to": "user123",
            "message": "hello",
            "idempotencyKey": "key-005"
        });

        let result = handle_send(&state, Some(&params), &conn).unwrap();

        // When no channel is specified, defaults to "default"
        assert_eq!(result["channel"], "default");
    }

    #[test]
    fn test_handle_send_idempotency_deduplication() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();

        // First send with idempotency key
        let params = json!({
            "to": "user123",
            "message": "hello",
            "idempotencyKey": "dedup-key-001",
            "channel": "default"
        });
        let result1 = handle_send(&state, Some(&params), &conn).unwrap();
        let message_id_1 = result1["messageId"].as_str().unwrap().to_string();

        // Second send with same idempotency key
        let params2 = json!({
            "to": "user123",
            "message": "hello again",
            "idempotencyKey": "dedup-key-001",
            "channel": "default"
        });
        let result2 = handle_send(&state, Some(&params2), &conn).unwrap();
        let message_id_2 = result2["messageId"].as_str().unwrap().to_string();

        // Same idempotency key should return the same message ID
        assert_eq!(message_id_1, message_id_2);

        // Only one message should exist in the pipeline
        assert_eq!(state.message_pipeline.queue_size("default"), 1);
    }

    #[test]
    fn test_handle_send_different_idempotency_keys_create_separate() {
        let state = WsServerState::new(WsServerConfig::default());
        let conn = make_test_conn();

        let params1 = json!({
            "to": "user123",
            "message": "hello",
            "idempotencyKey": "key-a",
            "channel": "default"
        });
        let result1 = handle_send(&state, Some(&params1), &conn).unwrap();

        let params2 = json!({
            "to": "user123",
            "message": "hello",
            "idempotencyKey": "key-b",
            "channel": "default"
        });
        let result2 = handle_send(&state, Some(&params2), &conn).unwrap();

        // Different idempotency keys should create different messages
        assert_ne!(
            result1["messageId"].as_str().unwrap(),
            result2["messageId"].as_str().unwrap()
        );
        assert_eq!(state.message_pipeline.queue_size("default"), 2);
    }
}
