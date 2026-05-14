# Public HTTP/WS DTO Inventory

Last reviewed: 2026-05-14.

This inventory marks browser-visible HTTP and WebSocket DTOs as `released`
unless the shape is process-internal or only a server-side adapter. Released
request DTOs should tolerate additive client fields unless a row below records
a narrower trust-boundary reason for `deny_unknown_fields`.

## WebSocket

| DTO / frame | Surface | Status | Compatibility notes |
| --- | --- | --- | --- |
| `ConnectParams`, `ClientInfo`, `DeviceIdentity`, `AuthParams` | WS `connect` request | released | Additive fields tolerated; unknown client metadata should not require lockstep upgrades. |
| `ResponseFrame`, `ErrorShape` | WS response envelope | released | Shared response envelope; additive payload fields are allowed by method-specific schemas. |
| `EventFrame`, `StateVersion` | WS event envelope | released | `seq`/`stateVersion` are stable event reconciliation fields. |
| `HelloOkPayload`, `ServerInfo`, `Features`, `Snapshot`, `PolicyInfo`, `DeviceTokenInfo` | WS `hello-ok` payload | released | Golden `handshake.json` is the source-of-truth fixture for policy fields. |
| `state.drop` payload | WS event payload | released | Golden `events.json` and runtime-derived tests must include `reasonTruncated`. |
| `MatrixVerificationInfo` | WS Matrix verification events and HTTP control responses | released | Struct serialization is pinned against WS golden required fields. |
| `ParsedRequest`, `FrameError`, `ConnectionContext`, rate-limit bookkeeping structs | WS server internals | internal | Not serialized as public protocol DTOs. |

## HTTP / Control

| DTO / frame | Surface | Status | Compatibility notes |
| --- | --- | --- | --- |
| `GatewayStatusResponse`, `RuntimeInfo` | `GET /control/status` | released | Additive fields allowed. |
| `ChannelsStatusResponse`, `ChannelStatusItem` | `GET /control/channels` | released | Matrix `extra.lastErrorKind` and forensic fields are public. |
| `ControlError`, `ControlErrorDetail` | Control HTTP error body | released | `detail` is additive and optional for older clients. |
| `MatrixDevicesResponse`, `MatrixVerificationsResponse`, `MatrixVerificationResponse`, `MatrixActionResponse` | Matrix control endpoints | released | Shares `MatrixVerificationInfo` with WS Matrix events. |
| `MatrixSendTestRequest`, `MatrixSendTestResponse`, `MatrixSendTestDelivery` | `POST /control/matrix/send-test` | released | Request tolerates additive fields; `delivery` is the tagged outcome body. |
| `MatrixVerificationStartRequest` | `POST /control/matrix/verifications/start` | released | Retains `deny_unknown_fields`: this security-sensitive action has only canonical Matrix identifiers; new fields must be explicitly reviewed. |
| `MatrixVerificationConfirmRequest` | `POST /control/matrix/verifications/confirm` | released | Retains `deny_unknown_fields` to reject ambiguous bodies such as `{"match":true,"noMatch":true}`. |
| `ConfigUpdateRequest`, `ConfigUpdateResponse`, `ConfigReadResponse` | Control config endpoints | released | Config value is intentionally dynamic; boundary validation happens after parse. |
| `ControlOnboardingStatusResponse`, `ControlProviderOnboardingStatus`, `ControlOnboardingApplyResponse` | Control onboarding endpoints | released | Provider-specific details are typed before reaching browser-visible payloads. |
| `GeminiApiKeyRequest`, OAuth callback query DTOs | Setup OAuth/API-key endpoints | released | Additive callback query parameters tolerated. |
| `TaskCreateRequest`, `TaskPolicyRequest`, `TaskListQuery`, `TaskCancelRequest`, `TaskRetryRequest`, `TaskResumeRequest`, `TaskUpdateRequest`, `TaskResponse`, `TaskListResponse` | Control task endpoints | released | Policy values are range-checked after parse; additive request fields are tolerated. |
| `ToolsInvokeRequest`, `ToolsInvokeResponse`, `ToolsError` | `POST /tools/invoke` | released | Tool args are intentionally dynamic at the adapter boundary. |
| `WakeRequest`, `WakeResponse`, `AgentRequest`, `AgentResponse`, `HooksErrorResponse` | Hooks HTTP endpoints | released | Additive request fields tolerated; route validation happens after parse. |
| `ChatCompletionsRequest`, `ChatCompletionResponse`, `ResponsesRequest`, `ResponsesResponse`, `ResponsesError` and nested OpenAI-compatible DTOs | OpenAI-compatible HTTP endpoints | released | Compatibility target is the external OpenAI-style wire shape. |
| Loader/runtime request structs such as `WitHttpRequest`, `WitWebhookRequest`, `ValidatedWakeRequest`, `ValidatedAgentRequest` | Provider/plugin adapters | internal | Not a released Carapace HTTP/WS contract. |
