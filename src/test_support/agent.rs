//! Shared LLM-provider test fixtures.

use crate::agent::provider::CompletionRequest;
use crate::agent::{AgentError, LlmProvider, StreamEvent};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Inert `LlmProvider` for tests that need a state with `Some(provider)`
/// but don't care about completion behavior. Returns an empty stream;
/// `crate::agent::spawn_run` drains it without any real network I/O.
pub(crate) struct StaticTestProvider;

#[async_trait::async_trait]
impl LlmProvider for StaticTestProvider {
    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel_token: CancellationToken,
    ) -> Result<mpsc::Receiver<StreamEvent>, AgentError> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(rx)
    }
}
