#!/usr/bin/env bash
set -e

# Configuration
VERTEX_PROJECT_ID="${VERTEX_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
VERTEX_LOCATION="${VERTEX_LOCATION:-us-central1}"
MODEL="vertex/gemini-2.5-flash"

if [ -z "$VERTEX_PROJECT_ID" ]; then
    echo "Error: VERTEX_PROJECT_ID not set and could not be inferred from gcloud."
    echo "Please set VERTEX_PROJECT_ID env var."
    exit 1
fi

echo "Testing Vertex AI Provider with:"
echo "Project: $VERTEX_PROJECT_ID"
echo "Location: $VERTEX_LOCATION"
echo "Model: $MODEL"

# Create a temporary config for testing
cat > test_vertex_config.json5 <<EOF
{
  gateway: {
    port: 3000,
    auth: {
      mode: "none"
    },
    openai: {
      chatCompletions: true
    }
  },
  vertex: {
    projectId: "${VERTEX_PROJECT_ID}",
    location: "${VERTEX_LOCATION}"
  },
  logging: {
    level: "debug"
  }
}
EOF

# Start the server in background
echo "Starting server..."
# We use target/debug/cara usually, or cargo run
CARAPACE_CONFIG_PATH="$(pwd)/test_vertex_config.json5"
export CARAPACE_CONFIG_PATH
./target/debug/cara &
SERVER_PID=$!

# Ensure we kill the server on exit
trap 'kill $SERVER_PID' EXIT

# Wait for server to be ready
echo "Waiting for server to start..."
sleep 5

# Send a request
echo "Sending request..."
curl -v -X POST http://localhost:3000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "'"$MODEL"'",
    "messages": [
      {"role": "user", "content": "Hello from Vertex AI test! What is 2+2?"}
    ],
    "stream": false
  }'

echo -e "\n\nTest complete."
