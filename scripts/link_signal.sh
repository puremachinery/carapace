#!/usr/bin/env bash
set -e

API_URL="http://127.0.0.1:8080"
DEVICE_NAME="carapace"

echo "==> Checking if Signal API is running..."
if ! curl -s "$API_URL/v1/about" > /dev/null; then
    echo "Error: Signal API is not reachable at $API_URL."
    echo "Please ensure you have run ./run_local_with_signal.sh first and that it is fully initialized."
    exit 1
fi

echo "==> Requesting linking QR code for device '$DEVICE_NAME'..."

# Fetch the raw QR code link URI string from the Signal API safely using jq
RESPONSE=$(curl -s "$API_URL/v1/qrcodelink/raw?device_name=$DEVICE_NAME")
URI=$(echo "$RESPONSE" | jq -r '.device_link_uri' || true)

if [ "$URI" = "null" ] || [ -z "$URI" ]; then
    echo "Failed to get linking URI. Response was:"
    echo "$RESPONSE"
    exit 1
fi

echo ""
echo "========================================================="
echo "Please scan the QR code below using the Signal app on your phone."
echo "(Settings -> Linked Devices -> +)"
echo "========================================================="
echo ""

# Use local qrencode to generate a perfect ASCII QR code in the terminal
nix run nixpkgs#qrencode -- -t UTF8 "$URI"

echo ""
echo "========================================================="
echo "If scanning fails, you can try scanning this exact string:"
echo "$URI"
echo "========================================================="
echo ""
echo "Waiting for you to scan and approve the link on your phone..."
while true; do
    ACCOUNTS=$(curl -s "$API_URL/v1/accounts")
    NUM_ACCOUNTS=$(echo "$ACCOUNTS" | jq '. | length' 2>/dev/null || echo "0")
    if [ "$NUM_ACCOUNTS" -gt 0 ]; then
        echo ""
        echo "========================================================="
        echo "✅ Link successful! The device has been securely added."
        echo "Linked accounts:"
        echo "$ACCOUNTS"
        echo "========================================================="
        echo "The '400 Bad Request' errors in carapace should now stop,"
        echo "and it is ready to process messages!"
        break
    fi
    sleep 2
done
