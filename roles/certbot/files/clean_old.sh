#!/bin/bash

set -euo pipefail

KEYS_DIR="/etc/letsencrypt/keys"
LIVE_DIR="/etc/letsencrypt/live"
TMP_FILE="$(mktemp)"

echo "🛡️  Auditing unused Certbot private keys..."
echo

# Step 1: Collect all keys in use (via symlinks in live/)
echo "🔍 Collecting active keys in use..."
find "$LIVE_DIR" -type l -name 'privkey.pem' -exec readlink -f {} \; | sort -u > "$TMP_FILE"

# Step 2: List all keys
echo "📦 All keys in: $KEYS_DIR"
ALL_KEYS=$(find "$KEYS_DIR" -type f -name '*_key-certbot.pem' | sort)

# Step 3: Compare and print unused keys
echo
echo "🧹 Unused keys:"
echo

UNUSED_KEYS=()
for key in $ALL_KEYS; do
    if ! grep -qF "$key" "$TMP_FILE"; then
        echo " - $key"
        UNUSED_KEYS+=("$key")
    fi
done

if [[ ${#UNUSED_KEYS[@]} -eq 0 ]]; then
    echo "✅ No unused keys found."
    rm -f "$TMP_FILE"
    exit 0
fi


for key in "${UNUSED_KEYS[@]}"; do
    echo "🗑️  Deleting: $key"
    rm -f "$key"
done
echo "✅ Cleanup complete."

rm -f "$TMP_FILE"
