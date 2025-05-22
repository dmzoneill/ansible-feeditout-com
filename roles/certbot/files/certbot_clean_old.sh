#!/bin/bash

set -euo pipefail

KEYS_DIR="/etc/letsencrypt/keys"
LIVE_DIR="/etc/letsencrypt/live"
TMP_DIR=$(mktemp -d)
USED_KEYS="$TMP_DIR/used_keys.txt"
ALL_KEYS="$TMP_DIR/all_keys.txt"
DELETED_COUNT=0
BATCH_SIZE=500

echo "📋 Finding active private keys in use..."
find "$LIVE_DIR" -type l -name 'privkey.pem' -exec readlink -f {} \; | sort -u > "$USED_KEYS"

echo "🧹 Starting batch cleanup of unused keys..."
find "$KEYS_DIR" -type f -name '*_key-certbot.pem' > "$ALL_KEYS"

# ✅ Correct: open file descriptor 3 for reading
exec 3< "$ALL_KEYS"

while IFS= read -r -u 3 key; do
    if ! grep -qF "$key" "$USED_KEYS"; then
        echo "🗑️  Deleting unused key: $key"
        rm -f "$key"
        ((DELETED_COUNT++))
    fi

    if (( DELETED_COUNT > 0 && DELETED_COUNT % BATCH_SIZE == 0 )); then
        echo "⏸️  Deleted $DELETED_COUNT keys so far... pausing briefly."
        sleep 2
    fi
done

exec 3<&-  # ✅ Close file descriptor
rm -rf "$TMP_DIR"

echo "✅ Finished. Total unused keys deleted: $DELETED_COUNT"
