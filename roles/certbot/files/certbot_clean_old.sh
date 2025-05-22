#!/bin/bash

set -euo pipefail

KEYS_DIR="/etc/letsencrypt/keys"
LIVE_DIR="/etc/letsencrypt/live"
USED_KEYS=$(mktemp)
DELETED_COUNT=0
BATCH_SIZE=500

echo "📋 Finding active private keys in use..."
find "$LIVE_DIR" -type l -name 'privkey.pem' -exec readlink -f {} \; | sort -u > "$USED_KEYS"

echo "🧹 Starting batch cleanup..."
find "$KEYS_DIR" -type f -name '*_key-certbot.pem' | while read -r key; do
    if ! grep -qF "$key" "$USED_KEYS"; then
        echo "🗑️  Deleting unused key: $key"
        rm -f "$key"
        ((DELETED_COUNT++))
    fi

    if (( DELETED_COUNT % BATCH_SIZE == 0 )) && (( DELETED_COUNT > 0 )); then
        echo "⏸️  Deleted $DELETED_COUNT keys so far... pausing briefly to avoid overload."
        sleep 2
    fi
done

rm -f "$USED_KEYS"
echo "✅ Done. Total deleted: $DELETED_COUNT"



KEYS_DIR="/etc/letsencrypt/keys"
LIVE_DIR="/etc/letsencrypt/live"
USED_KEYS=$(mktemp)
DELETED_COUNT=0
BATCH_SIZE=500

echo "📋 Finding active private keys in use..."
find "$LIVE_DIR" -type l -name privkey.pem -exec readlink -f {} \; | sort -u > "$USED_KEYS"

echo "🧹 Starting batch cleanup..."

# Use a file descriptor instead of piping to avoid subshell issues
find "$KEYS_DIR" -type f -name '*_key-certbot.pem' > /tmp/all_keys.txt

while IFS= read -r key; do
    if ! grep -qF "$key" "$USED_KEYS"; then
        echo "🗑️  Deleting unused key: $key"
        rm -f "$key"
        ((DELETED_COUNT++))
    fi

    if (( DELETED_COUNT % BATCH_SIZE == 0 )) && (( DELETED_COUNT > 0 )); then
        echo "⏸️  Deleted $DELETED_COUNT keys so far... pausing briefly."
        sleep 2
    fi
done < /tmp/all_keys.txt

rm -f "$USED_KEYS" /tmp/all_keys.txt
echo "✅ Finished. Total deleted: $DELETED_COUNT"