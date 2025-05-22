#!/bin/bash


KEYS_DIR="/etc/letsencrypt/keys"
DELETED_COUNT=0
BATCH_SIZE=500

echo "🔍 Scanning for orphaned Certbot keys (link count == 1)..."

find "$KEYS_DIR" -type f -name '*_key-certbot.pem' -printf '%n %p\n' | while read -r linkcount filepath; do
    if [[ "$linkcount" -eq 1 ]]; then
        echo "🗑️  Deleting orphaned key: $filepath"
        rm -f "$filepath"
        ((DELETED_COUNT++))

        if (( DELETED_COUNT % BATCH_SIZE == 0 )); then
            echo "⏸️  Deleted $DELETED_COUNT keys so far... pausing briefly."
            sleep 2
        fi
    fi
done

echo "✅ Done. Total deleted: $DELETED_COUNT"
