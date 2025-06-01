#!/bin/bash

BASE_DIR="/etc/letsencrypt"
DELETED_COUNT=0
BATCH_SIZE=500

cleanup_orphans() {
    local DIR=$1
    local LABEL=$2
    local PATTERN=$3

    if [[ ! -d "$DIR" ]]; then
        echo "⚠️  Skipping $LABEL cleanup: Directory $DIR does not exist."
        return
    fi

    echo "🔍 Scanning for orphaned $LABEL in $DIR matching '$PATTERN'..."

    find "$DIR" -type f -name "$PATTERN" | while read -r filepath; do
        # Get hardlink count
        linkcount=$(stat -c %h "$filepath" 2>/dev/null)
        if [[ "$linkcount" -eq 1 ]]; then
            echo "🗑️  Deleting orphaned $LABEL: $filepath"
            rm -f "$filepath"
            ((DELETED_COUNT++))
            if (( DELETED_COUNT % BATCH_SIZE == 0 )); then
                echo "⏸️  Deleted $DELETED_COUNT files so far... pausing briefly."
                sleep 2
            fi
        fi
    done
}

cleanup_orphans "$BASE_DIR/keys"  "key"         "*_key-certbot.pem"
cleanup_orphans "$BASE_DIR/csr"   "CSR"         "*_csr-certbot.pem"
cleanup_orphans "$BASE_DIR/certs" "certificate" "*.pem"

echo "✅ Done. Total deleted: $DELETED_COUNT"
