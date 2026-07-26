#!/bin/bash
set -euo pipefail

OUTPUT="/var/lib/node_exporter/textfile/ssl_certs.prom"
TEMP=$(mktemp)

echo "# HELP ssl_cert_expiry_timestamp SSL certificate expiry as Unix timestamp" > "$TEMP"
echo "# TYPE ssl_cert_expiry_timestamp gauge" >> "$TEMP"

for certdir in /etc/letsencrypt/live/*/; do
    [ -f "$certdir/cert.pem" ] || continue
    domain=$(basename "$certdir")
    [[ "$domain" == "README" ]] && continue
    expiry=$(openssl x509 -in "$certdir/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    [ -z "$expiry" ] && continue
    epoch=$(date -d "$expiry" +%s 2>/dev/null) || continue
    echo "ssl_cert_expiry_timestamp{domain=\"$domain\"} $epoch" >> "$TEMP"
done

mv "$TEMP" "$OUTPUT"
