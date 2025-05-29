#!/bin/bash
set -euo pipefail

APACHE_SITES_DIR="/etc/apache2/sites-enabled/*"
CERTBOT_LIVE_DIR="/etc/letsencrypt/live"

echo "🔄 Checking for missing domains at $(date)"

# Extract all domains from Apache configs
apache_domains=$(grep -rhoP 'Server(Name|Alias)\s+\K\S+' "$APACHE_SITES_DIR" | sort -u)

# Extract domains already in certs
certbot_domains=$(find "$CERTBOT_LIVE_DIR" -mindepth 1 -maxdepth 1 -type d | while read certdir; do
    openssl x509 -in "$certdir/cert.pem" -noout -text 2>/dev/null |
        grep -oP 'DNS:\K[^,]+' || true
done | sort -u)

# Identify missing domains
missing_domains=$(comm -23 <(echo "$apache_domains") <(echo "$certbot_domains"))

echo "===== Domains IN Apache BUT NOT in any Cert ====="
if [ -z "$missing_domains" ]; then
    echo "✅ No missing domains. All Apache domains are covered by Certbot certificates."
    exit 0
else
    echo "$missing_domains"
fi

# Group missing domains by base domain (e.g. fio.ie)
grouped_domains=$(echo "$missing_domains" | awk -F. '
{
    n=NF
    base=$(n-1) "." $n
    groups[base]=groups[base] ? groups[base] " " $0 : $0
}
END {
    for (g in groups) {
        print g ":" groups[g]
    }
}')

echo "Stopping Apache..."
systemctl stop apache2

while IFS=: read -r basedomain new_domains; do
    cert_path="$CERTBOT_LIVE_DIR/$basedomain"
    if [ -d "$cert_path" ]; then
        existing_domains=$(openssl x509 -in "$cert_path/cert.pem" -noout -text 2>/dev/null | grep -oP 'DNS:\K[^,]+' || true)
    else
        existing_domains=""
    fi

    # Combine and sort domains
    all_domains=$(echo -e "$basedomain\n$existing_domains\n$new_domains" | tr ' ' '\n' | sed '/^$/d' | sort -u)

    # Build certbot -d args
    domains_args=$(echo "$all_domains" | awk '{ print "-d", $1 }' | xargs)

    if [ -n "$domains_args" ]; then
        echo "Running: certbot certonly --standalone --cert-name $basedomain $domains_args"
        certbot certonly --standalone --cert-name "$basedomain" $domains_args \
            --agree-tos --non-interactive --register-unsafely-without-email --expand || {
            echo "⚠️ Certbot failed for $basedomain"
        }
    else
        echo "⚠️ Skipping $basedomain — no valid domain names found."
    fi
    echo
done <<< "$grouped_domains"

echo "Restarting Apache..."
systemctl start apache2
echo "✅ All done."
