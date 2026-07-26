# SslCertExpiryCritical

## Description

An SSL/TLS certificate will expire in fewer than 3 days. This is an imminent outage risk. HTTPS will stop working once the certificate expires, causing browser security warnings and API failures.

## Severity

**Critical**

## Possible Causes

- Certbot auto-renewal has been failing repeatedly
- Certbot timer disabled or missing
- DNS or HTTP challenge misconfiguration blocking all renewal attempts
- Let's Encrypt rate limits exhausted
- Domain DNS no longer points to this server
- Previous SslCertExpiringSoon alert was not actioned

## Investigation

```bash
# Check exactly when the cert expires
for cert in /etc/letsencrypt/live/*/fullchain.pem; do
  domain=$(basename $(dirname $cert))
  openssl x509 -enddate -noout -in "$cert" 2>/dev/null | sed "s/^/$domain: /"
done

# Check certbot renewal history for errors
cat /var/log/letsencrypt/letsencrypt.log | grep -E "error|fail|unable" | tail -20

# Try dry-run renewal to diagnose
certbot renew --dry-run 2>&1

# Check certbot timer status
systemctl status certbot.timer
journalctl -u certbot --since "3 days ago" --no-pager

# Verify DNS still points here
dig +short <domain> A
curl -sI http://<domain> | head -5

# Check Apache is serving port 80 for challenges
ss -tlnp | grep :80
```

## Resolution

**Act immediately -- this is time-critical.**

1. **Force renewal now**:
   ```bash
   certbot renew --force-renewal
   ```

2. **If that fails, try specifying the domain**:
   ```bash
   certbot certonly --apache -d <domain> -d www.<domain>
   ```

3. **If HTTP-01 challenge fails**, fix Apache to serve port 80:
   ```bash
   # Temporarily disable HTTPS redirect for .well-known
   # Ensure port 80 VirtualHost exists and is enabled
   apache2ctl configtest && systemctl reload apache2
   certbot renew --force-renewal
   ```

4. **Reload Apache after successful renewal**:
   ```bash
   systemctl reload apache2
   ```

5. **Verify the new certificate**:
   ```bash
   echo | openssl s_client -servername <domain> -connect <domain>:443 2>/dev/null | openssl x509 -noout -dates
   ```

6. **If completely blocked**, consider a temporary self-signed cert while debugging renewal (last resort, causes browser warnings).

7. **Fix the timer** to prevent recurrence:
   ```bash
   systemctl enable --now certbot.timer
   ```

## Prevention

- Respond to the SslCertExpiringSoon (14-day) warning promptly
- Verify `certbot.timer` is enabled and running
- Test renewal after any Apache or DNS change
- Configure certbot deploy hooks: `--deploy-hook "systemctl reload apache2"`
- Set up a separate monitoring check for certbot timer health
