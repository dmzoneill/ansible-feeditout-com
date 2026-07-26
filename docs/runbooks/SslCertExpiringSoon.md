# SslCertExpiringSoon

## Description

An SSL/TLS certificate will expire in fewer than 14 days. If not renewed, HTTPS connections will fail with certificate errors, breaking web access and API integrations.

## Severity

**Warning**

## Possible Causes

- Certbot auto-renewal failed silently
- Certbot timer/cron not enabled or not running
- DNS validation failure preventing renewal (DNS provider API issue)
- HTTP-01 challenge failing (Apache misconfiguration, port 80 blocked)
- Rate limit hit on Let's Encrypt
- Certificate for a domain no longer pointed at this server
- Manual certificate that was never set up for auto-renewal

## Investigation

```bash
# Check certificate expiry for all sites
for cert in /etc/letsencrypt/live/*/fullchain.pem; do
  domain=$(basename $(dirname $cert))
  expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
  echo "$domain: expires $expiry"
done

# Check a specific domain via the live service
echo | openssl s_client -servername <domain> -connect <domain>:443 2>/dev/null | openssl x509 -noout -dates

# Check certbot renewal status
certbot certificates

# Test renewal (dry run)
certbot renew --dry-run

# Check certbot timer
systemctl status certbot.timer
systemctl list-timers | grep certbot

# Check recent certbot logs
journalctl -u certbot --since "7 days ago" --no-pager
cat /var/log/letsencrypt/letsencrypt.log | tail -50

# Check if port 80 is accessible (for HTTP-01 challenge)
curl -I http://<domain>/.well-known/acme-challenge/test 2>/dev/null
```

## Resolution

1. **Attempt manual renewal**:
   ```bash
   certbot renew
   ```

2. **If renewal fails with HTTP-01 challenge**, ensure Apache serves `.well-known`:
   ```bash
   # Check Apache is listening on port 80
   ss -tlnp | grep :80

   # Ensure no redirect blocks the challenge path
   curl -v http://<domain>/.well-known/acme-challenge/test
   ```

3. **If DNS validation fails**, check DNS provider credentials and API access.

4. **Reload Apache after renewal**:
   ```bash
   systemctl reload apache2
   ```

5. **If rate-limited**, wait or use Let's Encrypt staging for testing:
   ```bash
   certbot renew --dry-run --staging
   ```

6. **Ensure the timer is enabled**:
   ```bash
   systemctl enable --now certbot.timer
   ```

## Prevention

- Verify `certbot.timer` is enabled on all servers
- Test renewal with `certbot renew --dry-run` after any Apache config change
- Set up this alert with a 30-day threshold as an early warning
- Configure certbot deploy hooks to reload Apache: `--deploy-hook "systemctl reload apache2"`
- Monitor renewal logs regularly
- Keep certbot updated: `apt-get update && apt-get upgrade certbot`
