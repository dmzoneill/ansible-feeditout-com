# AlertmanagerNotificationFailed

## Description

Alertmanager failed to deliver alert notifications to one or more receivers (email via Postfix, Slack webhook, PagerDuty, etc.). Alerts are firing but nobody is being notified, which can cause outages to go undetected.

## Severity

**Warning**

## Possible Causes

- Postfix (local mail relay) is down or misconfigured
- SMTP authentication failure or relay denied
- Slack/webhook endpoint unreachable or returning errors
- Alertmanager receiver configuration error (wrong URL, token, or email address)
- DNS resolution failure preventing Alertmanager from reaching external services
- TLS certificate issue on the notification endpoint
- Network firewall blocking outbound SMTP (port 25/587) or HTTPS (port 443)
- Alertmanager itself is overloaded or crashlooping

## Investigation

```bash
# Check Alertmanager notification failure metrics
curl -s http://localhost:9093/api/v2/status | python3 -m json.tool

# Check Alertmanager logs for send failures
journalctl -u alertmanager --since "1 hour ago" --no-pager | grep -iE "error|fail|notify"

# Check Alertmanager is running
systemctl status alertmanager

# Check notification metrics
curl -s 'http://localhost:9090/api/v1/query?query=alertmanager_notifications_failed_total' | python3 -m json.tool

# Check which integration is failing
curl -s 'http://localhost:9090/api/v1/query?query=alertmanager_notifications_failed_total{integration!=""}' | python3 -m json.tool

# If email notifications: check Postfix
systemctl status postfix
postqueue -p           # Check mail queue
tail -50 /var/log/mail.log

# Test email sending
echo "Test alert" | mail -s "Alertmanager test" root

# If webhook/Slack: test connectivity
curl -v https://hooks.slack.com/services/... 2>&1 | head -20

# Check DNS resolution
dig +short smtp.example.com  # or whatever SMTP relay is configured
nslookup hooks.slack.com

# Check Alertmanager config
amtool check-config /etc/alertmanager/alertmanager.yml
cat /etc/alertmanager/alertmanager.yml | grep -A10 "receivers:"
```

## Resolution

1. **If Postfix is down**:
   ```bash
   systemctl restart postfix
   # Flush any queued mail
   postqueue -f
   ```

2. **If mail queue is backed up**, check why:
   ```bash
   postqueue -p
   # Check for specific delivery errors
   tail -100 /var/log/mail.log | grep -E "reject|error|deferred"
   ```

3. **If webhook endpoint is unreachable**, verify the URL and connectivity:
   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"text":"test"}' <webhook_url>
   ```

4. **If configuration is wrong**, fix and reload:
   ```bash
   vim /etc/alertmanager/alertmanager.yml
   amtool check-config /etc/alertmanager/alertmanager.yml
   systemctl reload alertmanager
   ```

5. **If DNS is failing**:
   ```bash
   cat /etc/resolv.conf
   systemctl restart systemd-resolved 2>/dev/null
   ```

6. **Test that notifications work**:
   ```bash
   # Send a test alert
   amtool alert add test severity=critical -a http://localhost:9093
   # Check it was received, then resolve it
   amtool alert add test severity=critical --end=$(date -u +%Y-%m-%dT%H:%M:%S) -a http://localhost:9093
   ```

## Prevention

- Monitor `alertmanager_notifications_failed_total` as a critical metric
- Test notification channels after any configuration change
- Configure multiple notification receivers (email + Slack) for redundancy
- Ensure Postfix is monitored and has its own restart policy
- Use `amtool check-config` before deploying Alertmanager configuration changes
- Keep webhook tokens and credentials up to date
- Set up a dead man's switch (Watchdog alert) to detect complete notification failure
