# AlertmanagerDown

**Alert:** `node_systemd_unit_state{name="alertmanager.service", state="active"} != 1`

**Severity:** Critical

## Description

Alertmanager is down on port 9093. Prometheus can still collect metrics and evaluate rules, but alert notifications (email, Slack, webhooks) will not be delivered. Alerts will queue in Prometheus and be lost if Alertmanager is not restored before Prometheus's alert buffer fills. This is a silent failure -- problems occur but nobody gets notified.

## Possible Causes

- Configuration syntax error in `alertmanager.yml`
- Port 9093 conflict with another process
- Disk full preventing Alertmanager from writing its notification log or silences
- OOM kill (uncommon -- Alertmanager is lightweight)
- TLS or authentication error in notification config (SMTP credentials, webhook URLs)
- Binary missing or permissions issue after update
- Template syntax error in notification templates

## Investigation

```bash
# Service status
systemctl status alertmanager

# Journal logs
journalctl -u alertmanager --since "10 minutes ago" --no-pager

# Validate configuration
amtool check-config /etc/alertmanager/alertmanager.yml

# Check port
ss -tlnp | grep :9093

# Check disk space
df -h /var/lib/alertmanager

# Check Alertmanager data directory
ls -la /var/lib/alertmanager/

# Check binary exists
which alertmanager
```

## Resolution

1. Run `amtool check-config` to validate the configuration file.
2. If template error: check custom templates referenced in `alertmanager.yml`.
3. If disk full: free space, then restart.
4. If port conflict: identify and stop the conflicting process.
5. Restart: `systemctl restart alertmanager`
6. Verify: `curl -s http://localhost:9093/-/ready` should return 200.
7. Check Prometheus can reach it: `curl -s http://localhost:9090/api/v1/alertmanagers` should list the target.
8. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t alert_manager site.yml`

**Note:** While Alertmanager is down, alerts are not delivered. Check Prometheus for any pending alerts after recovery: `curl -s http://localhost:9090/api/v1/alerts | python3 -m json.tool`

## Prevention

- Always validate config before restarting (`amtool check-config`)
- Use Ansible `alert_manager` role for all configuration changes
- Set up a Prometheus `Watchdog` alert (always-firing) to detect Alertmanager delivery failures
- Test notification routes after changes (`amtool config routes test`)
- Monitor Alertmanager alongside Prometheus as a critical pair
