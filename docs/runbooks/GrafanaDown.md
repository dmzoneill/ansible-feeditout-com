# GrafanaDown

**Alert:** `node_systemd_unit_state{name="grafana-server.service", state="active"} != 1`

**Severity:** Critical

## Description

Grafana dashboard server is down on port 3000. This does not affect production services or alerting, but it removes visibility into system metrics. Operators cannot view dashboards to diagnose ongoing issues. If Grafana is the primary alerting channel (Grafana-managed alerts), those alerts will also stop.

## Possible Causes

- Configuration error in `/etc/grafana/grafana.ini`
- Database issue (SQLite lock or corruption in `/var/lib/grafana/grafana.db`)
- Port 3000 conflict with another process
- Plugin installation failure or incompatible plugin version
- Disk full on `/var/lib/grafana`
- Permission error on data directory or log directory
- Package upgrade requiring database migration that failed

## Investigation

```bash
# Service status
systemctl status grafana-server

# Journal logs
journalctl -u grafana-server --since "10 minutes ago" --no-pager

# Check Grafana log
tail -50 /var/log/grafana/grafana.log

# Check port
ss -tlnp | grep :3000

# Check disk space
df -h /var/lib/grafana

# Check database file
ls -la /var/lib/grafana/grafana.db

# Check data directory permissions
ls -la /var/lib/grafana/
ls -la /var/log/grafana/
```

## Resolution

1. Check `/var/log/grafana/grafana.log` for the specific error.
2. If database corruption: stop Grafana, back up `grafana.db`, try `sqlite3 /var/lib/grafana/grafana.db "PRAGMA integrity_check;"`. If corrupt, restore from backup.
3. If disk full: free space on `/var/lib/grafana` partition.
4. If permission error: ensure `/var/lib/grafana` and `/var/log/grafana` are owned by `grafana:grafana`.
5. If plugin error: remove the problematic plugin from `/var/lib/grafana/plugins/`.
6. Restart: `systemctl restart grafana-server`
7. Verify: `curl -sI http://localhost:3000/api/health` should return 200.
8. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t grafana site.yml`

## Prevention

- Use Ansible `grafana` role for configuration and plugin management
- Back up `grafana.db` regularly (dashboards, data sources, users)
- Monitor disk usage on `/var/lib/grafana`
- Pin Grafana plugin versions to avoid upgrade breakage
- Test Grafana upgrades in a staging environment before applying to production
