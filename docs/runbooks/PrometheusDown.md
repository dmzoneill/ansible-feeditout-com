# PrometheusDown

**Alert:** `node_systemd_unit_state{name="prometheus.service", state="active"} != 1`

**Severity:** Critical

## Description

Prometheus monitoring server is down on port 9090. While this does not affect production services directly, it means all metric collection has stopped and no alerts will fire. This is a monitoring blind spot -- other services could fail without notification. Alertmanager will also stop receiving alerts. Grafana dashboards will show gaps in data.

## Possible Causes

- Configuration syntax error in `prometheus.yml` or alert rule files
- TSDB corruption or WAL error
- Disk full on the Prometheus data directory
- OOM killer terminated Prometheus (TSDB can use significant memory)
- Port 9090 conflict with another process
- Bad alert rule syntax in `rules/*.yml` files
- Binary missing or permissions issue after manual update

## Investigation

```bash
# Service status
systemctl status prometheus

# Journal logs
journalctl -u prometheus --since "10 minutes ago" --no-pager

# Validate configuration
promtool check config /etc/prometheus/prometheus.yml

# Check alert rules syntax
promtool check rules /etc/prometheus/rules/*.yml

# Check disk space on data directory
df -h /var/lib/prometheus

# Check TSDB directory size
du -sh /var/lib/prometheus/

# Check port
ss -tlnp | grep :9090

# Check for OOM kills
dmesg | grep -i "oom\|killed" | grep -i prom
```

## Resolution

1. Run `promtool check config` and `promtool check rules` to validate configuration and alert rules.
2. If disk full: check retention settings (`--storage.tsdb.retention.time`), reduce retention, or free disk space.
3. If TSDB corruption: check for WAL errors in logs. As a last resort, remove the WAL directory (`/var/lib/prometheus/wal/`) to allow a fresh start (this loses recent uncompacted data).
4. If OOM: reduce the number of scrape targets or increase scrape interval.
5. Restart: `systemctl restart prometheus`
6. Verify: `curl -s http://localhost:9090/-/ready` should return 200.
7. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t prometheus site.yml`

**Note:** While Prometheus is down, no alerts will fire. Prioritize this recovery.

## Prevention

- Always validate config and rules before restarting (`promtool check config`, `promtool check rules`)
- Monitor Prometheus disk usage and set appropriate retention (`--storage.tsdb.retention.time`, `--storage.tsdb.retention.size`)
- Use Ansible `prometheus` role for configuration and rule changes
- Set up an external uptime check for Prometheus itself (deadman switch)
- Keep scrape intervals reasonable (15s default) and limit cardinality of custom metrics
