# PrometheusTargetDown

## Description

A Prometheus scrape target is unreachable. Prometheus cannot collect metrics from the target, creating a monitoring blind spot. If the target is a critical service, an outage may be occurring without alerting coverage.

## Severity

**Critical**

## Possible Causes

- Target service (node_exporter, mysqld_exporter, redis_exporter, etc.) has crashed
- Target host is down or unreachable
- Firewall blocking the scrape port
- Exporter listening on wrong interface (localhost vs all interfaces)
- Prometheus scrape configuration error (wrong port, path, or hostname)
- TLS/authentication mismatch between Prometheus and the target
- Network partition or DNS resolution failure

## Investigation

```bash
# Check Prometheus targets page for error details
curl -s http://localhost:9090/api/v1/targets | python3 -m json.tool | grep -A5 '"health":"down"'

# Check which targets are down
curl -s http://localhost:9090/api/v1/targets | python3 -c "
import json,sys
data=json.load(sys.stdin)
for t in data.get('data',{}).get('activeTargets',[]):
  if t['health']=='down':
    print(f\"{t['labels'].get('job','?')}: {t['scrapeUrl']} - {t.get('lastError','')}\")" 2>/dev/null

# Check if the exporter process is running
systemctl status prometheus-node-exporter
systemctl status prometheus-mysqld-exporter 2>/dev/null
systemctl status prometheus-redis-exporter 2>/dev/null

# Test the exporter endpoint directly
curl -s http://localhost:9100/metrics | head -5   # node_exporter
curl -s http://localhost:9104/metrics | head -5   # mysqld_exporter

# Check if the port is listening
ss -tlnp | grep -E "9090|9093|9100|9104|9121"

# Check firewall
iptables -L -n | grep -E "9100|9104|9121"

# Check Prometheus config for the target
grep -A10 "job_name" /etc/prometheus/prometheus.yml

# Check Prometheus own logs
journalctl -u prometheus --since "30 minutes ago" --no-pager | tail -20
```

## Resolution

1. **If the exporter service is down**, restart it:
   ```bash
   systemctl restart prometheus-node-exporter
   # or whichever exporter is affected
   ```

2. **If the host is unreachable**, investigate network/host issues separately.

3. **If firewall is blocking**, allow the scrape port:
   ```bash
   iptables -A INPUT -p tcp --dport 9100 -s <prometheus_ip> -j ACCEPT
   ```

4. **If binding to wrong interface**, update the exporter to listen on the correct address:
   ```bash
   # Check current listen address
   ss -tlnp | grep <port>
   # Update in the exporter's systemd unit or config
   ```

5. **If Prometheus config is wrong**, fix and reload:
   ```bash
   promtool check config /etc/prometheus/prometheus.yml
   systemctl reload prometheus
   ```

6. **Verify the target is up** in the Prometheus UI at `http://localhost:9090/targets`.

## Prevention

- Use `promtool check config` before applying Prometheus config changes
- Deploy exporters via Ansible with consistent configuration
- Ensure exporter systemd units have `Restart=on-failure`
- Monitor exporter processes alongside the services they export
- Use service discovery instead of static targets where possible
- Document all scrape targets and their expected ports
