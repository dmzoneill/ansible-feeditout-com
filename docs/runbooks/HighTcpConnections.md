# HighTcpConnections

## Description

The number of TCP connections in ESTABLISHED state exceeds 500. This may indicate unusually high traffic, connection leaks, or a denial-of-service condition.

## Severity

**Warning**

## Possible Causes

- Legitimate traffic spike
- Slow backend (MariaDB, Redis) causing connection pileup on Apache
- HTTP keep-alive holding connections open too long
- Application not closing database connections properly
- Connection pool misconfiguration
- Slowloris or similar slow-rate DoS attack
- Crawler or bot flood

## Investigation

```bash
# Count TCP connections by state
ss -s

# Count ESTABLISHED connections
ss -tn state established | wc -l

# Connections grouped by remote IP
ss -tn state established | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Connections grouped by local port (which service)
ss -tn state established | awk '{print $4}' | rev | cut -d: -f1 | rev | sort | uniq -c | sort -rn | head -20

# Check Apache connection status
apachectl status 2>/dev/null || curl -s http://localhost/server-status?auto

# Check Apache worker usage
apachectl fullstatus 2>/dev/null | grep -E "idle|busy"

# Check MariaDB connections
mysql -u root -e "SHOW STATUS LIKE 'Threads_connected';"
mysql -u root -e "SHOW PROCESSLIST;"

# Check Redis connections
redis-cli info clients

# Check for potential DoS - high connection count from single IP
ss -tn state established dst :80 -o | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
ss -tn state established dst :443 -o | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# Check Apache access logs for anomalies
tail -1000 /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

## Resolution

1. **If a single IP is responsible**, block it:
   ```bash
   iptables -A INPUT -s <IP> -j DROP
   # Or use fail2ban
   ```

2. **If Apache is overloaded**, tune connection handling:
   ```bash
   # Reduce KeepAliveTimeout
   # In /etc/apache2/apache2.conf:
   # KeepAliveTimeout 3
   systemctl reload apache2
   ```

3. **If MariaDB connections are piling up**, check for long-running queries:
   ```bash
   mysql -u root -e "SELECT id, user, host, time, state, LEFT(info,80) FROM information_schema.processlist WHERE time > 30 ORDER BY time DESC;"
   # Kill problematic queries
   mysql -u root -e "KILL <thread_id>;"
   ```

4. **If legitimate traffic**, increase limits:
   ```bash
   # Raise file descriptor limits and Apache MaxRequestWorkers
   # Check current kernel limits
   sysctl net.core.somaxconn
   sysctl net.ipv4.tcp_max_syn_backlog
   ```

## Prevention

- Configure appropriate `KeepAliveTimeout` (2-5 seconds)
- Set `MaxRequestWorkers` to match available resources
- Use connection pooling for database connections
- Deploy fail2ban rules for HTTP flood detection
- Monitor connection trends in Grafana
- Configure rate limiting in Apache with `mod_ratelimit` or `mod_evasive`
