# TcpTimeWaitHigh

## Description

The number of TCP sockets in TIME_WAIT state exceeds 1000. TIME_WAIT is a normal TCP state after connection close, but excessive accumulation can exhaust ephemeral ports and prevent new connections.

## Severity

**Warning**

## Possible Causes

- High rate of short-lived HTTP connections (clients not using keep-alive)
- Application making many short-lived connections to MariaDB or Redis
- Reverse proxy or health check creating rapid connect/disconnect cycles
- Prometheus scraping many targets with short-lived connections
- Aggressive crawlers/bots generating high request rates

## Investigation

```bash
# Count sockets by state
ss -s

# Count TIME_WAIT specifically
ss -tn state time-wait | wc -l

# TIME_WAIT by remote IP
ss -tn state time-wait | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# TIME_WAIT by local port
ss -tn state time-wait | awk '{print $4}' | rev | cut -d: -f1 | rev | sort | uniq -c | sort -rn | head -10

# Check ephemeral port range and usage
sysctl net.ipv4.ip_local_port_range
ss -tn state time-wait | wc -l

# Check current TCP reuse/recycle settings
sysctl net.ipv4.tcp_tw_reuse
sysctl net.ipv4.tcp_fin_timeout

# Check connection rate from Apache logs
awk '{print $4}' /var/log/apache2/access.log | cut -d: -f1-2 | uniq -c | tail -10

# Check if MariaDB connections are recycling fast
mysql -u root -e "SHOW STATUS LIKE 'Connections';"
```

## Resolution

1. **Enable TCP TIME_WAIT reuse** (safe for client-side connections):
   ```bash
   sysctl -w net.ipv4.tcp_tw_reuse=1
   # Make persistent in /etc/sysctl.d/99-tcp.conf
   echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.d/99-tcp.conf
   ```

2. **Reduce FIN timeout** (default 60s is often too long):
   ```bash
   sysctl -w net.ipv4.tcp_fin_timeout=15
   ```

3. **Widen the ephemeral port range**:
   ```bash
   sysctl -w net.ipv4.ip_local_port_range="1024 65535"
   ```

4. **Enable HTTP keep-alive** on Apache to reduce connection churn:
   ```apache
   KeepAlive On
   KeepAliveTimeout 5
   MaxKeepAliveRequests 100
   ```

5. **For application-level fixes**, use persistent connections to MariaDB and Redis rather than connect-per-request.

## Prevention

- Use persistent/pooled database connections in applications
- Enable HTTP keep-alive for both clients and upstream services
- Set `tcp_tw_reuse=1` and `tcp_fin_timeout=15` as system defaults
- Use Unix sockets for local MariaDB and Redis connections instead of TCP
- Monitor TIME_WAIT trends in Grafana to catch regressions early
