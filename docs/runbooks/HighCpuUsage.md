# HighCpuUsage

**Alert:** CPU usage exceeds 95% for more than 2 minutes.

**Severity:** Warning

## Possible Causes

- Runaway or misbehaving process (Apache, MariaDB, PHP-FPM, Redis)
- Crypto-mining malware or compromised process
- Traffic spike causing excessive Apache/PHP worker spawning
- MariaDB running expensive or unoptimised queries
- Backup or cron job consuming excessive CPU
- Kernel bug or driver issue causing high `%sys`

## Investigation

```bash
# Real-time process view sorted by CPU
top -bn1 -o %CPU | head -30

# Per-CPU breakdown
mpstat -P ALL 1 5

# Identify top CPU consumers
ps aux --sort=-%cpu | head -20

# Check Apache worker count
ps -C apache2 --no-headers | wc -l

# Check MariaDB process list for long-running queries
mysql -e "SHOW FULL PROCESSLIST;"

# Check for recent cron activity
journalctl -u cron --since "30 minutes ago"

# Check system load context
uptime
```

## Resolution

1. Identify the offending process from `top` or `ps` output.
2. If Apache/PHP: check access logs for traffic spikes (`tail -f /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head`). Consider rate limiting or blocking abusive IPs.
3. If MariaDB: kill long-running queries with `KILL <id>;` and investigate the query with `EXPLAIN`.
4. If a cron job: check `/etc/cron.d/` and user crontabs; reschedule to off-peak or `nice`/`ionice` it.
5. If unknown process: investigate with `ls -l /proc/<PID>/exe` and check for compromise.
6. As a last resort, `kill -9 <PID>` the offending process, then restart the relevant service.

## Prevention

- Set resource limits for Apache (`MaxRequestWorkers`), PHP-FPM (`pm.max_children`), and MariaDB (`max_connections`)
- Use `nice` and `ionice` for scheduled batch jobs
- Monitor slow query logs and optimise MariaDB queries
- Implement rate limiting in Apache or via fail2ban
- Keep software patched and regularly audit running processes
