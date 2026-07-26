# DiskSpacePrediction

**Alert:** Linear prediction estimates disk will be full within 24 hours.

**Severity:** Critical

## Possible Causes

- Rapidly growing log files (error loops, verbose logging, debug mode left on)
- Large data import or migration in progress
- Backup files accumulating on local disk
- Database growth (binary logs, table data, temporary tables)
- Mail queue growing due to delivery failures
- Application generating large temporary or upload files

## Investigation

```bash
# Current disk usage
df -h

# Identify what is growing -- compare current vs recent
du -sh /var/log/* 2>/dev/null | sort -rh | head -10
du -sh /var/lib/mysql/* 2>/dev/null | sort -rh | head -10

# Find files modified in the last hour and growing
find / -xdev -type f -mmin -60 -size +10M -exec ls -lh {} \; 2>/dev/null | sort -k5 -rh | head -20

# Watch real-time disk usage changes
watch -n 5 'df -h'

# Check log growth rate
ls -lhS /var/log/apache2/* /var/log/mysql/* /var/log/syslog /var/log/mail.log 2>/dev/null

# Check for active large writes
lsof / | awk '$7 > 100000000 {print}' | head -10

# Check MariaDB binary log growth
mysql -e "SHOW BINARY LOGS;" 2>/dev/null

# Check Postfix queue
postqueue -p | tail -1
```

## Resolution

1. Identify the fastest-growing files or directories.
2. If logs: rotate immediately (`logrotate -f /etc/logrotate.d/<service>`), fix the root cause (error loop, debug logging).
3. If database: purge old binary logs, optimise tables, archive old data.
4. If backups: move to remote storage, clean old local copies.
5. If mail queue: investigate delivery failures, flush stale entries.
6. If application data: identify the source, archive or clean as appropriate.
7. After addressing the growth, verify the prediction alert clears.

## Prevention

- Configure aggressive log rotation with size-based limits
- Set `expire_logs_days` for MariaDB binary logs
- Automate backup cleanup and off-server transfer
- Monitor disk usage rate of change, not just absolute values
- Set up tiered alerts at multiple thresholds before critical
- Implement application-level data retention and cleanup policies
