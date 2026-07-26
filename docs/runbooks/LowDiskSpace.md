# LowDiskSpace

**Alert:** Disk free space is below 5%.

**Severity:** Critical

## Possible Causes

- Log files growing uncontrolled (Apache, MariaDB, syslog, mail logs)
- Large backup files not cleaned up
- MariaDB binary logs or InnoDB tablespace growth
- Postfix mail queue backlog filling spool
- Core dumps or temporary files accumulating
- Package cache not cleaned after updates
- Application uploading or generating large files

## Investigation

```bash
# Check all filesystems
df -h

# Find which directories are consuming most space
du -sh /* 2>/dev/null | sort -rh | head -20
du -sh /var/* 2>/dev/null | sort -rh | head -10
du -sh /var/log/* 2>/dev/null | sort -rh | head -10

# Find large files modified recently
find / -xdev -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null

# Check log sizes
ls -lhS /var/log/*.log /var/log/apache2/* /var/log/mysql/* 2>/dev/null | head -20

# Check MariaDB binary log usage
mysql -e "SHOW BINARY LOGS;" 2>/dev/null

# Check Postfix queue size
du -sh /var/spool/postfix/

# Check apt cache
du -sh /var/cache/apt/archives/
```

## Resolution

1. Identify the largest space consumers with `du`.
2. Rotate and compress logs: `logrotate -f /etc/logrotate.conf`.
3. Clean old logs: `journalctl --vacuum-size=500M`.
4. Purge MariaDB binary logs: `PURGE BINARY LOGS BEFORE NOW() - INTERVAL 3 DAY;`.
5. Clean apt cache: `apt-get clean`.
6. Remove old kernels: `apt-get autoremove --purge`.
7. Clear Postfix deferred queue if stale: `postsuper -d ALL deferred`.
8. Remove identified large temporary or orphaned files.

**Do not delete files you cannot identify. Investigate first.**

## Prevention

- Configure logrotate with size limits and retention policies for all services
- Set `expire_logs_days` in MariaDB configuration
- Schedule regular cleanup of `/tmp`, `/var/tmp`, and apt cache
- Monitor disk usage trends and set alerts at multiple thresholds (20%, 10%, 5%)
- Ensure backups are stored off-server or cleaned after transfer
