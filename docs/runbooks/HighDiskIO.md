# HighDiskIO

**Alert:** Disk I/O utilisation exceeds 75% for more than 2 minutes.

**Severity:** Warning

## Possible Causes

- MariaDB performing heavy queries, full table scans, or large joins
- Backup job (rsync, mysqldump, tar) saturating disk
- Log rotation or compression running
- Swapping due to memory pressure
- Postfix mail queue processing a large batch
- Filesystem check or repair running
- Apache serving large static files under heavy load

## Investigation

```bash
# Check disk I/O utilisation per device
iostat -xz 1 5

# Identify processes causing most I/O
iotop -bn1 -o | head -20

# Check if swap is being actively used (si/so columns)
vmstat 1 5

# Check for active backup processes
ps aux | grep -E "rsync|mysqldump|tar|gzip"

# MariaDB I/O status
mysql -e "SHOW GLOBAL STATUS LIKE 'Innodb_data%';"
mysql -e "SHOW GLOBAL STATUS LIKE 'Innodb_os_log%';"

# Check Postfix mail queue size
postqueue -p | tail -1

# Recent cron/systemd timer activity
journalctl -u cron --since "30 minutes ago"
systemctl list-timers --all
```

## Resolution

1. Identify the process causing high I/O from `iotop` output.
2. If backup: reschedule to off-peak hours. Use `ionice -c3` to run at idle I/O priority.
3. If MariaDB: check slow query log, kill expensive queries, add missing indexes. Consider enabling `innodb_io_capacity` tuning.
4. If swapping: address memory pressure first (see HighMemoryUsage runbook).
5. If Postfix: flush or hold the queue as appropriate (`postsuper -h ALL` to hold, investigate, then release).
6. If log rotation: ensure `compress` and `delaycompress` are set in logrotate configs.

## Prevention

- Schedule backups and heavy batch jobs during off-peak hours with `ionice -c3`
- Enable and monitor MariaDB slow query log
- Ensure adequate RAM to avoid swapping
- Use SSDs where possible for database and mail spool volumes
- Tune `innodb_io_capacity` and `innodb_io_capacity_max` for your storage
