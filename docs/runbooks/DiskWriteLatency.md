# DiskWriteLatency

**Alert:** Disk write latency exceeds 100ms.

**Severity:** Warning

## Possible Causes

- Disk hardware degradation or imminent failure
- Heavy concurrent write I/O saturating the disk
- RAID array degraded and rebuilding
- Filesystem journal contention
- Write-back cache disabled or full (battery-backed cache failure)
- MariaDB or Postfix performing heavy synchronous writes
- Virtualisation layer storage contention
- SAN/NAS latency issues (if using network storage)

## Investigation

```bash
# Check disk latency and utilisation
iostat -xz 1 5

# Look at await and w_await (write wait time) columns
iostat -xz -p ALL 1 3

# Check for disk errors in kernel log
dmesg | grep -i -E "error|fail|reset|timeout" | grep -i -E "sd|ata|scsi" | tail -20

# Check SMART health
smartctl -a /dev/sda 2>/dev/null | grep -E "Reallocated|Pending|Uncorrect|Temperature"

# Identify processes doing most writes
iotop -bn1 -o 2>/dev/null | head -15

# Check RAID status
cat /proc/mdstat 2>/dev/null

# Check filesystem mount options (barrier/journal settings)
mount | grep -E "ext4|xfs"

# MariaDB write activity
mysql -e "SHOW GLOBAL STATUS LIKE 'Innodb_data_written';"
mysql -e "SHOW GLOBAL STATUS LIKE 'Innodb_os_log_written';"

# Check I/O scheduler
cat /sys/block/sda/queue/scheduler 2>/dev/null
```

## Resolution

1. Check `iostat` output: if `%util` is near 100% with high `w_await`, the disk is write-saturated.
2. If disk errors in `dmesg` or SMART warnings: plan disk replacement immediately. Back up data.
3. If RAID degraded: replace failed drive, monitor rebuild.
4. If MariaDB is the heaviest writer: tune `innodb_flush_log_at_trx_commit` (set to `2` for better performance with acceptable crash risk), check `innodb_io_capacity`.
5. If log writes: ensure log rotation is functioning, reduce log verbosity.
6. Tune I/O scheduler: `echo mq-deadline > /sys/block/sda/queue/scheduler`.
7. If virtualised: check hypervisor storage contention and I/O limits.

## Prevention

- Monitor SMART attributes and replace disks proactively
- Use SSDs for write-intensive workloads (database, mail spool)
- Tune MariaDB `innodb_flush_log_at_trx_commit` and `innodb_io_capacity` for the storage
- Separate database, logs, and mail spool onto different disks/volumes where possible
- Ensure RAID write-back cache battery is healthy
- Keep filesystems below 80% capacity to reduce fragmentation impact
