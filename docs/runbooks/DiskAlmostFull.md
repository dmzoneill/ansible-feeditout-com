# DiskAlmostFull

**Alert:** Disk free space is below 500 MB.

**Severity:** Critical

## Possible Causes

- All causes from LowDiskSpace, now at a critical threshold
- Runaway log writing (application error loop, mail delivery failure loop)
- Large database dump or import in progress
- Disk was already low and a routine operation consumed remaining space

## Investigation

```bash
# Immediate space check
df -h
df -i  # also check inodes

# Largest directories
du -sh /* 2>/dev/null | sort -rh | head -10
du -sh /var/log/* 2>/dev/null | sort -rh | head -10

# Files opened and still growing (deleted but held open)
lsof +L1 2>/dev/null | head -20

# Recently modified large files
find / -xdev -type f -size +50M -mmin -60 -exec ls -lh {} \; 2>/dev/null

# Check for deleted-but-open files consuming space
lsof / | grep deleted | sort -k7 -rn | head -10
```

## Resolution

**Act immediately -- services will fail when disk reaches 0%.**

1. Quick wins to free space now:
   - `journalctl --vacuum-size=200M`
   - `apt-get clean`
   - `> /var/log/apache2/access.log` (truncate, do not delete, to avoid breaking logrotate)
   - `find /tmp -type f -atime +1 -delete`
2. If `lsof` shows deleted-but-open files holding space, restart the owning process to release them.
3. If MariaDB binary logs are large: `PURGE BINARY LOGS BEFORE NOW() - INTERVAL 1 DAY;`.
4. Move large files to another volume or off-server if deletion is not safe.
5. Once space is recovered, investigate and address the root cause (see LowDiskSpace runbook).

## Prevention

- Set up tiered alerting (20%, 10%, 5%, 500MB) to catch problems early
- Automate log rotation and retention policies
- Monitor for deleted-but-open files as part of regular checks
- Ensure sufficient disk provisioning with growth headroom
- Keep LowDiskSpace runbook procedures current
