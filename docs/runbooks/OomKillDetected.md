# OomKillDetected

## Description

The Linux OOM (Out of Memory) killer has terminated one or more processes because the system ran out of available memory. This is a last-resort kernel mechanism to prevent a complete system hang.

## Severity

**Critical**

## Possible Causes

- Memory leak in an application (Apache, MariaDB, Redis, PHP-FPM)
- Insufficient physical RAM for the workload
- Redis maxmemory not configured or set too high
- MariaDB `innodb_buffer_pool_size` over-provisioned relative to available RAM
- Runaway cron job or background process consuming excessive memory
- Swap disabled or undersized

## Investigation

```bash
# Check which process was killed (most recent)
dmesg -T | grep -i "oom-killer\|out of memory" | tail -20

# Check system journal for OOM events
journalctl -k --since "1 hour ago" | grep -i oom

# Current memory usage overview
free -h

# Top memory consumers
ps aux --sort=-%mem | head -20

# Check if swap is enabled and usage
swapon --show
cat /proc/swaps

# Check per-process memory usage in detail
smem -tk 2>/dev/null || ps -eo pid,user,rss,vsize,comm --sort=-rss | head -20

# Check MariaDB memory usage
mysqladmin -u root status
mysql -u root -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';"

# Check Redis memory usage
redis-cli info memory | grep -E "used_memory_human|maxmemory_human"

# Check Apache memory usage
systemctl status apache2
ps aux | grep apache2 | awk '{sum+=$6} END {print "Total Apache RSS (KB):", sum}'

# Check cgroup memory limits if applicable
cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null
```

## Resolution

1. **Identify the killed process** from `dmesg` output and restart it if needed:
   ```bash
   systemctl restart apache2    # or mariadb, redis, etc.
   ```

2. **If MariaDB was killed**, check data integrity:
   ```bash
   systemctl start mariadb
   journalctl -u mariadb --since "10 minutes ago"
   mysqlcheck --all-databases --auto-repair
   ```

3. **Reduce memory pressure immediately**:
   - Clear filesystem caches: `sync && echo 3 > /proc/sys/vm/drop_caches`
   - Restart non-essential services

4. **Tune the offending service**:
   - MariaDB: Lower `innodb_buffer_pool_size` in `/etc/mysql/mariadb.conf.d/`
   - Redis: Set `maxmemory` and `maxmemory-policy` in `/etc/redis/redis.conf`
   - Apache: Reduce `MaxRequestWorkers` in mpm config

5. **If recurring**, add swap or increase RAM.

## Prevention

- Set appropriate `maxmemory` for Redis with an eviction policy
- Size MariaDB buffer pool to no more than 50-70% of available RAM
- Configure Apache `MaxRequestWorkers` based on available memory
- Enable and size swap appropriately (at least 1x RAM for small servers)
- Use systemd `MemoryMax=` directives to cap service memory
- Set up the MemoryPressureHigh alert to catch issues before OOM
