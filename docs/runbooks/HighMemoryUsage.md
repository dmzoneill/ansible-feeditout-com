# HighMemoryUsage

**Alert:** Memory usage exceeds 95% for more than 2 minutes.

**Severity:** Warning

## Possible Causes

- Memory leak in Apache/PHP-FPM workers
- MariaDB buffer pool or query cache sized too large for available RAM
- Redis dataset exceeding expected size or `maxmemory` not set
- OOM killer not yet triggered but system is thrashing
- Too many Apache/PHP-FPM workers spawned under load
- Backup process or log processing consuming excessive memory

## Investigation

```bash
# Overall memory and swap usage
free -h

# Top memory consumers
ps aux --sort=-%mem | head -20

# Detailed memory breakdown
cat /proc/meminfo

# Check for OOM killer activity
dmesg | grep -i "out of memory"
journalctl -k --since "1 hour ago" | grep -i oom

# MariaDB memory usage
mysql -e "SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool%';"
mysql -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';"

# Redis memory usage
redis-cli INFO memory | grep -E "used_memory_human|maxmemory_human"

# Apache/PHP-FPM worker memory
ps -C apache2 -o pid,rss,vsz,comm --sort=-rss | head -20
```

## Resolution

1. Identify the largest memory consumers from `ps` output.
2. If Apache/PHP-FPM: restart the service to reclaim leaked memory (`systemctl restart apache2`). Reduce `MaxRequestWorkers` or `pm.max_children`.
3. If MariaDB: tune `innodb_buffer_pool_size` to no more than 50-60% of total RAM. Flush query cache if oversized.
4. If Redis: check `maxmemory` policy is set; evict keys or increase `maxmemory` if appropriate.
5. Clear OS page cache if it is not being reclaimed: `sync && echo 3 > /proc/sys/vm/drop_caches` (temporary measure).
6. If OOM killer has fired, check which process was killed and restart it.

## Prevention

- Set `MaxRequestWorkers` and `pm.max_children` appropriate to available RAM
- Configure Redis `maxmemory` and eviction policy
- Size MariaDB `innodb_buffer_pool_size` appropriately (50-60% of total RAM)
- Set `MaxConnectionsPerChild` in Apache to recycle workers periodically
- Monitor memory trends and plan capacity upgrades before hitting limits
