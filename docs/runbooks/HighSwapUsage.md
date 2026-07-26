# HighSwapUsage

**Alert:** Swap usage exceeds 60%.

**Severity:** Warning

## Possible Causes

- Insufficient physical RAM for running workload
- Memory leak in Apache/PHP-FPM, MariaDB, or another service
- MariaDB buffer pool oversized relative to available RAM
- Redis dataset exceeding available memory
- Multiple services competing for limited RAM
- vm.swappiness set too high, encouraging premature swapping

## Investigation

```bash
# Check swap and memory usage
free -h
swapon --show

# Identify which processes are using swap
for pid in /proc/[0-9]*; do
  awk '/VmSwap/{printf "%s %s KB %s\n", "'${pid##*/}'", $2, FILENAME}' $pid/status 2>/dev/null
done | sort -k2 -rn | head -20

# Alternative: per-process swap usage
smem -rs swap 2>/dev/null | head -20

# Check current swappiness
cat /proc/sys/vm/swappiness

# Check which processes are using the most memory
ps aux --sort=-%mem | head -20

# Check for OOM pressure
dmesg | grep -i "out of memory" | tail -5

# MariaDB memory configuration
mysql -e "SHOW VARIABLES LIKE '%buffer_pool_size%';"
```

## Resolution

1. Identify processes consuming swap from investigation commands.
2. Restart memory-leaking services to reclaim swap: `systemctl restart apache2`.
3. Reduce MariaDB `innodb_buffer_pool_size` if oversized.
4. Set Redis `maxmemory` if not configured.
5. Lower swappiness if too aggressive: `sysctl vm.swappiness=10`.
6. If workload legitimately requires more RAM, plan a memory upgrade.
7. As a temporary measure, clear swap (only if RAM can absorb it): `swapoff -a && swapon -a`.

## Prevention

- Right-size service memory configurations for available RAM
- Set `vm.swappiness=10` in `/etc/sysctl.d/` for server workloads
- Configure `MaxConnectionsPerChild` in Apache to recycle workers
- Set `maxmemory` and eviction policy in Redis
- Monitor memory trends and plan capacity before hitting limits
