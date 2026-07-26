# MemoryPressureHigh

## Description

The system is experiencing more than 100 major page faults per second. Major page faults occur when a process accesses memory that must be read from disk (swap), indicating the system is under significant memory pressure and actively swapping.

## Severity

**Warning**

## Possible Causes

- Physical memory overcommitted by running services
- Memory leak causing gradual exhaustion
- Large dataset being processed in memory (database queries, log processing)
- Swap being used as primary memory extension
- MariaDB or Redis working set exceeds available RAM
- Apache/PHP-FPM spawning too many worker processes

## Investigation

```bash
# Check current memory and swap usage
free -h

# Check swap activity (si/so columns show swap in/out per second)
vmstat 1 5

# Check major page faults per process
ps -eo pid,user,maj_flt,min_flt,rss,comm --sort=-maj_flt | head -20

# Monitor page faults in real time
sar -B 1 10

# Check which processes are using swap
for pid in /proc/[0-9]*; do
  name=$(cat $pid/comm 2>/dev/null)
  swap=$(awk '/VmSwap/{print $2}' $pid/status 2>/dev/null)
  [ -n "$swap" ] && [ "$swap" -gt 0 ] && echo "$swap kB - $name (PID $(basename $pid))"
done | sort -rn | head -20

# Check I/O wait (high wa% indicates disk bottleneck from swapping)
top -bn1 | head -5

# Check MariaDB buffer pool usage
mysql -u root -e "SHOW ENGINE INNODB STATUS\G" | grep -A5 "BUFFER POOL AND MEMORY"

# Check Redis memory
redis-cli info memory
```

## Resolution

1. **Identify the source** of memory pressure from the investigation commands above.

2. **Reduce immediate pressure**:
   ```bash
   # Clear page cache if filesystem cache is the issue
   sync && echo 1 > /proc/sys/vm/drop_caches
   ```

3. **Tune services**:
   - Reduce Apache `MaxRequestWorkers` or switch to event MPM
   - Lower MariaDB `innodb_buffer_pool_size`
   - Set Redis `maxmemory` with a suitable eviction policy
   - Reduce PHP-FPM `pm.max_children`

4. **Adjust swappiness** if swap is being used too aggressively:
   ```bash
   # Check current value
   cat /proc/sys/vm/swappiness
   # Reduce (persistent via /etc/sysctl.conf)
   sysctl vm.swappiness=10
   ```

5. **If persistent**, plan to add more RAM or migrate workloads.

## Prevention

- Size services to fit within available RAM with headroom
- Monitor memory trends in Grafana to catch gradual leaks
- Set `vm.swappiness=10` for database workloads
- Use systemd `MemoryHigh=` and `MemoryMax=` to prevent runaway processes
- Schedule memory-intensive jobs (backups, reports) during off-peak hours
