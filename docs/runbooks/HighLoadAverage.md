# HighLoadAverage

**Alert:** System load average exceeds 1.5x the number of CPUs.

**Severity:** Warning

## Possible Causes

- High CPU usage from Apache/PHP, MariaDB, or batch jobs
- I/O wait from disk saturation (processes blocked on disk)
- Too many processes in uninterruptible sleep (D state)
- Fork bomb or runaway process spawning
- Network I/O stalls causing process accumulation
- Insufficient CPUs for the workload

## Investigation

```bash
# Check load average and CPU count
uptime
nproc

# Breakdown: is it CPU, I/O, or process count?
vmstat 1 5

# Check for processes in D (uninterruptible sleep) state
ps aux | awk '$8 ~ /D/ {print}'

# Top CPU and I/O consumers
top -bn1 -o %CPU | head -20
iotop -bn1 -o 2>/dev/null | head -20

# Check I/O wait percentage
iostat -x 1 3

# Count running processes
ps -eo state | sort | uniq -c | sort -rn

# Check Apache worker count
ps -C apache2 --no-headers | wc -l

# Check for fork storms
ps -ef | awk '{print $3}' | sort | uniq -c | sort -rn | head -10
```

## Resolution

1. Determine if load is CPU-bound, I/O-bound, or process-count-bound using `vmstat` (check `us`, `sy`, `wa` columns).
2. If CPU-bound: see HighCpuUsage runbook. Identify and address the offending process.
3. If I/O-bound (`wa` is high): see HighDiskIO runbook. Check for backup jobs, heavy queries, or swap thrashing.
4. If many D-state processes: investigate the blocking resource (NFS mount, disk failure, network storage).
5. If Apache workers are excessive: reduce `MaxRequestWorkers` and restart.
6. If fork storm: identify the parent process and kill the tree (`kill -9 -<PGID>`).

## Prevention

- Right-size `MaxRequestWorkers` and `pm.max_children` for available CPUs and RAM
- Schedule batch jobs with `nice` and `ionice` to reduce contention
- Monitor I/O wait as a separate metric alongside load average
- Ensure NFS mounts use `soft` and `timeo` options to avoid indefinite hangs
- Plan CPU capacity based on workload growth trends
