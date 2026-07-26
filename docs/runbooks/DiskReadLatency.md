# DiskReadLatency

**Alert:** Disk read latency exceeds 100ms.

**Severity:** Warning

## Possible Causes

- Disk hardware degradation or imminent failure
- Heavy concurrent read I/O saturating the disk
- RAID array degraded and rebuilding
- Filesystem fragmentation (HDD)
- Insufficient I/O scheduler tuning for workload
- Virtualisation layer storage contention
- SAN/NAS latency issues (if using network storage)
- Swap thrashing causing excessive disk reads

## Investigation

```bash
# Check disk latency and utilisation
iostat -xz 1 5

# Look at await (average wait time) and r_await (read wait time)
iostat -xz -p ALL 1 3

# Check for disk errors in kernel log
dmesg | grep -i -E "error|fail|reset|timeout" | grep -i -E "sd|ata|scsi" | tail -20

# Check SMART health (if physical disk)
smartctl -a /dev/sda 2>/dev/null | grep -E "Reallocated|Pending|Uncorrect|Temperature"

# Check RAID status
cat /proc/mdstat 2>/dev/null
mdadm --detail /dev/md* 2>/dev/null

# Identify processes doing most reads
iotop -bn1 -o 2>/dev/null | head -15

# Check if swapping is contributing
vmstat 1 5

# Check I/O scheduler
cat /sys/block/sda/queue/scheduler 2>/dev/null
```

## Resolution

1. Check `iostat` output: if `%util` is high alongside latency, the disk is saturated.
2. If disk errors in `dmesg` or SMART warnings: plan disk replacement immediately. Back up data.
3. If RAID degraded: replace failed drive, monitor rebuild progress.
4. If saturated by a specific process: throttle or reschedule it (see HighDiskIO runbook).
5. If swapping: address memory pressure (see HighSwapUsage runbook).
6. Tune I/O scheduler if needed: `echo mq-deadline > /sys/block/sda/queue/scheduler` for database workloads.
7. If virtualised: check hypervisor storage latency and contention with other VMs.

## Prevention

- Monitor SMART attributes and replace disks proactively
- Use SSDs for latency-sensitive workloads (database, mail spool)
- Ensure RAID arrays have hot spares configured
- Tune I/O scheduler for the workload profile
- Avoid placing heavy-read and heavy-write workloads on the same physical disk
- Ensure adequate RAM to minimise disk reads (filesystem cache, buffer pool)
