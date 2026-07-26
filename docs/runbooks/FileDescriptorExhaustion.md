# FileDescriptorExhaustion

## Description

File descriptor usage has exceeded 80% of the system or per-process allocation limit. When file descriptors are exhausted, processes cannot open files, accept network connections, or create pipes, causing service failures.

## Severity

**Critical**

## Possible Causes

- File descriptor leak in an application (unclosed files, sockets, or pipes)
- Apache or MariaDB handling too many concurrent connections
- Redis with many client connections
- Too many open log files or watch descriptors
- System-wide limit (`fs.file-max`) set too low
- Per-process limit (`ulimit -n`) too low for the workload
- Prometheus or Grafana opening many connections to targets

## Investigation

```bash
# System-wide file descriptor usage
cat /proc/sys/fs/file-nr
# Output: <allocated> <free> <max>

# System-wide limit
sysctl fs.file-max

# Top processes by open file descriptors
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
  name=$(cat /proc/$pid/comm 2>/dev/null)
  [ "$count" -gt 100 ] && echo "$count $name (PID $pid)"
done | sort -rn | head -20

# Check limits for a specific service (e.g., apache2)
pid=$(pgrep -o apache2)
cat /proc/$pid/limits 2>/dev/null | grep "open files"
ls /proc/$pid/fd 2>/dev/null | wc -l

# Check systemd service limits
systemctl show apache2 | grep LimitNOFILE
systemctl show mariadb | grep LimitNOFILE

# Check what types of FDs a process has open
ls -la /proc/<PID>/fd | awk '{print $NF}' | sed 's/.*\///' | sort | uniq -c | sort -rn | head -20

# Check for inotify watch exhaustion
sysctl fs.inotify.max_user_watches
find /proc/*/fdinfo -name '*.fdinfo' -exec grep -l inotify {} \; 2>/dev/null | head
```

## Resolution

1. **Identify the leaking process** and restart it:
   ```bash
   systemctl restart apache2  # or the offending service
   ```

2. **Increase system-wide limit** if genuinely too low:
   ```bash
   sysctl -w fs.file-max=524288
   # Persist in /etc/sysctl.d/99-file-max.conf
   ```

3. **Increase per-service limits** via systemd override:
   ```bash
   systemctl edit apache2
   # Add:
   # [Service]
   # LimitNOFILE=65536
   systemctl daemon-reload
   systemctl restart apache2
   ```

4. **If application-level leak**, identify unclosed resources:
   ```bash
   # Check what specific FDs are open
   ls -la /proc/<PID>/fd | head -50
   # Look for many sockets or pipes
   ls -la /proc/<PID>/fd | grep -c socket
   ```

5. **Fix the leak** in application code or configuration, then restart.

## Prevention

- Set appropriate `LimitNOFILE` in systemd unit files for all services
- Ensure applications properly close files and sockets in error paths
- Monitor FD usage trends per service in Grafana
- Set `fs.file-max` high enough for the workload (e.g., 524288)
- Configure connection limits in Apache (`MaxRequestWorkers`) and MariaDB (`max_connections`)
- Use connection pooling to avoid FD waste
