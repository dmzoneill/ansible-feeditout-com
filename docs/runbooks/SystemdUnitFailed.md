# SystemdUnitFailed

## Description

One or more systemd units are in a `failed` state. This means a service, timer, mount, or other unit has crashed, failed to start, or exited with an error. Critical services (Apache, MariaDB, Redis, Postfix, Prometheus) in failed state directly impact availability.

## Severity

**Critical**

## Possible Causes

- Service crashed due to a bug or resource exhaustion
- Configuration error after a change (syntax error, missing file)
- Dependency service unavailable (e.g., MariaDB down causing app failure)
- Disk full preventing service from writing logs or data
- Permission change breaking service access to files or sockets
- Failed systemd timer (backup job, certbot renewal, log rotation)
- OOM killer terminated the process

## Investigation

```bash
# List all failed units
systemctl --failed

# Get detailed status of a specific failed unit
systemctl status <unit-name>

# Check journal logs for the failed unit
journalctl -u <unit-name> --since "1 hour ago" --no-pager

# Check for common critical services
for svc in apache2 mariadb redis-server postfix prometheus alertmanager grafana-server; do
  status=$(systemctl is-active $svc 2>/dev/null)
  echo "$svc: $status"
done

# Check if OOM killed the process
dmesg -T | grep -i "oom.*$(systemctl show -p MainPID <unit-name> --value)"

# Check disk space (common cause of failures)
df -h

# Check for configuration errors
apache2ctl configtest 2>&1
mysql --help --verbose 2>&1 | tail -5
redis-cli ping

# Check permissions on service files
systemctl cat <unit-name> | head -20
```

## Resolution

1. **Check logs first** to understand why the unit failed:
   ```bash
   journalctl -u <unit-name> -n 50 --no-pager
   ```

2. **Fix the root cause** (config error, disk space, permissions, etc.).

3. **Reset the failed state and restart**:
   ```bash
   systemctl reset-failed <unit-name>
   systemctl start <unit-name>
   ```

4. **If a timer failed**, check the timer and associated service:
   ```bash
   systemctl status <timer-name>.timer
   systemctl status <timer-name>.service
   journalctl -u <timer-name>.service --since "1 hour ago"
   ```

5. **If the service keeps crashing**, check for resource limits:
   ```bash
   systemctl show <unit-name> | grep -E "Limit|Restart"
   ```

6. **Verify recovery**:
   ```bash
   systemctl is-active <unit-name>
   systemctl --failed  # Should no longer list the unit
   ```

## Prevention

- Configure `Restart=on-failure` with `RestartSec=5s` in critical service units
- Set `StartLimitIntervalSec` and `StartLimitBurst` to prevent restart loops
- Use `systemctl edit` for overrides rather than modifying packaged unit files
- Test configuration changes before restarting services (`apache2ctl configtest`, `postconf check`)
- Monitor disk space to prevent full-disk failures
- Set up log rotation to prevent log files from filling disks
