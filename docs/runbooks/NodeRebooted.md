# NodeRebooted

**Alert:** System uptime is less than 2 minutes (node has rebooted).

**Severity:** Info

## Possible Causes

- Planned reboot after package/kernel update
- Unplanned reboot due to kernel panic or hardware failure
- OOM killer triggered a critical process, leading to system instability
- Power loss or hypervisor-initiated restart
- Watchdog timer triggered reboot
- Manual reboot by an administrator

## Investigation

```bash
# Check current uptime
uptime

# Check reboot history
last reboot | head -10
who -b

# Check for kernel panic or crash before reboot
journalctl -b -1 -p err --no-pager 2>/dev/null | tail -30

# Check if reboot was initiated by a user
journalctl -b -1 | grep -i -E "shutdown|reboot|halt" | tail -10
last -x shutdown reboot | head -10

# Check for OOM events before reboot
journalctl -b -1 | grep -i "out of memory" 2>/dev/null

# Verify all services are running after reboot
systemctl --failed
systemctl is-active apache2 mariadb postfix redis-server

# Check for pending package updates (was this a planned reboot?)
cat /var/run/reboot-required 2>/dev/null
```

## Resolution

1. If planned reboot: verify all services are running (`systemctl --failed`).
2. Restart any failed services: `systemctl start <service>`.
3. If unplanned: check previous boot journal (`journalctl -b -1`) for root cause.
4. If kernel panic: check `dmesg` from previous boot and hardware error logs.
5. If OOM: address memory issues (see HighMemoryUsage runbook).
6. Verify application health checks pass (HTTP endpoints, mail delivery, database connectivity).
7. Document the reboot cause in the incident log.

## Prevention

- Schedule planned reboots during maintenance windows
- Enable `kdump` for kernel crash analysis
- Configure OOM killer priorities to protect critical services
- Use UPS for power protection and configure graceful shutdown
- Monitor and alert on pre-reboot conditions (memory pressure, kernel errors)
