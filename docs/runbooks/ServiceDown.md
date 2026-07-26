# ServiceDown

**Alert:** A systemd service is not in the `active` state (`node_systemd_unit_state{state="active"} != 1`).

**Severity:** Critical

## Description

This is the generic pattern used by all service-down alerts on feeditout.com. Each monitored service has a Prometheus alert rule that watches `node_systemd_unit_state` via node_exporter. When the unit leaves the `active` state for more than 10 seconds, an alert fires. The alert annotation includes the unit name and current state.

## Possible Causes

- Service crashed or was killed (OOM, segfault, unhandled exception)
- Service was manually stopped
- Failed dependency (a required mount, socket, or prerequisite service is down)
- Configuration error after a change (syntax error, missing file, bad permissions)
- Package upgrade left the service in a failed state
- Resource exhaustion (disk full, out of memory, file descriptor limit)
- Ansible run disabled or stopped the service

## Investigation

```bash
# Check the service status (replace <unit> with the service name from the alert)
systemctl status <unit>

# View recent journal logs for the service
journalctl -u <unit> --since "10 minutes ago" --no-pager

# Check if the service is masked or disabled
systemctl is-enabled <unit>

# List failed units across the system
systemctl --failed

# Check for resource issues
df -h
free -m
dmesg | tail -30

# Check if Ansible recently ran and changed something
journalctl -u ansible-pull --since "1 hour ago" --no-pager
```

## Resolution

1. Read the `systemctl status` and `journalctl` output to determine why the service stopped.
2. If configuration error: fix the config, validate it (most services have a config-test flag), then restart.
3. If resource exhaustion: free disk space or memory, then restart the service.
4. If dependency failure: resolve the upstream dependency first, then restart.
5. Restart the service: `systemctl restart <unit>`
6. Verify it is running: `systemctl is-active <unit>`
7. If the service keeps crashing, check for core dumps: `coredumpctl list`
8. For persistent issues, re-run the Ansible role from `/opt/ansible` to restore known-good configuration.

## Prevention

- Use Ansible roles in `/opt/ansible` for all configuration changes to ensure consistency
- Set appropriate resource limits in systemd unit files (`MemoryMax`, `LimitNOFILE`)
- Monitor disk and memory usage with separate alerts to catch exhaustion early
- Test configuration changes with the service's built-in validation before restarting
- Keep packages updated and review changelogs before upgrades
