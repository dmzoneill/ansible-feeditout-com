# ClamavDaemonDown

**Alert:** `node_systemd_unit_state{name="clamav-daemon.service", state="active"} != 1`

**Severity:** Critical

## Description

The ClamAV antivirus daemon (`clamd`) is down. This affects real-time virus scanning of email via the ClamAV milter integration with Postfix. Inbound email will not be scanned for malware. Depending on Postfix milter configuration, mail delivery may also be blocked if the milter is configured as required rather than optional.

## Possible Causes

- Virus database not yet downloaded (freshclam has not completed initial update)
- Insufficient memory (ClamAV loads the entire virus database into RAM, typically 1-1.5 GB)
- OOM killer terminated clamd
- Corrupted virus database files in `/var/lib/clamav/`
- Socket file permissions issue (`/run/clamav/clamd.ctl`)
- Freshclam service down, leading to stale or missing database
- Configuration error in `/etc/clamav/clamd.conf`

## Investigation

```bash
# Service status
systemctl status clamav-daemon

# Journal logs
journalctl -u clamav-daemon --since "10 minutes ago" --no-pager

# Check ClamAV log
tail -50 /var/log/clamav/clamav.log

# Check freshclam status (database updater)
systemctl status clamav-freshclam

# Check database files exist and are recent
ls -la /var/lib/clamav/

# Check memory (ClamAV is memory-heavy)
free -m

# Check for OOM kills
dmesg | grep -i "oom\|killed" | grep -i clam

# Check socket
ls -la /run/clamav/clamd.ctl
```

## Resolution

1. Check if freshclam has downloaded the virus database (`ls -la /var/lib/clamav/`). If empty, run `freshclam` manually and wait for download.
2. If OOM: check if the server has enough RAM for the ClamAV database (needs ~1 GB free).
3. If corrupted database: remove files in `/var/lib/clamav/` and run `freshclam` to re-download.
4. If socket issue: ensure `/run/clamav/` exists and is owned by `clamav:clamav`.
5. Restart: `systemctl restart clamav-daemon`
6. Verify: `clamdscan --ping` or `echo PING | nc -U /run/clamav/clamd.ctl`
7. Check milter integration: `systemctl status clamav-milter`
8. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t clamav site.yml`

## Prevention

- Ensure sufficient RAM is available (ClamAV needs ~1-1.5 GB for database)
- Keep freshclam service running for automatic database updates
- Monitor both `clamav-daemon` and `clamav-freshclam` services
- Use Ansible `clamav` role for configuration changes
- Consider setting `OnAccessMaxFileSize` to limit memory impact of large file scans
