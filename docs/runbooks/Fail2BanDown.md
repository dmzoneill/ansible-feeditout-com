# Fail2BanDown

**Alert:** `node_systemd_unit_state{name="fail2ban.service", state="active"} != 1`

**Severity:** Critical

## Description

Fail2ban intrusion prevention service is down. While this does not cause an immediate outage, it leaves the server exposed to brute-force attacks on SSH (port 33), SMTP, Apache, and other services. Existing bans are lost when fail2ban stops, so previously blocked attackers can resume immediately.

## Possible Causes

- Configuration syntax error in `/etc/fail2ban/jail.local` or a filter file
- Python error or incompatibility after package upgrade
- Log file referenced in a jail does not exist or is unreadable
- Backend issue (systemd journal backend or pyinotify)
- Socket file conflict or stale PID file
- iptables/nftables chain conflict preventing ban actions

## Investigation

```bash
# Service status
systemctl status fail2ban

# Journal logs
journalctl -u fail2ban --since "10 minutes ago" --no-pager

# Validate configuration
fail2ban-client -t

# Check fail2ban log
tail -50 /var/log/fail2ban.log

# Check that referenced log files exist
fail2ban-client status | grep "Jail list"

# Check firewall state
iptables -L f2b-sshd -n 2>/dev/null || nft list chain inet filter f2b-sshd 2>/dev/null

# Check for stale PID/socket
ls -la /run/fail2ban/
```

## Resolution

1. Run `fail2ban-client -t` to validate configuration; fix any syntax errors.
2. If a jail references a missing log file: disable that jail or create the log file.
3. If stale PID/socket: remove `/run/fail2ban/fail2ban.sock` and `/run/fail2ban/fail2ban.pid`.
4. If iptables chain error: flush fail2ban chains (`iptables -F f2b-sshd`) before restart.
5. Restart: `systemctl restart fail2ban`
6. Verify: `fail2ban-client status` should list active jails.
7. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t fail2ban site.yml`

## Prevention

- Always run `fail2ban-client -t` after configuration changes
- Use Ansible `fail2ban` role for all jail and filter changes
- Ensure log files referenced by jails are created by their respective services
- Monitor fail2ban status alongside the services it protects
- Use `fail2ban-client set <jail> banip <IP>` for persistent manual bans rather than direct iptables rules
