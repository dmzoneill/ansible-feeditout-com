# PostfixMainDown

**Alert:** `node_systemd_unit_state{name="postfix.service", state="active"} != 1`

**Severity:** Critical

## Description

The Postfix mail server main instance is down. This affects all inbound and outbound email for feeditout.com. SMTP ports 25 (inbound mail), 465 (SMTPS), and 587 (submission) are no longer accepting connections. Mail will queue on remote servers temporarily, but prolonged downtime risks bounced messages.

## Possible Causes

- Configuration syntax error in `main.cf` or `master.cf`
- Port conflict on 25, 465, or 587
- TLS certificate issue (expired or missing cert referenced in config)
- Disk full preventing mail queue writes (`/var/spool/postfix`)
- DNS resolution failure (Postfix cannot resolve its own hostname)
- Milter connection failure (OpenDKIM, OpenDMARC, ClamAV milter, SpamAssassin)
- Chroot environment broken after package upgrade
- PostSRSd dependency failure

## Investigation

```bash
# Service status
systemctl status postfix

# Journal logs
journalctl -u postfix --since "10 minutes ago" --no-pager

# Validate configuration
postfix check

# Check SMTP ports
ss -tlnp | grep -E ':25|:465|:587'

# Check mail queue
mailq | tail -5

# Check disk space on mail spool
df -h /var/spool/postfix

# Check dependent services
systemctl status opendkim opendmarc clamav-milter postsrsd

# Test DNS resolution
postconf myhostname
host $(postconf -h myhostname)
```

## Resolution

1. Run `postfix check` to validate configuration; fix any reported errors.
2. If milter dependency: restart the failing milter service, then restart Postfix.
3. If disk full: clear deferred/bounced mail (`postsuper -d ALL deferred`) and free disk space.
4. If TLS cert issue: verify cert paths in `main.cf` (`smtpd_tls_cert_file`, `smtpd_tls_key_file`).
5. If DNS issue: check `/etc/resolv.conf` and test resolution.
6. Restart Postfix: `systemctl restart postfix`
7. Verify: `echo "test" | mail -s "test" root` and check `mailq`.
8. For persistent issues, re-run Ansible: `cd /opt/ansible && ansible-playbook -t postfix site.yml`

## Prevention

- Always run `postfix check` after configuration changes
- Monitor disk usage on `/var/spool/postfix` to prevent queue disk exhaustion
- Set up mail queue size alerts
- Use Ansible `postfix` role for all configuration changes
- Monitor dependent milter services (OpenDKIM, OpenDMARC, ClamAV) with their own alerts
