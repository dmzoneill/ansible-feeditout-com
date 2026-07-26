# Apache2Down

**Alert:** `node_systemd_unit_state{name="apache2.service", state="active"} != 1`

**Severity:** Critical

## Description

The Apache2 web server is down. This directly impacts all HTTP/HTTPS traffic for feeditout.com. Ports 80 and 443 are unreachable, meaning all websites, virtual hosts, and any reverse-proxied services are offline.

## Possible Causes

- Configuration syntax error after a change (`apache2ctl configtest` would fail)
- Port conflict -- another process bound to port 80 or 443
- SSL certificate issue (expired, missing, or corrupt cert file)
- Ran out of file descriptors or worker processes
- Module loading failure (missing `.so` file after package upgrade)
- Disk full preventing log writes or PID file creation
- PHP-FPM socket unavailable causing cascading failure
- OOM killer terminated Apache workers

## Investigation

```bash
# Service status and recent failure reason
systemctl status apache2

# Journal logs for the crash
journalctl -u apache2 --since "10 minutes ago" --no-pager

# Validate configuration
apache2ctl configtest

# Check if ports 80/443 are in use by something else
ss -tlnp | grep -E ':80|:443'

# Check disk space (logs can fill disks)
df -h /var/log/apache2

# Check for OOM kills
dmesg | grep -i "oom\|killed"

# Test SSL certificate readability
openssl x509 -in /etc/letsencrypt/live/feeditout.com/fullchain.pem -noout -dates 2>&1

# Check PHP-FPM socket availability
systemctl status php*-fpm
ls -la /run/php/
```

## Resolution

1. Run `apache2ctl configtest` -- if it reports errors, fix the configuration.
2. If port conflict: identify the conflicting process with `ss -tlnp` and stop it.
3. If SSL issue: check cert paths in vhost configs and verify certs exist and are readable.
4. If disk full: rotate or truncate logs (`truncate -s 0 /var/log/apache2/error.log`), then restart.
5. If PHP-FPM is down: restart PHP-FPM first (`systemctl restart php*-fpm`).
6. Restart Apache: `systemctl restart apache2`
7. Verify: `curl -sI http://localhost` and `curl -sI https://localhost`
8. If configuration is badly broken, restore from Ansible: `cd /opt/ansible && ansible-playbook -t apache2 site.yml`

## Prevention

- Always run `apache2ctl configtest` before restarting after config changes
- Use Ansible `apache2` role for all vhost and module changes
- Set up log rotation to prevent disk exhaustion (`/etc/logrotate.d/apache2`)
- Monitor disk usage and certificate expiry with separate alerts
- Set `MaxRequestWorkers` appropriately for available memory
