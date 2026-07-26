# ClockDriftDetected

## Description

System clock offset exceeds 50ms from the NTP reference. Clock drift can cause TLS certificate validation failures, log correlation issues, cron job mistiming, database replication problems, and Prometheus metric timestamp errors.

## Severity

**Warning**

## Possible Causes

- NTP daemon (chrony/systemd-timesyncd) not running or misconfigured
- Firewall blocking NTP traffic (UDP port 123)
- Unreachable or overloaded NTP servers
- VM clock skew (hypervisor not providing accurate time)
- Hardware clock (RTC) drifting significantly
- High system load causing NTP processing delays

## Investigation

```bash
# Check which NTP service is running
systemctl status chronyd 2>/dev/null || systemctl status systemd-timesyncd 2>/dev/null

# If chrony: check synchronization status
chronyc tracking 2>/dev/null
chronyc sources -v 2>/dev/null

# If systemd-timesyncd: check status
timedatectl status
timedatectl timesync-status 2>/dev/null

# Check current offset
chronyc tracking 2>/dev/null | grep "System time"

# Check if NTP port is reachable
nc -zu pool.ntp.org 123 && echo "NTP reachable" || echo "NTP blocked"

# Check firewall rules for NTP
iptables -L -n | grep 123

# Check hardware clock vs system clock
hwclock --show
date -u

# Check system load (high load can delay NTP)
uptime
```

## Resolution

1. **If NTP service is stopped**, start it:
   ```bash
   systemctl enable --now chronyd
   # or
   systemctl enable --now systemd-timesyncd
   ```

2. **Force immediate sync** with chrony:
   ```bash
   chronyc makestep
   ```

3. **If NTP servers are unreachable**, check and fix firewall:
   ```bash
   iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
   iptables -A INPUT -p udp --sport 123 -j ACCEPT
   ```

4. **If NTP servers are overloaded**, configure closer/more reliable servers in `/etc/chrony/chrony.conf`:
   ```
   server 0.debian.pool.ntp.org iburst
   server 1.debian.pool.ntp.org iburst
   ```
   Then restart: `systemctl restart chronyd`

5. **On VMs**, ensure hypervisor time sync is enabled or disable it in favor of NTP if it conflicts.

## Prevention

- Use chrony (preferred over ntpd for modern systems)
- Configure at least 3 NTP sources for redundancy
- Use `iburst` option for faster initial sync after reboot
- Ensure NTP traffic is allowed through firewalls
- Monitor clock offset trends in Grafana
- Set `makestep 1 3` in chrony.conf to allow large corrections on startup
