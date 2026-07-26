# RedisServerDown

**Alert:** `node_systemd_unit_state{name="redis-server.service", state="active"} != 1`

**Severity:** Critical

## Description

Redis cache server is down on port 6379. This affects application caching, session storage, and any services that depend on Redis (including Webdis). Applications may experience degraded performance or errors if they cannot fall back gracefully.

## Possible Causes

- OOM killer terminated Redis (Redis is memory-hungry and a common OOM target)
- Memory limit exceeded (`maxmemory` reached with no eviction policy)
- RDB/AOF persistence failure due to disk full or permissions
- Configuration syntax error in `/etc/redis/redis.conf`
- Background save (`BGSAVE`) fork failure due to overcommit settings
- Corrupted AOF file preventing startup
- Socket/PID file permission issue after reboot

## Investigation

```bash
# Service status
systemctl status redis-server

# Journal logs
journalctl -u redis-server --since "10 minutes ago" --no-pager

# Check Redis log
tail -50 /var/log/redis/redis-server.log

# Check memory
free -m
cat /proc/sys/vm/overcommit_memory

# Check disk space
df -h /var/lib/redis

# Check for OOM kills
dmesg | grep -i "oom\|killed" | grep -i redis

# Check port availability
ss -tlnp | grep :6379
```

## Resolution

1. Check Redis log for the specific failure reason.
2. If OOM: ensure `vm.overcommit_memory = 1` is set (`sysctl vm.overcommit_memory=1`); reduce `maxmemory` if needed.
3. If disk full: free space, then restart.
4. If corrupted AOF: run `redis-check-aof --fix /var/lib/redis/appendonly.aof`.
5. If RDB save failure: check `/var/lib/redis` permissions (should be `redis:redis`).
6. Restart: `systemctl restart redis-server`
7. Verify: `redis-cli ping` should return `PONG`.
8. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t redis site.yml`

## Prevention

- Set `maxmemory` with an appropriate eviction policy (`allkeys-lru`)
- Set `vm.overcommit_memory = 1` in sysctl to prevent fork failures
- Monitor Redis memory usage via `redis-cli info memory`
- Use Ansible `redis` role for configuration changes
- Monitor disk usage on `/var/lib/redis`
