# MariadbDown

**Alert:** `node_systemd_unit_state{name="mariadb.service", state="active"} != 1`

**Severity:** Critical

## Description

MariaDB database server is down on port 3306. This impacts all applications depending on the database, including WordPress sites and any other web applications on feeditout.com. Apache/PHP will return 500 errors for database-backed pages.

## Possible Causes

- InnoDB crash recovery failure (corrupted tablespace or redo log)
- Disk full preventing writes to data directory or tmp
- OOM killer terminated mysqld
- Configuration error in `/etc/mysql/` after a change
- Corrupted or missing system tables
- Exceeded `max_connections` causing connection storm on restart
- Socket file or PID file permissions issue
- Package upgrade requiring table upgrade (`mysql_upgrade`)

## Investigation

```bash
# Service status
systemctl status mariadb

# Journal logs -- MariaDB logs extensively on crash
journalctl -u mariadb --since "10 minutes ago" --no-pager

# Check MariaDB error log
tail -50 /var/log/mysql/error.log

# Check disk space on data directory
df -h /var/lib/mysql

# Check for OOM kills
dmesg | grep -i "oom\|killed" | grep -i mysql

# Check if port is in use
ss -tlnp | grep :3306

# Check data directory permissions
ls -la /var/lib/mysql/
ls -la /run/mysqld/
```

## Resolution

1. Read the error log (`/var/log/mysql/error.log`) for the root cause.
2. If disk full: free space on the data partition, remove old binary logs if enabled (`PURGE BINARY LOGS BEFORE NOW() - INTERVAL 7 DAY;`).
3. If OOM: check if `innodb_buffer_pool_size` is too large for available memory; reduce it.
4. If InnoDB corruption: try starting with `innodb_force_recovery=1` in `/etc/mysql/mariadb.conf.d/50-server.cnf`, dump data, then reinitialize.
5. If permissions: ensure `/run/mysqld/` exists and is owned by `mysql:mysql`.
6. Restart: `systemctl restart mariadb`
7. Verify: `mysql -e "SELECT 1;"` and `mysql -e "SHOW DATABASES;"`
8. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t mysql site.yml`

## Prevention

- Monitor disk usage on `/var/lib/mysql` to prevent data directory from filling
- Set `innodb_buffer_pool_size` to no more than 50-70% of available RAM
- Enable slow query log and review periodically
- Set up regular database backups and test restores
- Use Ansible `mysql` role for all configuration changes
