# InodeExhaustion

**Alert:** Filesystem inode usage exceeds 95% (less than 5% free).

**Severity:** Critical

## Possible Causes

- Massive number of small files (session files, cache files, mail queue)
- PHP session files not being cleaned up
- Postfix deferred queue with thousands of entries
- Temporary files accumulating in `/tmp` or `/var/tmp`
- Build artifacts or package cache with many small files
- Application creating many small log, lock, or PID files

## Investigation

```bash
# Check inode usage across filesystems
df -i

# Find directories with the most files (start from root of affected filesystem)
find / -xdev -type d -exec sh -c 'echo "$(find "$1" -maxdepth 1 -type f | wc -l) $1"' _ {} \; 2>/dev/null | sort -rn | head -20

# Faster alternative: check known problem directories
for d in /tmp /var/tmp /var/spool/postfix /var/lib/php/sessions /var/cache; do
  echo "$(find "$d" -type f 2>/dev/null | wc -l) $d"
done | sort -rn

# Check Postfix queue file count
find /var/spool/postfix -type f | wc -l

# Check PHP session directory
ls /var/lib/php/sessions/ 2>/dev/null | wc -l

# Check /tmp file count
find /tmp -type f | wc -l
```

## Resolution

1. Identify the directory consuming the most inodes from investigation.
2. If PHP sessions: clean old sessions (`find /var/lib/php/sessions -type f -mtime +1 -delete`).
3. If Postfix queue: purge deferred/bounce queue (`postsuper -d ALL deferred`).
4. If `/tmp`: remove old temp files (`find /tmp -type f -atime +2 -delete`).
5. If cache directory: clear the relevant application or package cache.
6. **Note:** Unlike disk space, inodes cannot be added without reformatting. If the filesystem is genuinely too small, plan a migration to a filesystem with more inodes.

## Prevention

- Configure PHP session garbage collection (`session.gc_maxlifetime`, `session.gc_probability`)
- Set up systemd-tmpfiles or tmpreaper for `/tmp` and `/var/tmp` cleanup
- Monitor Postfix queue size and address delivery failures promptly
- Use `df -i` in regular monitoring alongside `df -h`
- Consider XFS or ext4 with larger inode ratios for filesystems expected to hold many small files
