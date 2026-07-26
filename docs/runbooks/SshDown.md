# SshDown

**Alert:** `node_systemd_unit_state{name="ssh.service", state="active"} != 1`

**Severity:** Critical

## Description

The SSH daemon is down. On feeditout.com, SSH runs on custom port 33 (not the default 22). Loss of SSH means no remote administrative access to the server. This is the most critical infrastructure service -- without it, recovery requires out-of-band access (console, IPMI/KVM, or hosting provider panel).

## Possible Causes

- Configuration error in `/etc/ssh/sshd_config` (bad syntax, invalid option)
- Host key file missing or corrupted
- Port 33 bound by another process
- PAM configuration error preventing sshd startup
- Disk full preventing PID file creation
- Privilege separation directory missing (`/run/sshd`)
- Package upgrade changed config defaults

## Investigation

If you still have an active SSH session, investigate immediately before it times out.

```bash
# Service status
systemctl status ssh

# Journal logs
journalctl -u ssh --since "10 minutes ago" --no-pager

# Validate sshd configuration
sshd -t

# Check if port 33 is in use
ss -tlnp | grep :33

# Check host keys exist
ls -la /etc/ssh/ssh_host_*

# Check privilege separation directory
ls -la /run/sshd/

# Check PAM
cat /etc/pam.d/sshd
```

If locked out, use the hosting provider's console/KVM access to log in locally.

## Resolution

1. Run `sshd -t` to validate configuration; fix any errors.
2. If host keys missing: regenerate with `ssh-keygen -A`.
3. If `/run/sshd` missing: `mkdir -p /run/sshd && chmod 0755 /run/sshd`.
4. If port conflict: identify and stop the conflicting process.
5. Restart: `systemctl restart ssh`
6. Verify from another terminal: `ssh -p 33 feeditout.com`
7. For persistent issues, restore from Ansible: `cd /opt/ansible && ansible-playbook -t sshd site.yml`

**Warning:** Do not close your current SSH session until you have confirmed sshd is running and you can establish a new connection.

## Prevention

- Always run `sshd -t` before restarting after config changes
- Keep a second SSH session open when making SSH configuration changes
- Use Ansible `sshd` role for all configuration changes
- Ensure out-of-band console access is available and tested
- Monitor SSH service with a high-priority alert (this one fires after only 10 seconds)
