# EntropyPoolLow

## Description

The kernel entropy pool has dropped below 100 bits. Low entropy can cause blocking in applications that read from `/dev/random` and degrade the quality of cryptographic operations including TLS handshakes, key generation, and session token creation.

## Severity

**Warning**

## Possible Causes

- Virtual machine without `virtio-rng` or hardware RNG passthrough
- Heavy TLS traffic exhausting entropy faster than it is generated
- Application using `/dev/random` (blocking) instead of `/dev/urandom`
- No hardware RNG (RDRAND, TPM) available
- `haveged` or `rng-tools` not installed or not running

## Investigation

```bash
# Check current entropy available
cat /proc/sys/kernel/random/entropy_avail

# Check pool size
cat /proc/sys/kernel/random/poolsize

# Check if hardware RNG is available
cat /sys/devices/virtual/misc/hw_random/rng_available 2>/dev/null

# Check if rng-tools or haveged is installed and running
systemctl status rng-tools 2>/dev/null
systemctl status haveged 2>/dev/null

# Check CPU for RDRAND support
grep -o rdrand /proc/cpuinfo | head -1

# Check if any process is blocking on /dev/random
lsof /dev/random 2>/dev/null

# Check TLS handshake rate (indicator of entropy consumption)
ss -tn state established dst :443 | wc -l
```

## Resolution

1. **Install and enable `haveged`** (software entropy daemon):
   ```bash
   apt-get install haveged
   systemctl enable --now haveged
   ```

2. **Or install `rng-tools`** if hardware RNG is available:
   ```bash
   apt-get install rng-tools
   systemctl enable --now rng-tools
   ```

3. **On VMs**, ensure `virtio-rng` device is passed through from the hypervisor.

4. **Verify entropy recovered**:
   ```bash
   cat /proc/sys/kernel/random/entropy_avail
   # Should be well above 100
   ```

5. **Check for applications using `/dev/random`** and switch them to `/dev/urandom` where appropriate (most applications should use `urandom`).

## Prevention

- Install `haveged` or `rng-tools` on all servers, especially VMs
- Ensure `virtio-rng` is configured for virtual machines
- Use `/dev/urandom` instead of `/dev/random` in application configurations
- Monitor entropy levels in Grafana
- Modern kernels (5.6+) make `/dev/random` non-blocking when CRNG is initialized; verify kernel version with `uname -r`
