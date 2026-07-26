# NetworkTransmitErrors

**Alert:** Network interface is reporting transmit errors.

**Severity:** Warning

## Possible Causes

- Faulty network cable or connector
- NIC hardware failure or driver bug
- Network switch port errors or congestion
- TX ring buffer too small for traffic volume
- Duplex mismatch causing late collisions
- NIC firmware bug
- Virtualization layer network misconfiguration

## Investigation

```bash
# Check interface error counters
ip -s link show

# Detailed NIC transmit statistics
ethtool -S <interface> 2>/dev/null | grep -i -E "tx.*error|tx.*drop|collision|carrier"

# Check current link settings and negotiation
ethtool <interface> 2>/dev/null

# Check ring buffer sizes
ethtool -g <interface> 2>/dev/null

# Check for carrier or link errors in kernel log
dmesg | grep -i -E "link|carrier|tx|transmit" | tail -20

# Check network traffic volume
sar -n DEV 1 5 2>/dev/null || ss -s

# Monitor errors in real-time
watch -n 1 'cat /proc/net/dev'
```

## Resolution

1. Identify which interface is reporting errors from `ip -s link show`.
2. Check physical layer: reseat cables, try a different switch port or cable.
3. If collisions detected: check for duplex mismatch, force correct settings.
4. Increase TX ring buffer if undersized: `ethtool -G <iface> tx 4096`.
5. If driver issue: update kernel and NIC drivers.
6. If virtualised: check hypervisor virtual switch and NIC driver (e.g., switch to `virtio-net`).
7. If errors persist after physical checks, consider NIC replacement.

## Prevention

- Monitor NIC error counters as part of routine health checks
- Ensure consistent duplex and speed settings across links
- Keep NIC drivers and firmware updated
- Size ring buffers appropriately for expected traffic
- Use bonded/teamed interfaces for redundancy where possible
