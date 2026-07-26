# NetworkReceiveErrors

**Alert:** Network interface is reporting receive errors.

**Severity:** Warning

## Possible Causes

- Faulty network cable or connector
- NIC hardware failure or driver bug
- Network switch port errors
- MTU mismatch between hosts
- Network congestion causing buffer overflows
- Duplex/speed mismatch (auto-negotiation failure)
- Virtualization layer network misconfiguration

## Investigation

```bash
# Check interface error counters
ip -s link show

# Detailed NIC statistics
ethtool -S <interface> 2>/dev/null | grep -i -E "error|drop|miss|fifo"

# Check current link settings
ethtool <interface> 2>/dev/null

# Check for interface flapping in logs
journalctl -u NetworkManager --since "1 hour ago" 2>/dev/null
dmesg | grep -i -E "link|eth|ens|net" | tail -20

# Check MTU settings
ip link show | grep mtu

# Monitor errors in real-time
watch -n 1 'cat /proc/net/dev'

# Check for packet drops at the kernel level
nstat -az | grep -i -E "drop|error"
```

## Resolution

1. Identify which interface is reporting errors from `ip -s link show`.
2. Check physical layer: reseat cables, try a different switch port or cable.
3. If duplex/speed mismatch: force correct settings with `ethtool -s <iface> speed 1000 duplex full`.
4. If MTU mismatch: align MTU across the network path (`ip link set <iface> mtu 1500`).
5. If driver issue: check for kernel/driver updates (`apt list --upgradable | grep linux`).
6. If virtualised: check hypervisor network configuration and virtual switch settings.
7. If errors persist after physical checks, consider NIC replacement.

## Prevention

- Monitor NIC error counters as part of routine health checks
- Use consistent MTU settings across the network
- Keep network drivers and firmware updated
- Use bonded/teamed interfaces for redundancy where possible
- Document network topology and expected link settings
