# NetworkDroppedPackets

## Description

Network packets are being dropped on one or more interfaces. Dropped packets indicate the system cannot process incoming or outgoing traffic fast enough, leading to data loss and degraded performance.

## Severity

**Warning**

## Possible Causes

- Network interface ring buffer overflow (high traffic volume)
- CPU unable to process packets fast enough (softirq bottleneck)
- iptables/nftables rules dropping traffic
- Network driver bugs or misconfiguration
- MTU mismatch causing fragmentation drops
- Socket receive buffer too small
- NIC hardware errors

## Investigation

```bash
# Check dropped packets per interface
ip -s link show

# Detailed interface statistics including drops and errors
cat /proc/net/dev

# Check which interface and direction (RX vs TX)
netstat -i

# Check for NIC ring buffer overruns
ethtool -S eth0 2>/dev/null | grep -iE "drop|error|miss|fifo"

# Check softirq processing (high counts may indicate CPU bottleneck)
cat /proc/net/softnet_stat | awk '{print "CPU"NR-1": dropped="strtonum("0x"$2)" time_squeeze="strtonum("0x"$3)}'

# Check iptables drop counters
iptables -L -v -n | grep -i drop
iptables -L -v -n -t raw 2>/dev/null

# Check socket buffer sizes
sysctl net.core.rmem_max
sysctl net.core.wmem_max
sysctl net.core.netdev_max_backlog

# Check for conntrack table overflow
dmesg | grep -i "nf_conntrack: table full"
sysctl net.netfilter.nf_conntrack_count 2>/dev/null
sysctl net.netfilter.nf_conntrack_max 2>/dev/null

# Check network interface for hardware errors
ethtool eth0 2>/dev/null
```

## Resolution

1. **If ring buffer overflow**, increase the ring buffer size:
   ```bash
   ethtool -g eth0  # Show current/max
   ethtool -G eth0 rx 4096 tx 4096
   ```

2. **If socket buffer overflow**, increase buffer sizes:
   ```bash
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.wmem_max=16777216
   sysctl -w net.core.netdev_max_backlog=5000
   ```

3. **If conntrack table full**:
   ```bash
   sysctl -w net.netfilter.nf_conntrack_max=262144
   ```

4. **If iptables is dropping**, review rules:
   ```bash
   iptables -L -v -n --line-numbers
   # Adjust rules as needed
   ```

5. **If driver/hardware issue**, check for updated drivers or replace NIC.

## Prevention

- Set adequate socket buffer sizes in `/etc/sysctl.d/`
- Size conntrack table for expected connection volume
- Monitor interface statistics trends in Grafana
- Keep network drivers and firmware updated
- Use `ethtool -G` to set ring buffer sizes at boot via a udev rule or systemd unit
- Review iptables rules periodically for overly aggressive drop rules
