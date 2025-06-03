def iptables_build_rule(rule, chain):
    parts = [f"-A {chain}"]

    proto = rule.get("proto")
    if proto:
        parts.append(f"-p {proto}")
        # iptables -S includes -m <proto> for tcp/udp
        if proto in ("tcp", "udp"):
            parts.append(f"-m {proto}")

    # Interfaces
    if "in_interface" in rule:
        parts.append(f"-i {rule['in_interface']}")
    if "out_interface" in rule:
        parts.append(f"-o {rule['out_interface']}")

    # Track all used match modules
    modules = []

    # Module-driven logic
    if "match" in rule:
        modules.append(rule["match"])
    if "ctstate" in rule:
        modules.append("conntrack")
    if "state" in rule:
        modules.append("state")

    # Deduplicate modules preserving order
    seen = set()
    for mod in modules:
        if mod not in seen:
            parts.append(f"-m {mod}")
            seen.add(mod)

    # Module-specific options
    if "ctstate" in rule:
        parts.append(f"--ctstate {rule['ctstate']}")
    if "state" in rule:
        parts.append(f"--state {rule['state']}")
    if "sport" in rule:
        parts.append(f"--sport {rule['sport']}")
    if "dport" in rule:
        parts.append(f"--dport {rule['dport']}")

    # Jump and log-specific options
    jump = rule.get("jump")
    if jump == "LOG":
        parts.append("-j LOG")
        if "log_prefix" in rule:
            prefix = rule["log_prefix"].replace('"', r'\"')
            parts.append(f'--log-prefix "{prefix}"')
        if "log_level" in rule:
            parts.append(f"--log-level {rule['log_level']}")
    elif jump:
        parts.append(f"-j {jump}")

    return " ".join(parts)


class FilterModule(object):
    def filters(self):
        return {
            'iptables_build_rule': iptables_build_rule
        }
