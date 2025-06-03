def iptables_build_rule(rule, chain):
    parts = [f"-A {chain}"]

    proto = rule.get("proto")
    if proto:
        parts.append(f"-p {proto}")

    # Keep track of modules to avoid duplicates
    modules = set()

    # conntrack/state modules
    if "ctstate" in rule:
        modules.add("conntrack")
        parts.append(f"--ctstate {rule['ctstate']}")

    if "state" in rule:
        modules.add("state")
        parts.append(f"--state {rule['state']}")

    # Explicit match module
    if "match" in rule:
        modules.add(rule["match"])

    for mod in sorted(modules):
        parts.append(f"-m {mod}")

    # Interfaces
    if "in_interface" in rule:
        parts.append(f"-i {rule['in_interface']}")
    if "out_interface" in rule:
        parts.append(f"-o {rule['out_interface']}")

    # Ports
    if "sport" in rule:
        parts.append(f"--sport {rule['sport']}")
    if "dport" in rule:
        parts.append(f"--dport {rule['dport']}")

    # Jump target
    jump = rule.get("jump")
    if jump == "LOG":
        parts.append("-j LOG")
        if "log_prefix" in rule:
            parts.append(f"--log-prefix \"{rule['log_prefix']}\"")
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
