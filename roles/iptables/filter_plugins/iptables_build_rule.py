def iptables_build_rule(rule, chain):
    parts = [f"-A {chain}"]

    proto = rule.get("proto")
    if proto:
        parts.append(f"-p {proto}")

    if rule.get("match"):
        parts.append(f"-m {rule['match']}")

    # Add shorthand for conntrack module if requested
    if rule.get("conntrack"):
        parts.append("-m conntrack")

    if "state" in rule:
        parts.append(f"-m state --state {rule['state']}")

    if "ctstate" in rule:
        parts.append(f"--ctstate {rule['ctstate']}")

    if "in_interface" in rule:
        parts.append(f"-i {rule['in_interface']}")

    if "out_interface" in rule:
        parts.append(f"-o {rule['out_interface']}")

    if "sport" in rule:
        parts.append(f"--sport {rule['sport']}")

    if "dport" in rule:
        parts.append(f"--dport {rule['dport']}")

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
