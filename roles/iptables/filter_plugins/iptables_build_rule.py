def iptables_build_rule(rule, chain):
    parts = [f"-A {chain}"]

    proto = rule.get("proto")
    if proto:
        parts.append(f"-p {proto}")

    if "match" in rule:
        parts.append(f"-m {rule['match']}")

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

    if "jump" in rule:
        parts.append(f"-j {rule['jump']}")

    return " ".join(parts)

class FilterModule(object):
    def filters(self):
        return {
            'iptables_build_rule': iptables_build_rule
        }
