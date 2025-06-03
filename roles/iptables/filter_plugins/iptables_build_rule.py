def iptables_build_rule(rule, chain):
    parts = [f"-A {chain}"]

    proto = rule.get("proto")
    if proto:
        parts.append(f"-p {proto}")

    # Interfaces
    if "in_interface" in rule:
        parts.append(f"-i {rule['in_interface']}")
    if "out_interface" in rule:
        parts.append(f"-o {rule['out_interface']}")

    # Track modules added
    modules = []

    # Match modules and their required arguments (correct ordering!)
    if "ctstate" in rule:
        modules.append("conntrack")

    if "state" in rule:
        modules.append("state")

    if "match" in rule:
        modules.append(rule["match"])

    # Deduplicate while preserving order
    seen = set()
    for mod in modules:
        if mod not in seen:
            parts.append(f"-m {mod}")
            seen.add(mod)

    # Now add the module options (must come after -m)
    if "ctstate" in rule:
        parts.append(f"--ctstate {rule['ctstate']}")

    if "state" in rule:
        parts.append(f"--state {rule['state']}")

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
