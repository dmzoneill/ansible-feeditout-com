def to_nice_input_rule(rule):
    parts = ["-A ANSIBLE_INPUT"]
    if "match" in rule:
        parts.append(f"-m {rule['match']}")
    if "ctstate" in rule:
        parts.append(f"--ctstate {rule['ctstate']}")
    if "proto" in rule:
        parts.append(f"-p {rule['proto']}")
    if "dport" in rule:
        parts.append(f"--dport {rule['dport']}")
    if "in_interface" in rule:
        parts.append(f"-i {rule['in_interface']}")
    parts.append(f"-j {rule['jump']}")
    return " ".join(parts)

def to_nice_output_rule(rule):
    parts = ["-A ANSIBLE_OUTPUT"]
    if "proto" in rule:
        parts.append(f"-p {rule['proto']}")
    if "sport" in rule:
        parts.append(f"--sport {rule['sport']}")
    if "dport" in rule:
        parts.append(f"--dport {rule['dport']}")
    if "state" in rule:
        parts.append(f"-m state --state {rule['state']}")
    parts.append(f"-j {rule['jump']}")
    return " ".join(parts)

class FilterModule(object):
    def filters(self):
        return {
            "to_nice_input_rule": to_nice_input_rule,
            "to_nice_output_rule": to_nice_output_rule,
        }
