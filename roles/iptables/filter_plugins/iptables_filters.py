def iptables_build_rule(rule_dict, chain):
    args = [f"-A {chain}"]
    if 'in_interface' in rule_dict:
        args.append(f"-i {rule_dict['in_interface']}")
    if 'out_interface' in rule_dict:
        args.append(f"-o {rule_dict['out_interface']}")
    if 'proto' in rule_dict:
        args.append(f"-p {rule_dict['proto']}")
        args.append(f"-m {rule_dict['proto']}")
    if 'match' in rule_dict:
        args.append(f"-m {rule_dict['match']}")
    if 'ctstate' in rule_dict:
        args.append(f"--ctstate {rule_dict['ctstate']}")
    if 'state' in rule_dict:
        args.append(f"-m state --state {rule_dict['state']}")
    if 'dport' in rule_dict:
        args.append(f"--dport {rule_dict['dport']}")
    if 'sport' in rule_dict:
        args.append(f"--sport {rule_dict['sport']}")
    if 'jump' in rule_dict:
        args.append(f"-j {rule_dict['jump']}")
    return ' '.join(args)

class FilterModule(object):
    def filters(self):
        return {
            'iptables_build_rule': iptables_build_rule
        }
