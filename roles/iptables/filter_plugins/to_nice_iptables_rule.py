def to_nice_iptables_rule(rule, chain):
    return "-A {} {}".format(chain, ' '.join('--{} {}'.format(k, v) for k, v in rule.items()))