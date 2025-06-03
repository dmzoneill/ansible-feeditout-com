def normalize_iptables_rule(rule):
    import re
    rule = re.sub(r'--log-level \d+', '', rule)
    rule = re.sub(r'-p all', '', rule)
    rule = re.sub(r'\s+', ' ', rule).strip()
    return rule

class FilterModule(object):
    def filters(self):
        return {
            'normalize_iptables_rule': normalize_iptables_rule
        }
