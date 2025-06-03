#!/usr/bin/env python3

import subprocess
import yaml
import os
import sys
import urllib.request

def run(cmd, check=False):
    print(f"[+] {cmd}")
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True, check=check)
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    return result

def chain_exists(tool, chain):
    result = run(f"/sbin/{tool} -L {chain} -n", check=False)
    return result.returncode == 0

def ensure_chain(tool, chain):
    if not chain_exists(tool, chain):
        run(f"/sbin/{tool} -N {chain}")

def ensure_jump(tool, parent_chain, target_chain):
    check = run(f"/sbin/{tool} -C {parent_chain} -j {target_chain}", check=False)
    if check.returncode != 0:
        run(f"/sbin/{tool} -I {parent_chain} 1 -j {target_chain}")

def build_rule(rule_dict, chain):
    parts = []

    proto = rule_dict.get("proto")
    if proto and proto != "all":
        parts.append(f"-p {proto}")
        if proto in ("tcp", "udp"):
            parts.append(f"-m {proto}")

    if "in_interface" in rule_dict:
        parts.append(f"-i {rule_dict['in_interface']}")
    if "out_interface" in rule_dict:
        parts.append(f"-o {rule_dict['out_interface']}")

    if "ctstate" in rule_dict:
        parts.append("-m conntrack")
        parts.append(f"--ctstate {rule_dict['ctstate']}")
    elif rule_dict.get("match") and rule_dict["match"] != "conntrack":
        parts.append(f"-m {rule_dict['match']}")

    if "state" in rule_dict:
        parts.append("-m state")
        parts.append(f"--state {rule_dict['state']}")
    if "sport" in rule_dict:
        parts.append(f"--sport {rule_dict['sport']}")
    if "dport" in rule_dict:
        parts.append(f"--dport {rule_dict['dport']}")

    jump = rule_dict.get("jump")
    if jump == "LOG":
        parts.append("-j LOG")
        if "log_prefix" in rule_dict:
            parts.append(f"--log-prefix \"{rule_dict['log_prefix']}\"")
        if "log_level" in rule_dict:
            parts.append(f"--log-level {rule_dict['log_level']}")
    elif jump:
        parts.append(f"-j {jump}")

    return " ".join(parts)

def get_current_rules(tool, chain):
    result = run(f"/sbin/{tool} -S {chain}", check=False)
    rules = []
    for line in result.stdout.splitlines():
        if line.startswith(f"-A {chain} "):
            rules.append(" ".join(line.strip().split()))
    return rules

def sync_ansible_chains(tool, rules_dict):
    for chain, desired_rules in rules_dict.items():
        existing = set(get_current_rules(tool, chain))
        desired = set(f"-A {chain} {build_rule(r, chain)}" for r in desired_rules)

        for rule in desired - existing:
            print(f"Adding rule: {rule}")
            run(f"/sbin/{tool} {rule}")
        for rule in existing - desired:
            original = rule.replace("-A", "-D", 1)
            print(f"Removing rule: {original}")
            run(f"/sbin/{tool} {original}")

def apply_rules(tool, rules_dict):
    for chain in rules_dict:
        ensure_chain(tool, chain)
        ensure_jump(tool, "INPUT" if "INPUT" in chain else "OUTPUT", chain)
    sync_ansible_chains(tool, rules_dict)

def apply_policies(tool, policy_map):
    for chain, policy in policy_map.items():
        run(f"/sbin/{tool} -P {chain} {policy}")

def github_accessible():
    try:
        urllib.request.urlopen("https://github.com", timeout=3)
        return True
    except:
        return False

def disaster_recovery():
    for tool in ("iptables", "ip6tables"):
        run(f"/sbin/{tool} -F")
        run(f"/sbin/{tool} -X")
        run(f"/sbin/{tool} -P INPUT ACCEPT")
        run(f"/sbin/{tool} -P OUTPUT ACCEPT")
        run(f"/sbin/{tool} -P FORWARD ACCEPT")

def main():
    config_file = "/etc/ansible/iptables.yml"
    if not os.path.exists(config_file):
        print(f"Missing config file: {config_file}", file=sys.stderr)
        sys.exit(1)

    with open(config_file) as f:
        config = yaml.safe_load(f)

    if not github_accessible():
        print("GitHub not reachable. Entering disaster recovery mode.")
        disaster_recovery()
        return

    policies = config.get("policies", {})
    rules = config.get("rules", {})

    for tool in ("iptables", "ip6tables"):
        version = "ipv6" if tool == "ip6tables" else "ipv4"
        apply_rules(tool, rules)
        apply_policies(tool, policies.get(version, {}))

if __name__ == "__main__":
    main()
