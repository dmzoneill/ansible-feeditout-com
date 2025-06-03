import subprocess
import yaml
import os
import sys
import urllib.request
import shlex
import pprint

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
    print("[DEBUG] Rule dictionary:")
    pprint.pprint(rule_dict)

    proto = rule_dict.get("proto")
    match_module = rule_dict.get("match")
    ctstate = rule_dict.get("ctstate")
    state = rule_dict.get("state")
    sport = rule_dict.get("sport")
    dport = rule_dict.get("dport")
    in_if = rule_dict.get("in_interface")
    out_if = rule_dict.get("out_interface")
    jump = rule_dict.get("jump")
    log_prefix = rule_dict.get("log_prefix")
    log_level = rule_dict.get("log_level")

    parts = [f"-A {chain}"]

    if proto and proto != "all":
        parts.append(f"-p {proto}")
    if in_if:
        parts.append(f"-i {in_if}")
    if out_if:
        parts.append(f"-o {out_if}")

    if ctstate:
        parts.append("-m conntrack")
    if match_module and match_module != "conntrack":
        parts.append(f"-m {match_module}")
    if state:
        parts.append("-m state")
    if proto in ("tcp", "udp"):
        parts.append(f"-m {proto}")

    if ctstate:
        parts.append(f"--ctstate {ctstate}")
    if state:
        parts.append(f"--state {state}")
    if sport:
        parts.append(f"--sport {sport}")
    if dport:
        parts.append(f"--dport {dport}")

    if jump == "LOG":
        parts.append("-j LOG")
        if log_prefix:
            parts.append(f"--log-prefix '{log_prefix}'")
        if log_level:
            parts.append(f"--log-level {log_level}")
    elif jump:
        parts.append(f"-j {jump}")

    pprint.pprint(parts)
    return " ".join(parts)

def get_current_rules(tool, chain):
    result = run(f"/sbin/{tool} -S {chain}", check=False)
    return [line.strip() for line in result.stdout.splitlines() if line.startswith(f"-A {chain} ")]

def normalize_rule(rule_line):
    tokens = shlex.split(rule_line)
    try:
        index = tokens.index("-A") + 1
    except ValueError:
        return rule_line

    prefix = " ".join(tokens[:index + 1])
    args = tokens[index + 1:]

    grouped = []
    skip_next = False
    for i, tok in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
            grouped.append((tok, args[i + 1]))
            skip_next = True
        else:
            grouped.append((tok,))

    sorted_grouped = sorted(grouped, key=lambda g: g[0])
    flat = [" ".join(group) for group in sorted_grouped]

    return f"{prefix} {' '.join(flat)}"

def sync_ansible_chains(tool, rules_dict):
    for chain, desired_rules in rules_dict.items():
        existing_raw = get_current_rules(tool, chain)
        desired_raw = [build_rule(r, chain) for r in desired_rules]

        existing_set = set(normalize_rule(r) for r in existing_raw)
        desired_set = set(normalize_rule(r) for r in desired_raw)

        print(f"\n=== Syncing {tool.upper()} {chain} ===")
        print("[DEBUG] Existing rules:")
        for rule in existing_set:
            print(f"  {rule}")

        print("[DEBUG] Desired rules:")
        for rule in desired_set:
            print(f"  {rule}")

        to_add = desired_set - existing_set
        to_remove = existing_set - desired_set

        print("[DEBUG] Rules to add:")
        for rule in to_add:
            print(f"  {rule}")

        print("[DEBUG] Rules to remove:")
        for rule in to_remove:
            print(f"  {rule}")

        for rule in to_add:
            print(f"Adding rule: {rule}")
            run(f"/sbin/{tool} {rule}")
        for rule in to_remove:
            print(f"Removing rule: {rule}")
            run(f"/sbin/{tool} {rule.replace('-A', '-D', 1)}")

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
        apply_rules(tool, rules)
        apply_policies(tool, policies.get("ipv6" if tool == "ip6tables" else "ipv4", {}))

if __name__ == "__main__":
    main()
