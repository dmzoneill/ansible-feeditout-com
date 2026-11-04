#!/usr/bin/env python3
"""Synchronise iptables/ip6tables chains with /etc/ansible/iptables.yml."""

import http.client
import os
import pprint
import shlex
import subprocess
import sys

import yaml


def run(cmd, check=False):
    """Run a command (no shell) and echo its output."""
    print(f"[+] {cmd}")
    result = subprocess.run(
        shlex.split(cmd),
        text=True,
        capture_output=True,
        check=check,
    )
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    return result


def chain_exists(tool, chain):
    """Return True if the chain exists for the given tool."""
    result = run(f"/sbin/{tool} -L {chain} -n", check=False)
    return result.returncode == 0


def ensure_chain(tool, chain):
    """Create the chain if it does not exist."""
    if not chain_exists(tool, chain):
        run(f"/sbin/{tool} -N {chain}")


def ensure_jump(tool, parent_chain, target_chain):
    """Insert a jump from parent_chain to target_chain if missing."""
    check = run(f"/sbin/{tool} -C {parent_chain} -j {target_chain}", check=False)
    if check.returncode != 0:
        run(f"/sbin/{tool} -I {parent_chain} 1 -j {target_chain}")


def _optional_parts(rule_dict, options):
    """Return "flag value" strings for each (key, flag) whose value is set."""
    return [f"{flag} {rule_dict[key]}" for key, flag in options if rule_dict.get(key)]


def _match_parts(rule_dict):
    """Return the -m match-module arguments for a rule."""
    proto = rule_dict.get("proto")
    match_module = rule_dict.get("match")
    parts = []
    if rule_dict.get("ctstate"):
        parts.append("-m conntrack")
    if match_module and match_module != "conntrack":
        parts.append(f"-m {match_module}")
    if rule_dict.get("state"):
        parts.append("-m state")
    if proto in ("tcp", "udp"):
        parts.append(f"-m {proto}")
    return parts


def _jump_parts(rule_dict):
    """Return the -j target arguments for a rule."""
    jump = rule_dict.get("jump")
    log_prefix = rule_dict.get("log_prefix")
    if jump == "LOG":
        # Exclude log-level from rule string comparison (iptables -S omits it)
        if log_prefix:
            return ["-j LOG", f"--log-prefix {shlex.quote(log_prefix)}"]
        return ["-j LOG"]
    if jump:
        return [f"-j {jump}"]
    return []


def build_rule(rule_dict, chain):
    """Build an iptables -A rule string from a rule dictionary."""
    print("[DEBUG] Rule dictionary:")
    pprint.pprint(rule_dict)

    proto = rule_dict.get("proto")
    parts = [f"-A {chain}"]
    if proto and proto != "all":
        parts.append(f"-p {proto}")
    iface_options = (("in_interface", "-i"), ("out_interface", "-o"))
    parts += _optional_parts(rule_dict, iface_options)
    parts += _match_parts(rule_dict)
    state_options = (
        ("ctstate", "--ctstate"),
        ("state", "--state"),
        ("sport", "--sport"),
        ("dport", "--dport"),
    )
    parts += _optional_parts(rule_dict, state_options)
    parts += _jump_parts(rule_dict)

    pprint.pprint(parts)
    return " ".join(parts)


def get_current_rules(tool, chain):
    """Return the current -A rules of a chain as reported by -S."""
    result = run(f"/sbin/{tool} -S {chain}", check=False)
    prefix = f"-A {chain} "
    lines = result.stdout.splitlines()
    return [line.strip() for line in lines if line.startswith(prefix)]


def normalize_rule(rule_line):
    """Normalise a rule string, dropping --log-level and its value."""
    tokens = shlex.split(rule_line)
    try:
        index = tokens.index("-A") + 1
    except ValueError:
        return rule_line

    prefix = " ".join(tokens[: index + 1])
    args = tokens[index + 1 :]

    filtered_args = []
    skip = False
    for tok in args:
        if skip:
            skip = False
            continue
        if tok == "--log-level":
            skip = True
            continue
        filtered_args.append(tok)

    return f"{prefix} {' '.join(filtered_args)}"


def sync_ansible_chains(tool, rules_dict):
    """Add missing and remove stale rules so each chain matches rules_dict."""
    for chain, desired_rules in rules_dict.items():
        existing_raw = get_current_rules(tool, chain)
        desired_raw = [build_rule(r, chain) for r in desired_rules]

        existing_set = {normalize_rule(r) for r in existing_raw}
        desired_set = {normalize_rule(r) for r in desired_raw}

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
            tokens = shlex.split(rule)
            safe_cmd = " ".join(shlex.quote(t) for t in tokens)
            run(f"/sbin/{tool} {safe_cmd}")
            _changes[0] = True
        for rule in to_remove:
            print(f"Removing rule: {rule}")
            delete_rule = rule.replace("-A", "-D", 1)
            tokens = shlex.split(delete_rule)
            safe_cmd = " ".join(shlex.quote(t) for t in tokens)
            run(f"/sbin/{tool} {safe_cmd}")
            _changes[0] = True


_changes = [False]


def apply_rules(tool, rules_dict):
    """Ensure chains and jumps exist, then sync their rules."""
    for chain in rules_dict:
        ensure_chain(tool, chain)
        ensure_jump(tool, "INPUT" if "INPUT" in chain else "OUTPUT", chain)
    sync_ansible_chains(tool, rules_dict)


def apply_policies(tool, policy_map):
    """Set the default policy of each built-in chain."""
    for chain, policy in policy_map.items():
        run(f"/sbin/{tool} -P {chain} {policy}")


def github_accessible():
    """Return True if https://github.com answers within 3 seconds."""
    conn = http.client.HTTPSConnection("github.com", timeout=3)
    try:
        conn.request("HEAD", "/")
        conn.getresponse()
        return True
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()


def disaster_recovery():
    """Flush all rules and set ACCEPT policies (lock-out protection)."""
    for tool in ("iptables", "ip6tables"):
        run(f"/sbin/{tool} -F")
        run(f"/sbin/{tool} -X")
        run(f"/sbin/{tool} -P INPUT ACCEPT")
        run(f"/sbin/{tool} -P OUTPUT ACCEPT")
        run(f"/sbin/{tool} -P FORWARD ACCEPT")


def main():
    """Entry point."""
    config_file = "/etc/ansible/iptables.yml"
    if not os.path.exists(config_file):
        print(f"Missing config file: {config_file}", file=sys.stderr)
        sys.exit(1)

    with open(config_file, encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if not github_accessible():
        print("GitHub not reachable. Entering disaster recovery mode.")
        disaster_recovery()
        return

    policies = config.get("policies", {})
    rules = config.get("rules", {})

    for tool in ("iptables", "ip6tables"):
        apply_rules(tool, rules)
        family = "ipv6" if tool == "ip6tables" else "ipv4"
        apply_policies(tool, policies.get(family, {}))

    if not _changes[0]:
        print("No changes")


if __name__ == "__main__":
    main()
