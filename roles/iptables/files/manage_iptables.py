#!/usr/bin/env python3
import yaml
import subprocess
import os
import sys
import socket


def log(msg):
    print(f"[INFO] {msg}")


def is_github_accessible():
    try:
        socket.gethostbyname("github.com")
        return True
    except socket.error:
        return False


def run(cmd, check=True):
    log(f"Running: {cmd}")
    return subprocess.run(cmd, shell=True, check=check)


def flush_all_tables():
    for tool in ["iptables", "ip6tables"]:
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            run(f"/sbin/{tool} -P {chain} ACCEPT", check=False)
            run(f"/sbin/{tool} -F", check=False)
            run(f"/sbin/{tool} -X", check=False)


def apply_policy(tool, chain, policy):
    run(f"/sbin/{tool} -P {chain} {policy}", check=False)


def apply_rule(tool, chain, rule):
    cmd = f"/sbin/{tool} -A {chain}"
    if "proto" in rule:
        proto = rule["proto"]
        cmd += f" -p {proto}"
        if proto in ("tcp", "udp"):
            cmd += f" -m {proto}"
    if "match" in rule:
        cmd += f" -m {rule['match']}"
    if "ctstate" in rule:
        cmd += f" -m conntrack --ctstate {rule['ctstate']}"
    if "state" in rule:
        cmd += f" -m state --state {rule['state']}"
    if "in_interface" in rule:
        cmd += f" -i {rule['in_interface']}"
    if "out_interface" in rule:
        cmd += f" -o {rule['out_interface']}"
    if "sport" in rule:
        cmd += f" --sport {rule['sport']}"
    if "dport" in rule:
        cmd += f" --dport {rule['dport']}"
    if "jump" in rule:
        cmd += f" -j {rule['jump']}"
        if rule["jump"] == "LOG":
            if "log_prefix" in rule:
                cmd += f" --log-prefix \"{rule['log_prefix']}\""
            if "log_level" in rule:
                cmd += f" --log-level {rule['log_level']}"
    run(cmd, check=False)


def ensure_custom_chain(tool, chain):
    result = subprocess.run(f"/sbin/{tool} -S", shell=True, capture_output=True, text=True)
    if f":{chain} " not in result.stdout:
        run(f"/sbin/{tool} -N {chain}", check=False)


def ensure_jump_from_main_chain(tool, main_chain, custom_chain):
    result = subprocess.run(f"/sbin/{tool} -S {main_chain}", shell=True, capture_output=True, text=True)
    if f"-A {main_chain} -j {custom_chain}" not in result.stdout:
        run(f"/sbin/{tool} -I {main_chain} 1 -j {custom_chain}", check=False)


def main(config_path):
    if not os.path.exists(config_path):
        print(f"Missing config file: {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    if not is_github_accessible():
        print("Disaster recovery: github.com is not reachable. Flushing rules...")
        flush_all_tables()
        sys.exit(0)

    iptables_cfg = config.get("iptables", {})
    policies = iptables_cfg.get("policies", {})
    rulesets = iptables_cfg.get("rules", {})

    for tool in ["iptables", "ip6tables"]:
        version = "ipv4" if tool == "iptables" else "ipv6"

        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            policy = policies.get(version, {}).get(chain)
            if policy:
                apply_policy(tool, chain, policy)

        for custom_chain, rules in rulesets.items():
            ensure_custom_chain(tool, custom_chain)
            main_chain = "INPUT" if "INPUT" in custom_chain else "OUTPUT"
            ensure_jump_from_main_chain(tool, main_chain, custom_chain)

            run(f"/sbin/{tool} -F {custom_chain}", check=False)
            for rule in rules:
                apply_rule(tool, custom_chain, rule)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: manage_iptables.py /path/to/config.yml")
        sys.exit(1)
    main(sys.argv[1])
