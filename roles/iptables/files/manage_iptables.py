import subprocess
import yaml
import os
import sys
import logging
import socket

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
log = logging.getLogger("iptables-update")

RULES_FILE = "/etc/ansible/iptables.yml"


def run(cmd, check=True):
    log.debug(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0:
        log.error(f"Command failed: {cmd}\n{result.stderr}")
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result.stdout.strip()


def ensure_custom_chain(tool, chain):
    run(f"/sbin/{tool} -N {chain} || true", check=False)


def ensure_jump_from_main_chain(tool, main_chain, custom_chain):
    existing = run(f"/sbin/{tool} -S {main_chain} || true", check=False)
    if f"-A {main_chain} -j {custom_chain}" not in existing:
        run(f"/sbin/{tool} -I {main_chain} 1 -j {custom_chain}")


def normalize_rule(rule):
    parts = [f"-A"]
    proto = rule.get("proto")
    if proto:
        parts.extend(["-p", proto])
        if proto in ("tcp", "udp"):
            parts.extend(["-m", proto])

    if "in_interface" in rule:
        parts.extend(["-i", rule["in_interface"]])
    if "out_interface" in rule:
        parts.extend(["-o", rule["out_interface"]])

    if "match" in rule:
        parts.extend(["-m", rule["match"]])
    if "ctstate" in rule:
        parts.extend(["-m", "conntrack", "--ctstate", rule["ctstate"]])
    if "state" in rule:
        parts.extend(["-m", "state", "--state", rule["state"]])
    if "sport" in rule:
        parts.extend(["--sport", str(rule["sport"])])
    if "dport" in rule:
        parts.extend(["--dport", str(rule["dport"])])

    jump = rule.get("jump")
    if jump == "LOG":
        parts.extend(["-j", "LOG"])
        if "log_prefix" in rule:
            parts.extend(["--log-prefix", f'\"{rule["log_prefix"]}\"'])
        if "log_level" in rule:
            parts.extend(["--log-level", str(rule["log_level"])])
    elif jump:
        parts.extend(["-j", jump])

    return " ".join(parts)


def apply_rule(tool, chain, rule):
    rule_str = normalize_rule(rule).replace("-A", f"-C {chain}", 1)
    result = subprocess.run(f"/sbin/{tool} {rule_str}", shell=True)
    if result.returncode != 0:
        add_cmd = normalize_rule(rule).replace("-A", f"-A {chain}", 1)
        run(f"/sbin/{tool} {add_cmd}")


def set_default_policies(policies):
    for version, chains in policies.items():
        tool = "iptables" if version == "ipv4" else "ip6tables"
        for chain, policy in chains.items():
            run(f"/sbin/{tool} -P {chain} {policy}", check=False)


def disaster_recovery_check():
    try:
        socket.gethostbyname("github.com")
    except Exception:
        log.error("Disaster recovery triggered: github.com is unreachable")
        for tool in ["iptables", "ip6tables"]:
            run(f"/sbin/{tool} -F")
            run(f"/sbin/{tool} -X")
            for chain in ["INPUT", "OUTPUT", "FORWARD"]:
                run(f"/sbin/{tool} -P {chain} ACCEPT")
        sys.exit(0)


def main():
    if not os.path.exists(RULES_FILE):
        log.error(f"Rules file not found: {RULES_FILE}")
        sys.exit(1)

    disaster_recovery_check()

    with open(RULES_FILE, "r") as f:
        data = yaml.safe_load(f)

    policies = data.get("iptables", {}).get("policies", {})
    rulesets = data.get("iptables", {}).get("rules", {})

    set_default_policies(policies)

    for tool in ["iptables", "ip6tables"]:
        if tool == "ip6tables":
            continue  # for now only apply IPv4 rules

        for custom_chain, rules in rulesets.items():
            ensure_custom_chain(tool, custom_chain)
            main_chain = "INPUT" if "INPUT" in custom_chain else "OUTPUT"
            ensure_jump_from_main_chain(tool, main_chain, custom_chain)

            run(f"/sbin/{tool} -F {custom_chain}", check=False)
            for rule in rules:
                apply_rule(tool, custom_chain, rule)

    for tool in ["iptables", "ip6tables"]:
        version = "6" if tool == "ip6tables" else "4"
        run(f"/sbin/{tool}-save > /etc/iptables/rules.v{version}", check=False)


if __name__ == "__main__":
    main()
