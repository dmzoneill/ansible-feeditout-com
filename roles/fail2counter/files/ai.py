
class AiError(Exception):
    pass


class OpenAIProvider:
    def __init__(self) -> None:
        self.api_key: str = str(os.environ.get("OPENAI_API_KEY"))
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set in the environment.")
        self.endpoint: str = "https://api.openai.com/v1/chat/completions"
        self.model: str = "gpt-4o-mini"

    def improve_text(self, prompt: str, text: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": text},
            ],
            "temperature": 0.4,
        }

        response = requests.post(self.endpoint, json=body, headers=headers, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()

        raise AiError(
            f"OpenAI API call failed: {response.status_code} - {response.text}"
        )

# Load exploit list
capture(f"Loading Metasploit module list from {EXPLOITS_FILE}")
if not os.path.exists(EXPLOITS_FILE):
    capture(f"Exploit list not found: {EXPLOITS_FILE}", level="ERROR")
    exit(1)

with open(EXPLOITS_FILE, "r") as f:
    exploits_list = f.read()

capture(f"Loaded {len(exploits_list.splitlines())} Metasploit modules.")

system_prompt = f"""You are a cybersecurity expert helping choose Metasploit modules for post-breach analysis.

Below is a list of available Metasploit modules:

{exploits_list}

You will be given Nmap results for a scanned IP address. Using the list above,
suggest which modules are likely applicable. Only return a valid metasploit
rc file for each module identified from the list, no explanations. In the
RC file, add known parameters like RHOSTS, RPORT, etc for the given exploit.

e.g:

use exploit/linux/ssh/ceragon_fibeair_known_privkey
set RHOSTS 192.0.2.1
set RPORT 22
run

"""

provider = OpenAIProvider()


def write_msf_rc(ip: str, modules: list[str]) -> str:
    rc_path = f"/tmp/ip-{ip}.rc"
    with open(rc_path, "w") as f:
        for mod in modules:
            f.write(f"use {mod}\n")
            f.write(f"set RHOSTS {ip}\n")
            f.write("set RPORT 80\n")  # You can adjust this dynamically later
            f.write("run\n\n")
    return rc_path


def run_msf(ip: str, rc_path: str) -> str:
    output_path = f"/tmp/ip-{ip}.msfout"
    env = os.environ.copy()
    env["HOME"] = "/root"  # or "/tmp" as needed

    try:
        result = subprocess.run(
            ["/usr/bin/msfconsole", "-q", "-r", rc_path],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )

        with open(output_path, "w") as f:
            f.write(result.stdout)

        return result.stdout
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Metasploit run exceeded 2 minutes"
    except Exception as e:
        return f"[ERROR] Metasploit execution failed: {e}"


    # continue

    # try:
    #     capture(f"Sending to OpenAI for analysis...")
    #     result = provider.improve_text(system_prompt, f"Nmap output:\n{nmap_output}")
    #     result = result.replace("```", "").strip()
    #     capture(f"OpenAI response:\n{result}")

    #     modules = [line.strip() for line in result.strip().splitlines() if line.strip().startswith("use exploit")]
    #     if not modules:
    #         capture(f"No valid Metasploit modules returned for {ip}", level="WARNING")
    #         continue

    #     rc_path = write_msf_rc(ip, modules)
    #     capture(f"Written Metasploit RC file to {rc_path}")

    #     msf_result = run_msf(ip, rc_path)
    #     capture(f"Metasploit output for {ip}:\n{msf_result}")

    #     send_email(
    #         subject=f"[Fail2Ban Report] Analysis for {ip}",
    #         body="\n".join(logs)
    #     )

    # except Exception as e:
    #     log(f"OpenAI or Metasploit processing failed for {ip}: {e}", level="ERROR")
