import json
import time

from namecheap.client import Namecheap
from namecheap.errors import NamecheapError

client = Namecheap()
print(client.config)

try:
    # Get list of domains in your account
    result = client.domains.list(page=1, page_size=20)
    # Process domain list
    domains = result.get("domains", {})

    for domain in domains:
        if domain.get("Name") == "feeditout.online":
            continue

        print(f"Domain: {domain.get('Name')}")
        print(f"  Expires: {domain.get('Expires')}")
        records = client.domains.dns.get_hosts(domain.get("Name"))
        file_path = domain.get("Name") + ".json"

        # Read the file and parse as JSON
        with open(file_path + ".bak." + str(time.time()), "w") as f:
            f.write(json.dumps(records, indent=4))

        # Read the file and parse as JSON
        with open(file_path, "r") as f:
            data = json.load(f)
            client.domains.dns.set_hosts(domain.get("Name"), data)

except NamecheapError as e:
    print(f"API Error: {e}")
