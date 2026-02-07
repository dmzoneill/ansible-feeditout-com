import os
import mysql.connector
from typing import List, Dict

def fetch_open_ports(
    db_config: Dict[str, str]
) -> List[Dict[str, str]]:
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    query = """
    SELECT 
        h.ip_address,
        h.id AS host_id,
        s.id AS service_id,
        p.port_number,
        p.protocol,
        s.service_name,
        s.product,
        s.version,
        s.extra_info
    FROM services s
    JOIN ports p ON s.port_id = p.id
    JOIN scans sc ON p.scan_id = sc.id
    JOIN hosts h ON sc.host_id = h.id
    WHERE p.state = 'open'
    ORDER BY h.ip_address, p.port_number;
    """

    cursor.execute(query)
    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return results


if __name__ == "__main__":
    db_config = {
        'host': 'localhost',
        'user': 'fail2counter',
        'password': os.environ.get('FAIL2COUNTER_PASSWORD', ''),
        'database': 'fail2counter'
    }

    open_ports = fetch_open_ports(db_config)

    for target in open_ports:
        print(f"[{target['ip_address']}:{target['port_number']}/{target['protocol']}] "
              f"{target['service_name']} - {target['product']} {target['version']}")

    print(f"\nTotal open services: {len(open_ports)}")
