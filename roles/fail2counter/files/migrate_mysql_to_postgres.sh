#!/bin/bash
# One-time migration of fail2counter data from MySQL to PostgreSQL
# Only runs if the marker file doesn't exist and MySQL has data

set -euo pipefail

MARKER="/opt/fail2counter/.pg_migration_complete"
TMPDIR="/tmp/fail2counter_migration"

if [ -f "$MARKER" ]; then
    echo "[SKIP] Migration already completed"
    exit 0
fi

# Check if MySQL has fail2counter data
MYSQL_COUNT=$(mysql -N -e "SELECT COUNT(*) FROM fail2counter.hosts;" 2>/dev/null || echo "0")
if [ "$MYSQL_COUNT" = "0" ]; then
    echo "[SKIP] No data in MySQL to migrate"
    touch "$MARKER"
    exit 0
fi

echo "[*] Starting MySQL -> PostgreSQL migration ($MYSQL_COUNT hosts)"

mkdir -p "$TMPDIR"

# Export from MySQL to CSV
echo "[*] Exporting MySQL tables to CSV..."

mysql -N -B -e "SELECT id, ip_address, COALESCE(hostname, ''), COALESCE(created_at, NOW()) FROM fail2counter.hosts;" \
    | sed 's/\t/,/g' > "$TMPDIR/hosts.csv"

mysql -N -B -e "SELECT id, host_id, COALESCE(scan_time, NOW()), COALESCE(scan_type, ''), COALESCE(latency_seconds, 0), COALESCE(duration_seconds, 0), COALESCE(created_at, NOW()) FROM fail2counter.scans;" \
    | sed 's/\t/,/g' > "$TMPDIR/scans.csv"

mysql -N -B -e "SELECT id, scan_id, port_number, COALESCE(protocol, 'tcp'), COALESCE(state, 'open') FROM fail2counter.ports;" \
    | sed 's/\t/,/g' > "$TMPDIR/ports.csv"

mysql -N -B -e "SELECT id, port_id, COALESCE(service_name, ''), COALESCE(product, ''), COALESCE(version, ''), COALESCE(extra_info, ''), COALESCE(is_ssl, 0), COALESCE(recognized, 1) FROM fail2counter.services;" \
    | sed 's/\t/,/g' > "$TMPDIR/services.csv"

# Check for new-schema tables (may not exist in old MySQL)
HAS_EXPLOITS=$(mysql -N -e "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='fail2counter' AND table_name='exploits' AND column_name='scan_id';" 2>/dev/null || echo "0")

if [ "$HAS_EXPLOITS" != "0" ]; then
    mysql -N -B -e "SELECT id, scan_id, host_id, module_path, COALESCE(rhosts, ''), COALESCE(rport, 0), COALESCE(rc_file_path, ''), COALESCE(status, 'suggested'), COALESCE(created_at, NOW()) FROM fail2counter.exploits;" \
        | sed 's/\t/,/g' > "$TMPDIR/exploits.csv" 2>/dev/null || true

    mysql -N -B -e "SELECT id, exploit_id, COALESCE(output_text, ''), COALESCE(exit_code, 0), COALESCE(duration_seconds, 0), COALESCE(created_at, NOW()) FROM fail2counter.exploit_results;" \
        | sed 's/\t/,/g' > "$TMPDIR/exploit_results.csv" 2>/dev/null || true

    mysql -N -B -e "SELECT id, host_id, COALESCE(exploit_id, 0), COALESCE(notification_type, 'email'), COALESCE(status, 'pending'), COALESCE(contact_info, ''), COALESCE(message, ''), COALESCE(created_at, NOW()), sent_at FROM fail2counter.notifications;" \
        | sed 's/\t/,/g' > "$TMPDIR/notifications.csv" 2>/dev/null || true
fi

# Also check for legacy exploits table (old schema without scan_id)
HAS_LEGACY=$(mysql -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='fail2counter' AND table_name='exploits_legacy';" 2>/dev/null || echo "0")

echo "[*] Exported CSV files:"
ls -lh "$TMPDIR"/*.csv

# Import into PostgreSQL
echo "[*] Importing into PostgreSQL..."

# Truncate target tables in reverse dependency order
sudo -u postgres psql -d fail2counter -c "
    TRUNCATE notifications, exploit_results, exploits, services, ports, scans, hosts CASCADE;
"

# Import hosts
echo "[*] Importing hosts..."
sudo -u postgres psql -d fail2counter -c "\COPY hosts(id, ip_address, hostname, created_at) FROM '$TMPDIR/hosts.csv' WITH (FORMAT csv);"

# Import scans
echo "[*] Importing scans..."
sudo -u postgres psql -d fail2counter -c "\COPY scans(id, host_id, scan_time, scan_type, latency_seconds, duration_seconds, created_at) FROM '$TMPDIR/scans.csv' WITH (FORMAT csv);"

# Import ports
echo "[*] Importing ports..."
sudo -u postgres psql -d fail2counter -c "\COPY ports(id, scan_id, port_number, protocol, state) FROM '$TMPDIR/ports.csv' WITH (FORMAT csv);"

# Import services
echo "[*] Importing services..."
sudo -u postgres psql -d fail2counter -c "\COPY services(id, port_id, service_name, product, version, extra_info, is_ssl, recognized) FROM '$TMPDIR/services.csv' WITH (FORMAT csv);"

# Import new-schema exploit tables if they exist
if [ -s "$TMPDIR/exploits.csv" ] 2>/dev/null; then
    echo "[*] Importing exploits..."
    sudo -u postgres psql -d fail2counter -c "\COPY exploits(id, scan_id, host_id, module_path, rhosts, rport, rc_file_path, status, created_at) FROM '$TMPDIR/exploits.csv' WITH (FORMAT csv);"
fi

if [ -s "$TMPDIR/exploit_results.csv" ] 2>/dev/null; then
    echo "[*] Importing exploit_results..."
    sudo -u postgres psql -d fail2counter -c "\COPY exploit_results(id, exploit_id, output_text, exit_code, duration_seconds, created_at) FROM '$TMPDIR/exploit_results.csv' WITH (FORMAT csv);"
fi

if [ -s "$TMPDIR/notifications.csv" ] 2>/dev/null; then
    echo "[*] Importing notifications..."
    sudo -u postgres psql -d fail2counter -c "\COPY notifications(id, host_id, exploit_id, notification_type, status, contact_info, message, created_at, sent_at) FROM '$TMPDIR/notifications.csv' WITH (FORMAT csv);"
fi

# Reset sequences to max id + 1
echo "[*] Resetting sequences..."
sudo -u postgres psql -d fail2counter -c "
    SELECT setval('hosts_id_seq', COALESCE((SELECT MAX(id) FROM hosts), 0) + 1, false);
    SELECT setval('scans_id_seq', COALESCE((SELECT MAX(id) FROM scans), 0) + 1, false);
    SELECT setval('ports_id_seq', COALESCE((SELECT MAX(id) FROM ports), 0) + 1, false);
    SELECT setval('services_id_seq', COALESCE((SELECT MAX(id) FROM services), 0) + 1, false);
    SELECT setval('exploits_id_seq', COALESCE((SELECT MAX(id) FROM exploits), 0) + 1, false);
    SELECT setval('exploit_results_id_seq', COALESCE((SELECT MAX(id) FROM exploit_results), 0) + 1, false);
    SELECT setval('notifications_id_seq', COALESCE((SELECT MAX(id) FROM notifications), 0) + 1, false);
"

# Verify migration
PG_COUNT=$(sudo -u postgres psql -t -d fail2counter -c "SELECT COUNT(*) FROM hosts;" | tr -d ' ')
echo "[*] Verification: MySQL had $MYSQL_COUNT hosts, PostgreSQL now has $PG_COUNT hosts"

if [ "$PG_COUNT" -ge "$MYSQL_COUNT" ]; then
    echo "[*] Migration verified successfully"

    # Drop MySQL tables
    echo "[*] Dropping MySQL fail2counter tables..."
    mysql -e "DROP DATABASE IF EXISTS fail2counter;" 2>/dev/null || true
    echo "[*] MySQL fail2counter database dropped"

    # Mark migration complete
    touch "$MARKER"
    echo "[*] Migration complete. Marker written to $MARKER"
else
    echo "[ERROR] Row count mismatch! MySQL=$MYSQL_COUNT PostgreSQL=$PG_COUNT"
    echo "[ERROR] NOT dropping MySQL data. Investigate before retrying."
    echo "[ERROR] Remove $MARKER and fix the issue, then re-run."
    exit 1
fi

# Cleanup
rm -rf "$TMPDIR"
echo "[*] Done"
