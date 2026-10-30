#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1. Scanning a clean fixture home ==="
python3 scan.py --home fixtures/clean_home --tmp fixtures/clean_home --skip-crontab
clean_status=$?
echo "exit code: $clean_status"
echo

echo "=== 2. Scanning a fixture home with the documented IOCs planted ==="
set +e
python3 scan.py --home fixtures/compromised_home --tmp fixtures/compromised_tmp --skip-crontab
compromised_status=$?
set -e
echo "exit code: $compromised_status"
echo

echo "=== 3. Scanning this machine's real home (informational) ==="
python3 scan.py || true
