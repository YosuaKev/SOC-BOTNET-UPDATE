#!/usr/bin/env bash
set -euo pipefail

VERSION="1.3.2-xff"
DEFAULT_TRUSTED_PROXY="10.70.184.2"
INSTALL_ROOT="/opt/zeek-botnet-detector"
SERVICE_NAME="zeek-behavior-detector.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_PY="$SCRIPT_DIR/src/behavior_detector.py"
REPO_DIR=""
TRUSTED_PROXIES=()

usage() {
  cat <<'EOF'
Usage:
  sudo ./apply-xff-update.sh [options]

Options:
  --trusted-proxy IP   Trusted WAF/reverse-proxy IP. Repeatable.
                       Default: 10.70.184.2
  --repo PATH          Also update PATH/src/behavior_detector.py in SOC-BOTNET source.
  --install-root PATH  Installed detector root. Default: /opt/zeek-botnet-detector
  -h, --help           Show help.

This update does NOT alter the RF model, threshold, Zeek package, Filebeat main
service, or Elasticsearch destination. It only replaces behavior_detector.py and
adds a systemd drop-in that tells the detector which proxy IPs may supply trusted
X-Forwarded-For data.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trusted-proxy)
      [[ $# -ge 2 ]] || { echo "ERROR: --trusted-proxy requires an IP" >&2; exit 2; }
      TRUSTED_PROXIES+=("$2")
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || { echo "ERROR: --repo requires a path" >&2; exit 2; }
      REPO_DIR="$2"
      shift 2
      ;;
    --install-root)
      [[ $# -ge 2 ]] || { echo "ERROR: --install-root requires a path" >&2; exit 2; }
      INSTALL_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run with sudo/root." >&2
  exit 1
fi

if [[ ${#TRUSTED_PROXIES[@]} -eq 0 ]]; then
  TRUSTED_PROXIES=("$DEFAULT_TRUSTED_PROXY")
fi

if [[ ! -f "$SOURCE_PY" ]]; then
  echo "ERROR: update payload missing: $SOURCE_PY" >&2
  exit 1
fi

python3 - "$SOURCE_PY" "${TRUSTED_PROXIES[@]}" <<'PY'
import ipaddress, py_compile, sys
src = sys.argv[1]
py_compile.compile(src, doraise=True)
for value in sys.argv[2:]:
    ipaddress.ip_address(value)
print("[OK] Python syntax and trusted-proxy IP validation passed")
PY

DEST_PY="$INSTALL_ROOT/src/behavior_detector.py"
if [[ ! -d "$INSTALL_ROOT/src" ]]; then
  echo "ERROR: existing installation not found at $INSTALL_ROOT/src" >&2
  echo "Run the base v1.3.1 installer first, or use install-v1.3.2.sh." >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
if [[ -f "$DEST_PY" ]]; then
  cp -a "$DEST_PY" "$DEST_PY.bak.$STAMP"
  echo "[OK] Backup: $DEST_PY.bak.$STAMP"
fi
install -m 0755 "$SOURCE_PY" "$DEST_PY"
echo "[OK] Installed XFF-aware behavior detector: $DEST_PY"

if [[ -n "$REPO_DIR" ]]; then
  REPO_DIR="$(readlink -f "$REPO_DIR")"
  if [[ ! -d "$REPO_DIR/src" ]]; then
    echo "ERROR: repo src directory not found: $REPO_DIR/src" >&2
    exit 1
  fi
  if [[ -f "$REPO_DIR/src/behavior_detector.py" ]]; then
    cp -a "$REPO_DIR/src/behavior_detector.py" "$REPO_DIR/src/behavior_detector.py.bak.$STAMP"
  fi
  install -m 0755 "$SOURCE_PY" "$REPO_DIR/src/behavior_detector.py"
  echo "[OK] Updated repository copy: $REPO_DIR/src/behavior_detector.py"
fi

DROPIN_DIR="/etc/systemd/system/${SERVICE_NAME}.d"
DROPIN_FILE="$DROPIN_DIR/20-trusted-xff.conf"
mkdir -p "$DROPIN_DIR"
TRUSTED_JOINED="$(IFS=,; echo "${TRUSTED_PROXIES[*]}")"
cat > "$DROPIN_FILE" <<EOF
[Service]
Environment="TRUSTED_PROXIES=$TRUSTED_JOINED"
EOF
chmod 0644 "$DROPIN_FILE"
echo "[OK] Trusted proxy configuration: $DROPIN_FILE"
echo "     TRUSTED_PROXIES=$TRUSTED_JOINED"

systemctl daemon-reload
if systemctl list-unit-files "$SERVICE_NAME" --no-legend 2>/dev/null | grep -q "$SERVICE_NAME"; then
  systemctl restart "$SERVICE_NAME"
  sleep 1
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "[OK] $SERVICE_NAME is active"
  else
    echo "ERROR: $SERVICE_NAME failed after update." >&2
    journalctl -u "$SERVICE_NAME" -n 60 --no-pager >&2 || true
    exit 1
  fi
else
  echo "WARNING: $SERVICE_NAME unit was not found; detector file is updated but service was not restarted." >&2
fi

echo
echo "Update complete: Zeek Botnet + Behavior installer $VERSION"
echo "HTTP behavior alerts now use trusted X-Forwarded-For as src_ip when available."
echo "The Zeek-observed proxy/firewall IP is retained as observed_src_ip/zeek_src_ip."
echo "Non-HTTP rules still use id.orig_h because X-Forwarded-For does not exist for those protocols."
