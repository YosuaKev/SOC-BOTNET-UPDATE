#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR=""
TRUSTED_PROXIES=()
BASE_ARGS=()
SKIP_BASE=false

usage() {
  cat <<'EOF'
Zeek Botnet + Behavior v1.3.2 XFF wrapper

Fresh install using the existing SOC-BOTNET v1.3.1 repository:
  sudo ./install-v1.3.2.sh --repo /home/raka/SOC-BOTNET \
    --interface ens160 --trusted-proxy 10.70.184.2

Update an already-installed v1.3.1 VM only:
  sudo ./install-v1.3.2.sh --skip-base --repo /home/raka/SOC-BOTNET \
    --trusted-proxy 10.70.184.2

Options handled by this wrapper:
  --repo PATH
  --trusted-proxy IP     repeatable
  --skip-base            do not run the original repository install.sh

All other options are forwarded unchanged to the original SOC-BOTNET install.sh,
for example --interface ens160 or --skip-zeek-install.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || { echo "ERROR: --repo requires a path" >&2; exit 2; }
      REPO_DIR="$2"
      shift 2
      ;;
    --trusted-proxy)
      [[ $# -ge 2 ]] || { echo "ERROR: --trusted-proxy requires an IP" >&2; exit 2; }
      TRUSTED_PROXIES+=("$2")
      shift 2
      ;;
    --skip-base)
      SKIP_BASE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      BASE_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run with sudo/root." >&2
  exit 1
fi

if [[ -z "$REPO_DIR" ]]; then
  # Common case: this update folder was copied under or next to SOC-BOTNET.
  if [[ -f "$PWD/install.sh" && -d "$PWD/src" ]]; then
    REPO_DIR="$PWD"
  elif [[ -f "$SCRIPT_DIR/../install.sh" && -d "$SCRIPT_DIR/../src" ]]; then
    REPO_DIR="$(readlink -f "$SCRIPT_DIR/..")"
  fi
fi

if [[ "$SKIP_BASE" == false ]]; then
  if [[ -z "$REPO_DIR" || ! -f "$REPO_DIR/install.sh" ]]; then
    echo "ERROR: original SOC-BOTNET install.sh was not found." >&2
    echo "Use --repo /path/to/SOC-BOTNET or clone the repository first." >&2
    exit 1
  fi
  echo "[1/2] Running existing SOC-BOTNET base installer..."
  (cd "$REPO_DIR" && ./install.sh "${BASE_ARGS[@]}")
else
  echo "[1/2] Base installer skipped; applying update to current installation."
fi

echo "[2/2] Applying trusted X-Forwarded-For update..."
UPDATE_ARGS=()
if [[ -n "$REPO_DIR" ]]; then
  UPDATE_ARGS+=(--repo "$REPO_DIR")
fi
for proxy in "${TRUSTED_PROXIES[@]}"; do
  UPDATE_ARGS+=(--trusted-proxy "$proxy")
done
"$SCRIPT_DIR/apply-xff-update.sh" "${UPDATE_ARGS[@]}"

echo
echo "Done. Run: sudo $SCRIPT_DIR/verify-xff.sh"
