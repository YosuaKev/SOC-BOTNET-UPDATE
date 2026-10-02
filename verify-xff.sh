#!/usr/bin/env bash
set -euo pipefail

SERVICE="zeek-behavior-detector.service"
INSTALL_ROOT="/opt/zeek-botnet-detector"
PY="$INSTALL_ROOT/src/behavior_detector.py"
ALERT_LOG="$INSTALL_ROOT/logs/behavior_alerts.jsonl"

printf '%s\n' '=== XFF ORIGINAL CLIENT IP VERIFICATION ==='

if [[ -f "$PY" ]]; then
  echo "[OK] behavior_detector.py exists"
  python3 -m py_compile "$PY"
  grep -q 'x_forwarded_for' "$PY" && echo "[OK] XFF code present"
else
  echo "[FAIL] Missing $PY"
fi

echo
echo "Trusted proxy systemd configuration:"
systemctl show "$SERVICE" -p Environment --no-pager 2>/dev/null || true

echo
echo "Service status:"
if systemctl is-active --quiet "$SERVICE"; then
  echo "[OK] $SERVICE active"
else
  echo "[FAIL] $SERVICE not active"
fi

echo
echo "Recent service log:"
journalctl -u "$SERVICE" -n 25 --no-pager 2>/dev/null || true

HTTP_LOG=""
for candidate in \
  /opt/zeek/logs/current/http.log \
  /var/log/zeek/logs/current/http.log \
  /var/log/zeek/current/http.log; do
  if [[ -f "$candidate" ]]; then
    HTTP_LOG="$candidate"
    break
  fi
done

if [[ -n "$HTTP_LOG" ]]; then
  echo
echo "Zeek HTTP log: $HTTP_LOG"
  echo "Recent requests containing X-Forwarded-For:"
  tail -n 5000 "$HTTP_LOG" 2>/dev/null | jq -c 'select(.proxied != null) | {observed_src_ip:."id.orig_h",proxied:.proxied,host:.host,uri:.uri}' 2>/dev/null | tail -n 5 || true
else
  echo
echo "[WARN] http.log not found in known locations."
fi

if [[ -f "$ALERT_LOG" ]]; then
  echo
echo "Recent behavior alerts with source-IP fields:"
  tail -n 50 "$ALERT_LOG" | jq -c '{alert_type,src_ip,original_src_ip,observed_src_ip,source_ip_source,host,uri}' 2>/dev/null | tail -n 10 || true
else
  echo
echo "[INFO] No behavior alert file yet: $ALERT_LOG"
fi

echo
echo "Expected for HTTP behind trusted proxy:"
echo '  src_ip            = original client IP from X-Forwarded-For'
echo '  original_src_ip   = original client IP from X-Forwarded-For'
echo '  observed_src_ip   = firewall/WAF IP observed by Zeek'
echo '  source_ip_source  = x_forwarded_for'
