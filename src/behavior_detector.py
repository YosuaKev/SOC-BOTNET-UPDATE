#!/usr/bin/env python3

import argparse
import ipaddress
import json
import math
import os
import re
import signal
import statistics
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_HTTP_LOG = "/opt/zeek/logs/current/http.log"
DEFAULT_CONN_LOG = "/opt/zeek/logs/current/conn.log"
DEFAULT_ALERT_LOG = "/opt/zeek-botnet-detector/logs/behavior_alerts.jsonl"

DEFAULT_WINDOW = 60
DEFAULT_HTTP_THRESHOLD = 20
DEFAULT_SSH_THRESHOLD = 10
DEFAULT_PORT_THRESHOLD = 15
DEFAULT_HOST_THRESHOLD = 15
DEFAULT_FLOOD_WINDOW = 10
DEFAULT_FLOOD_THRESHOLD = 100
DEFAULT_BEACON_WINDOW = 600
DEFAULT_BEACON_MIN_CONNECTIONS = 6
DEFAULT_BEACON_MIN_INTERVAL = 5.0
DEFAULT_BEACON_MAX_INTERVAL = 300.0
DEFAULT_BEACON_MAX_CV = 0.15
DEFAULT_COOLDOWN = 60
POLL_INTERVAL = 0.25
DEFAULT_TRUSTED_PROXIES = ("10.70.184.2",)

LOGIN_KEYWORDS = (
    "/login",
    "login.php",
    "/signin",
    "/sign-in",
    "/auth",
    "/authenticate",
    "/session",
    "/user/login",
    "wp-login.php",
)

XFF_RE = re.compile(r"^\s*X-FORWARDED-FOR\s*->\s*(.+?)\s*$", re.IGNORECASE)

_STOP = threading.Event()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json_line(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")
        fh.flush()


def parse_service(value):
    value = value.strip()
    if not value:
        raise ValueError("empty service")
    if value.startswith("["):
        host, sep, tail = value[1:].partition("]:")
        if not sep:
            raise ValueError(f"invalid service: {value}")
        return host, int(tail)
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ValueError(f"invalid service: {value}")
    return host, int(port)


def normalize_ip(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    # XFF may contain an IPv4 address with an appended port in non-standard deployments.
    if value.count(":") == 1 and "." in value:
        possible_ip, possible_port = value.rsplit(":", 1)
        if possible_port.isdigit():
            value = possible_ip
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_xff_values(event):
    """Return all syntactically valid IPs found in Zeek http.log `proxied` XFF entries."""
    proxied = event.get("proxied")
    if not isinstance(proxied, list):
        return [], None

    raw_value = None
    addresses = []
    for item in proxied:
        if not isinstance(item, str):
            continue
        match = XFF_RE.match(item)
        if not match:
            continue
        raw_value = match.group(1).strip()
        for token in raw_value.split(","):
            candidate = normalize_ip(token.strip())
            if candidate:
                addresses.append(candidate)
    return addresses, raw_value


def resolve_http_source(event, trusted_proxies):
    """
    Resolve the client address for an HTTP event.

    Security rule: X-Forwarded-For is used only when the TCP peer observed by Zeek
    (`id.orig_h`) is explicitly trusted. For an XFF chain, walk from right to left
    and discard trusted proxy hops, selecting the first remaining address.
    """
    observed = normalize_ip(event.get("id.orig_h")) or str(event.get("id.orig_h", "")).strip()
    result = {
        "src_ip": observed,
        "original_src_ip": None,
        "observed_src_ip": observed,
        "zeek_src_ip": observed,
        "proxy_ip": None,
        "source_ip_source": "zeek_id.orig_h",
        "xff_raw": None,
        "xff_chain": [],
    }

    if not observed or observed not in trusted_proxies:
        return result

    chain, raw_value = parse_xff_values(event)
    if not chain:
        return result

    candidate = None
    for address in reversed(chain):
        if address not in trusted_proxies:
            candidate = address
            break

    if not candidate:
        return result

    result.update({
        "src_ip": candidate,
        "original_src_ip": candidate,
        "observed_src_ip": observed,
        "zeek_src_ip": observed,
        "proxy_ip": observed,
        "source_ip_source": "x_forwarded_for",
        "xff_raw": raw_value,
        "xff_chain": chain,
    })
    return result


def conn_source_fields(event):
    observed = normalize_ip(event.get("id.orig_h")) or str(event.get("id.orig_h", "")).strip()
    return {
        "src_ip": observed,
        "original_src_ip": None,
        "observed_src_ip": observed,
        "zeek_src_ip": observed,
        "proxy_ip": None,
        "source_ip_source": "zeek_id.orig_h",
        "xff_raw": None,
        "xff_chain": [],
    }


def is_login_uri(uri):
    value = (uri or "").lower()
    return any(keyword in value for keyword in LOGIN_KEYWORDS)


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def event_ts(event):
    return safe_float(event.get("ts"), time.time())


class JsonTail:
    def __init__(self, path, label):
        self.path = path
        self.label = label
        self._fh = None
        self._inode = None
        self._announced_wait = False

    def close(self):
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass
        self._fh = None
        self._inode = None

    def _open_if_available(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            if not self._announced_wait:
                print(f"[WAIT] {self.label} not available: {self.path}", flush=True)
                self._announced_wait = True
            self.close()
            return False

        if self._fh is not None and self._inode == st.st_ino:
            return True

        self.close()
        self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
        self._inode = st.st_ino
        self._fh.seek(0, os.SEEK_END)
        self._announced_wait = False
        print(f"[OPEN] {self.label}: {self.path}", flush=True)
        return True

    def read_line(self):
        if not self._open_if_available():
            return None

        line = self._fh.readline()
        if line:
            return line

        try:
            st = os.stat(self.path)
            if st.st_ino != self._inode or st.st_size < self._fh.tell():
                self.close()
        except FileNotFoundError:
            self.close()
        return None


class BehaviorDetector:
    def __init__(self, args):
        self.args = args
        self.trusted_proxies = set(args.trusted_proxy)
        self.ignore_services = {parse_service(v) for v in args.ignore_service}
        self.lock = threading.Lock()

        self.http_events = defaultdict(deque)
        self.ssh_events = defaultdict(deque)
        self.port_events = defaultdict(deque)
        self.host_events = defaultdict(deque)
        self.flood_events = defaultdict(deque)
        self.beacon_events = defaultdict(deque)
        self.last_alert = {}

    def ignored_service(self, event):
        dst_ip = normalize_ip(event.get("id.resp_h")) or str(event.get("id.resp_h", "")).strip()
        dst_port = safe_int(event.get("id.resp_p"), -1)
        return (dst_ip, dst_port) in self.ignore_services

    def cooldown_ok(self, key, now):
        last = self.last_alert.get(key, 0.0)
        if now - last < self.args.cooldown:
            return False
        self.last_alert[key] = now
        return True

    @staticmethod
    def trim_queue(queue, cutoff):
        while queue and queue[0] < cutoff:
            queue.popleft()

    def emit(self, alert):
        alert.setdefault("event_time_utc", utc_now())
        alert.setdefault("detector_mode", "shadow")
        alert.setdefault("log_type", "zeek_behavior_alert")
        alert.setdefault("event_dataset", "capstone.zeek_behavior")
        write_json_line(self.args.alert_log, alert)
        src = alert.get("src_ip") or "?"
        observed = alert.get("observed_src_ip") or "?"
        suffix = ""
        if src != observed:
            suffix = f" (observed via proxy {observed})"
        print(f"[ALERT] {alert['alert_type']} source={src}{suffix}", flush=True)

    def process_http(self, event):
        if self.ignored_service(event):
            return
        method = str(event.get("method", "")).upper()
        uri = str(event.get("uri", ""))
        if method != "POST" or not is_login_uri(uri):
            return

        source = resolve_http_source(event, self.trusted_proxies)
        src_ip = source["src_ip"]
        if not src_ip:
            return

        now = event_ts(event)
        key = (src_ip, str(event.get("host", "")), uri.split("?", 1)[0])
        queue = self.http_events[key]
        queue.append(now)
        self.trim_queue(queue, now - self.args.window)

        if len(queue) < self.args.http_threshold:
            return
        cooldown_key = ("HTTP_BRUTE_FORCE",) + key
        if not self.cooldown_ok(cooldown_key, now):
            return

        alert = {
            "alert_type": "HTTP_BRUTE_FORCE",
            "severity": "HIGH",
            **source,
            "src_port": safe_int(event.get("id.orig_p"), 0),
            "dst_ip": str(event.get("id.resp_h", "")),
            "dst_port": safe_int(event.get("id.resp_p"), 0),
            "proto": "tcp",
            "uid": event.get("uid"),
            "host": event.get("host"),
            "uri": uri,
            "method": method,
            "user_agent": event.get("user_agent"),
            "attempts": len(queue),
            "window_seconds": self.args.window,
            "threshold": self.args.http_threshold,
            "zeek_ts": now,
        }
        self.emit(alert)

    def process_conn(self, event):
        if self.ignored_service(event):
            return
        proto = str(event.get("proto", "")).lower()
        if proto not in {"tcp", "udp"}:
            return
        source = conn_source_fields(event)
        src_ip = source["src_ip"]
        if not src_ip:
            return
        dst_ip = str(event.get("id.resp_h", ""))
        dst_port = safe_int(event.get("id.resp_p"), 0)
        now = event_ts(event)

        self._check_ssh(event, source, src_ip, dst_ip, dst_port, proto, now)
        self._check_port_scan(event, source, src_ip, dst_ip, dst_port, proto, now)
        self._check_host_scan(event, source, src_ip, dst_ip, dst_port, proto, now)
        self._check_flood(event, source, src_ip, dst_ip, dst_port, proto, now)
        self._check_beacon(event, source, src_ip, dst_ip, dst_port, proto, now)

    def _base_conn_alert(self, event, source, dst_ip, dst_port, proto, now):
        return {
            **source,
            "src_port": safe_int(event.get("id.orig_p"), 0),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "uid": event.get("uid"),
            "conn_state": event.get("conn_state"),
            "history": event.get("history"),
            "zeek_ts": now,
        }

    def _check_ssh(self, event, source, src_ip, dst_ip, dst_port, proto, now):
        if proto != "tcp" or dst_port != 22:
            return
        key = (src_ip, dst_ip)
        queue = self.ssh_events[key]
        queue.append(now)
        self.trim_queue(queue, now - self.args.window)
        if len(queue) < self.args.ssh_threshold:
            return
        cooldown_key = ("SSH_BRUTE_FORCE",) + key
        if not self.cooldown_ok(cooldown_key, now):
            return
        alert = self._base_conn_alert(event, source, dst_ip, dst_port, proto, now)
        alert.update({
            "alert_type": "SSH_BRUTE_FORCE",
            "severity": "HIGH",
            "attempts": len(queue),
            "window_seconds": self.args.window,
            "threshold": self.args.ssh_threshold,
            "note": "Suspected SSH brute-force behavior based on repeated TCP/22 connections; authentication failures are not verified by Zeek conn.log.",
        })
        self.emit(alert)

    def _check_port_scan(self, event, source, src_ip, dst_ip, dst_port, proto, now):
        key = (src_ip, dst_ip)
        queue = self.port_events[key]
        queue.append((now, dst_port))
        cutoff = now - self.args.window
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        ports = {port for _, port in queue if port > 0}
        if len(ports) < self.args.port_threshold:
            return
        cooldown_key = ("PORT_SCAN",) + key
        if not self.cooldown_ok(cooldown_key, now):
            return
        alert = self._base_conn_alert(event, source, dst_ip, dst_port, proto, now)
        alert.update({
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "unique_ports": len(ports),
            "ports_sample": sorted(ports)[:50],
            "window_seconds": self.args.window,
            "threshold": self.args.port_threshold,
        })
        self.emit(alert)

    def _check_host_scan(self, event, source, src_ip, dst_ip, dst_port, proto, now):
        key = src_ip
        queue = self.host_events[key]
        queue.append((now, dst_ip))
        cutoff = now - self.args.window
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        hosts = {host for _, host in queue if host}
        if len(hosts) < self.args.host_threshold:
            return
        cooldown_key = ("HOST_SCAN", src_ip)
        if not self.cooldown_ok(cooldown_key, now):
            return
        alert = self._base_conn_alert(event, source, dst_ip, dst_port, proto, now)
        alert.update({
            "alert_type": "HOST_SCAN",
            "severity": "HIGH",
            "unique_hosts": len(hosts),
            "hosts_sample": sorted(hosts)[:50],
            "window_seconds": self.args.window,
            "threshold": self.args.host_threshold,
        })
        self.emit(alert)

    def _check_flood(self, event, source, src_ip, dst_ip, dst_port, proto, now):
        key = src_ip
        queue = self.flood_events[key]
        queue.append(now)
        self.trim_queue(queue, now - self.args.flood_window)
        if len(queue) < self.args.flood_threshold:
            return
        cooldown_key = ("CONNECTION_FLOOD", src_ip)
        if not self.cooldown_ok(cooldown_key, now):
            return
        alert = self._base_conn_alert(event, source, dst_ip, dst_port, proto, now)
        alert.update({
            "alert_type": "CONNECTION_FLOOD",
            "severity": "HIGH",
            "connections": len(queue),
            "window_seconds": self.args.flood_window,
            "threshold": self.args.flood_threshold,
        })
        self.emit(alert)

    def _check_beacon(self, event, source, src_ip, dst_ip, dst_port, proto, now):
        if not dst_ip or dst_port <= 0:
            return
        key = (src_ip, dst_ip, dst_port, proto)
        queue = self.beacon_events[key]
        queue.append(now)
        self.trim_queue(queue, now - self.args.beacon_window)
        if len(queue) < self.args.beacon_min_connections:
            return

        times = list(queue)
        intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < self.args.beacon_min_connections - 1:
            return
        mean_interval = statistics.fmean(intervals)
        if not (self.args.beacon_min_interval <= mean_interval <= self.args.beacon_max_interval):
            return
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean_interval if mean_interval > 0 else math.inf
        if cv > self.args.beacon_max_cv:
            return

        cooldown_key = ("BEACONING",) + key
        if not self.cooldown_ok(cooldown_key, now):
            return
        alert = self._base_conn_alert(event, source, dst_ip, dst_port, proto, now)
        alert.update({
            "alert_type": "BEACONING",
            "severity": "MEDIUM",
            "connections": len(queue),
            "observation_window_seconds": self.args.beacon_window,
            "mean_interval_seconds": round(mean_interval, 6),
            "interval_stdev_seconds": round(stdev, 6),
            "interval_cv": round(cv, 6),
            "max_cv": self.args.beacon_max_cv,
        })
        self.emit(alert)


def load_env_trusted_proxies():
    raw = os.getenv("TRUSTED_PROXIES", "")
    values = []
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        ip = normalize_ip(token)
        if ip:
            values.append(ip)
    return values


def parse_args():
    parser = argparse.ArgumentParser(description="Zeek behavior detector with trusted X-Forwarded-For support")
    parser.add_argument("--http-log", default=DEFAULT_HTTP_LOG)
    parser.add_argument("--conn-log", default=DEFAULT_CONN_LOG)
    parser.add_argument("--alert-log", default=DEFAULT_ALERT_LOG)
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    parser.add_argument("--http-threshold", type=int, default=DEFAULT_HTTP_THRESHOLD)
    parser.add_argument("--ssh-threshold", type=int, default=DEFAULT_SSH_THRESHOLD)
    parser.add_argument("--port-threshold", type=int, default=DEFAULT_PORT_THRESHOLD)
    parser.add_argument("--host-threshold", type=int, default=DEFAULT_HOST_THRESHOLD)
    parser.add_argument("--flood-window", type=int, default=DEFAULT_FLOOD_WINDOW)
    parser.add_argument("--flood-threshold", type=int, default=DEFAULT_FLOOD_THRESHOLD)
    parser.add_argument("--beacon-window", type=int, default=DEFAULT_BEACON_WINDOW)
    parser.add_argument("--beacon-min-connections", type=int, default=DEFAULT_BEACON_MIN_CONNECTIONS)
    parser.add_argument("--beacon-min-interval", type=float, default=DEFAULT_BEACON_MIN_INTERVAL)
    parser.add_argument("--beacon-max-interval", type=float, default=DEFAULT_BEACON_MAX_INTERVAL)
    parser.add_argument("--beacon-max-cv", type=float, default=DEFAULT_BEACON_MAX_CV)
    parser.add_argument("--cooldown", type=int, default=DEFAULT_COOLDOWN)
    parser.add_argument("--trusted-proxy", action="append", default=[], help="Trusted direct proxy/WAF IP; repeatable")
    parser.add_argument("--ignore-service", action="append", default=[], help="Ignore destination service IP:PORT; repeatable")
    args = parser.parse_args()

    merged = []
    configured = load_env_trusted_proxies() + args.trusted_proxy
    if not configured:
        configured = list(DEFAULT_TRUSTED_PROXIES)
    for value in configured:
        ip = normalize_ip(value)
        if ip and ip not in merged:
            merged.append(ip)
    args.trusted_proxy = merged
    return args


def follow_http(detector):
    tail = JsonTail(detector.args.http_log, "http.log")
    try:
        while not _STOP.is_set():
            line = tail.read_line()
            if line is None:
                _STOP.wait(POLL_INTERVAL)
                continue
            try:
                event = json.loads(line)
                detector.process_http(event)
            except json.JSONDecodeError:
                continue
            except Exception as exc:
                print(f"[WARN] http event error: {exc}", flush=True)
    finally:
        tail.close()


def follow_conn(detector):
    tail = JsonTail(detector.args.conn_log, "conn.log")
    try:
        while not _STOP.is_set():
            line = tail.read_line()
            if line is None:
                _STOP.wait(POLL_INTERVAL)
                continue
            try:
                event = json.loads(line)
                detector.process_conn(event)
            except json.JSONDecodeError:
                continue
            except Exception as exc:
                print(f"[WARN] conn event error: {exc}", flush=True)
    finally:
        tail.close()


def main():
    args = parse_args()
    Path(args.alert_log).parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80, flush=True)
    print("ZEEK BEHAVIOR DETECTOR - SHADOW MODE - XFF ORIGINAL CLIENT IP", flush=True)
    print("=" * 80, flush=True)
    print(f"HTTP log            : {args.http_log}", flush=True)
    print(f"Connection log      : {args.conn_log}", flush=True)
    print(f"Alert log           : {args.alert_log}", flush=True)
    print(f"Trusted proxies     : {', '.join(args.trusted_proxy) if args.trusted_proxy else '(none)'}", flush=True)
    print(f"Window              : {args.window} seconds", flush=True)
    print(f"HTTP threshold      : {args.http_threshold} POST login requests", flush=True)
    print(f"SSH threshold       : {args.ssh_threshold} TCP/22 connections", flush=True)
    print(f"Port threshold      : {args.port_threshold} unique ports", flush=True)
    print(f"Host threshold      : {args.host_threshold} unique hosts", flush=True)
    print(f"Flood threshold     : {args.flood_threshold}/{args.flood_window}s", flush=True)
    print(f"Beacon              : n>={args.beacon_min_connections}, interval={args.beacon_min_interval}-{args.beacon_max_interval}s, CV<={args.beacon_max_cv}", flush=True)
    print(f"Cooldown            : {args.cooldown} seconds", flush=True)
    print("=" * 80, flush=True)

    detector = BehaviorDetector(args)

    def stop_handler(signum, frame):
        _STOP.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    threads = [
        threading.Thread(target=follow_http, args=(detector,), name="http-follower", daemon=True),
        threading.Thread(target=follow_conn, args=(detector,), name="conn-follower", daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        while not _STOP.wait(1.0):
            pass
    finally:
        for thread in threads:
            thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
