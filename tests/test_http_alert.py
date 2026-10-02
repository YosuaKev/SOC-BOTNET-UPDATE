import importlib.util
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

MODULE = Path(__file__).resolve().parents[1] / 'src' / 'behavior_detector.py'
spec = importlib.util.spec_from_file_location('behavior_detector', MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory() as td:
    alert_log = str(Path(td) / 'behavior_alerts.jsonl')
    args = SimpleNamespace(
        trusted_proxy=['10.70.184.2'],
        ignore_service=[],
        alert_log=alert_log,
        cooldown=60,
        window=60,
        http_threshold=2,
        ssh_threshold=10,
        port_threshold=15,
        host_threshold=15,
        flood_window=10,
        flood_threshold=100,
        beacon_window=600,
        beacon_min_connections=6,
        beacon_min_interval=5.0,
        beacon_max_interval=300.0,
        beacon_max_cv=0.15,
    )
    d = mod.BehaviorDetector(args)
    base = {
        'id.orig_h': '10.70.184.2',
        'id.orig_p': 32720,
        'id.resp_h': '10.70.184.24',
        'id.resp_p': 80,
        'method': 'POST',
        'host': 'ejournal3.undip.ac.id',
        'uri': '/index.php/jfrumt/login',
        'user_agent': 'test',
        'proxied': ['X-FORWARDED-FOR -> 88.223.209.120'],
    }
    for i, ts in enumerate((1000.0, 1001.0), start=1):
        event = dict(base, ts=ts, uid=f'C{i}')
        d.process_http(event)

    lines = Path(alert_log).read_text().splitlines()
    assert len(lines) == 1, lines
    alert = json.loads(lines[0])
    assert alert['src_ip'] == '88.223.209.120', alert
    assert alert['original_src_ip'] == '88.223.209.120', alert
    assert alert['observed_src_ip'] == '10.70.184.2', alert
    assert alert['source_ip_source'] == 'x_forwarded_for', alert
    assert alert['alert_type'] == 'HTTP_BRUTE_FORCE', alert
    print('PASS: HTTP alert uses original XFF client IP and preserves observed proxy IP')
