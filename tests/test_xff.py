import importlib.util
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'src' / 'behavior_detector.py'
spec = importlib.util.spec_from_file_location('behavior_detector', MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

sample = {
    'id.orig_h': '10.70.184.2',
    'proxied': ['X-FORWARDED-FOR -> 149.102.243.44'],
}
r = mod.resolve_http_source(sample, {'10.70.184.2'})
assert r['src_ip'] == '149.102.243.44', r
assert r['original_src_ip'] == '149.102.243.44', r
assert r['observed_src_ip'] == '10.70.184.2', r
assert r['source_ip_source'] == 'x_forwarded_for', r

untrusted = mod.resolve_http_source(sample, set())
assert untrusted['src_ip'] == '10.70.184.2', untrusted
assert untrusted['original_src_ip'] is None, untrusted
assert untrusted['source_ip_source'] == 'zeek_id.orig_h', untrusted

chain = {
    'id.orig_h': '10.70.184.2',
    'proxied': ['X-FORWARDED-FOR -> 203.0.113.10, 10.70.184.3'],
}
r = mod.resolve_http_source(chain, {'10.70.184.2', '10.70.184.3'})
assert r['src_ip'] == '203.0.113.10', r
print('PASS: XFF source-IP resolution')
