import copy
from app.fortress_live import result
from app.fortress_advanced_core import analyze_head_facts
from app.fortress_mvp_api import _valid_observation


def test_worker_facts_are_required_and_consistent_with_legacy():
    out = result('https://example.invalid/')
    out['tls'] = {'certificate': 'verified', 'hostname': 'verified', 'protocol': 'TLSv1.3', 'not_before': 'Jan  1 00:00:00 2025 GMT', 'not_after': 'Jan  1 00:00:00 2030 GMT'}
    out['http_status'] = 200
    out['failure_code'] = 'none'
    out['headers'] = {key: 'absent' for key in out['headers']}
    out['advanced'] = analyze_head_facts(b'HTTP/1.1 200 OK\r\n\r\n')
    assert _valid_observation(out, out['target'])
    for mutate in ('missing', 'status', 'hsts', 'version', 'extra'):
        bad = copy.deepcopy(out)
        if mutate == 'missing': bad['advanced'] = None
        if mutate == 'status': bad['advanced']['observations']['http_status'] = 403
        if mutate == 'hsts': bad['headers']['hsts'] = 'present'
        if mutate == 'version': bad['advanced']['schema_version'] = 'fortress.head-facts/2'
        if mutate == 'extra': bad['advanced']['secret'] = 'FAKE_SECRET'
        assert not _valid_observation(bad, out['target']), mutate
