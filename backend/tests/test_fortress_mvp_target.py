import json
from app import fortress_mvp as m


def test_fixture_target_and_requested_route():
    for scenario in ('ok', 'forbidden', 'tls-error'):
        result = m.run_demo(scenario)
        assert result['target'] == 'https://standard-lab.invalid/'
        assert result['route'] == '/'
        assert 'fixture=secret' not in json.dumps(result)


def test_internal_target_redacts_path_query_and_never_resolves_for_this_test(monkeypatch):
    def stop(host, deadline):
        raise OSError('no network')
    monkeypatch.setattr(m, '_public_socket', stop)
    root = m.diagnose('https://example.org/', authorized=True)
    assert root['target'] == 'https://example.org/'
    assert root['route'] == '/'
    sensitive = m.diagnose('https://example.org/private-token?session=secret', authorized=True)
    assert sensitive['target'] == 'https://example.org/[redacted path]'
    assert sensitive['route'] == '[redacted route]'
    assert 'private-token' not in json.dumps(sensitive)
    assert 'secret' not in json.dumps(sensitive)
    assert m.diagnose('https://example.org/', authorized=False)['target'] is None
