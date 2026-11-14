from urllib.parse import urlsplit

import pytest
from app import fortress_discovery_policy as policy


SENSITIVE = [
    '/user/profile', '/users', '/profile', '/account', '/private', '/secure',
    '/billing', '/auth', '/session', '/settings', '/cart', '/shop',
    '/commande', '/compte', '/orders', '/order', '/panier', '/paiement',
    '/facture', '/customer', '/client', '/address', '/messages',
    '/User/Profile', '/docs/user-profile.html', '/public/private_data',
    '/user~profile', '/%75ser/profile', '/user%2fprofile', '/user%252fprofile',
    '/profile?x=1', '/profile#section', '/profile\\details', '/x~delete', '/x~api',
]


def run(links, *, redirect=None):
    calls = []
    now = [0.0]
    def exchange(url, cap, timeout):
        calls.append(urlsplit(url).path)
        if redirect is not None:
            return {'status': 302, 'decoded_bytes': 0, 'links': [], 'location': redirect}
        return {'status': 200, 'decoded_bytes': 1, 'links': links if len(calls) == 1 else [], 'location': None}
    def sleep(delay):
        now[0] += delay
    limits = policy.Limits(pages=5, requests=10, depth=1, interval=1, page_bytes=1000, total_bytes=3000, seconds=20)
    result = policy.discover('https://example.invalid', ['/'], '/', exchange, limits=limits,
                             clock=lambda: now[0], sleep=sleep, dynamic=True)
    return calls, result


@pytest.mark.parametrize('path', SENSITIVE)
def test_sensitive_link_never_requested(path):
    calls, result = run([path, '/about', '/services.html'])
    assert calls == ['/', '/about', '/services.html']
    assert result['reason'] == 'scope_blocked'


@pytest.mark.parametrize('path', ['/private', '/user/profile', '/billing', 'https://outside.invalid/'])
def test_sensitive_or_cross_origin_redirect_stops(path):
    calls, result = run([], redirect=path)
    assert calls == ['/']
    assert result['reason'] == 'redirect_blocked'


def test_owned_tls_fixture_excludes_sensitive_links(monkeypatch):
    from app import fortress_discovery_lab as lab
    from app import fortress_discovery_transport as transport
    html = b'<a href="/user/profile">user</a><a href="/private">private</a><a href="/billing">billing</a><a href="/about">about</a><a href="/services.html">services</a><a href="https://outside.invalid/">outside</a>'
    monkeypatch.setattr(lab, '_ROUTES', {'/': (200, html), '/about': (200, b'about'), '/services.html': (200, b'services')})
    calls = []
    now = [0.0]
    def exchange(url, cap, timeout):
        path = urlsplit(url).path
        calls.append(path)
        status, response = lab._one_exchange(path)
        body = response.split(b'\r\n\r\n', 1)[1]
        parser = transport._Links(url, report_excluded=True)
        parser.feed(body.decode('utf-8'))
        return {'status': status, 'decoded_bytes': len(body), 'links': parser.links, 'location': None}
    def sleep(delay):
        now[0] += delay
    limits = policy.Limits(pages=5, requests=10, depth=1, interval=1, page_bytes=1000, total_bytes=3000, seconds=20)
    result = policy.discover('https://standard-lab.invalid', ['/'], '/', exchange, limits=limits,
                             clock=lambda: now[0], sleep=sleep, dynamic=True)
    assert calls == ['/', '/about', '/services.html']
    assert result['requests'] == 3 and result['pages'] == 3
    assert result['reason'] == 'scope_blocked'
