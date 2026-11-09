import unittest

from app.fortress_live import validate_url, parse_head


class LiveUnitTests(unittest.TestCase):
    def test_url_redacts_path_and_query(self):
        self.assertEqual(validate_url('https://example.com:8443/private?secret=1'),
                         ('example.com', 8443, '/private?secret=1', 'https://example.com:8443/'))

    def test_rejects_unsafe_urls(self):
        for url in ('http://example.com/', 'https://user@example.com/', 'https://127.0.0.1/',
                    'https://example.com/a\r\nHost:x', 'https://example.com/%xx',
                    'https://example.com/#fragment', 'https://localhost/', 'https://example.com:0/'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)

    def test_head_redirect_is_observation_not_followed(self):
        status, headers = parse_head(b'HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/\r\nContent-Security-Policy: x\r\n\r\n')
        self.assertEqual(status, 302)
        self.assertEqual(headers['csp'], 'present')
        self.assertEqual(headers['hsts'], 'absent')

    def test_malformed_header_rejected(self):
        with self.assertRaises(ValueError):
            parse_head(b'HTTP/1.1 200 OK\r\n bad-fold\r\n\r\n')
