import ssl
import time
from app.fortress_live import exchange_connected, result


def test_partial_response_timeout_is_closed_without_exception_or_raw_output():
    class TLS:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def settimeout(self, _): pass
        def do_handshake(self): pass
        def getpeercert(self): return {'notBefore': 'Jan  1 00:00:00 2025 GMT', 'notAfter': 'Jan  1 00:00:00 2030 GMT'}
        def version(self): return 'TLSv1.3'
        def sendall(self, _): pass
        def recv(self, _):
            if not hasattr(self, 'sent'):
                self.sent = True
                return b'HTTP/1.1 200 OK\r\nSet-Cookie: PRIVATE_MARKER=secret'
            raise TimeoutError('PRIVATE_MARKER')
    class Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        def wrap_socket(self, *args, **kwargs): return TLS()
    class Socket:
        def settimeout(self, _): pass
    out = result('https://example.invalid/')
    exchange_connected(Socket(), 'example.invalid', 'example.invalid', '/', Context(), time.monotonic()+5, out)
    assert out['failure_code'] == 'timeout'
    assert out['http_status'] is None and out['advanced'] is None
    assert 'PRIVATE_MARKER' not in repr(out)
