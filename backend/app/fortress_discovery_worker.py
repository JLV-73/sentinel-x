"""Windows-supervised discovery workers and fixed owned HTTPS laboratory.

The live and fixed laboratory modes are distinct. Live accepts only an exact
validated route scope; laboratory loopback overrides exist only in test code.
Windows Job native-failure, cross-session ACL and cancellation limits remain.
"""
import ctypes
from dataclasses import asdict
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from .fortress_job import run_gated, OutputLimitExceeded


class DiscoveryOutputLimitExceeded(RuntimeError):
    """The discovery result cannot be returned within the output budget."""

_lock = threading.Lock()


def _guard_network():
    """The private entry point is offline; only a separate test harness may replace this."""
    from . import fortress_discovery_transport as transport
    transport.socket.getaddrinfo = lambda *args: []
    def no_socket(*args, **kwargs):
        raise RuntimeError('network disabled in lab')
    transport.socket.socket = no_socket


def _discovery(data, *, observed=False):
    from . import fortress_discovery_policy as policy
    from . import fortress_discovery_transport as transport
    if set(data) != {'mode', 'origin', 'routes', 'start', 'limits'} or data['mode'] != ('observed_lab' if observed else 'discovery'):
        raise ValueError('invalid lab parameters')
    origin, routes, start = data['origin'], data['routes'], data['start']
    canonical = policy._origin(origin)
    if (canonical is None or not canonical[8:].split(':')[0].endswith('.invalid')
            or not isinstance(routes, list) or not routes or len(routes) > 20
            or any(not isinstance(r, str) or len(r) > 256 or policy._path(r) is None for r in routes)
            or not isinstance(start, str) or policy._route(start, '/', canonical, set(routes)) is None):
        raise ValueError('invalid lab scope')
    limits = policy.Limits(**data['limits'])
    _guard_network()
    if observed:
        return policy.discover_observed(origin, routes, start, transport.exchange_observed, limits=limits)
    return policy.discover(origin, routes, start, transport.exchange, limits=limits)


def _discovery_observed_lab(data):
    return _discovery(data, observed=True)


def validate_live_scope(target, routes):
    from . import fortress_discovery_policy as policy
    from . import fortress_discovery_transport as transport
    if (type(target) is not str or type(routes) is not list or not 1 <= len(routes) <= 20
            or any(type(r) is not str or len(r) > 256 or policy._path(r) is None
                   or r.lower().endswith(('.js', '.mjs', '.cjs', '.css')) for r in routes)
            or len(set(routes)) != len(routes)):
        raise ValueError('invalid scope')
    host, port, start, authority = transport._target(target)
    origin = policy._origin('https://' + authority)
    if origin is None or policy._route(start, '/', origin, set(routes)) is None:
        raise ValueError('invalid scope')
    from .fortress_discovery_policy import Limits
    payload = _live_payload(target, routes, Limits(seconds=110))
    if len(payload) > 2048:
        raise ValueError('invalid scope')
    return origin, start


def validate_dynamic_scope(target, routes, limits):
    from .fortress_discovery_policy import dynamic_limits
    dynamic_limits(limits)
    if type(routes) is not list or routes != ['/']:
        raise ValueError('invalid dynamic scope')
    origin, start = validate_live_scope(target, routes)
    if start != '/' or target != origin + '/':
        raise ValueError('invalid dynamic scope')
    return origin, start


def _live_payload(target, routes, limits, dynamic=False, private_view=False):
    data = {'mode': 'observed_dynamic' if dynamic else 'observed_live', 'target': target, 'routes': routes, 'limits': asdict(limits)}
    if private_view:
        data['private_view'] = True
    return json.dumps(data, ensure_ascii=True, allow_nan=False).encode('ascii')


def _discovery_observed_live(data):
    from . import fortress_discovery_policy as policy
    from . import fortress_discovery_transport as transport
    if (type(data) is not dict or set(data) not in ({'mode', 'target', 'routes', 'limits'}, {'mode', 'target', 'routes', 'limits', 'private_view'})
            or ('private_view' in data and type(data['private_view']) is not bool)
            or data['mode'] not in ('observed_live', 'observed_dynamic')):
        raise ValueError('invalid scope')
    dynamic = data['mode'] == 'observed_dynamic'
    origin, start = (validate_dynamic_scope(data['target'], data['routes'], data['limits']) if dynamic
                     else validate_live_scope(data['target'], data['routes']))
    limits = policy.dynamic_limits(data['limits']) if dynamic else policy.Limits(**data['limits'])
    events = []
    def exchange(url, cap, timeout):
        answer, event = transport.capture_observed(url, cap, timeout)
        events.append(event)
        return answer
    result = policy.discover_observed(origin, data['routes'], start, exchange, limits=limits, _live_paths=True, dynamic=dynamic, private_view=data.get('private_view') is True)
    # Sequential policy stops on an exchange without a page record.
    for page, event in zip(result['pages'], events):
        if '_tls' in event:
            page['tls'] = event['_tls']
    result['provenance'] = 'live'
    result['limits'].remove('lab_only')
    # The lab projection maps scope_blocked to unknown, but unsupported 2xx
    # responses also produce unknown and take priority over earlier exclusions.
    if (result['reason'] == 'unknown' and result['limits'][0] != 'excluded_links:0'
            and not any(page['state'] == 'incomplete' for page in result['pages'])):
        result['reason'] = 'scope_blocked'
    reason = result['reason']
    phase = {'none': 'none', 'scope_blocked': 'scope', 'redirect_blocked': 'scope',
             'redirect_loop': 'scope', 'http_refused': 'http', 'request_limit': 'budget',
             'page_limit': 'budget', 'byte_limit': 'budget', 'depth_limit': 'budget',
             'duration_limit': 'budget'}.get(reason, 'unknown')
    if reason in ('incomplete', 'transport_error') and events:
        phase = events[-1]['phase'] if events[-1]['phase'] != 'none' else 'unknown'
    if reason == 'duration_limit' and events and events[-1]['phase'] == 'timeout':
        phase = 'timeout'
    def total(key):
        values = [event[key] for event in events]
        return sum(values) if len(events) == result['requests'] and all(type(v) is int for v in values) else None
    result['diagnostic'] = {'phase': phase, 'requests_sent': total('requests_sent'),
                            'responses_received': total('responses_received')}
    from .fortress_discovery_contract import valid_live
    if not valid_live(result):
        raise ValueError('invalid worker result')
    return result


def run_observed_live(target, routes, limits=None, private_view=False):
    # Discard exception chains and all scope-bearing inner frames before raising.
    # This cannot erase frames already owned by callers.
    failure = None
    try:
        return _run_observed_live(target, routes, limits, private_view)
    except BlockingIOError:
        failure = 'busy'
    except OutputLimitExceeded:
        failure = 'capacity'
    except (ValueError, TypeError):
        failure = 'scope'
    except Exception:
        failure = 'worker'
    target = routes = limits = None
    if failure == 'busy':
        raise BlockingIOError('worker busy')
    if failure == 'capacity':
        raise DiscoveryOutputLimitExceeded('discovery output capacity exceeded; observations unavailable')
    if failure == 'scope':
        raise ValueError('invalid scope')
    raise RuntimeError('discovery worker unavailable')


def _run_observed_live(target, routes, requested_limits=None, private_view=False):
    from .fortress_discovery_policy import Limits, dynamic_limits
    from .fortress_discovery_contract import valid_live
    if type(private_view) is not bool:
        raise ValueError('invalid scope')
    dynamic = requested_limits is not None
    if dynamic:
        validate_dynamic_scope(target, routes, requested_limits)
        limits = dynamic_limits(requested_limits)
    else:
        validate_live_scope(target, routes)
        limits = Limits(seconds=110)
    payload = _live_payload(target, routes, limits, dynamic, private_view)
    if len(payload) > 2048:
        raise ValueError('invalid scope')
    if not _lock.acquire(blocking=False):
        raise BlockingIOError('worker busy')
    try:
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_discovery_worker import _child;raise SystemExit(_child())"
        raw = run_gated([sys.executable, '-I', '-c', code, backend], limits.seconds if dynamic else 120, payload, output_limit=262144)
        try:
            result = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError):
            result = None
        raw = None
        if (not valid_live(result) or ('private_paths' in result) != private_view or result['requests'] > (limits.requests if dynamic else min(len(routes), limits.requests))
                or len(result['pages']) > limits.requests or result['bytes'] > limits.total_bytes
                or result['bytes'] > result['requests'] * limits.page_bytes
                or (dynamic and (sum(p['state'] == 'complete' for p in result['pages']) > limits.pages
                                 or any(p['depth'] > limits.depth for p in result['pages'])))):
            result = None
            payload = target = routes = None
            raise RuntimeError('invalid worker result')
        return result
    finally:
        _lock.release()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _parse_result(raw, limits, route_count):
    # Do not propagate JSONDecodeError: it retains the entire document.
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {'pages', 'requests', 'bytes', 'complete', 'reason'}
                or any(type(value[k]) is not int or value[k] < 0 for k in ('pages', 'requests', 'bytes'))
                or type(value['complete']) is not bool or type(value['reason']) is not str
                or value['reason'] not in {'none', 'unknown', 'scope_blocked', 'page_limit', 'request_limit', 'byte_limit',
                    'duration_limit', 'transport_error', 'incomplete', 'redirect_blocked', 'redirect_loop',
                    'depth_limit', 'http_refused'}):
            return None
        pages, requests, size = value['pages'], value['requests'], value['bytes']
        reason = value['reason']
        if (pages > requests or pages > limits.pages or requests > limits.requests
                or requests > route_count or size > limits.total_bytes or size > requests * limits.page_bytes
                or value['complete'] != (reason == 'none')
                or (value['complete'] and pages == 0)
                or (reason == 'page_limit' and pages != limits.pages)
                or (reason == 'request_limit' and requests != limits.requests)
                or (reason in ('page_limit', 'request_limit') and requests >= route_count)
                or (reason in ('unknown', 'transport_error', 'incomplete', 'redirect_blocked', 'redirect_loop', 'http_refused')
                    and requests <= pages)
                or (reason == 'depth_limit' and pages == 0)
                or (reason == 'scope_blocked' and requests > 0 and pages == 0)
                or (requests == 0 and reason not in ('scope_blocked', 'duration_limit'))):
            return None
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None


def run_discovery_lab(origin, routes, start, *, limits, timeout):
    """Run offline discovery under a Windows job. No API or network overrides."""
    from .fortress_discovery_policy import Limits
    if (not isinstance(limits, Limits) or type(timeout) not in (int, float)
            or not math.isfinite(timeout) or not 0 < timeout <= 10):
        raise ValueError('invalid lab parameters')
    data = {'mode': 'discovery', 'origin': origin, 'routes': routes, 'start': start,
            'limits': asdict(limits)}
    payload = json.dumps(data, ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(payload) > 2048:
        raise ValueError('invalid lab parameters')
    if not _lock.acquire(blocking=False):
        raise RuntimeError('lab worker busy')
    try:
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_discovery_worker import _child;raise SystemExit(_child())"
        raw = run_gated([sys.executable, '-I', '-c', code, backend], timeout, payload)
        result = _parse_result(raw, limits, len(set(routes)) if isinstance(routes, list) and all(isinstance(r, str) for r in routes) else 0)
        del raw
        if result is None:
            raise RuntimeError('invalid lab result')
        return result
    finally:
        _lock.release()


def run_observed_lab(origin, routes, start, *, limits, timeout):
    """Offline-only observed adapter, supervised by the existing Windows Job."""
    from .fortress_discovery_policy import Limits
    from .fortress_discovery_contract import valid_lab
    if (not isinstance(limits, Limits) or type(timeout) not in (int, float)
            or not math.isfinite(timeout) or not 0 < timeout <= 10):
        raise ValueError('invalid lab parameters')
    data = {'mode': 'observed_lab', 'origin': origin, 'routes': routes, 'start': start,
            'limits': asdict(limits)}
    payload = json.dumps(data, ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(payload) > 2048:
        raise ValueError('invalid lab parameters')
    if not _lock.acquire(blocking=False):
        raise RuntimeError('lab worker busy')
    try:
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_discovery_worker import _child;raise SystemExit(_child())"
        raw = run_gated([sys.executable, '-I', '-c', code, backend], timeout, payload)
        try:
            result = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError):
            result = None
        raw = None
        if not valid_lab(result):
            raise RuntimeError('invalid lab result')
        return result
    finally:
        _lock.release()


def run_owned_https_lab():
    """Run the fixed owned TLS fixture only, inside the existing Windows Job."""
    if not _lock.acquire(blocking=False):
        raise BlockingIOError('lab busy')
    try:
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_discovery_worker import _child;raise SystemExit(_child())"
        raw = run_gated([sys.executable, '-I', '-c', code, backend], 120, b'{"mode":"owned_https_lab"}')
        try:
            result = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError):
            result = None
        raw = None
        from .fortress_discovery_contract import valid_lab
        if not valid_lab(result):
            raise RuntimeError('invalid lab result')
        return result
    finally:
        _lock.release()


def run_lab(mode, *, timeout, delay=0, marker=None):
    """Run one synthetic DNS operation; marker is a test-only file prefix.

    Timeout includes process startup and DNS, not necessarily cleanup time.
    On Windows native cleanup failure no safe subsequent execution is claimed.
    """
    if (mode not in ('dns_delay', 'descendant', 'dns_gate') or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
            or not 0 < timeout <= 10 or isinstance(delay, bool)
            or not isinstance(delay, (int, float)) or not math.isfinite(delay)
            or not 0 <= delay <= 5):
        raise ValueError('invalid lab parameters')
    if marker is not None and (not isinstance(marker, str) or not os.path.isabs(marker) or len(marker) > 512):
        raise ValueError('invalid marker')
    if mode == 'dns_gate' and marker is None:
        raise ValueError('invalid marker')
    if not _lock.acquire(blocking=False):
        raise RuntimeError('lab worker busy')
    try:
        payload = json.dumps({'mode': mode, 'delay': delay, 'marker': marker}, ensure_ascii=True).encode('ascii')
        backend = str(Path(__file__).resolve().parents[1])
        code = "import sys;sys.path.insert(0,sys.argv[1]);from app.fortress_discovery_worker import _child;raise SystemExit(_child())"
        raw = run_gated([sys.executable, '-I', '-c', code, backend], timeout, payload)
        valid = raw == b'{"error":"blocked","status":null,"decoded_bytes":null}'
        del raw
        if not valid:
            raise RuntimeError('invalid lab result')
        return {'error': 'blocked', 'status': None, 'decoded_bytes': None}
    finally:
        _lock.release()


def _child():
    if os.name != 'nt' or sys.stdin.buffer.readline(4) != b'GO\n':
        return 1
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    mutex = kernel.CreateMutexW(None, True, 'Global\\SentinelXDiscoveryLabWorkerV024')
    if not mutex or ctypes.get_last_error() == 183:
        return 1
    # Process termination releases this handle; it remains held during cleanup.
    raw = sys.stdin.buffer.read(2049)
    if len(raw) > 2048:
        return 1
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object)
        if data == {'mode': 'owned_https_lab'}:
            from .fortress_discovery_lab import run_lab as owned_lab
            from .fortress_discovery_contract import project_lab
            result = project_lab(owned_lab())
            sys.stdout.write(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
            return 0
        if isinstance(data, dict) and data.get('mode') in ('observed_live', 'observed_dynamic'):
            result = _discovery_observed_live(data)
            sys.stdout.write(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
            return 0
        if isinstance(data, dict) and data.get('mode') == 'observed_lab':
            result = _discovery_observed_lab(data)
            sys.stdout.write(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
            return 0
        if isinstance(data, dict) and data.get('mode') == 'discovery':
            result = _discovery(data)
            sys.stdout.write(json.dumps(result, separators=(',', ':'), ensure_ascii=True))
            return 0
        if set(data) != {'mode', 'delay', 'marker'} or data['mode'] not in ('dns_delay', 'descendant', 'dns_gate'):
            return 1
        delay, marker = data['delay'], data['marker']
        if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not 0 <= delay <= 5:
            return 1
        if marker is not None and (not isinstance(marker, str) or not os.path.isabs(marker) or len(marker) > 512):
            return 1
        if data['mode'] == 'dns_gate' and marker is None:
            return 1
        from . import fortress_discovery_transport as transport
        def synthetic_dns(*args):
            if marker:
                Path(marker + '.started').write_text('started', encoding='ascii')
            if data['mode'] == 'dns_gate':
                while not Path(marker + '.release').exists():
                    time.sleep(.02)
            if data['mode'] == 'descendant' and marker:
                code = "import pathlib,sys,time;pathlib.Path(sys.argv[2]+'.started').write_text('started');time.sleep(float(sys.argv[1]));pathlib.Path(sys.argv[2]).write_text('late')"
                subprocess.Popen([sys.executable, '-I', '-c', code, str(delay / 2), marker + '.descendant'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(delay)
            if marker:
                Path(marker + '.late').write_text('late', encoding='ascii')
            return []
        transport.socket.getaddrinfo = synthetic_dns
        # Defensive: an accidental change of resolver result still cannot connect.
        def no_socket(*args, **kwargs):
            raise RuntimeError('network disabled in lab')
        transport.socket.socket = no_socket
        result = transport.get('https://example.invalid/', timeout=8)
        if result != {'error': 'blocked', 'status': None, 'decoded_bytes': None}:
            return 1
        sys.stdout.buffer.write(b'{"error":"blocked","status":null,"decoded_bytes":null}')
        return 0
    except Exception:
        return 1
