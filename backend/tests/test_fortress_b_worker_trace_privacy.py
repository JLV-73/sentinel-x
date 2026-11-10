"""Worker rejection must not retain synthetic output in exception frames."""
import traceback
from unittest.mock import patch

import pytest
from app import fortress_mvp_api as api


@pytest.mark.parametrize('payload', [
    b'{"secret":"FAKE_WORKER_MARKER",',
    b'{"secret":"FAKE_WORKER_MARKER", "secret": 2}',
    b'{"outer":{"secret":"FAKE_WORKER_MARKER", "secret": 2}}',
    b'{"secret":"FAKE_WORKER_MARKER"}',
    b'FAKE_WORKER_MARKER' + b' ' * api._OUTPUT_LIMIT,
], ids=['invalid-json', 'duplicate', 'nested-duplicate', 'invalid-schema', 'oversize'])
def test_rejected_worker_output_not_retained(payload):
    target = 'https://example.invalid/'
    with patch.object(api, 'run_gated', return_value=payload):
        with pytest.raises(ValueError) as caught:
            api._run_live(target, target)
    exc = caught.value
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        captured = traceback.TracebackException.from_exception(exc, capture_locals=True)
        for frame in captured.stack:
            if frame.filename.replace('\\', '/').endswith('/app/fortress_mvp_api.py'):
                assert 'FAKE_WORKER_MARKER' not in repr(frame.locals)
        tb = exc.__traceback__
        while tb:
            if tb.tb_frame.f_code.co_filename.replace('\\', '/').endswith('/app/fortress_mvp_api.py'):
                assert 'FAKE_WORKER_MARKER' not in repr(tb.tb_frame.f_locals)
            tb = tb.tb_next
        assert 'FAKE_WORKER_MARKER' not in str(exc)
        # Walk both chains, even when a context is suppressed.
        assert exc.__cause__ is None and exc.__context__ is None
        exc = exc.__cause__ or exc.__context__
    assert api._LIVE_LOCK.acquire(blocking=False)
    api._LIVE_LOCK.release()
