import json
import traceback

import pytest

from app import fortress_advanced_adapters as adapters


@pytest.mark.parametrize('name', ['adapt_fixture', 'adapt_live', 'adapt_imported'])
def test_rejected_input_never_escapes_in_result_or_traceback(name, monkeypatch):
    marker = 'SYNTHETIC_PRIVATE_MARKER_84920'

    def invalid():
        return {'untrusted': marker}

    # Internal validator faults may themselves contain untrusted data.
    def broken_validator(_):
        raise ValueError(marker)

    for inject_fault in (False, True):
        if inject_fault:
            monkeypatch.setattr(adapters, 'validate_report', broken_validator)
        try:
            outcome = getattr(adapters, name)(invalid())
        except Exception as exc:
            captured = ''.join(traceback.TracebackException.from_exception(exc, capture_locals=True).format())
            # Check only adapter frames: this caller necessarily retains marker.
            internal = ''.join(''.join(frame.locals.values()) for frame in traceback.TracebackException.from_exception(exc, capture_locals=True).stack if 'fortress_advanced_adapters.py' in frame.filename)
            assert marker not in internal, captured
            pytest.fail('adapter must return a closed rejection, not raise')
        assert outcome == {'error': 'invalid_sanitized_report'}
        assert marker not in json.dumps(outcome)
        assert not adapters.validate_adapter(outcome)

        # A downstream failure cannot retain already-returned adapter frames.
        def later_failure(value):
            assert value == {'error': 'invalid_sanitized_report'}
            raise RuntimeError('downstream failure')

        try:
            later_failure(outcome)
        except RuntimeError as exc:
            trace = traceback.TracebackException.from_exception(exc, capture_locals=True)
            assert marker not in str(trace)
            frames = [frame for frame in trace.stack if frame.name == 'later_failure' or 'fortress_advanced_adapters.py' in frame.filename]
            assert all('fortress_advanced_adapters.py' not in frame.filename for frame in frames)
            assert marker not in repr([frame.locals for frame in frames])


def test_parser_valueerror_cause_is_not_reliably_classified(monkeypatch):
    from app import fortress_advanced_core as core

    def internal_fault(_):
        raise ValueError('synthetic internal error')

    monkeypatch.setattr(core, 'parse_head', internal_fault)
    result = core.analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    assert result['execution']['state'] == 'incomplete'
    assert result['observations'] == core.empty()
    assert result['findings'] == []
    assert core.validate_report(result)
