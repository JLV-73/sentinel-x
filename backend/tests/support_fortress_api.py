"""Isolated test assembly; no production installation."""
from app.fortress_standard_contract import DraftFortressAdapter as _RealAdapter, _project
from app.fortress_checks import evaluate_findings


def fake_audit_result(payload):
    """Controlled test DTO, constructed without service, DNS or transport."""
    findings = []
    for index, _ in enumerate(payload['routes'], 1):
        for finding in evaluate_findings({}, route='[redacted route]', method='GET', date='2020-01-01'):
            finding['route_index'] = index
            finding['evidence_code'] = 'indeterminate'
            findings.append(finding)
    return {'audit_id': '00000000-0000-0000-0000-000000000000', 'mode': 'standard',
            'started_at': '2020-01-01T00:00:00', 'finished_at': '2020-01-01T00:00:00',
            'scope': {'origin': '[redacted]', 'paths': ['[redacted route]'] * len(payload['routes'])},
            'requests_used': 0, 'complete': False, 'findings': findings,
            'route_execution': [{'route_index': i, 'state': 'not_started'} for i in range(1, len(payload['routes']) + 1)],
            'limitations': ['Incomplete prototype: CORS and probes not performed; advisory assessment unavailable.']}


class DraftFortressAdapter(_RealAdapter):
    """Legacy test-only sentinel translation; real projection is still exercised."""
    async def _handle(self, scope, receive):
        sentinel = False
        def consumer(payload):
            nonlocal sentinel
            result = self.consumer(payload)
            if type(result) is dict and result == {'ok': True} and type(result['ok']) is bool:
                sentinel = True
                return fake_audit_result(payload)
            return result
        adapter = _RealAdapter(consumer, host=self.host, origin=self.origin, timeout=self.timeout)
        status, result = await adapter._handle(scope, receive)
        if sentinel and status == 200:
            return status, {'ok': True}
        return status, result


def make_qualification_app(consumer):
    """Assemble an isolated FastAPI contract for trusted tests only.

    This lives under tests and is not imported or mounted by the main app.
    The consumer is injected by Python code, never derived from an HTTP request.
    """
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.router.redirect_slashes = False
    adapter = _RealAdapter(consumer)

    @app.post('/api/fortress/audit')
    async def qualification_route(request: Request):
        status, result = await adapter._handle(request.scope, request.receive)
        return JSONResponse(status_code=status, content=result)

    return app