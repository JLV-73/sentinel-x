"""Internal-only input translation; does not execute, mount or authorize an audit.

Accept raw JSON text so duplicate keys cannot be lost before validation. The
caller must independently verify authorization and protect the returned URL.
"""
import json

from .fortress_service import _validate
from .fortress_transport import _parse

__all__ = ('prepare_single_scope', 'SingleScopeError')


class SingleScopeError(ValueError):
    """Redacted refusal of a single-scope request."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def prepare_single_scope(raw_json):
    """Translate exact JSON fields url, authorized and method into audit schema.

    authorized=true attests permission and safe use of this exact GET route.
    This pure guard does no DNS or network I/O and never invokes an audit.
    """
    try:
        if type(raw_json) is not str or len(raw_json) > 8192:
            raise ValueError()
        value = json.loads(raw_json, object_pairs_hook=_unique_object)
        if (type(value) is not dict or set(value) != {'url', 'authorized', 'method'}
                or value['authorized'] is not True or type(value['url']) is not str
                or type(value['method']) is not str or value['method'] != 'GET'):
            raise ValueError()
        url = value['url']
        if '?' in url or _parse(url)[0][0] != 'https':
            raise ValueError()
        result = {'level': 'standard', 'authorized': True, 'routes': [
            {'url': url, 'safe_use_confirmed': True, 'methods': ['GET'],
             'cors_get': False, 'parameters': []}]}
        _validate(result, 'en')
        return result
    except Exception:
        # Leave the handler before raising, so parser exceptions (and their raw
        # JSON documents) are not retained as the refusal's hidden context.
        pass
    # A traceback can retain this frame; do not retain request data in it.
    raw_json = value = url = result = None
    raise SingleScopeError('invalid single scope') from None
