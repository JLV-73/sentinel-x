"""Private, lossy route projection; even a generic word can itself be secret.

This is an optional in-memory API output, never a shareable-report input.
Depth and collisions remain visible; whitelist membership is not a secrecy proof.
"""
from urllib.parse import urlsplit

WORDS = frozenset({'about', 'contact', 'services', 'products', 'team', 'news', 'blog',
                   'faq', 'pricing', 'legal', 'privacy', 'terms', 'help'})
MASK = '[masqué]'
MAX_DEPTH = 8


def project(path):
    try:
        path = urlsplit(path).path
        if not path.startswith('/'):
            return '/' + MASK
        parts = path[1:].split('/') if path != '/' else []
        if len(parts) > MAX_DEPTH:
            parts = parts[:MAX_DEPTH - 1] + [MASK]
        return '/' + '/'.join(p if p in WORDS else MASK for p in parts)
    except (TypeError, ValueError):
        return '/' + MASK


def valid_path(path):
    if type(path) is not str or not path.startswith('/'):
        return False
    if path == '/':
        return True
    parts = path[1:].split('/')
    return len(parts) <= MAX_DEPTH and all(p in WORDS or p == MASK for p in parts)
