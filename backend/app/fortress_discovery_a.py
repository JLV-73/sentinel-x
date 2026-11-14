"""Experimental offline HTML summary; no network transport or API integration.

Counts are not a crawl frontier or a security decision. Do not use this module
as permission to issue requests. Raw document contents are never returned.
"""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import re


_DANGEROUS = re.compile(r'(?:^|[/_.-])(?:logout|logoff|signout|delete|remove|destroy|reset|admin|checkout|purchase|unsubscribe)(?:$|[/_.-])', re.I)


def _eligible(href, base):
    try:
        if not isinstance(href, str) or not href or len(href) > 2048 or not href.isascii():
            return False
        if re.search(r'[\x00-\x20\x7f\\%]', href):
            return False
        target = urlsplit(urljoin(base, href))
        source = urlsplit(base)
        return (target.scheme == 'https' and target.hostname == source.hostname
                and (target.port or 443) == (source.port or 443)
                and target.username is None and target.password is None
                and not target.query and not target.fragment
                and not _DANGEROUS.search(target.path))
    except ValueError:
        return False


class _Summary(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.counts = dict(internal_links=0, excluded_links=0, scripts=0, stylesheets=0, forms=0, api_references=0)

    def handle_starttag(self, tag, attrs):
        # Duplicate attributes are ambiguous; do not count an anchor as eligible.
        values = {}
        duplicate = set()
        for key, value in attrs:
            if key in values:
                duplicate.add(key)
            values[key] = value
        for attr in ('href', 'src', 'action'):
            value = values.get(attr)
            if isinstance(value, str) and re.search(r'(?:^|/)api(?:/|\?|#|$)', value, re.I):
                self.counts['api_references'] += 1
        if tag == 'a' and 'href' in values:
            key = 'internal_links' if 'href' not in duplicate and _eligible(values['href'], self.base) else 'excluded_links'
            self.counts[key] += 1
        elif tag == 'script' and 'src' in values:
            self.counts['scripts'] += 1
        elif tag == 'link' and 'stylesheet' in (values.get('rel') or '').lower().split() and 'href' in values:
            self.counts['stylesheets'] += 1
        elif tag == 'form':
            self.counts['forms'] += 1


def summarize_html(document, base):
    """Return only reference counts, with no URL, body, headers or exceptions."""
    if not isinstance(document, str) or len(document.encode('utf-8')) > 512 * 1024:
        return None
    try:
        parsed = urlsplit(base)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            return None
        parsed.port
        parser = _Summary(base)
        parser.feed(document)
        parser.close()
        return parser.counts
    except (TypeError, ValueError, RecursionError):
        return None
