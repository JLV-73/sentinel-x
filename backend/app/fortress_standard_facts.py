"""Internal finite observations, not policy validation or security conclusions.

The caller must supply complete, single-response headers; values are never returned.
"""
import re


def header_value_facts(headers, complete):
    result = {}
    for name, field in (('hsts', 'strict-transport-security'), ('csp', 'content-security-policy')):
        values = [value for key, value in headers if key.lower() == field]
        fact = 'unknown'
        if complete is True and not values:
            fact = 'absent'
        elif complete is True and len(values) == 1:
            value = values[0].strip(' \t')
            if not value:
                fact = 'empty'
            elif len(value) <= 4096 and value.isascii() and not any(ord(c) < 32 or ord(c) == 127 for c in value):
                value = value.lower()
                if name == 'hsts' and re.fullmatch(r'max-age=[0-9]{1,10}(?:; *includesubdomains)?(?:; *preload)?', value):
                    fact = 'zero_max_age' if int(value.split(';', 1)[0].split('=', 1)[1]) == 0 else 'positive_max_age'
                elif name == 'csp' and value == "default-src 'none'":
                    fact = 'default_src_none'
        result[name] = fact
    return result
