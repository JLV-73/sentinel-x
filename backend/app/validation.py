"""Validate original CISA JSON without coercion or discarded fields."""
from datetime import date, datetime
import json
import re

from jsonschema import Draft7Validator, FormatChecker


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-JSON number: " + value)


def validate_catalog(raw, schema, now):
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)
    validator = Draft7Validator(schema, format_checker=FormatChecker())
    error = next(validator.iter_errors(document), None)
    if error:
        # Do not echo the complete, potentially hostile document into the API/log.
        raise ValueError("Schema validation failed at " + "/".join(map(str, error.absolute_path)) + ": " + error.validator)
    if document["count"] != len(document["vulnerabilities"]):
        raise ValueError("Catalog count mismatch")
    release_text = document["dateReleased"]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", release_text):
        raise ValueError("Invalid release timestamp")
    release = datetime.fromisoformat(release_text.replace("Z", "+00:00"))
    if release > now:
        raise ValueError("Catalog release is in the future")
    seen = set()
    for item in document["vulnerabilities"]:
        cve = item["cveID"]
        # The official schema's $ anchor also accepts a final newline. Require
        # the complete, unchanged ASCII identifier; never strip or normalize it.
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve):
            raise ValueError("Invalid CVE identifier")
        if cve in seen:
            raise ValueError("Duplicate CVE: " + cve)
        seen.add(cve)
        added = date.fromisoformat(item["dateAdded"])
        due = date.fromisoformat(item["dueDate"])
        if added > due:
            raise ValueError("dateAdded exceeds dueDate: " + cve)
        if added > release.date() or added > now.date():
            raise ValueError("dateAdded exceeds catalog release/current date: " + cve)
    return document
