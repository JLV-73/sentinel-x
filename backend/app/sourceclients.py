"""Fixed-origin offline-testable NVD/FIRST readers; no startup collection."""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import re
import time
from urllib.parse import urlencode, urlsplit

import httpx

ENDPOINTS = {"nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
             "epss": "https://api.first.org/data/v1/epss"}
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.ASCII)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cve_id(value):
    require(isinstance(value, str) and CVE_PATTERN.fullmatch(value) is not None, "Invalid CVE identifier")
    return value


def text(value, nullable=False):
    require((nullable and value is None) or isinstance(value, str), "Expected text")
    return value


def sequence(value):
    require(isinstance(value, list), "Expected array")
    return value


def mapping(value):
    require(isinstance(value, dict), "Expected object")
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError("Nonfinite JSON number: " + value)
    try:
        def decimal(value):
            parsed = float(value)
            require(math.isfinite(parsed), "Nonfinite JSON number")
            return parsed
        return mapping(json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=decimal))
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid JSON encoding/depth") from error


def instant(value, now):
    text(value)
    require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+]00:00)?", value) is not None,
            "Invalid UTC timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    require(parsed <= now, "Future timestamp")
    return parsed


def number(value, maximum):
    require(type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value), "Score outside range/type")
    return value


def language_values(items):
    for item in sequence(items):
        mapping(item)
        text(item.get("lang"))
        text(item.get("value"))
    return items


def official_records(items):
    for item in sequence(items):
        mapping(item)
    return items


def configuration_node(node):
    mapping(node)
    if "operator" in node:
        require(node["operator"] in ("AND", "OR"), "Invalid CPE operator")
    if "negate" in node:
        require(type(node["negate"]) is bool, "Invalid CPE negate")
    for key in ("nodes", "children"):
        if key in node:
            for child in sequence(node[key]):
                configuration_node(child)
    if "cpeMatch" in node:
        for match in official_records(node["cpeMatch"]):
            require(type(match.get("vulnerable")) is bool, "Invalid CPE vulnerable flag")
            require(text(match.get("criteria")).startswith("cpe:"), "Invalid CPE criteria")
            text(match.get("matchCriteriaId"))
            for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                if key in match:
                    text(match[key])


def parse_nvd(raw, requested, now):
    cve_id(requested)
    doc = strict_json(raw)
    require(doc.get("format") == "NVD_CVE" and doc.get("version") == "2.0", "Invalid NVD format/version")
    instant(doc.get("timestamp"), now)
    entries = sequence(doc.get("vulnerabilities"))
    for name in ("totalResults", "resultsPerPage", "startIndex"):
        require(type(doc.get(name)) is int and doc[name] >= 0, "Invalid NVD count")
    require(doc["startIndex"] == 0 and doc["totalResults"] == len(entries) and len(entries) <= 1
            and doc["resultsPerPage"] == len(entries), "Unexpected NVD result count")
    if not entries:
        return None
    record = mapping(mapping(entries[0]).get("cve"))
    require(cve_id(record.get("id")) == requested, "Foreign NVD CVE")
    published, modified = record.get("published"), record.get("lastModified")
    require(instant(published, now) <= instant(modified, now), "NVD modification predates publication")
    # NVD timestamps without an offset are officially UTC, not browser-local.
    published = published if published.endswith(("Z", "+00:00")) else published + "Z"
    modified = modified if modified.endswith(("Z", "+00:00")) else modified + "Z"
    descriptions = language_values(record.get("descriptions"))
    metrics = mapping(record.get("metrics", {}))
    cvss = []
    for name, entries in metrics.items():
        # Official metrics may also contain SSVC or other non-CVSS records.
        # They remain in the hashed raw source; they are not CVSS scores.
        if not name.startswith("cvssMetric"):
            continue
        require(re.fullmatch(r"cvssMetricV[0-9]+", name) is not None, "Invalid CVSS metric name")
        for metric in sequence(entries):
            mapping(metric)
            data = mapping(metric.get("cvssData"))
            version = text(data.get("version"))
            require(re.fullmatch(r"[0-9]+\.[0-9]+", version) is not None and name == "cvssMetricV" + ("2" if version == "2.0" else version.replace(".", "")), "CVSS version mismatch")
            source = text(metric.get("source"))
            require(bool(source), "Missing CVSS source")
            cvss.append({"version": version, "base_score": number(data.get("baseScore"), 10),
                         "base_severity": text(data.get("baseSeverity", metric.get("baseSeverity")), nullable=True),
                         "vector": text(data.get("vectorString"), nullable=True), "source": source,
                         "type": text(metric.get("type"), nullable=True), "record_modified": modified})
    weaknesses = official_records(record.get("weaknesses", []))
    for item in weaknesses:
        text(item.get("source"))
        text(item.get("type"))
        language_values(item.get("description"))
    references = official_records(record.get("references", []))
    for item in references:
        url = text(item.get("url"))
        require(urlsplit(url).scheme in ("http", "https") and bool(urlsplit(url).netloc), "Invalid reference URL")
        if "source" in item:
            text(item["source"])
        if "tags" in item:
            for tag in sequence(item["tags"]):
                text(tag)
    configurations = official_records(record.get("configurations", []))
    for node in configurations:
        configuration_node(node)
    return {"id": requested, "published": published, "last_modified": modified,
            "vuln_status": text(record.get("vulnStatus"), nullable=True), "descriptions": descriptions,
            "cvss": cvss, "weaknesses": weaknesses, "references": references, "configurations": configurations}


def epss_number(value):
    if isinstance(value, str):
        require(re.fullmatch(r"(?:0|1)(?:\.[0-9]+)?", value) is not None, "Invalid EPSS decimal")
        value = float(value)
    return number(value, 1)


def parse_epss(raw, requested, now):
    for value in requested:
        cve_id(value)
    require(len(set(requested)) == len(requested), "Duplicate requested CVEs")
    doc = strict_json(raw)
    require(doc.get("status") == "OK" and type(doc.get("status-code")) is int and doc["status-code"] == 200
            and doc.get("version") == "1.0", "Invalid EPSS envelope")
    records = sequence(doc.get("data"))
    for name in ("total", "offset", "limit"):
        require(type(doc.get(name)) is int and doc[name] >= 0, "Invalid EPSS count")
    require(doc["offset"] == 0 and doc["total"] == len(records) and doc["limit"] >= len(records), "Incomplete EPSS response")
    result = dict.fromkeys(requested)
    seen = set()
    for item in records:
        mapping(item)
        value = cve_id(item.get("cve"))
        require(value in result and value not in seen, "Foreign/duplicate EPSS CVE")
        seen.add(value)
        day = text(item.get("date"))
        require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day) is not None, "Invalid EPSS date")
        from datetime import date
        require(date.fromisoformat(day) <= now.date(), "Future EPSS date")
        result[value] = {"cve": value, "epss": epss_number(item.get("epss")),
                         "percentile": epss_number(item.get("percentile")), "date": day}
    return result


def pack_epss(ids):
    batches, batch = [], []
    for value in dict.fromkeys(ids):
        cve_id(value)
        if batch and (len(batch) == 100 or len(",".join(batch + [value])) > 1800):
            batches.append(batch)
            batch = []
        batch.append(value)
    if batch:
        batches.append(batch)
    return batches


@dataclass(frozen=True)
class Fetched:
    url: str
    raw: bytes
    status_code: int
    retry_after: str | None


class SourceClient:
    def __init__(self):
        self.transport = None
        self.max_bytes = 8 * 1024 * 1024
        self.monotonic = time.monotonic
        self.budget_seconds = 45

    def request(self, source, ids, before_request=None, on_response=None):
        require(source in ENDPOINTS, "Source is not allowlisted")
        require(isinstance(ids, list) and 1 <= len(ids) <= (1 if source == "nvd" else 100), "Invalid source request size")
        require(len(set(ids)) == len(ids), "Duplicate requested CVEs")
        for value in ids:
            cve_id(value)
        joined = ",".join(ids)
        require(source == "nvd" or len(joined) <= 1800, "EPSS CVE filter exceeds limit")
        params = {"cveId": joined} if source == "nvd" else {"cve": joined, "limit": len(ids)}
        url = ENDPOINTS[source] + "?" + urlencode(params, safe=",")
        deadline = self.monotonic() + self.budget_seconds
        # Cooperative budget, not a hard wall-clock ceiling: an in-flight
        # read can postpone the next budget check by <=20s.
        with httpx.Client(transport=self.transport, verify=True, follow_redirects=False, trust_env=False,
                          timeout=httpx.Timeout(20, connect=10), headers={"User-Agent": "SENTINEL-X/1.0 (manual intelligence reader)", "Accept": "application/json", "Accept-Encoding": "identity"}) as client:
            self.check_deadline(deadline)
            if before_request is not None:
                before_request()  # Persistent reservation immediately before the real start.
            self.check_deadline(deadline)
            remaining = deadline - self.monotonic()
            with client.stream("GET", url, timeout=httpx.Timeout(min(20, remaining), connect=min(10, remaining))) as response:
                if on_response is not None:
                    on_response(response)  # Honour rate headers even if the body then fails.
                self.check_deadline(deadline)
                encoding = response.headers.get("content-encoding")
                require(encoding is None or encoding.strip().lower() == "identity", "Unsupported source Content-Encoding; identity required")
                length = response.headers.get("content-length")
                if length is not None:
                    require(re.fullmatch(r"[0-9]+", length) is not None and int(length) <= self.max_bytes, "Source exceeds size limit")
                content = bytearray()
                # Never let HTTPX allocate a decompressed chunk before the bound.
                # Injected transports may supply an already buffered identity body.
                chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    self.check_deadline(deadline)
                    require(len(content) + len(chunk) <= self.max_bytes, "Source exceeds size limit")
                    content.extend(chunk)
                self.check_deadline(deadline)
                return Fetched(url, bytes(content), response.status_code, response.headers.get("retry-after"))

    def check_deadline(self, deadline):
        require(self.monotonic() < deadline, "Download time budget exhausted")
