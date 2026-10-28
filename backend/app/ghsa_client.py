"""One anonymous fixed-origin advisory page; offline transport injectable."""
from urllib.parse import urlencode
import re
import httpx
from .sourceclients import SourceClient, Fetched, cve_id, strict_json, sequence, mapping, text, instant, number, require

ENDPOINT = "https://api.github.com/advisories"


class GhsaClient(SourceClient):
    def request(self, value, before_request=None, on_response=None):
        cve_id(value)
        url = ENDPOINT + "?" + urlencode({"cve_id": value, "type": "reviewed", "per_page": 100})
        deadline = self.monotonic() + self.budget_seconds
        with httpx.Client(transport=self.transport, verify=True, follow_redirects=False, trust_env=False,
                          timeout=httpx.Timeout(20, connect=10), headers={
                              "User-Agent": "SENTINEL-X/1.0 (manual intelligence reader)",
                              "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                              "X-GitHub-Api-Version": "2022-11-28"}) as client:
            self.check_deadline(deadline)
            if before_request is not None:
                before_request()
            self.check_deadline(deadline)
            remaining = deadline - self.monotonic()
            # Cooperative budget: an in-flight read may delay a check by <=20s.
            with client.stream("GET", url, timeout=httpx.Timeout(min(20, remaining), connect=min(10, remaining))) as response:
                if on_response is not None:
                    on_response(response)
                self.check_deadline(deadline)
                if any("next" in link.get("rel", "").lower().split() for link in response.links.values()):
                    raise ValueError("Incomplete GHSA response: next page exceeds single-request limit")
                encoding = response.headers.get("content-encoding")
                if encoding is not None and encoding.strip().lower() != "identity":
                    raise ValueError("Unsupported source Content-Encoding; identity required")
                length = response.headers.get("content-length")
                if length is not None and (re.fullmatch(r"[0-9]+", length) is None or int(length) > self.max_bytes):
                    raise ValueError("Source exceeds size limit")
                content = bytearray()
                chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    self.check_deadline(deadline)
                    if len(content) + len(chunk) > self.max_bytes:
                        raise ValueError("Source exceeds size limit")
                    content.extend(chunk)
                self.check_deadline(deadline)
                return Fetched(url, bytes(content), response.status_code, response.headers.get("retry-after"))


def parse_ghsa(raw, requested, now):
    cve_id(requested)
    # Reuse strict duplicate/nonfinite/depth checks while admitting a JSON array.
    doc = strict_json(b'{"advisories":' + raw + b'}')
    if set(doc) != {"advisories"}:
        raise ValueError("Expected one complete JSON array")
    entries = sequence(doc["advisories"])
    if not entries:
        return None
    require(len(entries) <= 100, "GHSA result exceeds one-page limit")
    seen, updated = set(), []
    for record in entries:
        mapping(record)
        identifier = text(record.get("ghsa_id"))
        require(re.fullmatch(r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}", identifier) is not None,
                "Invalid GHSA identifier")
        require(identifier not in seen, "Duplicate GHSA advisory")
        seen.add(identifier)
        require(cve_id(record.get("cve_id")) == requested, "Foreign GHSA CVE")
        require(record.get("type") == "reviewed", "Expected reviewed GHSA advisory")
        require(record.get("html_url") == "https://github.com/advisories/" + identifier, "Invalid GHSA URL")
        for key in ("summary", "description", "severity"):
            text(record.get(key))
        identifiers = sequence(record.get("identifiers"))
        pairs = set()
        for item in identifiers:
            mapping(item)
            kind, value = text(item.get("type")), text(item.get("value"))
            require(kind != "CVE" or cve_id(value) == requested, "Foreign GHSA CVE identifier")
            require(kind != "GHSA" or value == identifier, "Foreign GHSA identifier")
            pairs.add((kind, value))
        require(("CVE", requested) in pairs and ("GHSA", identifier) in pairs, "Missing advisory identifiers")
        dates = {}
        for key in ("published_at", "updated_at", "github_reviewed_at", "nvd_published_at", "withdrawn_at"):
            value = record.get(key)
            if value is not None:
                dates[key] = instant(value, now)
        if "published_at" in dates and "updated_at" in dates:
            require(dates["published_at"] <= dates["updated_at"], "GHSA update predates publication")
        if "updated_at" in dates:
            updated.append((dates["updated_at"], record["updated_at"]))
        for vulnerability in sequence(record.get("vulnerabilities")):
            mapping(vulnerability)
            package = mapping(vulnerability.get("package"))
            text(package.get("ecosystem"))
            text(package.get("name"))
            text(vulnerability.get("vulnerable_version_range"), nullable=True)
            text(vulnerability.get("first_patched_version"), nullable=True)
        metrics = [record.get("cvss")]
        if record.get("cvss_severities") is not None:
            metrics.extend(mapping(record["cvss_severities"]).values())
        for metric in metrics:
            if metric is not None:
                mapping(metric)
                text(metric.get("vector_string"), nullable=True)
                number(metric.get("score"), 10)
    return {"date": max(updated, key=lambda pair: pair[0])[1] if updated else None, "advisories": entries}
