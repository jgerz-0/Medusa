"""Deterministic advisory source clients for CVE enrichment."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

try:  # pragma: no cover - exercised indirectly via tests
    import requests
    from requests import Response, Session
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

    class Session:  # type: ignore
        """Minimal shim used when requests is unavailable during tests."""

        def get(self, *args: Any, **kwargs: Any) -> Response:
            raise RuntimeError("requests library required for HTTP interactions")

    class Response:  # type: ignore
        ...


DEFAULT_TIMEOUT = 30
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"


class AdvisorySourceError(Exception):
    """Raised when a deterministic advisory lookup fails."""


def _sort_data(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: _sort_data(data[key]) for key in sorted(data)}
    if isinstance(data, list):
        return [_sort_data(item) for item in data]
    return data


def _load_json(response: Response) -> Dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as exc:  # pragma: no cover - defensive guard
        body = response.text if hasattr(response, "text") else "<binary>"
        raise AdvisorySourceError(f"invalid JSON payload: {body[:200]}") from exc
    if not isinstance(payload, dict):
        raise AdvisorySourceError("advisory response must be a JSON object")
    return payload


def fetch_nvd_advisory(
    cve_id: str,
    *,
    session: Optional[Session] = None,
    user_agent: Optional[str] = None,
    base_url: str = NVD_API_URL,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Return a deterministic advisory payload from the NVD API."""

    if not cve_id:
        raise AdvisorySourceError("cve_id is required for NVD lookups")

    http = session or (requests.Session() if requests else Session())
    headers = {"Accept": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent

    response = http.get(
        base_url,
        params={"cveId": cve_id},
        timeout=timeout,
        headers=headers,
    )
    response.raise_for_status()
    document = _load_json(response)
    vulnerabilities = document.get("vulnerabilities") or []
    for record in vulnerabilities:
        cve = record.get("cve") or {}
        if str(cve.get("id", "")).upper() == cve_id.upper():
            description = ""
            descriptions = cve.get("descriptions") or []
            if descriptions:
                description = descriptions[0].get("value", "")
            metrics = cve.get("metrics") or {}
            cvss_score: Optional[float] = None
            severity: Optional[str] = None
            if metrics:
                for metric in metrics.values():
                    if isinstance(metric, list) and metric:
                        cvss_data = metric[0].get("cvssData") or {}
                        cvss_score = cvss_data.get("baseScore")
                        severity = metric[0].get("baseSeverity") or severity
                        break
            timestamps = cve.get("published") or record.get("published")
            published_at = _parse_timestamp(timestamps)
            modified_at = _parse_timestamp(cve.get("lastModified") or record.get("lastModified"))
            references = _collect_references(cve.get("references", {}).get("referenceData", []))
            return {
                "source": "nvd",
                "identifier": cve_id.upper(),
                "summary": description or None,
                "severity": severity.upper() if isinstance(severity, str) else severity,
                "cvss_score": cvss_score,
                "published": published_at,
                "modified": modified_at,
                "references": references,
                "raw": _sort_data(record),
            }
    raise AdvisorySourceError(f"cve_id {cve_id} not found in NVD response")


def fetch_circl_advisory(
    cve_id: str,
    *,
    session: Optional[Session] = None,
    user_agent: Optional[str] = None,
    base_url: str = CIRCL_API_URL,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Return a deterministic advisory payload from the CIRCL CVE API."""

    if not cve_id:
        raise AdvisorySourceError("cve_id is required for CIRCL lookups")

    http = session or (requests.Session() if requests else Session())
    headers = {"Accept": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent

    response = http.get(
        f"{base_url.rstrip('/')}/{cve_id}",
        timeout=timeout,
        headers=headers,
    )
    response.raise_for_status()
    document = _load_json(response)
    summary = document.get("summary") or document.get("description")
    severity = document.get("cvss")
    if isinstance(severity, dict):
        cvss_score = severity.get("score")
        severity_label = severity.get("severity") or document.get("access", {}).get("vector")
    else:
        cvss_score = document.get("cvss") if isinstance(document.get("cvss"), (float, int)) else None
        severity_label = document.get("impact", {}).get("severity")
    published_at = _parse_timestamp(document.get("Published"))
    modified_at = _parse_timestamp(document.get("last-modified"))
    references = _collect_references(document.get("references", []))
    return {
        "source": "circl",
        "identifier": cve_id.upper(),
        "summary": summary,
        "severity": severity_label.upper() if isinstance(severity_label, str) else severity_label,
        "cvss_score": float(cvss_score) if isinstance(cvss_score, (float, int)) else None,
        "published": published_at,
        "modified": modified_at,
        "references": references,
        "raw": _sort_data(document),
    }


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed
    return None


def _collect_references(references: Iterable[Any]) -> list[str]:
    urls: list[str] = []
    for reference in references:
        if isinstance(reference, dict):
            url = reference.get("url") or reference.get("URL")
            if isinstance(url, str):
                urls.append(url)
        elif isinstance(reference, str):
            urls.append(reference)
    return sorted(set(urls))

