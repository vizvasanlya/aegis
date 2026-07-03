"""Parse OpenAPI/Swagger specifications and extract endpoint summaries for Aegis agents."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


def parse_api_spec(spec_path: str) -> dict[str, Any]:
    """Parse an OpenAPI/Swagger specification file (JSON or YAML).

    Returns a dict with:
      - ``title``: API title from the spec
      - ``version``: API version
      - ``base_url``: first server URL (if present)
      - ``endpoints``: list of endpoint summaries
      - ``raw``: the full parsed spec for agent consumption
    """
    path = Path(spec_path)
    if not path.exists():
        raise FileNotFoundError(f"API spec file not found: {spec_path}")

    text = path.read_text(encoding="utf-8")
    spec = _load_spec(text, path.suffix.lower())
    return _extract_info(spec)


def _load_spec(text: str, suffix: str) -> dict[str, Any]:
    """Load spec from JSON or YAML text."""
    if suffix in (".json",):
        return json.loads(text)

    # YAML support (try PyYAML if available, fall back to json for .yaml that is
    # actually JSON-formatted)
    try:
        import yaml  # noqa: PLC0415

        return yaml.safe_load(text)  # type: ignore[no-any-return]
    except ImportError:
        if suffix in (".yaml", ".yml"):
            raise ValueError(
                "YAML API specs require PyYAML. Install it with: pip install pyyaml"
            ) from None
        return json.loads(text)


def _extract_info(spec: dict[str, Any]) -> dict[str, Any]:
    """Extract structured info from a parsed OpenAPI/Swagger spec."""
    info = spec.get("info") or {}
    title = info.get("title", "Unknown API")
    version = info.get("version", "unknown")

    # Base URL: prefer top-level ``servers`` (OpenAPI 3.x), fall back to
    # ``host``+``basePath`` (Swagger 2.x).
    base_url = ""
    servers = spec.get("servers") or []
    if servers and isinstance(servers, list):
        base_url = servers[0].get("url", "")
    else:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        if host:
            schemes = spec.get("schemes") or ["https"]
            base_url = f"{schemes[0]}://{host}{base_path}"

    endpoints = _extract_endpoints(spec)

    return {
        "title": title,
        "version": version,
        "base_url": base_url,
        "endpoints": endpoints,
        "raw": spec,
    }


def _extract_endpoints(spec: dict[str, Any]) -> list[dict[str, str]]:
    """Extract a flat list of endpoint summaries from the spec."""
    # OpenAPI 3.x paths live under ``paths``; same for Swagger 2.x
    paths = spec.get("paths") or {}
    endpoints: list[dict[str, str]] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            operation = path_item.get(method)
            if not isinstance(operation, dict):
                continue
            summary = operation.get("summary", "")
            operation_id = operation.get("operationId", "")
            tags = operation.get("tags") or []
            endpoints.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "summary": summary,
                    "operationId": operation_id,
                    "tags": ", ".join(tags) if isinstance(tags, list) else str(tags),
                }
            )

    return endpoints


def format_spec_for_agent(api_info: dict[str, Any]) -> str:
    """Format parsed API spec info into a human-readable block for the agent system prompt."""
    lines: list[str] = []
    lines.append(f"API Specification: {api_info['title']} (v{api_info['version']})")
    if api_info["base_url"]:
        lines.append(f"Base URL: {api_info['base_url']}")
    lines.append("")

    endpoints = api_info.get("endpoints") or []
    if not endpoints:
        lines.append("No endpoints found in the specification.")
        return "\n".join(lines)

    lines.append(f"Discovered {len(endpoints)} endpoint(s):")
    lines.append("")

    for ep in endpoints:
        method = ep["method"]
        path = ep["path"]
        summary = f" — {ep['summary']}" if ep.get("summary") else ""
        tags = f" [{ep['tags']}]" if ep.get("tags") else ""
        lines.append(f"  {method:7s} {path}{summary}{tags}")

    lines.append("")
    lines.append(
        "Use this specification to guide your testing. Prioritize endpoints based on "
        "tags, HTTP method, and potential attack surface. Test every endpoint for "
        "authentication, authorization, injection, and business logic vulnerabilities."
    )

    return "\n".join(lines)


def format_spec_as_target_detail(api_info: dict[str, Any]) -> str:
    """Format the spec as a compact target detail string for the run record."""
    endpoints = api_info.get("endpoints") or []
    return (
        f"{api_info['title']} v{api_info['version']} "
        f"({len(endpoints)} endpoints, base: {api_info.get('base_url', 'N/A')})"
    )
