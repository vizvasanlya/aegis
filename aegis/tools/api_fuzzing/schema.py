"""OpenAPI/Swagger schema parser and endpoint extractor."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import requests


logger = logging.getLogger(__name__)

_SCHEMA_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
]

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


@dataclass
class Parameter:
    name: str
    location: str  # query, path, header, cookie
    required: bool = False
    schema_type: str = "string"
    description: str = ""
    enum: list[str] = field(default_factory=list)
    default: Any = None


@dataclass
class RequestBody:
    content_type: str = "application/json"
    schema: dict[str, Any] = field(default_factory=dict)
    required: bool = True


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    parameters: list[Parameter] = field(default_factory=list)
    request_body: RequestBody | None = None
    responses: dict[str, str] = field(default_factory=dict)
    security: list[dict[str, list[str]]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _load_spec(spec_path: str) -> dict[str, Any] | None:
    """Load OpenAPI/Swagger spec from file path or URL."""
    import json

    try:
        if spec_path.startswith(("http://", "https://")):
            resp = requests.get(spec_path, timeout=15)
            resp.raise_for_status()
            content = resp.text
        else:
            from pathlib import Path

            path = Path(spec_path)
            if not path.exists():
                logger.error("Spec file not found: %s", spec_path)
                return None
            content = path.read_text(encoding="utf-8")

        # Try JSON first
        try:
            return json.loads(content)
        except (json.JSONDecodeError, ValueError):
            pass

        # Try YAML
        try:
            import yaml

            return yaml.safe_load(content)
        except Exception:
            logger.error("Failed to parse spec as JSON or YAML: %s", spec_path)
            return None

    except Exception as exc:
        logger.error("Failed to load spec: %s", exc)
        return None


def _extract_base_url(spec: dict[str, Any]) -> str:
    """Extract base URL from OpenAPI 3.x or Swagger 2.x spec."""
    # OpenAPI 3.x
    servers = spec.get("servers", [])
    if servers and isinstance(servers, list):
        url = servers[0].get("url", "")
        if url:
            return url.rstrip("/")

    # Swagger 2.x
    host = spec.get("host", "")
    if host:
        schemes = spec.get("schemes", ["https"])
        base_path = spec.get("basePath", "")
        return f"{schemes[0]}://{host}{base_path}".rstrip("/")

    return ""


def _extract_parameters(
    params: list[dict[str, Any]], spec: dict[str, Any]
) -> list[Parameter]:
    """Extract parameters from OpenAPI operation."""
    result = []
    for p in params:
        if "$ref" in p:
            ref_name = p["$ref"].split("/")[-1]
            p = spec.get("components", {}).get("parameters", {}).get(ref_name, p)

        schema = p.get("schema", {})
        result.append(
            Parameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                schema_type=schema.get("type", "string"),
                description=p.get("description", ""),
                enum=schema.get("enum", []),
                default=schema.get("default"),
            )
        )
    return result


def _extract_request_body(
    body: dict[str, Any] | None, spec: dict[str, Any]
) -> RequestBody | None:
    """Extract request body from OpenAPI 3.x operation."""
    if not body:
        return None

    content = body.get("content", {})
    json_content = content.get("application/json", {})
    schema = json_content.get("schema", {})

    if "$ref" in schema:
        ref_name = schema["$ref"].split("/")[-1]
        schema = spec.get("components", {}).get("schemas", {}).get(ref_name, schema)

    return RequestBody(
        content_type="application/json",
        schema=schema,
        required=body.get("required", True),
    )


def parse_openapi_spec(spec: dict[str, Any]) -> list[Endpoint]:
    """Parse OpenAPI/Swagger spec and extract all endpoints."""
    endpoints = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        # Path-level parameters
        path_params = path_item.get("parameters", [])

        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            # Merge path-level and operation-level parameters
            op_params = operation.get("parameters", [])
            all_params_raw = path_params + op_params
            parameters = _extract_parameters(all_params_raw, spec)

            # Request body (OpenAPI 3.x)
            request_body = _extract_request_body(
                operation.get("requestBody"), spec
            )

            # Swagger 2.x body parameter
            if not request_body:
                for p in all_params_raw:
                    if p.get("in") == "body":
                        schema = p.get("schema", {})
                        if "$ref" in schema:
                            ref_name = schema["$ref"].split("/")[-1]
                            schema = spec.get("definitions", {}).get(ref_name, schema)
                        request_body = RequestBody(
                            content_type="application/json",
                            schema=schema,
                            required=p.get("required", True),
                        )
                        break

            # Responses
            responses = {}
            for code, resp in operation.get("responses", {}).items():
                desc = resp.get("description", "") if isinstance(resp, dict) else ""
                responses[str(code)] = desc

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId", ""),
                    summary=operation.get("summary", ""),
                    parameters=parameters,
                    request_body=request_body,
                    responses=responses,
                    security=operation.get("security", []),
                    tags=operation.get("tags", []),
                )
            )

    return endpoints


def discover_schema(base_url: str) -> dict[str, None] | None:
    """Auto-discover OpenAPI/Swagger schema from common paths."""
    base = base_url.rstrip("/")

    for path in _SCHEMA_PATHS:
        url = f"{base}{path}"
        try:
            resp = requests.get(url, timeout=10, verify=False)
            if resp.status_code != 200:
                continue

            import json

            try:
                schema = resp.json()
            except (json.JSONDecodeError, ValueError):
                try:
                    import yaml

                    schema = yaml.safe_load(resp.text)
                except Exception:
                    continue

            if isinstance(schema, dict) and (
                "openapi" in schema or "swagger" in schema
            ):
                logger.info("Discovered API schema at %s", url)
                return schema

        except Exception:
            continue

    return None


def extract_endpoints_from_js(js_content: str) -> list[dict[str, str]]:
    """Extract API endpoints from JavaScript bundle source code."""
    endpoints = []

    # Pattern: fetch/axios/request calls with URL strings
    url_patterns = [
        r'(?:fetch|axios|\.get|\.post|\.put|\.patch|\.delete)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:url|endpoint|path|api)\s*[:=]\s*["\']([^"\']*(?:/api/|/v\d+/)[^"\']*)["\']',
        r'["\']((?:/api/|/v\d+/)[^"\']*)["\']',
    ]

    seen = set()
    for pattern in url_patterns:
        for match in re.finditer(pattern, js_content):
            url = match.group(1)
            if url and url not in seen and not url.startswith("http"):
                seen.add(url)
                # Infer method from context
                method = "GET"
                line_start = max(0, match.start() - 50)
                context = js_content[line_start : match.start()].lower()
                if "post" in context or "create" in context:
                    method = "POST"
                elif "put" in context or "update" in context:
                    method = "PUT"
                elif "delete" in context or "remove" in context:
                    method = "DELETE"
                elif "patch" in context:
                    method = "PATCH"

                endpoints.append({"path": url, "method": method})

    return endpoints
