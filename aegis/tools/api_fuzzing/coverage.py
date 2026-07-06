"""API test coverage tracking."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from aegis.tools.api_fuzzing.schema import Endpoint


logger = logging.getLogger(__name__)


@dataclass
class EndpointCoverage:
    endpoint: str
    method: str
    tested: bool = False
    tests_run: int = 0
    vulnerabilities_found: int = 0
    categories_tested: list[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    total_endpoints: int = 0
    endpoints_tested: int = 0
    endpoints_with_vulns: int = 0
    total_tests: int = 0
    total_vulns: int = 0
    coverage_percent: float = 0.0
    endpoint_details: list[EndpointCoverage] = field(default_factory=list)
    untested_endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_endpoints": self.total_endpoints,
            "endpoints_tested": self.endpoints_tested,
            "endpoints_with_vulns": self.endpoints_with_vulns,
            "coverage_percent": round(self.coverage_percent, 1),
            "total_tests": self.total_tests,
            "total_vulnerabilities": self.total_vulns,
            "untested_endpoints": self.untested_endpoints,
            "endpoint_details": [
                {
                    "endpoint": e.endpoint,
                    "method": e.method,
                    "tested": e.tested,
                    "tests_run": e.tests_run,
                    "vulnerabilities_found": e.vulnerabilities_found,
                    "categories": e.categories_tested,
                }
                for e in self.endpoint_details
            ],
        }


class CoverageTracker:
    """Track API test coverage across endpoints."""

    def __init__(self, endpoints: list[Endpoint]):
        self.coverage: dict[str, EndpointCoverage] = {}
        for ep in endpoints:
            key = f"{ep.method.upper()} {ep.path}"
            self.coverage[key] = EndpointCoverage(
                endpoint=ep.path,
                method=ep.method.upper(),
            )

    def record_test(self, endpoint: str, method: str, category: str) -> None:
        """Record that a test was run against an endpoint."""
        key = f"{method.upper()} {endpoint}"
        if key in self.coverage:
            self.coverage[key].tested = True
            self.coverage[key].tests_run += 1
            if category not in self.coverage[key].categories_tested:
                self.coverage[key].categories_tested.append(category)

    def record_vulnerability(self, endpoint: str, method: str) -> None:
        """Record that a vulnerability was found at an endpoint."""
        key = f"{method.upper()} {endpoint}"
        if key in self.coverage:
            self.coverage[key].vulnerabilities_found += 1

    def generate_report(self) -> CoverageReport:
        """Generate a coverage report."""
        details = list(self.coverage.values())
        tested = [d for d in details if d.tested]
        with_vulns = [d for d in details if d.vulnerabilities_found > 0]
        untested = [f"{d.method} {d.endpoint}" for d in details if not d.tested]

        total_endpoints = len(details)
        coverage_pct = (len(tested) / total_endpoints * 100) if total_endpoints > 0 else 0

        return CoverageReport(
            total_endpoints=total_endpoints,
            endpoints_tested=len(tested),
            endpoints_with_vulns=len(with_vulns),
            total_tests=sum(d.tests_run for d in details),
            total_vulns=sum(d.vulnerabilities_found for d in details),
            coverage_percent=coverage_pct,
            endpoint_details=details,
            untested_endpoints=untested,
        )

    def to_json(self) -> str:
        """Export coverage report as JSON."""
        return json.dumps(self.generate_report().to_dict(), indent=2)
