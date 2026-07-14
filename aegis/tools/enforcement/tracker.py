"""Test tracking with uniqueness enforcement and minimum requirements."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from aegis.tools.enforcement.minimums import MINIMUM_REQUIREMENTS


class TestTracker:
    """Track tests with uniqueness enforcement and minimum requirement checks."""

    def __init__(self) -> None:
        self.tests: list[dict[str, Any]] = []
        self._test_keys: set[str] = set()
        self._category_tools: dict[str, set[str]] = {}
        self._category_endpoints: dict[str, set[str]] = {}
        self._category_sub_categories: dict[str, set[str]] = {}

    def log_test(
        self,
        category: str,
        endpoint: str,
        test_type: str,
        tool: str,
        sub_category: str = "",
        payload: str = "",
    ) -> bool:
        """Log a test with deduplication. Returns True if new test, False if duplicate."""
        payload_hash = hashlib.md5(payload.encode()).hexdigest()[:16] if payload else ""
        key = f"{category}:{endpoint}:{test_type}:{payload_hash}"

        if key in self._test_keys:
            return False

        self._test_keys.add(key)
        self.tests.append(
            {
                "category": category,
                "endpoint": endpoint,
                "test_type": test_type,
                "tool": tool,
                "sub_category": sub_category,
                "payload_hash": payload_hash,
                "timestamp": time.time(),
            }
        )

        # Track per-category stats
        self._category_tools.setdefault(category, set()).add(tool)
        self._category_endpoints.setdefault(category, set()).add(endpoint)
        if sub_category:
            self._category_sub_categories.setdefault(category, set()).add(sub_category)

        return True

    def get_category_stats(self, category: str) -> dict[str, Any]:
        """Get statistics for a category."""
        cat_tests = [t for t in self.tests if t["category"] == category]
        unique_tests = len(set(f"{t['endpoint']}:{t['test_type']}" for t in cat_tests))
        return {
            "unique_tests": unique_tests,
            "unique_endpoints": len(self._category_endpoints.get(category, set())),
            "tools_used": self._category_tools.get(category, set()),
            "sub_categories": self._category_sub_categories.get(category, set()),
        }

    def check_minimums(self, category: str) -> tuple[bool, list[str]]:
        """Check if minimum requirements are met. Returns (passed, missing_reasons)."""
        reqs = MINIMUM_REQUIREMENTS.get(category, {})
        stats = self.get_category_stats(category)
        missing: list[str] = []

        min_tests = reqs.get("min_unique_tests", 0)
        if stats["unique_tests"] < min_tests:
            missing.append(f"Only {stats['unique_tests']} unique tests, need {min_tests}")

        min_endpoints = reqs.get("min_unique_endpoints", 0)
        if stats["unique_endpoints"] < min_endpoints:
            missing.append(
                f"Only {stats['unique_endpoints']} endpoints tested, need {min_endpoints}"
            )

        required_tools = reqs.get("required_tools", set())
        if required_tools and not required_tools.issubset(stats["tools_used"]):
            missing_tools = required_tools - stats["tools_used"]
            missing.append(f"Missing required tools: {', '.join(sorted(missing_tools))}")

        min_subs = reqs.get("min_sub_categories", 0)
        if len(stats["sub_categories"]) < min_subs:
            missing.append(
                f"Only {len(stats['sub_categories'])} sub-categories tested, need {min_subs}"
            )

        return len(missing) == 0, missing

    def get_all_stats(self) -> dict[str, dict]:
        """Get stats for all categories."""
        return {cat: self.get_category_stats(cat) for cat in MINIMUM_REQUIREMENTS}

    def get_total_tests(self) -> int:
        """Get total unique tests across all categories."""
        return len(self._test_keys)

    def get_total_findings(self) -> int:
        """Get total findings across all categories."""
        return sum(1 for t in self.tests if t.get("finding"))


def get_tracker(ctx: Any) -> TestTracker:
    """Get or create the TestTracker from context."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    tracker = inner.get("_test_tracker")
    if tracker is None:
        tracker = TestTracker()
        inner["_test_tracker"] = tracker
    return tracker
