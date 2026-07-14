"""Batch testing with summarization to manage context window."""

from __future__ import annotations

import time
from typing import Any


class BatchTester:
    """Test in batches of 5, summarize after each batch to prevent context overflow."""

    def __init__(self, batch_size: int = 5) -> None:
        self.batch_size = batch_size
        self.summaries: list[dict[str, Any]] = []
        self.current_batch: list[dict[str, Any]] = []
        self.total_tests = 0
        self.total_findings = 0

    def add_test(self, test_result: dict[str, Any]) -> dict[str, Any] | None:
        """Add test result to current batch.

        Returns summary dict if batch is full (and was summarized), else None.
        """
        self.current_batch.append(test_result)
        self.total_tests += 1

        if test_result.get("finding"):
            self.total_findings += 1

        if len(self.current_batch) >= self.batch_size:
            return self._summarize_batch()
        return None

    def _summarize_batch(self) -> dict[str, Any]:
        """Summarize current batch and clear context."""
        if not self.current_batch:
            return {}

        summary = {
            "batch_id": len(self.summaries) + 1,
            "tests_run": len(self.current_batch),
            "endpoints_tested": list(set(t.get("endpoint", "") for t in self.current_batch)),
            "findings": [t for t in self.current_batch if t.get("finding")],
            "tools_used": list(set(t.get("tool", "curl") for t in self.current_batch)),
            "sub_categories": list(
                set(t.get("sub_category", "") for t in self.current_batch if t.get("sub_category"))
            ),
            "timestamp": time.time(),
        }

        self.summaries.append(summary)
        self.current_batch = []  # Clear context
        return summary

    def flush(self) -> dict[str, Any] | None:
        """Flush remaining tests in current batch."""
        if self.current_batch:
            return self._summarize_batch()
        return None

    def get_category_summary(self, category: str) -> dict[str, Any]:
        """Get compressed summary for a category."""
        cat_tests = [
            t
            for s in self.summaries
            for t in s.get("findings", [])
            if t.get("category") == category
        ]
        all_endpoints = list(
            set(ep for s in self.summaries for ep in s.get("endpoints_tested", []))
        )
        all_tools = list(set(tool for s in self.summaries for tool in s.get("tools_used", [])))

        return {
            "total_batches": len(self.summaries),
            "total_tests": sum(s["tests_run"] for s in self.summaries),
            "total_findings": len(cat_tests),
            "endpoints_tested": all_endpoints,
            "tools_used": all_tools,
        }

    def get_full_summary(self) -> dict[str, Any]:
        """Get complete summary across all batches."""
        return {
            "total_batches": len(self.summaries),
            "total_tests": self.total_tests,
            "total_findings": self.total_findings,
            "all_endpoints": list(
                set(ep for s in self.summaries for ep in s.get("endpoints_tested", []))
            ),
            "all_tools": list(
                set(tool for s in self.summaries for tool in s.get("tools_used", []))
            ),
        }
