"""Time boxing for scan phases."""

from __future__ import annotations

import time
from typing import Any

from aegis.tools.enforcement.minimums import TIME_ALLOCATION


class TimeBoxer:
    """Manage time allocation for scan phases."""

    def __init__(self) -> None:
        self.start_time = time.time()
        self.category_start: float | None = None
        self.current_category: str | None = None
        self.category_times: dict[str, float] = {}

    def start_category(self, category: str) -> None:
        """Start timing a category."""
        self.current_category = category
        self.category_start = time.time()

    def end_category(self) -> float:
        """End timing and return elapsed seconds."""
        if self.category_start is None:
            return 0.0
        elapsed = time.time() - self.category_start
        if self.current_category:
            self.category_times[self.current_category] = elapsed
        self.category_start = None
        return elapsed

    def check_time(self) -> tuple[bool, str]:
        """Check if current category has exceeded its time limit.

        Returns (exceeded, message).
        """
        if self.category_start is None:
            return False, ""

        elapsed = time.time() - self.category_start
        limit = TIME_ALLOCATION["per_category"]

        if elapsed > limit:
            return (
                True,
                f"Category {self.current_category} exceeded {limit}s limit "
                f"({elapsed:.0f}s elapsed)",
            )

        remaining = limit - elapsed
        return False, f"{remaining:.0f}s remaining for {self.current_category}"

    def get_total_elapsed(self) -> float:
        """Get total scan elapsed time."""
        return time.time() - self.start_time

    def get_time_report(self) -> dict[str, Any]:
        """Get time usage report."""
        total_category_time = sum(self.category_times.values())
        max_category_time = TIME_ALLOCATION["per_category"] * 8
        return {
            "total_elapsed": self.get_total_elapsed(),
            "per_category": dict(self.category_times),
            "total_category_time": total_category_time,
            "remaining_category_time": max(0, max_category_time - total_category_time),
            "within_budget": self.get_total_elapsed()
            < (
                TIME_ALLOCATION["recon"]
                + max_category_time
                + TIME_ALLOCATION["verification"]
                + TIME_ALLOCATION["reporting"]
            ),
        }
