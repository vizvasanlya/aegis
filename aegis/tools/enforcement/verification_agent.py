"""Verification agent for reviewing testing thoroughness."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from aegis.tools.enforcement.minimums import MANDATORY_CATEGORIES
from aegis.tools.enforcement.tracker import get_tracker


@function_tool(timeout=60, strict_mode=False)
async def verify_category(
    ctx: RunContextWrapper,
    category: str,
) -> str:
    """Verify that a testing category was tested thoroughly.

    Checks:
    - Minimum test count met
    - Minimum endpoints tested
    - Required tools used
    - Sub-categories covered
    - Evidence quality

    Args:
        category: One of the 8 mandatory category IDs.
    """
    if category not in MANDATORY_CATEGORIES:
        return json.dumps(
            {
                "success": False,
                "error": f"Invalid category: {category}. Valid: {', '.join(sorted(MANDATORY_CATEGORIES))}",
            }
        )

    tracker = get_tracker(ctx)
    passed, missing_reasons = tracker.check_minimums(category)
    stats = tracker.get_category_stats(category)

    # Get evidence from context
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    test_evidence = inner.get("test_evidence", {})
    category_evidence = test_evidence.get(category, {})
    has_tests = len(category_evidence.get("tests", [])) > 0
    has_endpoints = len(category_evidence.get("endpoints_tested", [])) > 0

    return json.dumps(
        {
            "success": True,
            "category": category,
            "category_name": MANDATORY_CATEGORIES[category],
            "minimums_met": passed,
            "missing_reasons": missing_reasons,
            "stats": {
                "unique_tests": stats["unique_tests"],
                "unique_endpoints": stats["unique_endpoints"],
                "tools_used": sorted(stats["tools_used"]),
                "sub_categories": sorted(stats["sub_categories"]),
            },
            "has_evidence": has_tests or has_endpoints,
            "recommendation": (
                "Category testing is sufficient."
                if passed
                else f"Continue testing. Missing: {'; '.join(missing_reasons)}"
            ),
        },
        ensure_ascii=False,
        default=str,
    )
