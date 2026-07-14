"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegis.skills import get_available_skills, load_skills
from aegis.utils.resource_paths import get_aegis_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    scan_context: dict[str, Any] | None = None,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Loads ONLY essential skills at startup. Other skills are loaded
    on-demand via the load_skill tool to prevent context window overflow.

    Order:
    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always — the scan mode strategy).
    3. ``tooling/python`` (always — Python execution guidance).
    4. ``coordination/root_agent`` for the root agent only.
    5. Whitebox-specific skills if applicable.
    """
    ordered: list[str] = list(requested or [])
    ordered.append(f"scan_modes/{scan_mode}")
    ordered.append("tooling/python")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")

    mobile_mode = bool(scan_context and scan_context.get("mobile_mode"))
    if mobile_mode:
        # Mobile mode loads all mobile skills at startup
        ordered.append("mobile/android_overview")
        ordered.append("mobile/android_vulnerabilities")
        ordered.append("mobile/ios_overview")
        ordered.append("mobile/ios_vulnerabilities")
        ordered.append("mobile/mobile_static_analysis")
        ordered.append("mobile/mobsf_integration")

    internal_mode = bool(scan_context and scan_context.get("internal_mode"))
    if internal_mode:
        # Internal mode loads all internal skills at startup
        ordered.append("internal/overview")
        ordered.append("internal/network_discovery")
        ordered.append("internal/active_directory")
        ordered.append("internal/credential_attacks")
        ordered.append("internal/lateral_movement")
        ordered.append("internal/service_enumeration")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        prompt_dir = get_aegis_resource_path("agents", _PROMPT_DIRNAME)
        skills_dir = get_aegis_resource_path("skills")
        env = Environment(
            loader=FileSystemLoader([prompt_dir, skills_dir]),
            autoescape=select_autoescape(
                enabled_extensions=(),
                default_for_string=False,
            ),
        )

        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            scan_context=system_prompt_context,
        )
        skill_content = load_skills(skills_to_load)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = env.get_template("system_prompt.jinja").render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            system_prompt_context=system_prompt_context or {},
            **skill_content,
        )
    except Exception:
        logger.exception("render_system_prompt failed; returning empty prompt")
        return ""
    else:
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)
