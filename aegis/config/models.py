"""SDK model configuration helpers."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agents import set_default_openai_api, set_default_openai_key, set_tracing_disabled
from agents.models.multi_provider import MultiProvider
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


if TYPE_CHECKING:
    from agents.models.interface import ModelProvider

    from aegis.config.settings import Settings

# Global settings reference for per-provider config lookup
_SETTINGS: Settings | None = None


def get_settings() -> Settings | None:
    return _SETTINGS


class AegisProvider(MultiProvider):
    """Route any non-OpenAI prefix through LiteLLM with the prefix preserved,
    so users type ``deepseek/deepseek-chat`` rather than
    ``litellm/deepseek/deepseek-chat``.
    """

    _OPENCODE_BASE_URL = "https://opencode.ai/zen/v1"

    # Provider prefix -> settings attribute name
    _PROVIDER_MAP: dict[str, str] = {
        "openai": "openai",
        "anthropic": "anthropic",
        "gemini": "gemini",
        "deepseek": "deepseek",
        "ollama": "ollama",
        "vertex_ai": "vertex_ai",
        "opencode": "openai",  # opencode uses openai-compatible API
    }

    def _resolve_prefixed_model(
        self,
        *,
        original_model_name: str,
        prefix: str,
        stripped_model_name: str | None,
    ) -> tuple[ModelProvider, str | None]:
        if prefix in {"litellm", "any-llm"}:
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )

        # For openai prefix, use default behavior
        if prefix == "openai":
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )

        # Apply per-provider config
        settings = get_settings()
        if settings and prefix in self._PROVIDER_MAP:
            provider_attr = self._PROVIDER_MAP[prefix]
            provider_settings = getattr(settings.llm, provider_attr, None)
            if provider_settings and provider_settings.api_key:
                _set_provider_env(prefix, provider_settings.api_key, provider_settings.base_url)

        # Route to litellm provider
        if prefix == "ollama" and stripped_model_name:
            return self._get_fallback_provider("litellm"), f"ollama_chat/{stripped_model_name}"
        if prefix == "opencode" and stripped_model_name:
            _configure_opencode_zen(stripped_model_name)
            return self._get_fallback_provider("litellm"), f"openai/{stripped_model_name}"
        return self._get_fallback_provider("litellm"), original_model_name


def _configure_opencode_zen(_model_name: str) -> None:
    """Configure LiteLLM for OpenCode Zen API."""
    import litellm

    base_url = AegisProvider._OPENCODE_BASE_URL
    os.environ["OPENAI_BASE_URL"] = base_url
    litellm.api_base = base_url  # type: ignore[attr-defined]
    set_default_openai_api("chat_completions")

    # Use the OPENCODE_API_KEY if set, otherwise use the generic LLM_API_KEY
    zen_key = os.environ.get("OPENCODE_API_KEY") or os.environ.get("LLM_API_KEY")
    if zen_key:
        os.environ["OPENAI_API_KEY"] = zen_key
        set_default_openai_key(zen_key, use_for_tracing=False)


def _set_provider_env(provider: str, api_key: str, base_url: str | None = None) -> None:
    """Set environment variables for a specific provider."""
    _ENV_MAP: dict[str, dict[str, str]] = {
        "gemini": {"key": "GEMINI_API_KEY", "extra_key": "GOOGLE_API_KEY"},
        "vertex_ai": {"key": "GOOGLE_API_KEY"},
        "anthropic": {"key": "ANTHROPIC_API_KEY"},
        "deepseek": {"key": "DEEPSEEK_API_KEY"},
        "ollama": {"key": "OLLAMA_API_KEY"},
    }

    if provider in _ENV_MAP:
        env_config = _ENV_MAP[provider]
        os.environ.setdefault(env_config["key"], api_key)
        if "extra_key" in env_config:
            os.environ.setdefault(env_config["extra_key"], api_key)
        if base_url and "base_url_key" in env_config:
            os.environ.setdefault(env_config["base_url_key"], base_url)


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
    ),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Aegis config to SDK-native defaults."""
    global _SETTINGS
    _SETTINGS = settings

    llm = settings.llm
    set_tracing_disabled(True)
    _configure_litellm_compatibility()

    # Configure OpenAI provider
    if llm.openai.api_key:
        set_default_openai_key(llm.openai.api_key, use_for_tracing=False)
        os.environ.setdefault("OPENAI_API_KEY", llm.openai.api_key)
    elif llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        os.environ.setdefault("OPENAI_API_KEY", llm.api_key)

    # Configure OpenAI base URL (only if explicitly set)
    if llm.openai.base_url:
        os.environ["OPENAI_BASE_URL"] = llm.openai.base_url
        set_default_openai_api("chat_completions")
    elif llm.api_base:
        os.environ["OPENAI_BASE_URL"] = llm.api_base
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")

    # Set provider-specific env vars from per-provider config
    for provider_attr in ("gemini", "vertex_ai", "anthropic", "deepseek", "ollama"):
        provider_settings = getattr(llm, provider_attr, None)
        if provider_settings and provider_settings.api_key:
            _set_provider_env(provider_attr, provider_settings.api_key, provider_settings.base_url)


def _configure_litellm_compatibility() -> None:
    """Enable LiteLLM's permissive param handling and disable its callbacks."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True
    litellm.turn_off_message_logging = True
    litellm.disable_streaming_logging = True
    litellm.suppress_debug_info = True

    _register_litellm_cost_callback()


def _register_litellm_cost_callback() -> None:
    import litellm

    from aegis.report.state import litellm_cost_callback

    for bucket_name in ("success_callback", "_async_success_callback"):
        bucket = getattr(litellm, bucket_name, None)
        if not isinstance(bucket, list):
            continue
        if litellm_cost_callback in bucket:
            continue
        bucket.append(litellm_cost_callback)


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    model = model_name.strip().lower()
    if "/" in model and not model.startswith("openai/"):
        return True
    if settings.llm.api_base:
        return True
    return not model_supports_reasoning(model_name)


def model_supports_reasoning(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    entry = litellm.model_cost.get(name)
    if entry is None and "/" in name:
        entry = litellm.model_cost.get(name.rsplit("/", 1)[1])
    return bool(entry and entry.get("supports_reasoning"))


def is_known_openai_bare_model(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    if not name or "/" in name:
        return False
    entry = litellm.model_cost.get(name)
    return bool(entry and entry.get("litellm_provider") == "openai")
