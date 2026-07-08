"""Aegis application settings — pydantic-settings powered."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]

_BASE_CONFIG = SettingsConfigDict(
    case_sensitive=False,
    populate_by_name=True,
    extra="ignore",
)


class ProviderSettings(BaseSettings):
    """Per-provider API key and base URL configuration."""

    model_config = _BASE_CONFIG

    api_key: str | None = None
    base_url: str | None = None


class LlmSettings(BaseSettings):
    model_config = _BASE_CONFIG

    model: str | None = Field(default=None, alias="AEGIS_LLM")
    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("LLM_API_KEY", "OPENAI_API_KEY", "OPENCODE_API_KEY"),
    )
    api_base: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "LLM_API_BASE",
            "OPENAI_API_BASE",
            "OPENAI_BASE_URL",
            "LITELLM_BASE_URL",
            "OLLAMA_API_BASE",
        ),
    )
    reasoning_effort: ReasoningEffort = Field(default="high", alias="AEGIS_REASONING_EFFORT")
    timeout: int = Field(default=300, alias="LLM_TIMEOUT")

    # Per-provider settings
    openai: ProviderSettings = Field(default_factory=ProviderSettings)
    anthropic: ProviderSettings = Field(default_factory=ProviderSettings)
    gemini: ProviderSettings = Field(default_factory=ProviderSettings)
    deepseek: ProviderSettings = Field(default_factory=ProviderSettings)
    ollama: ProviderSettings = Field(default_factory=ProviderSettings)
    vertex_ai: ProviderSettings = Field(default_factory=ProviderSettings)

    def model_post_init(self, __context: object) -> None:
        import os

        # Populate per-provider settings from env vars
        # Check AEGIS_<PROVIDER>_API_KEY first, then fall back to standard env vars
        _PROVIDER_ENV_MAP: dict[str, tuple[str, str, str, str]] = {
            "openai": ("AEGIS_OPENAI_API_KEY", "OPENAI_API_KEY", "AEGIS_OPENAI_BASE_URL", "OPENAI_BASE_URL"),
            "anthropic": ("AEGIS_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY", "AEGIS_ANTHROPIC_BASE_URL", "ANTHROPIC_BASE_URL"),
            "gemini": ("AEGIS_GEMINI_API_KEY", "GEMINI_API_KEY", "AEGIS_GEMINI_BASE_URL", "GEMINI_BASE_URL"),
            "deepseek": ("AEGIS_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY", "AEGIS_DEEPSEEK_BASE_URL", "DEEPSEEK_BASE_URL"),
            "ollama": ("AEGIS_OLLAMA_API_KEY", "OLLAMA_API_KEY", "AEGIS_OLLAMA_BASE_URL", "OLLAMA_BASE_URL"),
            "vertex_ai": ("AEGIS_VERTEX_AI_API_KEY", "GOOGLE_API_KEY", "AEGIS_VERTEX_AI_BASE_URL", "VERTEX_AI_BASE_URL"),
        }
        for provider_name, (aegis_key, std_key, aegis_url, std_url) in _PROVIDER_ENV_MAP.items():
            provider = getattr(self, provider_name)
            if not provider.api_key:
                provider.api_key = os.environ.get(aegis_key) or os.environ.get(std_key)
            if not provider.base_url:
                provider.base_url = os.environ.get(aegis_url) or os.environ.get(std_url)


class RuntimeSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/vizvasanlya/aegis-sandbox:latest",
        alias="AEGIS_IMAGE",
    )
    backend: str = Field(default="docker", alias="AEGIS_RUNTIME_BACKEND")
    # Hard cap on a local target's size before we refuse to stream it into the
    # sandbox file-by-file (the SDK copies every file individually, which stalls
    # on large repos). Above this, the user must bind-mount via ``--mount``.
    # Set to 0 (or less) to disable the pre-flight check entirely.
    max_local_copy_mb: int = Field(default=1024, alias="AEGIS_MAX_LOCAL_COPY_MB")


class TelemetrySettings(BaseSettings):
    model_config = _BASE_CONFIG

    enabled: bool = Field(default=True, alias="AEGIS_TELEMETRY")


class IntegrationSettings(BaseSettings):
    model_config = _BASE_CONFIG

    perplexity_api_key: str | None = Field(default=None, alias="PERPLEXITY_API_KEY")


class MobileSettings(BaseSettings):
    model_config = _BASE_CONFIG

    image: str = Field(
        default="ghcr.io/vizvasanlya/aegis-sandbox:latest",
        alias="AEGIS_MOBILE_IMAGE",
        description="Docker image for mobile app testing (includes Android/iOS tools).",
    )
    android_sdk_path: str | None = Field(
        default=None,
        alias="AEGIS_ANDROID_SDK_PATH",
        description="Path to Android SDK (for ADB/emulator-based dynamic testing).",
    )
    ios_device_udid: str | None = Field(
        default=None,
        alias="AEGIS_IOS_UDID",
        description="UDID of connected iOS device for dynamic testing.",
    )
    mobsf_url: str | None = Field(
        default=None,
        alias="AEGIS_MOBSF_URL",
        description="MobSF API URL for automated mobile analysis (e.g., http://host.docker.internal:8000).",
    )
    mobsf_api_key: str | None = Field(
        default=None,
        alias="AEGIS_MOBSF_API_KEY",
        description="MobSF API key for authentication. Found in MobSF web UI under API Docs.",
    )


class Settings(BaseSettings):
    model_config = _BASE_CONFIG

    llm: LlmSettings = Field(default_factory=LlmSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    mobile: MobileSettings = Field(default_factory=MobileSettings)
