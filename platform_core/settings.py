"""Typed platform configuration from environment variables and optional ``.env`` files."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class PlatformSettings(BaseSettings):
    """Validated service configuration (local-first defaults, safety on by default)."""

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    platform_safe_mode: bool = Field(default=True, validation_alias="PLATFORM_SAFE_MODE")
    platform_data_dir: Path = Field(
        default=Path("platform_data"), validation_alias="PLATFORM_DATA_DIR"
    )
    platform_api_key: str | None = Field(default=None, validation_alias="PLATFORM_API_KEY")
    er_platform_api_key: str | None = Field(default=None, validation_alias="ER_PLATFORM_API_KEY")
    fail_fast_on_startup: bool = Field(default=False, validation_alias="FAIL_FAST_ON_STARTUP")
    cors_allow_origins: str = Field(default="*", validation_alias="CORS_ALLOW_ORIGINS")
    service_name: str = Field(
        default="endpoint-reliability-platform", validation_alias="SERVICE_NAME"
    )
    service_version: str = Field(default="1.0.0", validation_alias="SERVICE_VERSION")
    require_ping_binary: bool = Field(default=False, validation_alias="REQUIRE_PING_BINARY")

    @field_validator("platform_safe_mode", mode="before")
    @classmethod
    def parse_bool_safe_mode(cls, value: object) -> bool:
        """Provide parse bool safe mode behavior for toolkit workflows.

        Args:
            value: Value supplied by the caller for value.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        if isinstance(value, bool):
            return value
        if value is None:
            return True
        return str(value).strip().lower() not in {"0", "false", "no", "off"}

    @field_validator("platform_data_dir", mode="before")
    @classmethod
    def parse_data_dir(cls, value: object) -> Path:
        """Provide parse data dir behavior for toolkit workflows.

        Args:
            value: Value supplied by the caller for value.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        if isinstance(value, Path):
            return value
        return Path(str(value))

    def resolved_api_key(self) -> str | None:
        """Provide resolved api key behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        for candidate in (self.platform_api_key, self.er_platform_api_key):
            if candidate and candidate.strip():
                return candidate.strip()
        return None

    def cors_origins_list(self) -> list[str]:
        """Provide cors origins list behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        raw = self.cors_allow_origins.strip()
        if raw == "*":
            return ["*"]
        return [part.strip() for part in raw.split(",") if part.strip()]

    def sync_process_env(self) -> None:
        """Mirror validated settings into ``os.environ`` for legacy call sites."""
        os.environ["PLATFORM_SAFE_MODE"] = "1" if self.platform_safe_mode else "0"
        os.environ["PLATFORM_DATA_DIR"] = str(self.platform_data_dir.resolve())
        key = self.resolved_api_key()
        if key:
            os.environ.setdefault("PLATFORM_API_KEY", key)


@lru_cache(maxsize=1)
def get_settings() -> PlatformSettings:
    """Get settings for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    settings = PlatformSettings()
    settings.sync_process_env()
    return settings


def reset_settings_cache() -> None:
    """Provide reset settings cache behavior for toolkit workflows.

    Returns:
        None.

    Side effects:
        None.
    """
    get_settings.cache_clear()
