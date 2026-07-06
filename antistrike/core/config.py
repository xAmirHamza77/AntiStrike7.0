"""Configuration management for Antistrike 7.0."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
RUNS_DIR = PROJECT_ROOT / "runs"
SKILLS_DIR = PROJECT_ROOT / "antistrike" / "skills"
PAYLOADS_DIR = PROJECT_ROOT / "antistrike" / "payloads"


class ServerSettings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 7700
    api_key: str | None = None
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:7701"])


class ScanSettings(BaseSettings):
    default_depth: str = "standard"
    max_concurrent_jobs: int = 8
    command_timeout: int = 300
    cache_ttl: int = 3600


class AuthorizationSettings(BaseSettings):
    require_scope_confirmation: bool = True
    log_all_actions: bool = True


class AntistrikeSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ANTISTRIKE_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    server: ServerSettings = Field(default_factory=ServerSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    authorization: AuthorizationSettings = Field(default_factory=AuthorizationSettings)
    telemetry_enabled: bool = False

    @classmethod
    def load(cls, config_path: Path | None = None) -> AntistrikeSettings:
        path = config_path or CONFIG_DIR / "antistrike.json"
        data: dict[str, Any] = {}
        if path.exists():
            with open(path) as f:
                data = json.load(f)
        return cls(**data)

    def save(self, config_path: Path | None = None) -> None:
        path = config_path or CONFIG_DIR / "antistrike.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.model_dump(), f, indent=2)


_settings: AntistrikeSettings | None = None


def get_settings() -> AntistrikeSettings:
    global _settings
    if _settings is None:
        _settings = AntistrikeSettings.load()
    return _settings


def ensure_dirs() -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)