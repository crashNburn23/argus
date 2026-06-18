from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM
    model_provider: Literal["anthropic", "ollama"] = "anthropic"
    model: str = "claude-sonnet-4-6"
    anthropic_api_key: SecretStr = SecretStr("")
    ollama_base_url: str = "http://localhost:11434"
    ollama_timeout_seconds: float = 300.0

    # Commercial feeds
    virustotal_api_key: SecretStr = SecretStr("")
    shodan_api_key: SecretStr = SecretStr("")
    recorded_future_api_key: SecretStr = SecretStr("")

    # Open-source feeds
    otx_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")

    # MISP
    misp_url: str = ""
    misp_api_key: SecretStr = SecretStr("")
    misp_verify_ssl: bool = True

    # SIEM
    siem_type: str = "file"
    siem_url: str | None = None
    siem_api_key: SecretStr | None = None
    siem_log_path: str | None = None
    # Splunk-specific
    splunk_username: str = ""
    splunk_password: SecretStr = SecretStr("")
    splunk_verify_ssl: bool = False

    # Storage
    cache_dir: Path = Path(".cache/argus")
    cache_size_bytes: int = 1_073_741_824
    db_path: Path = Path(".data/argus.db")
    cases_dir: Path = Path.home() / ".argus" / "cases"

    # Output
    reports_dir: Path = Path("reports")
    log_level: str = "INFO"

    # Data-disclosure mode:
    #   unrestricted    — data sent to configured model + all enabled external feeds
    #   confirm-external — prompt before each agent run that sends data externally
    #   local-only      — warn if model_provider is not 'ollama'; no external enrichment
    disclosure_mode: Literal["unrestricted", "confirm-external", "local-only"] = "unrestricted"

    def api_key(self, name: str) -> str:
        key_map = {
            "virustotal": self.virustotal_api_key,
            "shodan": self.shodan_api_key,
            "recorded_future": self.recorded_future_api_key,
            "otx": self.otx_api_key,
            "abuseipdb": self.abuseipdb_api_key,
            "misp": self.misp_api_key,
            "anthropic": self.anthropic_api_key,
        }
        secret = key_map.get(name)
        if secret is None:
            return ""
        return secret.get_secret_value()


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
