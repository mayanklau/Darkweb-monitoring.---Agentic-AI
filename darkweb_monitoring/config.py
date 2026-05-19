from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./darkweb_monitoring.sqlite3"
    allowed_origins: str = "http://localhost:8000,http://127.0.0.1:8000"
    auth_enabled: bool = False
    api_keys: str = "local-dev-key"
    admin_api_keys: str = "local-admin-key"
    google_application_credentials: str | None = None
    google_cloud_project: str | None = None
    vision_ocr_enabled: bool = False
    retention_days: int = Field(default=180, ge=1)
    max_upload_bytes: int = Field(default=10_485_760, ge=1)
    notification_webhook_url: str | None = None
    enable_scheduled_monitors: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def allowed_api_keys(self) -> set[str]:
        return {key.strip() for key in self.api_keys.split(",") if key.strip()}

    @property
    def allowed_admin_api_keys(self) -> set[str]:
        return {key.strip() for key in self.admin_api_keys.split(",") if key.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
