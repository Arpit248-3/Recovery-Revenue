"""
Centralized Configuration and Credential Management for WAPSI.
Reads configuration from process environment variables, optional .env files,
and Windows user environment registry when applicable.
Enforces strict secret masking, credential validation, and fail-closed production safety.
"""

from __future__ import annotations

import os
import sys
from typing import Optional, Set
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _get_windows_user_env(var_name: str) -> Optional[str]:
    """Fallback reader for Windows User Environment variables stored in registry."""
    if sys.platform != "win32":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            val, _ = winreg.QueryValueEx(key, var_name)
            return str(val) if val else None
    except Exception:
        return None


class WapsiSettings(BaseSettings):
    """
    Centralized WAPSI configuration with Pydantic v2 validation and SecretStr redaction.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True
    )

    # Environment
    wapsi_env: str = Field(default="development", alias="WAPSI_ENV")
    wapsi_log_level: str = Field(default="INFO", alias="WAPSI_LOG_LEVEL")
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    models_dir: str = Field(default="models", alias="MODELS_DIR")

    # Razorpay Credentials
    razorpay_mode: str = Field(default="test", alias="RAZORPAY_MODE")
    razorpay_key_id: Optional[str] = Field(default=None, alias="RAZORPAY_KEY_ID")
    razorpay_key_secret: Optional[SecretStr] = Field(default=None, alias="RAZORPAY_KEY_SECRET")
    razorpay_webhook_secret: Optional[SecretStr] = Field(default=None, alias="RAZORPAY_WEBHOOK_SECRET")

    # WAPSI Security
    wapsi_api_key: Optional[SecretStr] = Field(default=None, alias="WAPSI_API_KEY")
    wapsi_api_rate_limit: int = Field(default=120, alias="WAPSI_API_RATE_LIMIT")

    # Policy Defaults
    policy_dnd_start_hour: int = Field(default=21, alias="POLICY_DND_START_HOUR")
    policy_dnd_end_hour: int = Field(default=9, alias="POLICY_DND_END_HOUR")
    policy_max_daily_touches: int = Field(default=2, alias="POLICY_MAX_DAILY_TOUCHES")
    policy_min_ivr_amount: float = Field(default=1500.0, alias="POLICY_MIN_IVR_AMOUNT")

    # Database & Supabase Configuration
    database_url: Optional[str] = Field(default=None, alias="DATABASE_URL")
    supabase_url: str = Field(default="https://ffgsrwjhguvubmhuefyj.supabase.co", alias="SUPABASE_URL")
    supabase_anon_key: Optional[SecretStr] = Field(default=None, alias="SUPABASE_ANON_KEY")
    supabase_service_role_key: Optional[SecretStr] = Field(default=None, alias="SUPABASE_SERVICE_ROLE_KEY")
    customer_hash_salt: SecretStr = Field(default=SecretStr("wapsi_customer_hash_salt_demo_2026"), alias="CUSTOMER_HASH_SALT")

    @model_validator(mode="before")
    @classmethod
    def populate_windows_env_fallbacks(cls, values: dict) -> dict:
        """If key variables are absent in process env or .env, check Windows user environment."""
        if not isinstance(values, dict):
            values = {}

        for var_name in ["RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_MODE", "RAZORPAY_WEBHOOK_SECRET"]:
            field_key = var_name.lower()
            if not values.get(field_key) and not values.get(var_name) and not os.environ.get(var_name):
                reg_val = _get_windows_user_env(var_name)
                if reg_val:
                    values[var_name] = reg_val
        return values

    @field_validator("razorpay_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        mode = v.strip().lower()
        if mode not in {"test", "live"}:
            raise ValueError(f"RAZORPAY_MODE must be 'test' or 'live', got: '{v}'")
        return mode

    @field_validator("razorpay_key_id")
    @classmethod
    def validate_key_prefix(cls, v: Optional[str], info) -> Optional[str]:
        if not v:
            return v
        key = v.strip()
        mode = info.data.get("razorpay_mode", "test")
        if mode == "test" and not key.startswith("rzp_test_"):
            raise ValueError(f"RAZORPAY_KEY_ID in test mode must start with 'rzp_test_', got: '{key[:12]}...'")
        elif mode == "live" and not key.startswith("rzp_live_"):
            raise ValueError(f"RAZORPAY_KEY_ID in live mode must start with 'rzp_live_', got: '{key[:12]}...'")
        return key

    @model_validator(mode="after")
    def validate_production_safety(self) -> "WapsiSettings":
        """Fail closed in production if required secrets are absent."""
        if self.wapsi_env.lower() == "production" or self.razorpay_mode == "live":
            if not self.razorpay_key_id:
                raise ValueError("RAZORPAY_KEY_ID is required in production/live mode.")
            if not self.razorpay_key_secret or not self.razorpay_key_secret.get_secret_value():
                raise ValueError("RAZORPAY_KEY_SECRET is required in production/live mode.")
            if not self.razorpay_webhook_secret or not self.razorpay_webhook_secret.get_secret_value():
                raise ValueError("RAZORPAY_WEBHOOK_SECRET is required in production/live mode.")
        return self

    @property
    def masked_key_id(self) -> str:
        """Returns safe masked key id (e.g. rzp_test_****1234)."""
        if not self.razorpay_key_id:
            return "NOT_CONFIGURED"
        prefix = "rzp_test_" if self.razorpay_key_id.startswith("rzp_test_") else (
            "rzp_live_" if self.razorpay_key_id.startswith("rzp_live_") else self.razorpay_key_id[:8]
        )
        if len(self.razorpay_key_id) <= 12:
            return f"{prefix}****"
        return f"{prefix}****{self.razorpay_key_id[-4:]}"

    @property
    def has_key_secret(self) -> bool:
        return bool(self.razorpay_key_secret and self.razorpay_key_secret.get_secret_value())

    @property
    def has_webhook_secret(self) -> bool:
        return bool(self.razorpay_webhook_secret and self.razorpay_webhook_secret.get_secret_value())

    def get_valid_api_keys(self) -> Set[str]:
        """Returns set of authorized API keys for request authentication."""
        keys = set()
        if self.wapsi_api_key and self.wapsi_api_key.get_secret_value():
            keys.add(self.wapsi_api_key.get_secret_value())
        # In non-production, include standard demo key for backward-compatible test suites
        if self.wapsi_env.lower() != "production":
            keys.add("rzp_live_wapsi_key_demo")
            keys.add("rzp_test_wapsi_key_2026")
        return keys

    def get_webhook_secret_bytes(self) -> bytes:
        """Returns webhook secret as bytes for constant-time HMAC calculation."""
        if self.razorpay_webhook_secret and self.razorpay_webhook_secret.get_secret_value():
            return self.razorpay_webhook_secret.get_secret_value().encode("utf-8")
        if self.wapsi_env.lower() != "production":
            return b"rzp_webhook_secret_dev_demo"
        raise ValueError("RAZORPAY_WEBHOOK_SECRET must be configured in production.")

    def __repr__(self) -> str:
        return (
            f"WapsiSettings(env='{self.wapsi_env}', mode='{self.razorpay_mode}', "
            f"key_id='{self.masked_key_id}', has_secret={self.has_key_secret}, "
            f"models_dir='{self.models_dir}')"
        )


# Global singleton instance
_settings_instance: Optional[WapsiSettings] = None


def get_settings() -> WapsiSettings:
    """Returns the cached singleton WapsiSettings instance."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = WapsiSettings()
    return _settings_instance

