"""Central configuration for CivicShield. All values come from environment
variables (optionally loaded from a .env file via python-dotenv)."""
import os
from dataclasses import dataclass

from dotenv import find_dotenv, load_dotenv

# Search upward from the working directory so .env may live in backend/ or the repo root.
load_dotenv(find_dotenv(usecwd=True))


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _env_tuple(name: str, default: tuple) -> tuple:
    raw = os.getenv(name)
    return tuple(x.strip() for x in raw.split(",") if x.strip()) if raw else default


def _remediation_mode() -> str:
    # Fail safe: anything other than an explicit "live" means simulate.
    return "live" if os.getenv("REMEDIATION_MODE", "simulate").strip().lower() == "live" else "simulate"


@dataclass(frozen=True)
class Settings:
    # --- Stage 3 LLM providers ---
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm_timeout_s: float = _env_float("LLM_TIMEOUT_S", 15.0)

    # --- Stage 2 deterministic thresholds ---
    ph_min: float = 5.0            # pH < 5.0  -> HAZARDOUS
    ph_max: float = 9.0            # pH > 9.0  -> HAZARDOUS
    turbidity_max_ntu: float = 30.0
    tds_max_ppm: float = 1000.0
    dos_threshold_hz: float = 100.0
    max_payload_bytes: int = 2048

    # --- API / platform ---
    cors_origins: tuple = _env_tuple("CORS_ORIGINS", ("http://localhost:8501", "http://127.0.0.1:8501"))
    enable_attack_simulator: bool = _env_bool("ENABLE_ATTACK_SIMULATOR", True)
    remediation_mode: str = _remediation_mode()


settings = Settings()