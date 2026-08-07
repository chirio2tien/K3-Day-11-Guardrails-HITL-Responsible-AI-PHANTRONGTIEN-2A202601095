"""
Lab 11 — Configuration & API Key / Model Setup

Supports:
  - google  → Gemini via Google AI Studio (GOOGLE_API_KEY)
  - deepseek → DeepSeek via LiteLLM (DEEPSEEK_API_KEY)

Set in `.env`:
  LLM_PROVIDER=deepseek
  DEEPSEEK_API_KEY=sk-...
"""
from __future__ import annotations

import os
from pathlib import Path


def _load_dotenv_files() -> None:
    """Load repo-root `.env` into os.environ (does not override existing vars)."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    repo_root = Path(__file__).resolve().parents[2]
    env_path = repo_root / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)
    load_dotenv(override=False)


def _is_placeholder(value: str | None) -> bool:
    if not value:
        return True
    v = value.strip()
    return (not v) or v.startswith("your-") or "key-here" in v


def get_llm_provider() -> str:
    """Return ``deepseek`` or ``google`` (default google)."""
    _load_dotenv_files()
    explicit = (os.environ.get("LLM_PROVIDER") or "").strip().lower()
    if explicit in {"deepseek", "google"}:
        return explicit
    # Auto-pick DeepSeek when its key is present and Google key is missing/placeholder.
    if not _is_placeholder(os.environ.get("DEEPSEEK_API_KEY")) and _is_placeholder(
        os.environ.get("GOOGLE_API_KEY")
    ):
        return "deepseek"
    if not _is_placeholder(os.environ.get("DEEPSEEK_API_KEY")) and explicit == "deepseek":
        return "deepseek"
    return "google"


def get_deepseek_model_name() -> str:
    return (os.environ.get("DEEPSEEK_MODEL") or "deepseek/deepseek-chat").strip()


def get_google_model_name() -> str:
    return (os.environ.get("GOOGLE_MODEL") or "gemini-3.1-flash-lite").strip()


def get_llm_model():
    """Return an ADK-compatible model (str for Gemini, LiteLlm for DeepSeek)."""
    provider = get_llm_provider()
    if provider == "deepseek":
        from google.adk.models.lite_llm import LiteLlm

        api_key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        model_name = get_deepseek_model_name()
        # LiteLLM reads DEEPSEEK_API_KEY from the environment; also pass explicitly.
        return LiteLlm(model=model_name, api_key=api_key or None)

    return get_google_model_name()


def setup_api_key():
    """Load provider keys from `.env` / environment; prompt only if needed."""
    _load_dotenv_files()
    provider = get_llm_provider()
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = (
        os.environ.get("GOOGLE_GENAI_USE_VERTEXAI") or "0"
    )

    if provider == "deepseek":
        key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        if _is_placeholder(key):
            key = input("Enter DeepSeek API Key: ").strip()
            if not key:
                raise RuntimeError(
                    "DEEPSEEK_API_KEY missing. Put it in `.env`:\n"
                    "  LLM_PROVIDER=deepseek\n"
                    "  DEEPSEEK_API_KEY=sk-...\n"
                    "Get a key at https://platform.deepseek.com/api_keys"
                )
            os.environ["DEEPSEEK_API_KEY"] = key
        # Some OpenAI-compatible stacks also look at OPENAI_API_KEY.
        os.environ.setdefault("OPENAI_API_KEY", os.environ["DEEPSEEK_API_KEY"])
        print(f"API key loaded (provider=deepseek, model={get_deepseek_model_name()}).")
        return

    key = (os.environ.get("GOOGLE_API_KEY") or "").strip()
    if _is_placeholder(key):
        key = input("Enter Google API Key: ").strip()
        if not key:
            raise RuntimeError(
                "GOOGLE_API_KEY missing. Put it in `.env`, or switch to DeepSeek:\n"
                "  LLM_PROVIDER=deepseek\n"
                "  DEEPSEEK_API_KEY=sk-..."
            )
        os.environ["GOOGLE_API_KEY"] = key
    print(f"API key loaded (provider=google, model={get_google_model_name()}).")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
