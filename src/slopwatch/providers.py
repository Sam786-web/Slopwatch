"""Model providers. All use the OpenAI-compatible chat API, so one client fits all.

Model IDs on free tiers change often. If a call fails with "model not found",
run `slopwatch models <provider>` to see what is currently offered and edit MODELS.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    key_env: str | None  # None = no key needed (local)
    rpm: float  # requests per minute we allow ourselves (stay under the free-tier limit)


PROVIDERS: dict[str, Provider] = {
    "ollama": Provider("ollama", "http://localhost:11434/v1", None, rpm=60),
    "groq": Provider("groq", "https://api.groq.com/openai/v1", "GROQ_API_KEY", rpm=25),
    "gemini": Provider(
        "gemini", "https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_API_KEY", rpm=8
    ),
    # OpenRouter free models: ~20 req/min and a small DAILY cap without credits.
    "openrouter": Provider("openrouter", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY", rpm=12),
}

# The models SlopWatch studies, as "provider:model". Verified working 2026-11-05.
MODELS: list[str] = [
    "groq:openai/gpt-oss-120b",
    "groq:qwen/qwen3.8-27b",
    "gemini:gemini-3.5-flash",
    "openrouter:openrouter/free",
    # Local model is opt-in (slow on CPU, uses most of 8 GB RAM):
    #   slopwatch harvest --models ollama:qwen2.5:1.5b
]


# Per-model overrides for tight free-tier limits.
# Groq's free Qwen allows only 1,000 output tokens/minute, so cap answers and go slowly.
MODEL_OPTS: dict[str, dict] = {
    "groq:qwen/qwen3.8-27b": {"max_tokens": 900, "rpm": 1},
}


def split_model(spec: str) -> tuple[Provider, str]:
    provider, _, model = spec.partition(":")
    if provider not in PROVIDERS or not model:
        raise ValueError(f"Bad model spec {spec!r}; expected provider:model, provider in {list(PROVIDERS)}")
    return PROVIDERS[provider], model


def get_key(p: Provider) -> str | None:
    if p.key_env is None:
        return "ollama"  # placeholder; Ollama ignores it
    return os.getenv(p.key_env) or None


def client_for(p: Provider, timeout: float = 120, max_retries: int = 3) -> OpenAI:
    key = get_key(p)
    if key is None:
        raise RuntimeError(f"{p.key_env} is not set in .env")
    # max_retries makes the SDK back off and retry on 429 / 5xx automatically.
    return OpenAI(base_url=p.base_url, api_key=key, timeout=timeout, max_retries=max_retries)


def ask(provider: str, model: str, prompt: str, temperature: float = 0.7) -> str:
    p = PROVIDERS[provider]
    resp = client_for(p).chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    return resp.choices[0].message.content or ""
