"""Configuration and .env loading. Standard library only."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Repo root, resolved from this file's location."""
    return Path(__file__).resolve().parents[2]


def load_env(path: Path | None = None) -> dict[str, str]:
    """Parse a .env file into a dict.

    Real environment variables always win, so `VT_API_KEY=... uv run ...` overrides
    whatever is in the file. Unquoted values, `#` comments and blank lines are handled;
    anything fancier belongs in a real config library, which this project does not need.
    """
    env_path = path or (project_root() / ".env")
    values: dict[str, str] = {}
    try:
        raw = env_path.read_text(encoding="utf-8")
    except OSError:
        return values

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip("'\"")
        values[key.strip()] = value
    return values


def get(key: str, default: str | None = None) -> str | None:
    """Look up a setting: real environment first, then .env, then the default."""
    from_env = os.environ.get(key)
    if from_env:
        return from_env
    value = load_env().get(key)
    return value if value else default


def vt_api_key() -> str | None:
    key = get("VT_API_KEY")
    return key if key and not key.startswith("your") else None
