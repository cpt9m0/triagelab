"""Shared helpers for triagelab's hooks. Standard library only, cross-platform."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def project_dir() -> Path:
    """Claude Code sets CLAUDE_PROJECT_DIR; fall back to this file's repo root."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[1]


def read_event() -> dict:
    """Hook input arrives as one JSON object on stdin."""
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {}


def normalise(path: str) -> str:
    """Compare paths without caring about separators or case."""
    return path.replace("\\", "/").lower()


def run_tests(cwd: Path, timeout: int = 180) -> tuple[bool, str, bool]:
    """Run the test suite.

    Returns (passed, output, ran). `ran` is False when no usable test runner was
    found, which must never be reported as a failure - an environment problem is
    not a red suite.
    """
    attempts = (
        ["uv", "run", "--quiet", "pytest", "-q", "--no-header"],
        [sys.executable, "-m", "pytest", "-q", "--no-header"],
    )
    for cmd in attempts:
        try:
            proc = subprocess.run(
                cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return True, output, True
        if proc.returncode == 5:  # pytest: no tests collected
            return True, output, True

        # A non-zero exit only counts as a real failure when pytest actually ran.
        # Otherwise it is uv failing to build an environment, a missing module, or
        # similar, and we should fall through to the next runner.
        if _looks_like_pytest_output(output):
            return False, output, True
        continue

    return True, "", False


def _looks_like_pytest_output(output: str) -> bool:
    lowered = output.lower()
    markers = (
        "passed",
        "failed",
        "error at",
        "collected",
        "no tests ran",
        "assert",
        # Pytest ran and hit a collection error (e.g. a broken/missing import in a
        # test module). That is a real project problem, not a missing test runner,
        # so it must count as pytest output rather than fall through silently.
        "error collecting",
        "errors during collection",
        "short test summary info",
    )
    noise = ("no module named pytest", "failed to install", "error: failed", "not found")
    if any(n in lowered for n in noise):
        return False
    return any(m in lowered for m in markers)


def tail(text: str, lines: int = 25) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])
