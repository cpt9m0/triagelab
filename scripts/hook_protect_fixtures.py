"""PreToolUse hook: the sample fixtures are evidence, not scratch space.

Blocks any direct write to fixtures/samples/. The only sanctioned way to change
those files is editing fixtures/generate_samples.py and re-running it.

This is the difference between guidance and a guarantee: CLAUDE.md asks Claude not
to edit fixtures, this hook makes it impossible.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hooklib import normalise, read_event  # noqa: E402

PROTECTED = "fixtures/samples/"
GENERATOR = "generate_samples.py"
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SHELL_WRITE_HINTS = (">", ">>", "sed -i", "rm ", "mv ", "cp ", "tee ", "truncate", "dd ")


def blocked_reason(event: dict) -> str | None:
    tool = event.get("tool_name", "")
    payload = event.get("tool_input", {}) or {}

    if tool in WRITE_TOOLS:
        target = normalise(str(payload.get("file_path", "")))
        if PROTECTED in target:
            return f"{tool} targets {payload.get('file_path')}"

    if tool == "Bash":
        command = str(payload.get("command", ""))
        lowered = normalise(command)
        if PROTECTED in lowered and GENERATOR not in lowered:
            if any(hint in lowered for hint in SHELL_WRITE_HINTS):
                return f"shell command writes into {PROTECTED}: {command.strip()[:120]}"
    return None


def main() -> int:
    reason = blocked_reason(read_event())
    if reason is None:
        return 0

    print(
        "BLOCKED by triagelab policy: fixtures/samples/ is generated evidence and is "
        "never edited directly.\n"
        f"Detected: {reason}\n"
        "Do this instead: edit fixtures/generate_samples.py, then run "
        "`uv run python fixtures/generate_samples.py`.",
        file=sys.stderr,
    )
    return 2  # exit 2 blocks the tool call and shows stderr to Claude


if __name__ == "__main__":
    raise SystemExit(main())
