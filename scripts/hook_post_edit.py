"""PostToolUse hook: after any Python edit, prove the suite still passes.

Claude finds out about the breakage on the next turn instead of three edits later.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hooklib import normalise, project_dir, read_event, run_tests, tail  # noqa: E402

WATCHED = ("src/triagelab/", "tests/", "web/")


def main() -> int:
    event = read_event()
    target = normalise(str((event.get("tool_input") or {}).get("file_path", "")))
    if not target.endswith(".py") or not any(part in target for part in WATCHED):
        return 0

    passed, output, ran = run_tests(project_dir())
    if not ran:
        print("triagelab: no test runner available, skipping post-edit verification")
        return 0
    if passed:
        print("triagelab: test suite still green after edit")
        return 0

    print(
        "Tests are failing after that edit. Fix them before moving on.\n\n"
        + tail(output),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
