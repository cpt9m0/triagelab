"""Stop hook: do not let the session end on an unproven claim of success.

Claude asserting "done" is not evidence. A green suite is. If the tests fail, this
hook hands the failure back and the turn continues.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _hooklib import project_dir, read_event, run_tests, tail  # noqa: E402


def main() -> int:
    event = read_event()

    # stop_hook_active is True when this hook already blocked once. Honour it or the
    # session loops forever - the classic Stop-hook footgun.
    if event.get("stop_hook_active"):
        return 0

    passed, output, ran = run_tests(project_dir())
    if not ran or passed:
        return 0

    print(
        "Not done yet: the test suite is red. Fix the failures below, then finish.\n\n"
        + tail(output),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
