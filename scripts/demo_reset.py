"""Reset the repo to a clean pre-demo state. Safe to run between rehearsals.

Clears generated reports, regenerates the synthetic samples, and reports whether
the working tree still has changes you may want to discard before presenting.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    removed = 0
    for pattern in ("*.json", "*.md"):
        for path in (ROOT / "reports").glob(pattern):
            path.unlink()
            removed += 1
    print(f"cleared {removed} generated report file(s)")

    subprocess.run([sys.executable, str(ROOT / "fixtures" / "generate_samples.py")], check=True)

    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(ROOT), capture_output=True, text=True
    )
    dirty = [line for line in status.stdout.splitlines() if line.strip()]
    if dirty:
        print(f"\nworking tree has {len(dirty)} change(s):")
        for line in dirty[:20]:
            print(f"  {line}")
        print("\nrun `git checkout -- .` to drop them before demoing the live build")
    else:
        print("\nworking tree clean - ready to present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
