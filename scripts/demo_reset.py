"""Reset the repo to a clean pre-demo state. Safe to run between rehearsals.

Clears generated reports and uploaded files, then reports whether the working tree still
has changes you may want to discard before presenting. The repo is meant to start empty:
you add files live.

Pass --samples to also generate the optional synthetic fixtures, and --vt-cache to drop
cached VirusTotal responses (which costs quota to refill).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def clear(directory: Path) -> int:
    removed = 0
    for path in directory.glob("*"):
        if path.is_file() and path.name != ".gitkeep":
            path.unlink()
            removed += 1
    return removed


def main() -> int:
    print(f"cleared {clear(ROOT / 'reports')} report file(s)")
    print(f"cleared {clear(ROOT / 'uploads')} uploaded file(s)")

    if "--samples" in sys.argv:
        subprocess.run([sys.executable, str(ROOT / "fixtures" / "generate_samples.py")], check=True)
    if "--vt-cache" in sys.argv:
        cache = ROOT / ".vt_cache"
        print(f"cleared {clear(cache)} cached VirusTotal response(s)" if cache.is_dir() else "no VT cache")

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
