"""Command line interface: triagelab scan | report | batch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import DEFAULT_OUTDIR, build_report, write_report

BAND_MARK = {"low": "[ low  ]", "medium": "[medium]", "high": "[ HIGH ]", "critical": "[ CRIT ]"}


def _print_summary(report: dict) -> None:
    f = report["features"]
    print(f"{BAND_MARK[report['band']]} {f['name']}  score={report['score']}/100")
    print(f"  sha256   {f['sha256']}")
    print(f"  size     {f['size_bytes']} bytes    entropy {f['entropy']}")
    if report["matches"]:
        for m in report["matches"]:
            print(f"  match    {m['rule_id']} {m['name']} -> {', '.join(m['matched_terms'])}")
    else:
        print("  match    none")


def cmd_scan(args: argparse.Namespace) -> int:
    report = build_report(args.path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_summary(report)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = build_report(args.path)
    json_path, md_path = write_report(report, args.outdir)
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix != ".md")
    if not files:
        print(f"no files found in {directory}", file=sys.stderr)
        return 1

    rows = []
    for path in files:
        report = build_report(path)
        write_report(report, args.outdir)
        rows.append((report["band"], report["score"], path.name))

    rows.sort(key=lambda r: -r[1])
    width = max(len(r[2]) for r in rows)
    print(f"{'FILE'.ljust(width)}  SCORE  BAND")
    for band, sc, name in rows:
        print(f"{name.ljust(width)}  {str(sc).rjust(5)}  {band}")
    print(f"\n{len(rows)} file(s) triaged, reports in {args.outdir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triagelab",
        description="Static triage for synthetic lab samples. Never handles real malware.",
    )
    parser.add_argument("--version", action="version", version=f"triagelab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse one file and print a summary")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true", help="emit the full report as JSON")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="analyse one file and write JSON + Markdown reports")
    report.add_argument("path")
    report.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    report.set_defaults(func=cmd_report)

    batch = sub.add_parser("batch", help="triage every file in a directory")
    batch.add_argument("directory")
    batch.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    batch.set_defaults(func=cmd_batch)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
