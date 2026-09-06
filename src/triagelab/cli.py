"""Command line interface: triagelab scan | report | batch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import DEFAULT_OUTDIR, attach_vt, build_report, write_report

BAND_MARK = {"low": "[ low  ]", "medium": "[medium]", "high": "[ HIGH ]", "critical": "[ CRIT ]"}


def _print_vt(report: dict) -> None:
    vt = report.get("virustotal")
    if not vt:
        return
    if vt["status"] == "ok":
        print(f"  vt       {vt['detection_ratio']} detections"
              f"{' - ' + vt['threat_label'] if vt['threat_label'] else ''}"
              f"{' (cached)' if vt['cached'] else ''}")
        print(f"  vt link  {vt['permalink']}")
    else:
        print(f"  vt       {vt['status']}: {vt['message']}")


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
    if args.vt:
        attach_vt(report)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_summary(report)
        _print_vt(report)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    report = build_report(args.path)
    if args.vt:
        attach_vt(report)
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
        if args.vt:
            attach_vt(report)
        write_report(report, args.outdir)
        rows.append((report["band"], report["score"], path.name))

    rows.sort(key=lambda r: -r[1])
    width = max(len(r[2]) for r in rows)
    print(f"{'FILE'.ljust(width)}  SCORE  BAND")
    for band, sc, name in rows:
        print(f"{name.ljust(width)}  {str(sc).rjust(5)}  {band}")
    print(f"\n{len(rows)} file(s) triaged, reports in {args.outdir}")
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    """Publish a file to VirusTotal and optionally wait for the verdict."""
    import time

    from .intel import STATUS_PENDING, get_analysis, submit_file

    if not args.yes:
        print(
            "Refusing to upload without --yes.\n"
            "Submitting a file to VirusTotal PUBLISHES it: their Intelligence subscribers\n"
            "can download it afterwards, and it cannot be withdrawn. Never submit\n"
            "proprietary, confidential, or personal files.",
            file=sys.stderr,
        )
        return 2

    result = submit_file(args.path, confirm=True)
    print(f"{result.status}: {result.message}")
    if result.status != STATUS_PENDING:
        return 0 if result.status == "ok" else 1
    print(f"  analysis id  {result.analysis_id}")
    print(f"  permalink    {result.permalink}")

    if not args.wait:
        print("  run `triagelab scan <file> --vt` in a minute for the verdict")
        return 0

    for attempt in range(args.wait):
        time.sleep(20)  # the free tier allows 4 calls/min; poll well inside that
        polled = get_analysis(result.analysis_id, sha256=result.sha256)
        print(f"  [{attempt + 1}/{args.wait}] {polled.status} {polled.analysis_status}")
        if polled.status == "ok":
            print(f"  detections   {polled.detection_ratio}")
            print(f"  threat label {polled.threat_label or 'none'}")
            return 0
        if polled.status not in (STATUS_PENDING,):
            print(f"  {polled.message}")
            return 1
    print("  still analysing; check the permalink")
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
    scan.add_argument("--vt", action="store_true", help="also look the hash up on VirusTotal")
    scan.set_defaults(func=cmd_scan)

    report = sub.add_parser("report", help="analyse one file and write JSON + Markdown reports")
    report.add_argument("path")
    report.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    report.add_argument("--vt", action="store_true", help="also look the hash up on VirusTotal")
    report.set_defaults(func=cmd_report)

    batch = sub.add_parser("batch", help="triage every file in a directory")
    batch.add_argument("directory")
    batch.add_argument("-o", "--outdir", default=str(DEFAULT_OUTDIR))
    batch.add_argument(
        "--vt",
        action="store_true",
        help="look each hash up on VirusTotal (free tier is 4/min - slow for big batches)",
    )
    batch.set_defaults(func=cmd_batch)

    submit = sub.add_parser(
        "submit",
        help="upload a file to VirusTotal for analysis (PUBLISHES the file - requires --yes)",
    )
    submit.add_argument("path")
    submit.add_argument(
        "--yes",
        action="store_true",
        help="confirm you understand the upload publishes this file to VirusTotal",
    )
    submit.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="N",
        help="poll up to N times (20s apart) for the verdict",
    )
    submit.set_defaults(func=cmd_submit)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
