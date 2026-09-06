"""Report assembly and rendering."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .features import extract
from .rules import match_rules
from .scoring import score

DEFAULT_OUTDIR = Path("reports")
STRINGS_IN_REPORT = 40


def build_report(path: str | Path) -> dict:
    """Run the full triage pipeline over one file and return a plain dict."""
    features = extract(path)
    matches = match_rules(features.strings)
    result = score(features, matches)

    payload = features.to_dict()
    payload["strings"] = payload["strings"][:STRINGS_IN_REPORT]
    return {
        "tool": "triagelab",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "features": payload,
        "matches": [m.to_dict() for m in matches],
        "score": result.score,
        "band": result.band,
        "reasons": result.reasons,
    }


def render_markdown(report: dict) -> str:
    """Human-readable version of a report dict."""
    f = report["features"]
    lines = [
        f"# Triage report: {f['name']}",
        "",
        f"- **Risk**: {report['score']}/100 ({report['band']})",
        f"- **SHA256**: `{f['sha256']}`",
        f"- **Size**: {f['size_bytes']} bytes",
        f"- **Entropy**: {f['entropy']}",
        f"- **Generated**: {report['generated_at']} by triagelab {report['tool_version']}",
        "",
        "## Rule matches",
        "",
    ]
    if report["matches"]:
        lines.append("| Rule | Category | Severity | Matched terms |")
        lines.append("| --- | --- | --- | --- |")
        for m in report["matches"]:
            lines.append(
                f"| {m['rule_id']} {m['name']} | {m['category']} | {m['severity']} | "
                f"{', '.join(m['matched_terms'])} |"
            )
    else:
        lines.append("No rules matched.")

    lines += ["", "## Why this score", ""]
    lines += [f"- {r}" for r in report["reasons"]] or ["- No risk signals found."]
    lines += ["", "---", "", "Synthetic lab output. No real malicious code is handled by this tool."]
    return "\n".join(lines) + "\n"


def write_report(report: dict, outdir: str | Path = DEFAULT_OUTDIR) -> tuple[Path, Path]:
    """Write <name>.json and <name>.md, returning both paths."""
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(report["features"]["name"]).stem
    json_path = out / f"{stem}.json"
    md_path = out / f"{stem}.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path
