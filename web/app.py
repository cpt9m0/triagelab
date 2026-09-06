"""FastAPI dashboard over the reports directory.

Read-only: it renders whatever `triagelab batch` has already written. Third-party
imports are allowed here; the core package under src/ stays dependency-free.

Run: uv run --extra web uvicorn web.app:app --reload --port 8000
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

app = FastAPI(title="triagelab dashboard", docs_url="/api/docs")


def load_reports() -> list[dict]:
    """Every report on disk, worst first."""
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return sorted(reports, key=lambda r: -r.get("score", 0))


def load_report(stem: str) -> dict:
    path = REPORTS_DIR / f"{stem}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"no report named {stem}")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    reports = load_reports()
    summary = {band: 0 for band in ("critical", "high", "medium", "low")}
    for report in reports:
        summary[report.get("band", "low")] = summary.get(report.get("band", "low"), 0) + 1
    return TEMPLATES.TemplateResponse(
        request=request,
        name="index.html",
        context={"reports": reports, "summary": summary},
    )


@app.get("/report/{stem}", response_class=HTMLResponse)
def detail(request: Request, stem: str):
    return TEMPLATES.TemplateResponse(
        request=request, name="detail.html", context={"report": load_report(stem)}
    )


@app.get("/api/reports")
def api_reports() -> list[dict]:
    """JSON view of the same data, for scripting against the dashboard."""
    return [
        {"name": r["features"]["name"], "score": r["score"], "band": r["band"]}
        for r in load_reports()
    ]
