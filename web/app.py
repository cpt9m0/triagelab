"""FastAPI dashboard: upload real files, triage them, optionally check VirusTotal.

Third-party imports are allowed here; the core package under src/ stays dependency-free.

Safety posture: uploaded files are written to uploads/ and read as bytes. Nothing is
ever executed, unpacked, or run through a shell. VirusTotal lookups send only the
SHA256 - the file itself never leaves this machine.

Run: uv run --extra web uvicorn web.app:app --reload --port 8000
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from triagelab import intel  # noqa: E402
from triagelab.report import attach_vt, build_report, write_report  # noqa: E402

REPORTS_DIR = PROJECT_ROOT / "reports"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

app = FastAPI(title="triagelab dashboard", docs_url="/api/docs")


def safe_filename(name: str) -> str:
    """Strip any path components and anything exotic. Uploads are data, not paths.

    Backslashes are normalised first so a Windows-style path is split the same way on
    every platform - otherwise `C:\\dir\\evil.exe` survives as one long filename on Linux.
    """
    base = Path((name or "").replace("\\", "/")).name
    cleaned = SAFE_NAME.sub("_", base).strip("._") or "unnamed"
    return cleaned[:120]


def load_reports() -> list[dict]:
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return sorted(reports, key=lambda r: -r.get("score", 0))


def load_report(stem: str) -> dict:
    path = REPORTS_DIR / f"{safe_filename(stem)}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"no report named {stem}")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request, error: str = "", added: int = 0):
    reports = load_reports()
    summary = {band: 0 for band in ("critical", "high", "medium", "low")}
    for report in reports:
        band = report.get("band", "low")
        summary[band] = summary.get(band, 0) + 1
    return TEMPLATES.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "reports": reports,
            "summary": summary,
            "quota": intel.quota_status(),
            "has_key": bool(intel.vt_api_key()),
            "error": error,
            "added": added,
        },
    )


@app.post("/upload")
async def upload(files: list[UploadFile] = File(...)):
    """Accept one or more files, triage each, write a report. Never executes anything."""
    added = 0
    for upload_file in files:
        payload = await upload_file.read()
        if not payload:
            continue
        if len(payload) > MAX_UPLOAD_BYTES:
            return RedirectResponse(
                f"/?error=File+{safe_filename(upload_file.filename)}+exceeds+"
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
                status_code=303,
            )

        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        target = UPLOADS_DIR / safe_filename(upload_file.filename)
        target.write_bytes(payload)
        write_report(build_report(target), REPORTS_DIR)
        added += 1

    if added == 0:
        return RedirectResponse("/?error=No+files+received", status_code=303)
    return RedirectResponse(f"/?added={added}", status_code=303)


@app.get("/report/{stem}", response_class=HTMLResponse)
def detail(request: Request, stem: str):
    return TEMPLATES.TemplateResponse(
        request=request,
        name="detail.html",
        context={
            "report": load_report(stem),
            "stem": safe_filename(stem),
            "quota": intel.quota_status(),
            "has_key": bool(intel.vt_api_key()),
        },
    )


@app.post("/report/{stem}/vt")
def lookup_vt(stem: str, refresh: bool = False):
    """Look this sample's hash up on VirusTotal and persist the result into the report."""
    report = load_report(stem)
    attach_vt(report, use_cache=not refresh)
    write_report(report, REPORTS_DIR)
    return RedirectResponse(f"/report/{safe_filename(stem)}", status_code=303)


@app.post("/report/{stem}/vt-submit")
def submit_to_vt(stem: str):
    """Upload the file itself to VirusTotal. Deliberate, human-triggered, one click.

    Reached only from the button that appears when VirusTotal has never seen the hash,
    and only after the operator ticks the consent box in that form.
    """
    report = load_report(stem)
    source = Path(report["features"]["path"])
    if not source.is_file():
        raise HTTPException(status_code=404, detail=f"source file is gone: {source}")

    report["virustotal"] = intel.submit_file(source, confirm=True).to_dict()
    write_report(report, REPORTS_DIR)
    return RedirectResponse(f"/report/{safe_filename(stem)}", status_code=303)


@app.post("/report/{stem}/vt-check")
def check_vt_analysis(stem: str):
    """Poll a submitted analysis; on completion this becomes the full file report."""
    report = load_report(stem)
    vt = report.get("virustotal") or {}
    report["virustotal"] = intel.get_analysis(
        vt.get("analysis_id", ""), sha256=report["features"]["sha256"]
    ).to_dict()
    write_report(report, REPORTS_DIR)
    return RedirectResponse(f"/report/{safe_filename(stem)}", status_code=303)


@app.get("/api/reports")
def api_reports() -> list[dict]:
    return [
        {
            "name": r["features"]["name"],
            "score": r["score"],
            "band": r["band"],
            "sha256": r["features"]["sha256"],
            "vt": (r.get("virustotal") or {}).get("detection_ratio", ""),
        }
        for r in load_reports()
    ]


@app.get("/api/quota")
def api_quota() -> dict:
    return {**intel.quota_status(), "has_key": bool(intel.vt_api_key())}
