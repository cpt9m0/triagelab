"""VirusTotal lookups against the free public API.

Standard library only - urllib is enough. The client is deliberately defensive about
quota because the free tier is small and a live demo should never be the thing that
burns it:

* every response is cached on disk by hash, so repeat lookups cost nothing
* a rolling window caps live calls at 4 per minute
* a daily counter warns as you approach 500

Only the SHA256 is ever sent. The file itself never leaves the machine.

Free public API terms: not for business workflows, commercial products or services.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import project_root, vt_api_key

API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
CACHE_DIR = project_root() / ".vt_cache"
STATE_FILE = CACHE_DIR / "_quota.json"

CALLS_PER_MINUTE = 4
DAILY_QUOTA = 500
REQUEST_TIMEOUT = 20

STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_NO_KEY = "no_key"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_ERROR = "error"


@dataclass
class VTResult:
    status: str
    sha256: str
    message: str = ""
    cached: bool = False
    stats: dict = field(default_factory=dict)
    threat_label: str = ""
    type_description: str = ""
    names: list[str] = field(default_factory=list)
    first_submission: str = ""
    last_analysis: str = ""
    reputation: int = 0
    times_submitted: int = 0
    permalink: str = ""
    retry_after: int = 0

    @property
    def detection_ratio(self) -> str:
        if not self.stats:
            return ""
        flagged = self.stats.get("malicious", 0) + self.stats.get("suspicious", 0)
        total = sum(v for v in self.stats.values() if isinstance(v, int))
        return f"{flagged}/{total}" if total else ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["detection_ratio"] = self.detection_ratio
        return data


def _epoch_to_iso(value) -> str:
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return ""


def parse_payload(payload: dict, sha256: str, cached: bool = False) -> VTResult:
    """Turn a VirusTotal /files/{id} response into a VTResult."""
    attributes = (payload.get("data") or {}).get("attributes") or {}
    classification = attributes.get("popular_threat_classification") or {}
    names = [n for n in (attributes.get("names") or []) if isinstance(n, str)][:5]

    return VTResult(
        status=STATUS_OK,
        sha256=sha256,
        cached=cached,
        stats=attributes.get("last_analysis_stats") or {},
        threat_label=classification.get("suggested_threat_label", ""),
        type_description=attributes.get("type_description", ""),
        names=names,
        first_submission=_epoch_to_iso(attributes.get("first_submission_date")),
        last_analysis=_epoch_to_iso(attributes.get("last_analysis_date")),
        reputation=attributes.get("reputation", 0) or 0,
        times_submitted=attributes.get("times_submitted", 0) or 0,
        permalink=GUI_URL.format(sha256=sha256),
    )


def _read_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"calls": [], "daily": {}}


def _write_state(state: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def quota_status(now: float | None = None) -> dict:
    """How much of the free tier is left, without making a call."""
    now = now if now is not None else time.time()
    state = _read_state()
    recent = [t for t in state.get("calls", []) if now - t < 60]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    used_today = state.get("daily", {}).get(today, 0)

    retry_after = 0
    if len(recent) >= CALLS_PER_MINUTE:
        retry_after = int(60 - (now - min(recent))) + 1

    return {
        "calls_last_minute": len(recent),
        "calls_per_minute": CALLS_PER_MINUTE,
        "used_today": used_today,
        "daily_quota": DAILY_QUOTA,
        "retry_after": max(0, retry_after),
    }


def _record_call(now: float) -> None:
    state = _read_state()
    state["calls"] = [t for t in state.get("calls", []) if now - t < 60] + [now]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily = state.get("daily", {})
    daily[today] = daily.get(today, 0) + 1
    state["daily"] = {d: c for d, c in daily.items() if d >= today}
    _write_state(state)


def _cache_path(sha256: str) -> Path:
    return CACHE_DIR / f"{sha256}.json"


def read_cache(sha256: str) -> VTResult | None:
    path = _cache_path(sha256)
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if entry.get("not_found"):
        return VTResult(
            status=STATUS_NOT_FOUND,
            sha256=sha256,
            cached=True,
            message="Not present in the VirusTotal corpus (cached).",
        )
    return parse_payload(entry.get("payload", {}), sha256, cached=True)


def _write_cache(sha256: str, payload: dict | None, not_found: bool = False) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cache_path(sha256).write_text(
        json.dumps({"fetched_at": time.time(), "not_found": not_found, "payload": payload or {}}),
        encoding="utf-8",
    )


def _fetch(sha256: str, api_key: str) -> VTResult:
    request = urllib.request.Request(
        API_URL.format(sha256=sha256),
        headers={"x-apikey": api_key, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _write_cache(sha256, None, not_found=True)
            return VTResult(
                status=STATUS_NOT_FOUND,
                sha256=sha256,
                message="VirusTotal has never seen this file. That is normal for anything "
                "you built or generated locally.",
            )
        if exc.code == 401:
            return VTResult(
                status=STATUS_ERROR, sha256=sha256, message="VirusTotal rejected the API key (401)."
            )
        if exc.code == 429:
            return VTResult(
                status=STATUS_RATE_LIMITED,
                sha256=sha256,
                message="VirusTotal returned 429: quota exhausted. Free tier is 4/min, 500/day.",
                retry_after=60,
            )
        return VTResult(status=STATUS_ERROR, sha256=sha256, message=f"VirusTotal error {exc.code}.")
    except (urllib.error.URLError, TimeoutError) as exc:
        return VTResult(status=STATUS_ERROR, sha256=sha256, message=f"Network error: {exc}")
    except json.JSONDecodeError:
        return VTResult(status=STATUS_ERROR, sha256=sha256, message="Malformed response.")

    _write_cache(sha256, payload)
    return parse_payload(payload, sha256)


def lookup(sha256: str, use_cache: bool = True, api_key: str | None = None) -> VTResult:
    """Look a hash up on VirusTotal, cache-first and quota-aware."""
    sha256 = (sha256 or "").strip().lower()
    if len(sha256) != 64:
        return VTResult(status=STATUS_ERROR, sha256=sha256, message="Expected a 64-char SHA256.")

    if use_cache:
        cached = read_cache(sha256)
        if cached is not None:
            return cached

    key = api_key or vt_api_key()
    if not key:
        return VTResult(
            status=STATUS_NO_KEY,
            sha256=sha256,
            message="No VT_API_KEY set. Copy .env.example to .env and paste a free key "
            "from virustotal.com/gui/my-apikey.",
        )

    now = time.time()
    quota = quota_status(now)
    if quota["retry_after"]:
        return VTResult(
            status=STATUS_RATE_LIMITED,
            sha256=sha256,
            message=f"Local throttle: {CALLS_PER_MINUTE} lookups/min on the free tier. "
            f"Try again in {quota['retry_after']}s.",
            retry_after=quota["retry_after"],
        )
    if quota["used_today"] >= DAILY_QUOTA:
        return VTResult(
            status=STATUS_RATE_LIMITED,
            sha256=sha256,
            message=f"Daily free-tier quota of {DAILY_QUOTA} lookups is used up.",
        )

    _record_call(now)
    return _fetch(sha256, key)
