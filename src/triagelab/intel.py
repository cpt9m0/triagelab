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
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
BIG_UPLOAD_URL = "https://www.virustotal.com/api/v3/files/upload_url"
ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"

# The public API takes files up to 32MB directly; larger ones need a one-time upload URL.
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD_BYTES = 650 * 1024 * 1024
UPLOAD_TIMEOUT = 300
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
STATUS_PENDING = "pending"


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
    analysis_id: str = ""
    analysis_status: str = ""

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


def forget(sha256: str) -> None:
    """Drop a cached entry so the next lookup goes live.

    Used after a submission completes: the cached `not_found` from before the upload
    would otherwise mask the fresh result forever.
    """
    try:
        _cache_path(sha256.strip().lower()).unlink()
    except OSError:
        pass


def _multipart_envelope(field_name: str, filename: str) -> tuple[bytes, bytes, str]:
    """Head and tail of a multipart/form-data body. urllib ships no encoder.

    The file's bytes go between them, streamed from disk, so a 200MB upload never
    becomes a 200MB (let alone 400MB) Python object.
    """
    import uuid

    boundary = uuid.uuid4().hex
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename) or "sample"
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{safe}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head, tail, f"multipart/form-data; boundary={boundary}"


def _stream_multipart(head: bytes, path: Path, tail: bytes, chunk_size: int = 1024 * 1024):
    """Yield the request body a megabyte at a time."""
    yield head
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            yield chunk
    yield tail


def sha256_of(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file without holding it in memory."""
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _request_json(url: str, api_key: str, data=None, content_type: str | None = None,
                  timeout: int = REQUEST_TIMEOUT, content_length: int | None = None
                  ) -> tuple[dict | None, VTResult | None]:
    """Shared HTTP plumbing. Returns (payload, error_result) - exactly one is set.

    `data` may be bytes or an iterable of bytes; an iterable needs content_length so
    the request is sent with a real Content-Length rather than chunked, which the
    VirusTotal upload endpoint expects.
    """
    headers = {"x-apikey": api_key, "accept": "application/json"}
    if content_type:
        headers["content-type"] = content_type
    if content_length is not None:
        headers["content-length"] = str(content_length)
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return None, VTResult(status=STATUS_ERROR, sha256="", message="VirusTotal rejected the API key (401).")
        if exc.code == 429:
            return None, VTResult(
                status=STATUS_RATE_LIMITED,
                sha256="",
                message="VirusTotal returned 429: quota exhausted (free tier is 4/min, 500/day).",
                retry_after=60,
            )
        if exc.code == 413:
            return None, VTResult(status=STATUS_ERROR, sha256="", message="File is too large for VirusTotal.")
        return None, VTResult(status=STATUS_ERROR, sha256="", message=f"VirusTotal error {exc.code}.")
    except (urllib.error.URLError, TimeoutError) as exc:
        return None, VTResult(status=STATUS_ERROR, sha256="", message=f"Network error: {exc}")
    except json.JSONDecodeError:
        return None, VTResult(status=STATUS_ERROR, sha256="", message="Malformed response from VirusTotal.")


def _check_quota(sha256: str) -> VTResult | None:
    """Shared gate: key present, inside the free-tier limits. None means go ahead."""
    now = time.time()
    quota = quota_status(now)
    if quota["retry_after"]:
        return VTResult(
            status=STATUS_RATE_LIMITED,
            sha256=sha256,
            message=f"Local throttle: {CALLS_PER_MINUTE} calls/min on the free tier. "
            f"Try again in {quota['retry_after']}s.",
            retry_after=quota["retry_after"],
        )
    if quota["used_today"] >= DAILY_QUOTA:
        return VTResult(
            status=STATUS_RATE_LIMITED,
            sha256=sha256,
            message=f"Daily free-tier quota of {DAILY_QUOTA} calls is used up.",
        )
    return None


def submit_file(path: str | Path, confirm: bool = False, api_key: str | None = None) -> VTResult:
    """Upload a file to VirusTotal for analysis.

    THIS PUBLISHES THE FILE. Anything submitted becomes retrievable by VirusTotal
    Intelligence subscribers. Never submit proprietary, confidential, or personal
    files.

    `confirm` must be True. The flag exists so that no test, script, agent, or
    stray call can publish a file by accident: the dangerous path is the one you
    have to ask for by name. Callers pass it only in response to a human action.

    Returns a pending result carrying an analysis_id; poll it with get_analysis().
    """
    file_path = Path(path)
    if not confirm:
        return VTResult(
            status=STATUS_ERROR,
            sha256="",
            message="Refusing to upload without confirm=True. Submitting a file to "
            "VirusTotal publishes it to their subscribers and cannot be undone.",
        )
    try:
        size = file_path.stat().st_size
        digest = sha256_of(file_path)
    except OSError as exc:
        return VTResult(status=STATUS_ERROR, sha256="", message=f"Cannot read {file_path}: {exc}")

    if not size:
        return VTResult(
            status=STATUS_ERROR, sha256=digest, message="Refusing to submit an empty file."
        )
    if size > MAX_UPLOAD_BYTES:
        return VTResult(
            status=STATUS_ERROR,
            sha256=digest,
            message=f"File is {size // (1024 * 1024)}MB; VirusTotal's limit is 650MB.",
        )

    key = api_key or vt_api_key()
    if not key:
        return VTResult(status=STATUS_NO_KEY, sha256=digest, message="No VT_API_KEY set.")

    blocked = _check_quota(digest)
    if blocked:
        return blocked

    target = UPLOAD_URL
    if size > DIRECT_UPLOAD_LIMIT:
        _record_call(time.time())
        big, error = _request_json(BIG_UPLOAD_URL, key)
        if error:
            error.sha256 = digest
            return error
        target = (big or {}).get("data", "")
        if not target:
            return VTResult(status=STATUS_ERROR, sha256=digest, message="No upload URL returned.")

    head, tail, content_type = _multipart_envelope("file", file_path.name)
    _record_call(time.time())
    response, error = _request_json(
        target,
        key,
        data=_stream_multipart(head, file_path, tail),
        content_type=content_type,
        timeout=UPLOAD_TIMEOUT,
        content_length=len(head) + size + len(tail),
    )
    if error:
        error.sha256 = digest
        return error

    analysis_id = ((response or {}).get("data") or {}).get("id", "")
    forget(digest)  # the cached not_found must not mask the incoming result
    return VTResult(
        status=STATUS_PENDING,
        sha256=digest,
        analysis_id=analysis_id,
        analysis_status="queued",
        message="Uploaded. VirusTotal is analysing it; this usually takes under a minute.",
        permalink=GUI_URL.format(sha256=digest),
    )


def get_analysis(analysis_id: str, sha256: str = "", api_key: str | None = None) -> VTResult:
    """Poll a submitted analysis. When it completes, return the full file report."""
    if not analysis_id:
        return VTResult(status=STATUS_ERROR, sha256=sha256, message="No analysis id to check.")

    key = api_key or vt_api_key()
    if not key:
        return VTResult(status=STATUS_NO_KEY, sha256=sha256, message="No VT_API_KEY set.")

    blocked = _check_quota(sha256)
    if blocked:
        blocked.analysis_id = analysis_id
        return blocked

    _record_call(time.time())
    response, error = _request_json(ANALYSIS_URL.format(analysis_id=analysis_id), key)
    if error:
        error.sha256 = sha256
        error.analysis_id = analysis_id
        return error

    attributes = ((response or {}).get("data") or {}).get("attributes") or {}
    state = attributes.get("status", "unknown")

    if state != "completed":
        return VTResult(
            status=STATUS_PENDING,
            sha256=sha256,
            analysis_id=analysis_id,
            analysis_status=state,
            message=f"Analysis is {state}. Check again in a few seconds.",
            permalink=GUI_URL.format(sha256=sha256) if sha256 else "",
        )

    if sha256:
        forget(sha256)
        return lookup(sha256, use_cache=False, api_key=key)

    return VTResult(
        status=STATUS_OK,
        sha256=sha256,
        analysis_id=analysis_id,
        analysis_status="completed",
        stats=attributes.get("stats") or {},
    )
