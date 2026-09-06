"""VirusTotal client tests. No network: payloads are canned, quota state is isolated."""

import json
import time

import pytest

from triagelab import intel

CANNED = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 54,
                "suspicious": 2,
                "undetected": 12,
                "harmless": 0,
                "timeout": 0,
            },
            "popular_threat_classification": {"suggested_threat_label": "trojan.demo/testfile"},
            "type_description": "Win32 EXE",
            "names": ["invoice.exe", "setup.exe", "a.exe", "b.exe", "c.exe", "d.exe"],
            "first_submission_date": 1700000000,
            "last_analysis_date": 1750000000,
            "reputation": -42,
            "times_submitted": 918,
        }
    }
}
DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Never touch the real .vt_cache or the real quota counters during tests."""
    monkeypatch.setattr(intel, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(intel, "STATE_FILE", tmp_path / "cache" / "_quota.json")


def test_parse_payload_extracts_the_fields_we_display():
    result = intel.parse_payload(CANNED, DIGEST)
    assert result.status == intel.STATUS_OK
    assert result.threat_label == "trojan.demo/testfile"
    assert result.type_description == "Win32 EXE"
    assert result.first_submission == "2023-11-14"
    assert result.reputation == -42
    assert result.permalink.endswith(DIGEST)


def test_detection_ratio_counts_malicious_and_suspicious():
    assert intel.parse_payload(CANNED, DIGEST).detection_ratio == "56/68"


def test_known_names_are_capped_at_five():
    assert len(intel.parse_payload(CANNED, DIGEST).names) == 5


def test_empty_stats_yield_no_ratio():
    assert intel.parse_payload({"data": {"attributes": {}}}, DIGEST).detection_ratio == ""


def test_malformed_hash_is_rejected_before_any_call():
    assert intel.lookup("not-a-hash").status == intel.STATUS_ERROR


def test_missing_key_is_reported_not_crashed(monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: None)
    result = intel.lookup(DIGEST)
    assert result.status == intel.STATUS_NO_KEY
    assert "VT_API_KEY" in result.message


def test_cache_hit_avoids_the_network(monkeypatch):
    intel._write_cache(DIGEST, CANNED)
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(
        intel, "_fetch", lambda *a, **k: pytest.fail("cache hit should not reach the network")
    )
    result = intel.lookup(DIGEST)
    assert result.cached is True
    assert result.detection_ratio == "56/68"


def test_cached_not_found_is_remembered(monkeypatch):
    intel._write_cache(DIGEST, None, not_found=True)
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    assert intel.lookup(DIGEST).status == intel.STATUS_NOT_FOUND


def test_throttle_blocks_the_fifth_call_in_a_minute(monkeypatch):
    now = time.time()
    intel._write_state({"calls": [now] * intel.CALLS_PER_MINUTE, "daily": {}})
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(
        intel, "_fetch", lambda *a, **k: pytest.fail("throttle should block this call")
    )
    result = intel.lookup(DIGEST, use_cache=False)
    assert result.status == intel.STATUS_RATE_LIMITED
    assert result.retry_after > 0


def test_quota_status_ignores_calls_older_than_a_minute():
    intel._write_state({"calls": [time.time() - 120] * 10, "daily": {}})
    assert intel.quota_status()["calls_last_minute"] == 0
    assert intel.quota_status()["retry_after"] == 0


def test_daily_quota_exhaustion_is_reported(monkeypatch):
    from datetime import datetime, timezone

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    intel._write_state({"calls": [], "daily": {today: intel.DAILY_QUOTA}})
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    result = intel.lookup(DIGEST, use_cache=False)
    assert result.status == intel.STATUS_RATE_LIMITED
    assert "Daily" in result.message


def test_recording_a_call_increments_both_counters():
    intel._record_call(time.time())
    quota = intel.quota_status()
    assert quota["calls_last_minute"] == 1
    assert quota["used_today"] == 1


def test_result_serialises_for_the_report(tmp_path):
    payload = intel.parse_payload(CANNED, DIGEST).to_dict()
    assert json.loads(json.dumps(payload))["detection_ratio"] == "56/68"


# --- file submission -------------------------------------------------------
# Every test here is offline. Any attempt to reach the network fails the test,
# which is the guard that should have existed before a stray smoke test
# published a file to VirusTotal for real.


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def explode(*args, **kwargs):
        pytest.fail("test attempted a real network call")

    monkeypatch.setattr(intel, "_request_json", explode)


def test_submit_refuses_without_confirmation(tmp_path):
    sample = tmp_path / "thing.bin"
    sample.write_bytes(b"payload")
    result = intel.submit_file(sample)
    assert result.status == intel.STATUS_ERROR
    assert "confirm=True" in result.message


def test_submit_refuses_an_empty_file(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    sample = tmp_path / "empty.bin"
    sample.write_bytes(b"")
    assert "empty" in intel.submit_file(sample, confirm=True).message


def test_submit_refuses_oversized_files(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(intel, "MAX_UPLOAD_BYTES", 4)
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"more than four bytes")
    assert "650MB" in intel.submit_file(sample, confirm=True).message


def test_submit_without_key_never_reaches_the_network(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: None)
    sample = tmp_path / "thing.bin"
    sample.write_bytes(b"payload")
    assert intel.submit_file(sample, confirm=True).status == intel.STATUS_NO_KEY


def test_successful_submission_returns_a_pending_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(
        intel, "_request_json", lambda *a, **k: ({"data": {"id": "analysis-123"}}, None)
    )
    sample = tmp_path / "thing.bin"
    sample.write_bytes(b"payload")

    result = intel.submit_file(sample, confirm=True)
    assert result.status == intel.STATUS_PENDING
    assert result.analysis_id == "analysis-123"
    assert result.permalink.endswith(result.sha256)


def test_submission_clears_a_cached_not_found(tmp_path, monkeypatch):
    """Otherwise the stale 404 would mask the result we just paid to generate."""
    sample = tmp_path / "thing.bin"
    sample.write_bytes(b"payload")
    import hashlib

    digest = hashlib.sha256(b"payload").hexdigest()
    intel._write_cache(digest, None, not_found=True)
    assert intel.read_cache(digest).status == intel.STATUS_NOT_FOUND

    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(intel, "_request_json", lambda *a, **k: ({"data": {"id": "x"}}, None))
    intel.submit_file(sample, confirm=True)
    assert intel.read_cache(digest) is None


def test_analysis_still_running_reports_pending(monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(
        intel,
        "_request_json",
        lambda *a, **k: ({"data": {"attributes": {"status": "in-progress"}}}, None),
    )
    result = intel.get_analysis("analysis-123", sha256=DIGEST)
    assert result.status == intel.STATUS_PENDING
    assert result.analysis_status == "in-progress"


def test_completed_analysis_returns_the_full_file_report(monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(
        intel,
        "_request_json",
        lambda *a, **k: ({"data": {"attributes": {"status": "completed"}}}, None),
    )
    monkeypatch.setattr(
        intel, "lookup", lambda *a, **k: intel.parse_payload(CANNED, DIGEST)
    )
    result = intel.get_analysis("analysis-123", sha256=DIGEST)
    assert result.status == intel.STATUS_OK
    assert result.detection_ratio == "56/68"


def test_analysis_check_needs_an_id():
    assert intel.get_analysis("").status == intel.STATUS_ERROR


def test_multipart_envelope_is_well_formed(tmp_path):
    head, tail, content_type = intel._multipart_envelope("file", "odd name!.exe")
    boundary = content_type.split("boundary=")[1]
    assert head.startswith(f"--{boundary}".encode())
    assert tail == f"\r\n--{boundary}--\r\n".encode()
    assert b'filename="odd_name_.exe"' in head


def test_multipart_streams_the_file_in_chunks(tmp_path):
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"A" * (3 * 1024 * 1024))
    head, tail, _ = intel._multipart_envelope("file", "big.bin")

    chunks = list(intel._stream_multipart(head, sample, tail, chunk_size=1024 * 1024))
    assert chunks[0] == head and chunks[-1] == tail
    assert len(chunks) == 5  # head + three 1MB chunks + tail
    assert max(len(c) for c in chunks[1:-1]) == 1024 * 1024
    assert b"".join(chunks) == head + b"A" * (3 * 1024 * 1024) + tail


def test_streaming_hash_matches_hashing_it_all_at_once(tmp_path):
    import hashlib

    sample = tmp_path / "x.bin"
    payload = bytes(range(256)) * 8192
    sample.write_bytes(payload)
    assert intel.sha256_of(sample, chunk_size=4096) == hashlib.sha256(payload).hexdigest()


def test_upload_sends_a_real_content_length(tmp_path, monkeypatch):
    """An iterable body without Content-Length would go out chunked, which VT rejects."""
    captured = {}

    def fake_request(url, key, data=None, content_type=None, timeout=None, content_length=None):
        captured["length"] = content_length
        captured["streamed"] = hasattr(data, "__iter__") and not isinstance(data, bytes)
        return {"data": {"id": "an-1"}}, None

    monkeypatch.setattr(intel, "vt_api_key", lambda: "key")
    monkeypatch.setattr(intel, "_request_json", fake_request)

    sample = tmp_path / "thing.bin"
    sample.write_bytes(b"payload bytes")
    head, tail, _ = intel._multipart_envelope("file", "thing.bin")

    intel.submit_file(sample, confirm=True)
    assert captured["streamed"] is True
    assert captured["length"] == len(head) + 13 + len(tail)
