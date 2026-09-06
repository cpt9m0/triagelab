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
