"""Dashboard tests. The upload path must accept real binaries and never execute them."""

import pytest

from triagelab import intel

fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
pytest.importorskip("multipart", reason="python-multipart not installed")

from fastapi.testclient import TestClient  # noqa: E402

from web.app import app, safe_filename  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import web.app as webapp

    monkeypatch.setattr(webapp, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(webapp, "UPLOADS_DIR", tmp_path / "uploads")
    monkeypatch.setattr(intel, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(intel, "STATE_FILE", tmp_path / "cache" / "_quota.json")
    return TestClient(app)


@pytest.mark.parametrize(
    "given,expected",
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
        ("", "unnamed"),
        ("weird name!@#.bin", "weird_name_.bin"),
    ],
)
def test_upload_filenames_are_sanitised(given, expected):
    assert safe_filename(given) == expected


def test_empty_dashboard_invites_an_upload(client):
    assert "Nothing yet" in client.get("/").text


def test_uploading_a_binary_produces_a_report(client):
    payload = b"MZ\x90\x00" + b"VirtualAllocEx CreateRemoteThread" + bytes(range(256)) * 4
    response = client.post(
        "/upload", files=[("files", ("stub.exe", payload, "application/octet-stream"))]
    )
    assert response.status_code == 200
    assert "stub.exe" in response.text

    detail = client.get("/report/stub")
    assert detail.status_code == 200
    assert "Process injection primitives" in detail.text


def test_upload_rejects_nothing_gracefully(client):
    response = client.post("/upload", files=[("files", ("x.bin", b"", "application/octet-stream"))])
    assert "No files received" in response.text


def test_unknown_report_is_404(client):
    assert client.get("/report/never-triaged").status_code == 404


def test_vt_panel_reports_missing_key_instead_of_failing(client, monkeypatch):
    monkeypatch.setattr(intel, "vt_api_key", lambda: None)
    client.post("/upload", files=[("files", ("quiet.bin", b"hello world padding", "text/plain"))])
    response = client.post("/report/quiet/vt")
    assert response.status_code == 200
    assert "no_key" in response.text or "VT_API_KEY" in response.text


def test_not_found_offers_an_explicit_consented_upload(client, monkeypatch):
    monkeypatch.setattr(
        intel,
        "lookup",
        lambda *a, **k: intel.VTResult(status=intel.STATUS_NOT_FOUND, sha256="a" * 64,
                                       message="never seen"),
    )
    client.post("/upload", files=[("files", ("novel.bin", b"unique bytes here", "application/octet-stream"))])
    page = client.post("/report/novel/vt").text
    assert "Upload file for analysis" in page
    assert "publishes this file" in page
    assert 'type="checkbox"' in page


def test_submit_route_passes_explicit_confirmation(client, monkeypatch):
    seen = {}

    def fake_submit(path, confirm=False, api_key=None):
        seen["confirm"] = confirm
        return intel.VTResult(status=intel.STATUS_PENDING, sha256="b" * 64,
                              analysis_id="an-1", message="queued")

    monkeypatch.setattr(intel, "submit_file", fake_submit)
    client.post("/upload", files=[("files", ("thing.bin", b"payload bytes", "application/octet-stream"))])
    page = client.post("/report/thing/vt-submit").text

    assert seen["confirm"] is True
    assert "Check analysis" in page


def test_check_route_polls_the_analysis(client, monkeypatch):
    monkeypatch.setattr(
        intel,
        "submit_file",
        lambda *a, **k: intel.VTResult(status=intel.STATUS_PENDING, sha256="c" * 64, analysis_id="an-2"),
    )
    monkeypatch.setattr(
        intel,
        "get_analysis",
        lambda analysis_id, sha256="", **k: intel.VTResult(
            status=intel.STATUS_OK, sha256=sha256, stats={"malicious": 3, "undetected": 60}
        ),
    )
    client.post("/upload", files=[("files", ("poll.bin", b"payload bytes", "application/octet-stream"))])
    client.post("/report/poll/vt-submit")
    page = client.post("/report/poll/vt-check").text
    assert "3/63" in page
