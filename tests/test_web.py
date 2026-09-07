"""Dashboard tests. The upload path must accept real binaries and never execute them."""

import pytest

from triagelab import intel

fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
pytest.importorskip("multipart", reason="python-multipart not installed")
pytest.importorskip("httpx", reason="httpx not installed (required by starlette.testclient)")

from fastapi.testclient import TestClient
from web.app import app, safe_filename


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


def test_upload_limit_is_200mb():
    import web.app as webapp

    assert webapp.MAX_UPLOAD_BYTES == 200 * 1024 * 1024


def test_oversized_upload_is_rejected_and_leaves_no_file(client, monkeypatch):
    import web.app as webapp

    monkeypatch.setattr(webapp, "MAX_UPLOAD_BYTES", 1024)
    response = client.post(
        "/upload", files=[("files", ("huge.bin", b"x" * 4096, "application/octet-stream"))]
    )
    assert "exceeds" in response.text
    assert not (webapp.UPLOADS_DIR / "huge.bin").exists()


def test_multi_megabyte_upload_round_trips(client):
    payload = bytes(range(256)) * 20000  # ~5MB, crosses the 1MB chunk boundary
    response = client.post(
        "/upload", files=[("files", ("chunky.bin", payload, "application/octet-stream"))]
    )
    assert response.status_code == 200

    import hashlib

    import web.app as webapp

    written = (webapp.UPLOADS_DIR / "chunky.bin").read_bytes()
    assert hashlib.sha256(written).hexdigest() == hashlib.sha256(payload).hexdigest()


def test_scan_in_place_avoids_the_upload_path(client, tmp_path):
    """A local file is triaged without being copied into uploads/."""
    sample = tmp_path / "local_binary.exe"
    sample.write_bytes(b"MZ" + b"VirtualAllocEx CreateRemoteThread " * 4)

    response = client.post("/scan-path", data={"path": str(sample)})
    assert response.status_code == 200
    assert "local_binary.exe" in response.text

    import web.app as webapp

    assert not (webapp.UPLOADS_DIR / "local_binary.exe").exists()
    assert (webapp.REPORTS_DIR / "local_binary.json").is_file()


def test_scan_in_place_reports_a_missing_file(client, tmp_path):
    response = client.post("/scan-path", data={"path": str(tmp_path / "nope.bin")})
    assert "No such file" in response.text


def test_scan_in_place_rejects_a_directory(client, tmp_path):
    response = client.post("/scan-path", data={"path": str(tmp_path)})
    assert "Not a file" in response.text


def test_scan_in_place_tolerates_quoted_paths(client, tmp_path):
    """Windows' "Copy as path" wraps the path in quotes."""
    sample = tmp_path / "quoted.bin"
    sample.write_bytes(b"some bytes here")
    response = client.post("/scan-path", data={"path": f'"{sample}"'})
    assert "quoted.bin" in response.text
