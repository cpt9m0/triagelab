import json

from triagelab import report


def test_build_report_has_expected_shape(tmp_path):
    target = tmp_path / "injector.bin"
    target.write_bytes(b"VirtualAllocEx CreateRemoteThread WriteProcessMemory padding padding")
    result = report.build_report(target)
    assert result["tool"] == "triagelab"
    assert result["band"] in {"low", "medium", "high", "critical"}
    assert result["matches"][0]["rule_id"] == "TL001"
    assert result["reasons"]


def test_write_report_emits_json_and_markdown(tmp_path):
    target = tmp_path / "quiet.bin"
    target.write_bytes(b"nothing interesting in this file at all")
    json_path, md_path = report.write_report(report.build_report(target), tmp_path / "out")
    assert json_path.exists() and md_path.exists()
    assert json.loads(json_path.read_text())["features"]["name"] == "quiet.bin"
    assert md_path.read_text().startswith("# Triage report: quiet.bin")


def test_markdown_notes_when_no_rules_match(tmp_path):
    target = tmp_path / "quiet.bin"
    target.write_bytes(b"nothing interesting in this file at all")
    rendered = report.render_markdown(report.build_report(target))
    assert "No rules matched." in rendered
