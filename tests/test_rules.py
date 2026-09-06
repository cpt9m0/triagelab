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


def test_custom_rule_loading_is_the_live_demo_gap():
    """Guards the deliberate gap: this is what gets built during the talk."""
    with pytest.raises(NotImplementedError):
        rules.load_custom_rules()
