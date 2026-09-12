from triagelab import scoring
from triagelab.features import FileFeatures
from triagelab.rules import RuleMatch


def _features(**kwargs) -> FileFeatures:
    defaults = {
        "path": "x.bin",
        "name": "x.bin",
        "size_bytes": 100,
        "sha256": "0" * 64,
        "md5": "0" * 32,
        "entropy": 1.0,
        "printable_ratio": 1.0,
        "string_count": 0,
        "strings": [],
    }
    defaults.update(kwargs)
    return FileFeatures(**defaults)


def test_clean_file_scores_zero_and_bands_low():
    result = scoring.score(_features(), [])
    assert result.score == 0
    assert result.band == "low"


def test_high_entropy_adds_points():
    result = scoring.score(_features(entropy=7.9), [])
    assert result.score == 25
    assert "very high entropy" in result.reasons[0]


def test_severity_five_match_bands_high():
    match = RuleMatch("TL001", "Process injection primitives", "process-injection", 5, ["VirtualAllocEx"])
    result = scoring.score(_features(), [match])
    assert result.score == 30
    assert result.band == "medium"


def test_score_is_capped_at_100():
    matches = [RuleMatch(f"TL00{i}", "x", "y", 5, ["z"]) for i in range(5)]
    result = scoring.score(_features(entropy=7.9), matches)
    assert result.score == 100
    assert result.band == "critical"


def test_band_boundaries():
    assert scoring.band_for(0) == "low"
    assert scoring.band_for(19) == "low"
    assert scoring.band_for(20) == "medium"
    assert scoring.band_for(50) == "high"
    assert scoring.band_for(80) == "critical"


def test_empty_file_scores_zero_without_crashing():
    empty = _features(size_bytes=0, entropy=0.0, printable_ratio=0.0)
    result = scoring.score(empty, [])
    assert result.score == 0
    assert result.band == "low"
    assert "empty file - nothing to analyse" in result.reasons
