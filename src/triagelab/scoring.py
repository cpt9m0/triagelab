"""Risk scoring.

Deterministic and boring on purpose: a demo audience should be able to predict
the score from the inputs, and the tests should pin it exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .features import FileFeatures
from .rules import RuleMatch

BANDS = ((80, "critical"), (50, "high"), (20, "medium"), (0, "low"))
SEVERITY_POINTS = {1: 4, 2: 8, 3: 14, 4: 22, 5: 30}


@dataclass
class ScoreResult:
    score: int
    band: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "band": self.band, "reasons": self.reasons}


def entropy_points(entropy: float) -> tuple[int, str | None]:
    """High entropy suggests packed or encrypted content."""
    if entropy >= 7.2:
        return 25, f"very high entropy ({entropy:.2f}) - likely packed or encrypted"
    if entropy >= 6.5:
        return 15, f"elevated entropy ({entropy:.2f}) - possibly compressed"
    if entropy >= 5.5:
        return 5, f"moderate entropy ({entropy:.2f})"
    return 0, None


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"


def score(features: FileFeatures, matches: list[RuleMatch]) -> ScoreResult:
    """Combine entropy signal and rule severities into a 0-100 risk score."""
    total = 0
    reasons: list[str] = []

    points, reason = entropy_points(features.entropy)
    if reason:
        total += points
        reasons.append(reason)

    for match in matches:
        points = SEVERITY_POINTS.get(match.severity, 0)
        total += points
        reasons.append(
            f"{match.rule_id} {match.name} (severity {match.severity}): "
            + ", ".join(match.matched_terms)
        )

    if features.size_bytes == 0:
        reasons.append("empty file - nothing to analyse")

    total = max(0, min(100, total))
    return ScoreResult(score=total, band=band_for(total), reasons=reasons)
