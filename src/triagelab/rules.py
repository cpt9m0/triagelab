"""Indicator rules.

A rule is a named bundle of string patterns in one behavioural category. These
are *text* patterns only - the tool never executes anything it inspects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
CUSTOM_RULES_DIR = RULES_DIR / "custom"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: int  # 1 (informational) .. 5 (critical)
    patterns: tuple[str, ...]
    description: str


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    severity: int
    matched_terms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "matched_terms": self.matched_terms,
        }


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule(
        id="TL001",
        name="Process injection primitives",
        category="process-injection",
        severity=5,
        patterns=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection"),
        description="API names commonly chained to run code inside another process.",
    ),
    Rule(
        id="TL002",
        name="Registry persistence",
        category="persistence",
        severity=4,
        patterns=("RegSetValueEx", r"CurrentVersion\\Run", "schtasks /create"),
        description="Writes that survive reboot.",
    ),
    Rule(
        id="TL003",
        name="Remote payload retrieval",
        category="network",
        severity=4,
        patterns=("URLDownloadToFile", "InternetOpenUrl", "WinHttpSendRequest", "Invoke-WebRequest"),
        description="Fetches additional content from the network.",
    ),
    Rule(
        id="TL004",
        name="Encoded command execution",
        category="obfuscation",
        severity=4,
        patterns=("powershell -enc", "FromBase64String", "WScript.Shell", "cmd.exe /c"),
        description="Shell invocation through an encoding or scripting host layer.",
    ),
    Rule(
        id="TL005",
        name="Host reconnaissance",
        category="recon",
        severity=2,
        patterns=("GetComputerName", "GetUserName", "systeminfo", "ipconfig /all"),
        description="Collects host identity before deciding what to do next.",
    ),
    Rule(
        id="TL006",
        name="Anti-analysis checks",
        category="evasion",
        severity=3,
        patterns=("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "vmware", "VBoxService"),
        description="Looks for a debugger or virtual machine before running.",
    ),
    Rule(
        id="TL007",
        name="PowerShell download cradle",
        category="download-cradle",
        severity=4,
        patterns=(
            "Net.WebClient).DownloadString",
            "Net.WebClient).DownloadFile",
        ),
        description="Classic PowerShell one-liner that pulls and runs a remote payload in memory.",
    ),
)


def load_custom_rules(directory: Path | None = None) -> list[Rule]:
    """Load user-authored rules from rules/custom/*.json.

    NOT IMPLEMENTED. This is the deliberate gap built live during the talk
    (see README, "Rung 2 - Plan mode"). The /new-rule skill already writes
    rule files into rules/custom/; nothing reads them yet.
    """
    raise NotImplementedError(
        "custom rule loading is the live plan-mode demo - see README section 'Rung 2'"
    )


def all_rules() -> tuple[Rule, ...]:
    """Every rule the scorer should consider. Custom rules join here later."""
    return BUILTIN_RULES


def match_rules(strings: list[str], rules: tuple[Rule, ...] | None = None) -> list[RuleMatch]:
    """Match each rule's patterns against the extracted strings, case-insensitively."""
    haystack = "\n".join(strings)
    matches: list[RuleMatch] = []
    for rule in rules if rules is not None else all_rules():
        hits = [p for p in rule.patterns if re.search(re.escape(p), haystack, re.IGNORECASE)]
        if hits:
            matches.append(
                RuleMatch(
                    rule_id=rule.id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    matched_terms=hits,
                )
            )
    return matches
