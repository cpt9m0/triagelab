"""Static feature extraction. Pure standard library, no third-party imports."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

MIN_STRING_LEN = 5
MAX_STRINGS = 500
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)


@dataclass
class FileFeatures:
    """Everything we can learn about a file without executing it."""

    path: str
    name: str
    size_bytes: int
    sha256: str
    md5: str
    entropy: float
    printable_ratio: float
    string_count: int
    strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, 0.0 (uniform) to 8.0 (random).

    High entropy is the classic signal for compressed or packed content.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(data)


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN, limit: int = MAX_STRINGS) -> list[str]:
    """Pull printable ASCII runs out of a byte blob, like strings(1)."""
    if min_len == MIN_STRING_LEN:
        pattern = _PRINTABLE_RUN
    else:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out: list[str] = []
    for match in pattern.finditer(data):
        out.append(match.group().decode("ascii", errors="replace"))
        if len(out) >= limit:
            break
    return out


def extract(path: str | Path) -> FileFeatures:
    """Read a file and compute every static feature we score on."""
    p = Path(path)
    data = p.read_bytes()
    strings = extract_strings(data)
    return FileFeatures(
        path=str(p),
        name=p.name,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        entropy=round(shannon_entropy(data), 4),
        printable_ratio=round(printable_ratio(data), 4),
        string_count=len(strings),
        strings=strings,
    )
