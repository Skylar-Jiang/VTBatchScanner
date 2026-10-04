from __future__ import annotations

from dataclasses import dataclass
import re


SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass(frozen=True)
class DuplicateItem:
    line: int
    value: str
    first_line: int


@dataclass(frozen=True)
class InvalidItem:
    line: int
    value: str
    reason: str


@dataclass(frozen=True)
class InputPreview:
    valid_sha256s: list[str]
    duplicates: list[DuplicateItem]
    invalid: list[InvalidItem]


def preview_hashes(values: list[str]) -> InputPreview:
    valid_sha256s: list[str] = []
    duplicates: list[DuplicateItem] = []
    invalid: list[InvalidItem] = []
    first_lines: dict[str, int] = {}

    for line, raw_value in enumerate(values, start=1):
        value = raw_value.strip()
        if not SHA256_PATTERN.fullmatch(value):
            invalid.append(InvalidItem(line=line, value=raw_value, reason="invalid_format"))
            continue

        sha256 = value.lower()
        if sha256 in first_lines:
            duplicates.append(
                DuplicateItem(line=line, value=sha256, first_line=first_lines[sha256])
            )
            continue

        first_lines[sha256] = line
        valid_sha256s.append(sha256)

    return InputPreview(
        valid_sha256s=valid_sha256s,
        duplicates=duplicates,
        invalid=invalid,
    )

