from app.services.inputs import preview_hashes


VALID_HASH = "a" * 64


def test_preview_normalizes_deduplicates_and_reports_invalid_lines() -> None:
    preview = preview_hashes([VALID_HASH.upper(), VALID_HASH, "not-a-hash"])

    assert preview.valid_sha256s == [VALID_HASH]
    assert preview.duplicates[0].line == 2
    assert preview.duplicates[0].first_line == 1
    assert preview.invalid[0].line == 3
    assert preview.invalid[0].reason == "invalid_format"

