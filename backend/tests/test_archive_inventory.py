import hashlib
import io
import zipfile

from app.services.archive_inventory import inventory_zip


def test_nested_archive_hashes_bytes_without_extracting(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("../../sample.exe", b"inert test bytes")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("nested.zip", inner.getvalue())
    rows, errors = inventory_zip(outer.getvalue(), b"virus")
    assert not errors
    assert len(rows) == 1
    assert rows[0]["sha256"] == hashlib.sha256(b"inert test bytes").hexdigest()
    assert list(tmp_path.iterdir()) == []


def test_zip_compatible_executable_is_hashed_as_sample_not_unpacked():
    embedded = io.BytesIO()
    with zipfile.ZipFile(embedded, "w") as archive:
        archive.writestr("resource.txt", b"resource bytes")
    sample = b"MZ inert self-extracting fixture" + embedded.getvalue()
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("sample.exe", sample)
    rows, errors = inventory_zip(outer.getvalue(), b"virus")
    assert not errors
    assert rows == [{"path": "sample.exe", "size": len(sample), "sha256": hashlib.sha256(sample).hexdigest()}]
