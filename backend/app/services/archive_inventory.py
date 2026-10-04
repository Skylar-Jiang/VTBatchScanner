"""Read ZIP members as data in memory; never extract or execute members."""

import hashlib
import io
import zipfile


def inventory_zip(data: bytes, password: bytes, prefix: str = "", depth: int = 0) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    if depth > 5:
        return [], [{"path": prefix, "error": "nested_archive_depth_limit"}]
    rows: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                path = f"{prefix}!/{member.filename}" if prefix else member.filename
                if member.file_size > 256 * 1024 * 1024:
                    errors.append({"path": path, "error": "member_size_limit"})
                    continue
                try:
                    contents = archive.read(member, pwd=password)
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                    errors.append({"path": path, "error": type(exc).__name__})
                    continue
                if member.filename.lower().endswith(".zip") and zipfile.is_zipfile(io.BytesIO(contents)):
                    nested_rows, nested_errors = inventory_zip(contents, password, path, depth + 1)
                    rows.extend(nested_rows)
                    errors.extend(nested_errors)
                else:
                    rows.append({"path": path, "size": len(contents), "sha256": hashlib.sha256(contents).hexdigest()})
    except zipfile.BadZipFile:
        errors.append({"path": prefix, "error": "invalid_zip"})
    return rows, errors
