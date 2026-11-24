"""IO utilities: hashing, canonical JSON, atomic writes, strict JSON loading, Windows long-path safety.

Tuân thủ quy tắc Rule 8.2 (thay thế util.py) và Rule 23 (Windows/Linux filesystem compatibility).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Union

CHUNK_SIZE = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def to_safe_path(path: Union[Path, str]) -> Path:
    """Ensure path works on Windows even when exceeding 260 characters."""
    p_str = os.path.abspath(str(path))
    if os.name == "nt" and not p_str.startswith("\\\\?\\"):
        if p_str.startswith("\\\\"):
            p_str = "\\\\?\\UNC\\" + p_str[2:]
        else:
            p_str = "\\\\?\\" + p_str
    return Path(p_str)


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains the same key twice."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def read_json_strict(path: Path | str) -> Any:
    """Load JSON, rejecting duplicate object keys (never last-write-wins)."""
    safe_p = to_safe_path(path)
    with open(safe_p, "r", encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=_no_duplicates)


def canonical_json(value: Any) -> str:
    """Deterministic JSON text used for fingerprints."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def sha256_file(path: Path | str) -> tuple[str, int]:
    """Return (hex digest, byte count) of a file, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    safe_p = to_safe_path(path)
    with open(safe_p, "rb") as stream:
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.match(value.strip().lower()))


def normalize_label(value: str) -> str:
    return value.strip().casefold()


def to_posix_rel(path: Path, root: Path) -> str:
    """Relative path of *path* under *root* using '/' separators."""
    rel = os.path.relpath(str(path), str(root))
    return rel.replace(os.sep, "/")


def atomic_write_bytes(path: Path, data: bytes) -> str:
    """Write bytes to *path* via a temp file on the same filesystem, then rename."""
    safe_target = to_safe_path(path)
    safe_parent = safe_target.parent
    safe_parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=safe_target.name + ".", suffix=".tmp", dir=str(safe_parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, safe_target)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return sha256_bytes(data)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> str:
    return atomic_write_bytes(path, text.encode(encoding))


def write_json(path: Path, value: Any, *, indent: int = 2) -> str:
    text = json.dumps(value, indent=indent, ensure_ascii=False, sort_keys=False, default=str)
    return atomic_write_text(path, text + "\n")


def write_jsonl(path: Path, rows: Iterable[Any]) -> int:
    count = 0
    safe_target = to_safe_path(path)
    safe_target.parent.mkdir(parents=True, exist_ok=True)
    tmp = safe_target.with_name(safe_target.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, default=str))
            stream.write("\n")
            count += 1
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, safe_target)
    return count


def read_jsonl(path: Path | str) -> list[Any]:
    rows: list[Any] = []
    safe_p = to_safe_path(path)
    with open(safe_p, "r", encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"{path}:{line_no}: invalid JSON line: {exc}") from exc
    return rows


def json_cell(value: Any) -> str:
    """Serialize a list/dict for a CSV cell (never a delimiter-ambiguous join)."""
    if value is None:
        return ""
    if isinstance(value, (list, dict, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def excel_safe(value: str) -> str:
    """Neutralize cells that a spreadsheet would interpret as a formula."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def human_bytes(size: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0:
            return f"{size:,.1f} {unit}"
        size /= 1024.0
    return f"{size:,.1f} PiB"


def resolve_existing(path: Path) -> Path:
    return path.expanduser().resolve()


def path_is_within(child: Path, parent: Path) -> bool:
    """True when *child* is inside *parent* (resolved, case-insensitive on Windows)."""
    try:
        child_resolved = Path(os.path.normcase(str(child.resolve())))
        parent_resolved = Path(os.path.normcase(str(parent.resolve())))
    except OSError:  # pragma: no cover - defensive
        return False
    try:
        child_resolved.relative_to(parent_resolved)
        return True
    except ValueError:
        return False
