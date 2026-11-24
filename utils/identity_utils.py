"""Sample identity resolution utilities.

Tuân thủ Rule 8.2 (<domain>_utils.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

SHA256_NAME_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class IdentityInfo:
    source_id: str
    filename_sha256: Optional[str] = None
    target_sha256: Optional[str] = None
    sample_sha256: Optional[str] = None
    status: str = "unresolved"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "sample_sha256_filename": self.filename_sha256,
            "sample_sha256_target": self.target_sha256,
            "sample_sha256": self.sample_sha256,
            "sample_identity_status": self.status,
            "notes": list(self.notes),
        }


def sha256_from_filename(path: Path | str) -> Optional[str]:
    """Return the 64 hex SHA encoded in a file name, or None."""
    name = Path(path).name
    stem = name[:-5] if name.lower().endswith(".json") else name
    if SHA256_NAME_RE.match(stem):
        return stem.lower()
    return None


def resolve_identity(
    source_id: str,
    *,
    filename_sha256: Optional[str],
    target_sha256: Optional[str],
    notes: Optional[list[str]] = None,
) -> IdentityInfo:
    """Combine the filename and target hashes into one identity verdict."""
    info = IdentityInfo(source_id=source_id, filename_sha256=filename_sha256, target_sha256=target_sha256)
    if notes:
        info.notes.extend(notes)

    if filename_sha256 and target_sha256:
        if filename_sha256 == target_sha256:
            info.status = "filename_target_agree"
            info.sample_sha256 = filename_sha256
        else:
            info.status = "conflict"
            info.sample_sha256 = None
            info.notes.append("filename_and_target_hashes_differ")
    elif filename_sha256:
        info.status = "filename_unverified"
        info.sample_sha256 = filename_sha256
        info.notes.append("target_hash_not_checked")
    elif target_sha256:
        info.status = "target_only"
        info.sample_sha256 = target_sha256
        info.notes.append("filename_hash_absent")
    else:
        info.status = "unresolved"
        info.sample_sha256 = None
        info.notes.append("no_valid_sample_hash")
    return info
