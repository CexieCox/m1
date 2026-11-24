"""Label source loading utilities: grouped AVClass/CAPE mappings and the consensus index.

Tuân thủ Rule 8.2 (<domain>_utils.py).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

import ijson

from .errors import LabelDataError
from .models import LabelObservation
from .taxonomy_utils import Taxonomy
from .io_utils import DuplicateKeyError, normalize_label, sha256_file

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CONSENSUS_META_KEYS = (
    "reports_avclass_no_consensus",
    "reports_cape_no_consensus",
    "reports_both_no_consensus",
)
LABEL_KINDS = ("avclass", "cape")


class _Frame:
    __slots__ = ("kind", "key", "path", "data", "seen")

    def __init__(self, kind: str, path: list[str]):
        self.kind = kind
        self.key: Optional[str] = None
        self.path = path
        self.data: dict[str, Any] = {}
        self.seen: set[str] = set()


def _scan_json(path: Path) -> Iterator[tuple[list[str], dict[str, Any]]]:
    """Stream every JSON object in *path* together with its logical path."""
    frames: list[_Frame] = []
    try:
        with open(path, "rb") as stream:
            events = ijson.parse(stream)
            for _prefix, event, value in events:
                if event == "start_map":
                    if frames:
                        parent = frames[-1]
                        child_path = parent.path + ([parent.key] if parent.kind == "map" and parent.key else ["item"])
                    else:
                        child_path = []
                    frames.append(_Frame("map", child_path))
                elif event == "end_map":
                    frame = frames.pop()
                    yield frame.path, frame.data
                elif event == "start_array":
                    if frames:
                        parent = frames[-1]
                        child_path = parent.path + ([parent.key] if parent.kind == "map" and parent.key else ["item"])
                    else:
                        child_path = []
                    frames.append(_Frame("array", child_path))
                elif event == "end_array":
                    frames.pop()
                elif event == "map_key":
                    frame = frames[-1]
                    if frame.kind != "map":
                        raise DuplicateKeyError("map_key outside of a map")
                    if value in frame.seen:
                        raise DuplicateKeyError(f"duplicate JSON key {value!r} in {path.name}")
                    frame.seen.add(value)
                    frame.key = value
                else:  # scalar
                    frame = frames[-1]
                    if frame.kind == "map" and frame.key is not None:
                        frame.data[frame.key] = value
    except DuplicateKeyError as exc:
        raise LabelDataError(f"invalid JSON in {path}: {exc}", details={"file": str(path)}) from exc
    except ijson.JSONError as exc:
        raise LabelDataError(f"invalid JSON in {path}: {exc}", details={"file": str(path)}) from exc
    except OSError as exc:
        raise LabelDataError(f"cannot read label source {path}: {exc}") from exc


@dataclass
class LabelSourceStats:
    kind: str
    path: str
    content_sha256: str = ""
    declared_total: Optional[int] = None
    actual_total: int = 0
    unique_samples: int = 0
    records: int = 0
    duplicate_rows: int = 0
    invalid_rows: int = 0
    quarantined_rows: int = 0
    missing_label_records: int = 0
    conflicts: int = 0
    declared_count_mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "content_sha256": self.content_sha256,
            "declared_total": self.declared_total,
            "actual_total": self.actual_total,
            "unique_samples": self.unique_samples,
            "records": self.records,
            "duplicate_rows": self.duplicate_rows,
            "invalid_rows": self.invalid_rows,
            "quarantined_rows": self.quarantined_rows,
            "missing_label_records": self.missing_label_records,
            "conflicts": self.conflicts,
            "declared_count_mismatches": list(self.declared_count_mismatches),
        }


@dataclass
class ConsensusStats:
    path: str = ""
    content_sha256: str = ""
    entries: int = 0
    counters: dict[str, int] = field(default_factory=dict)
    invalid_rows: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "content_sha256": self.content_sha256,
            "entries": self.entries,
            "counters": dict(self.counters),
            "invalid_rows": self.invalid_rows,
        }


class LabelStore:
    """Observation store for the configured label sources."""

    def __init__(self, taxonomy: Taxonomy):
        self.taxonomy = taxonomy
        self._observations: dict[tuple[str, str], list[LabelObservation]] = {}
        self._by_sha: dict[str, list[LabelObservation]] = {}
        self.source_stats: dict[str, LabelSourceStats] = {}
        self.consensus_stats: ConsensusStats = ConsensusStats()
        self.quarantined_rows: list[dict[str, Any]] = []
        self.index_mismatches: dict[str, dict[str, Any]] = {}
        self.consensus_entries: dict[str, dict[str, str]] = {}

    def observations(self, kind: str, sample_sha256: Optional[str]) -> list[LabelObservation]:
        if not sample_sha256:
            return []
        return list(self._observations.get((kind, sample_sha256), ()))

    def primary(self, kind: str, sample_sha256: Optional[str]) -> Optional[LabelObservation]:
        items = self.observations(kind, sample_sha256)
        return items[0] if items else None

    def has_record(self, kind: str, sample_sha256: Optional[str]) -> bool:
        if not sample_sha256:
            return False
        return (kind, sample_sha256) in self._observations

    def all_for(self, sample_sha256: Optional[str]) -> list[LabelObservation]:
        if not sample_sha256:
            return []
        return list(self._by_sha.get(sample_sha256, ()))

    def mismatch(self, sample_sha256: str) -> Optional[dict[str, Any]]:
        return self.index_mismatches.get(sample_sha256)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": {kind: stats.to_dict() for kind, stats in self.source_stats.items()},
            "consensus": self.consensus_stats.to_dict(),
            "index_mismatch_count": len(self.index_mismatches),
            "quarantined_rows": len(self.quarantined_rows),
        }

    def load(self, avclass_path: Optional[Path], cape_path: Optional[Path], consensus_path: Optional[Path], row_errors: str) -> None:
        for kind, path in (("avclass", avclass_path), ("cape", cape_path)):
            if path is None:
                continue
            self._load_grouped_mapping(kind, path, row_errors)
        if consensus_path is not None:
            self._load_consensus(consensus_path, row_errors)
        self._reconcile_with_consensus()

    def _load_grouped_mapping(self, kind: str, path: Path, row_errors: str) -> None:
        stats = LabelSourceStats(kind=kind, path=str(path))
        digest, _size = sha256_file(path)
        stats.content_sha256 = digest
        self.source_stats[kind] = stats

        seen: dict[str, str] = {}
        conflicting: dict[str, list[str]] = {}
        family_counts: dict[str, int] = {}
        family_declared: dict[str, int] = {}
        root_scalars: dict[str, Any] = {}

        for obj_path, data in _scan_json(path):
            if not obj_path:
                root_scalars = data
                continue
            if len(obj_path) == 1:
                family = obj_path[0]
                declared = data.get("n_reports")
                if isinstance(declared, int):
                    family_declared[family] = declared
                else:
                    stats.declared_count_mismatches.append(f"family {family!r} has no declared n_reports")
                continue
            if len(obj_path) == 3 and obj_path[1] == "reports":
                family = obj_path[0]
                stats.records += 1
                family_counts[family] = family_counts.get(family, 0) + 1
                sha = data.get("sha256")
                report_name = data.get("report")
                if not isinstance(sha, str) or not SHA256_RE.match(sha.strip().lower()):
                    stats.invalid_rows += 1
                    self._quarantine(
                        row_errors,
                        {
                            "source_kind": kind,
                            "source_file": str(path),
                            "json_pointer": "/" + "/".join(_escape(part) for part in obj_path),
                            "reason": "invalid_or_missing_sha256",
                            "row": _safe_row(data),
                        },
                    )
                    continue
                sha = sha.strip().lower()
                limitations: list[str] = []
                if isinstance(report_name, str):
                    base = report_name.replace("\\", "/").rsplit("/", 1)[-1]
                    if SHA256_RE.match(base[:-5]) and base.lower() != f"{sha}.json":
                        limitations.append("report_filename_hash_mismatch")
                if sha in seen:
                    previous = seen[sha]
                    if previous == family:
                        stats.duplicate_rows += 1
                        for observation in self._observations.get((kind, sha), []):
                            if observation.raw_label == family:
                                observation.duplicate_count += 1
                                if limitations and limitations[0] not in observation.limitations:
                                    observation.limitations.append(limitations[0])
                        continue
                    stats.conflicts += 1
                    conflicting.setdefault(sha, [previous]).append(family)
                    continue
                seen[sha] = family
                observation = self._make_observation(
                    kind=kind,
                    sha=sha,
                    raw_label=family,
                    state="present",
                    provenance="mapping",
                    json_pointer="/" + "/".join(_escape(part) for part in obj_path),
                    source_file=str(path),
                    source_sha256=digest,
                    limitations=limitations,
                )
                self._store(observation)
                continue
            stats.invalid_rows += 1

        stats.actual_total = stats.records
        stats.unique_samples = len(seen)
        declared_total = root_scalars.get("n_reports")
        if isinstance(declared_total, int):
            stats.declared_total = declared_total
        else:
            stats.declared_count_mismatches.append("root map has no declared n_reports")
        if stats.declared_total is not None and stats.declared_total != stats.actual_total:
            stats.declared_count_mismatches.append(
                f"declared n_reports={stats.declared_total} but {stats.actual_total} records were read"
            )
        for family, declared in family_declared.items():
            actual = family_counts.get(family, 0)
            if declared != actual:
                stats.declared_count_mismatches.append(
                    f"family {family!r} declares n_reports={declared} but {actual} records were read"
                )
        for sha, families in conflicting.items():
            for family in families[1:]:
                observation = self._make_observation(
                    kind=kind,
                    sha=sha,
                    raw_label=family,
                    state="present",
                    provenance="mapping",
                    json_pointer=f"/{_escape(families[0])}/reports",
                    source_file=str(path),
                    source_sha256=digest,
                    limitations=["same_source_conflicting_family"],
                )
                self._store(observation)

    def _load_consensus(self, path: Path, row_errors: str) -> None:
        stats = ConsensusStats(path=str(path))
        digest, _size = sha256_file(path)
        stats.content_sha256 = digest
        self.consensus_stats = stats

        root_scalars: dict[str, Any] = {}
        for obj_path, data in _scan_json(path):
            if not obj_path:
                root_scalars = data
                continue
            sha = obj_path[0]
            if sha in CONSENSUS_META_KEYS:
                continue
            if not SHA256_RE.match(sha):
                stats.invalid_rows += 1
                self._quarantine(
                    row_errors,
                    {
                        "source_kind": "consensus",
                        "source_file": str(path),
                        "json_pointer": "/" + _escape(sha),
                        "reason": "invalid_sample_sha256_key",
                        "row": {"avclass": data.get("avclass"), "cape": data.get("cape")},
                    },
                )
                continue
            avclass = data.get("avclass")
            cape = data.get("cape")
            entry: dict[str, str] = {}
            if isinstance(avclass, str):
                entry["avclass"] = avclass
            elif avclass is None:
                entry["avclass"] = ""
            else:
                stats.invalid_rows += 1
                self._quarantine(
                    row_errors,
                    {
                        "source_kind": "consensus",
                        "source_file": str(path),
                        "json_pointer": "/" + _escape(sha) + "/avclass",
                        "reason": "invalid_label_type",
                        "row": {"avclass": avclass},
                    },
                )
                entry["avclass"] = ""
            if isinstance(cape, str):
                entry["cape"] = cape
            elif cape is None:
                entry["cape"] = ""
            else:
                stats.invalid_rows += 1
                self._quarantine(
                    row_errors,
                    {
                        "source_kind": "consensus",
                        "source_file": str(path),
                        "json_pointer": "/" + _escape(sha) + "/cape",
                        "reason": "invalid_label_type",
                        "row": {"cape": cape},
                    },
                )
                entry["cape"] = ""
            self.consensus_entries[sha] = entry
            stats.entries += 1

        for key in CONSENSUS_META_KEYS:
            value = root_scalars.get(key)
            stats.counters[key] = value if isinstance(value, int) else 0
        if "n_reports" in root_scalars:
            stats.counters["n_reports"] = root_scalars["n_reports"]

    def _reconcile_with_consensus(self) -> None:
        """Supplement missing sources and detect index mismatches."""
        if not self.consensus_entries:
            return
        for sha, entry in self.consensus_entries.items():
            for kind in LABEL_KINDS:
                consensus_label = entry.get(kind, "")
                has_mapping = self.has_record(kind, sha)
                if not has_mapping:
                    if self.taxonomy.is_missing(consensus_label):
                        raw = consensus_label
                        state = "missing_label"
                    else:
                        raw = consensus_label
                        state = "present"
                    observation = self._make_observation(
                        kind=kind,
                        sha=sha,
                        raw_label=raw,
                        state=state,
                        provenance="consensus_only",
                        json_pointer=f"/{_escape(sha)}/{kind}",
                        source_file=self.consensus_stats.path,
                        source_sha256=self.consensus_stats.content_sha256,
                        limitations=["consensus_only_supplement"],
                    )
                    self._store(observation)
                    continue
                mapping_observation = self.primary(kind, sha)
                assert mapping_observation is not None
                if self.taxonomy.is_missing(consensus_label) and self.taxonomy.is_missing(mapping_observation.raw_label):
                    continue
                if normalize_label(consensus_label) == normalize_label(mapping_observation.raw_label):
                    mapping_observation.provenance = "mapping+consensus_agree"
                    continue
                mapping_observation.provenance = "mapping+consensus_mismatch"
                mapping_observation.secondary_raw_label = consensus_label
                if "index_mismatch" not in mapping_observation.limitations:
                    mapping_observation.limitations.append("index_mismatch")
                self.index_mismatches[sha] = {
                    "sample_sha256": sha,
                    "source_kind": kind,
                    "mapping_label": mapping_observation.raw_label,
                    "consensus_label": consensus_label,
                }

    def _make_observation(
        self,
        *,
        kind: str,
        sha: str,
        raw_label: str,
        state: str,
        provenance: str,
        json_pointer: str,
        source_file: str,
        source_sha256: str,
        limitations: Optional[list[str]] = None,
    ) -> LabelObservation:
        normalized = normalize_label(raw_label) if isinstance(raw_label, str) else ""
        if state == "present" and self.taxonomy.is_missing(raw_label):
            state = "missing_label"
        canonical = self.taxonomy.canonical_for(raw_label) if state == "present" else None
        lims = list(limitations or [])
        if state == "missing_label":
            lims.append("label_value_missing")
        return LabelObservation(
            source_kind=kind,
            sample_sha256=sha,
            raw_label=raw_label if isinstance(raw_label, str) else repr(raw_label),
            normalized_label=normalized,
            canonical_family=canonical,
            state=state,
            provenance=provenance,
            json_pointer=json_pointer,
            source_file=source_file,
            source_sha256=source_sha256,
            limitations=lims,
        )

    def _store(self, observation: LabelObservation) -> None:
        self._observations.setdefault((observation.source_kind, observation.sample_sha256), []).append(observation)
        self._by_sha.setdefault(observation.sample_sha256, []).append(observation)
        stats = self.source_stats.get(observation.source_kind)
        if stats is not None:
            if observation.state == "missing_label":
                stats.missing_label_records += 1
            if "same_source_conflicting_family" in observation.limitations:
                stats.conflicts += 1

    def _quarantine(self, row_errors: str, payload: dict[str, Any]) -> None:
        if row_errors == "fail":
            raise LabelDataError(
                f"invalid label row in {payload.get('source_file')}: {payload.get('reason')}",
                details=payload,
            )
        self.quarantined_rows.append(payload)


def _escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def _safe_row(data: dict[str, Any]) -> dict[str, Any]:
    allowed = ("sha256", "report", "md5", "sha1", "SHA512", "name")
    return {key: data.get(key) for key in allowed if key in data}
