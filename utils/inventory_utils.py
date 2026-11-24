"""Label inventory utilities: join observations to locators and classify candidate reasons.

Tuân thủ Rule 8.2 (<domain>_utils.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .discovery_utils import DiscoveredFile
from .identity_utils import IdentityInfo, resolve_identity, sha256_from_filename
from .label_utils import LabelStore
from .models import LABEL_PAIR_STATES, LabelObservation, SourceRecord
from .taxonomy_utils import Taxonomy

PARTITION_SAME_FAMILY = "same_seed_family"
PARTITION_ONE_MISSING = "one_seed_other_missing"
PARTITION_DIFFERENT = "different_nonmissing_labels_review"


@dataclass
class InventoryEntry:
    source: SourceRecord
    identity: IdentityInfo
    observations: list[LabelObservation] = field(default_factory=list)
    label_pair_state: str = "unresolved"
    candidate_reasons: list[str] = field(default_factory=list)
    is_seed_candidate: bool = False
    is_candidate: bool = False
    seed_families: list[str] = field(default_factory=list)
    avclass_canonical: Optional[str] = None
    cape_canonical: Optional[str] = None
    baseline_partition: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "identity": self.identity.to_dict(),
            "label_observations": [o.to_dict() for o in self.observations],
            "label_pair_state": self.label_pair_state,
            "candidate_reasons": list(self.candidate_reasons),
            "is_seed_candidate": self.is_seed_candidate,
            "is_candidate": self.is_candidate,
            "seed_families": list(self.seed_families),
        }


@dataclass
class InventoryResult:
    entries: list[InventoryEntry] = field(default_factory=list)
    counters: dict[str, Any] = field(default_factory=dict)

    @property
    def seed_candidates(self) -> list[InventoryEntry]:
        return [entry for entry in self.entries if entry.is_seed_candidate]

    @property
    def candidates(self) -> list[InventoryEntry]:
        return [entry for entry in self.entries if entry.is_candidate]


def _kind_state(observations: Iterable[LabelObservation]) -> str:
    """absent | present | missing_label | conflict"""
    items = list(observations)
    if not items:
        return "absent"
    if len({item.normalized_label for item in items}) > 1:
        return "conflict"
    return "missing_label" if items[0].state == "missing_label" else "present"


def compute_label_pair_state(
    avclass_state: str,
    cape_state: str,
    avclass_label: Optional[str],
    cape_label: Optional[str],
    avclass_canonical: Optional[str],
    cape_canonical: Optional[str],
) -> str:
    """Implement the ``label_pair_state`` contract of spec section 8."""
    if avclass_state == "conflict" or cape_state == "conflict":
        return "source_conflict"
    if avclass_state == "absent" and cape_state == "absent":
        return "unresolved"
    present = [state for state in (avclass_state, cape_state) if state == "present"]
    missing = [state for state in (avclass_state, cape_state) if state == "missing_label"]
    if not present:
        if len(missing) == 2:
            return "both_missing"
        return "unresolved"
    if len(present) == 1:
        if missing or "absent" not in (avclass_state, cape_state):
            return "one_present"
        return "unresolved"
    if avclass_canonical and cape_canonical:
        return "same_canonical_family" if avclass_canonical == cape_canonical else "different_canonical_families"
    left = (avclass_label or "").strip().casefold()
    right = (cape_label or "").strip().casefold()
    return "same_unmapped_label" if left == right else "different_nonmissing_labels"


def build_inventory(
    files: list[DiscoveredFile],
    label_store: LabelStore,
    taxonomy: Taxonomy,
    *,
    target_sha256_by_source: Optional[dict[str, str]] = None,
    identity_mode: str = "auto",
) -> InventoryResult:
    """Join label observations to every discovered file."""
    result = InventoryResult()
    family_counts: dict[str, dict[str, int]] = {}
    partitions: dict[str, int] = {
        PARTITION_SAME_FAMILY: 0,
        PARTITION_ONE_MISSING: 0,
        PARTITION_DIFFERENT: 0,
    }

    targets = target_sha256_by_source or {}
    for item in files:
        filename_sha = sha256_from_filename(item.absolute_path)
        target_sha = targets.get(item.source_id)
        identity = resolve_identity(item.source_id, filename_sha256=filename_sha, target_sha256=target_sha)
        if identity_mode == "filename":
            label_sample = filename_sha
        elif identity_mode == "report":
            label_sample = target_sha
        else:
            label_sample = filename_sha or target_sha
        source = SourceRecord(
            source_id=item.source_id,
            root_id=item.root_id,
            relative_path=item.relative_path,
            absolute_path=item.absolute_path,
            size_bytes=item.size_bytes,
            mtime_ns=item.mtime_ns,
            processing_status="discovered",
            sample_sha256_filename=identity.filename_sha256,
            sample_sha256_target=None,
            sample_sha256=identity.sample_sha256,
            sample_identity_status=identity.status,
            secondary_locators=list(item.secondary_locators),
        )

        observations: list[LabelObservation] = []
        avclass_obs = label_store.observations("avclass", label_sample)
        cape_obs = label_store.observations("cape", label_sample)
        observations.extend(avclass_obs)
        observations.extend(cape_obs)

        avclass_state = _kind_state(avclass_obs)
        cape_state = _kind_state(cape_obs)
        avclass_label = avclass_obs[0].raw_label if avclass_obs else None
        cape_label = cape_obs[0].raw_label if cape_obs else None
        avclass_canonical = avclass_obs[0].canonical_family if avclass_obs else None
        cape_canonical = cape_obs[0].canonical_family if cape_obs else None

        pair_state = compute_label_pair_state(
            avclass_state,
            cape_state,
            avclass_label,
            cape_label,
            avclass_canonical,
            cape_canonical,
        )
        if pair_state not in LABEL_PAIR_STATES:
            pair_state = "unresolved"

        reasons: list[str] = []
        seed_families: list[str] = []
        for obs in observations:
            canonical = obs.canonical_family
            if canonical and taxonomy.is_seed_family(canonical) and canonical not in seed_families:
                seed_families.append(canonical)
        if seed_families:
            reasons.append("seed_label")
        for observation in observations:
            if observation.state == "present":
                if taxonomy.is_generic_label(observation.raw_label) or taxonomy.is_review_example(observation.raw_label):
                    if "generic_label_review" not in reasons:
                        reasons.append("generic_label_review")
        mismatch = label_store.mismatch(label_sample) if label_sample else None
        if mismatch is not None:
            if "label_index_conflict" not in reasons:
                reasons.append("label_index_conflict")

        source.label_pair_state = pair_state
        source.candidate_reasons = list(reasons)
        source.is_seed_candidate = "seed_label" in reasons
        source.is_candidate = bool(reasons)
        source.family_identity_status = "provisional" if seed_families else "unknown"

        entry = InventoryEntry(
            source=source,
            identity=identity,
            observations=observations,
            label_pair_state=pair_state,
            candidate_reasons=list(reasons),
            is_seed_candidate=source.is_seed_candidate,
            is_candidate=source.is_candidate,
            seed_families=seed_families,
            avclass_canonical=avclass_canonical,
            cape_canonical=cape_canonical,
        )

        if source.is_seed_candidate:
            entry.baseline_partition = _baseline_partition(pair_state)
            if entry.baseline_partition:
                partitions[entry.baseline_partition] += 1
            for canonical in sorted(set(seed_families)):
                bucket = family_counts.setdefault(
                    canonical, {"either_label": 0, "avclass": 0, "cape": 0, "both_same_family": 0}
                )
                bucket["either_label"] += 1
                bucket["avclass"] += int(any(o.canonical_family == canonical for o in avclass_obs))
                bucket["cape"] += int(any(o.canonical_family == canonical for o in cape_obs))
                bucket["both_same_family"] += int(
                    any(o.canonical_family == canonical for o in avclass_obs)
                    and any(o.canonical_family == canonical for o in cape_obs)
                )

        result.entries.append(entry)

    local_report_count = sum(1 for entry in result.entries if entry.identity.sample_sha256)
    seed_entries = [entry for entry in result.entries if entry.is_seed_candidate]
    candidate_entries = [entry for entry in result.entries if entry.is_candidate]
    result.counters = {
        "source_files": len(result.entries),
        "local_report_count": local_report_count,
        "files_without_resolved_sample": len(result.entries) - local_report_count,
        "seed_candidate_count": len(seed_entries),
        "seed_candidate_bytes": sum(entry.source.size_bytes for entry in seed_entries),
        "candidate_count": len(candidate_entries),
        "candidate_bytes": sum(entry.source.size_bytes for entry in candidate_entries),
        "outside_seed_unreviewed": local_report_count - len(seed_entries),
        "partitions": partitions,
        "family_counts": family_counts,
        "label_pair_states": _count_states(result.entries),
    }
    return result


def _baseline_partition(pair_state: str) -> Optional[str]:
    if pair_state == "same_canonical_family":
        return PARTITION_SAME_FAMILY
    if pair_state == "one_present":
        return PARTITION_ONE_MISSING
    if pair_state in ("different_canonical_families", "different_nonmissing_labels"):
        return PARTITION_DIFFERENT
    return None


def _count_states(entries: list[InventoryEntry]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.label_pair_state] = counts.get(entry.label_pair_state, 0) + 1
    return counts
