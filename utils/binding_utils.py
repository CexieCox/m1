"""Object -> process/execution bindings.

``conservative-v1`` never treats a filename, PID in a dump or a CAPE payload entry as an
execution binding on its own. Machine heuristics therefore only ever produce ``weak``
bindings, which are recorded for review but cannot make ``observed`` true. Only registry
``trusted_identity`` rules and valid human reviews produce trustworthy bindings.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import ProcessSummary
from .evidence_utils import ArtifactRecord, ReportEvidence
from .registry_utils import TrustedRuleRegistry

SUPPORT_LEVELS = ("unsupported", "weak", "trusted", "reviewed")
TRUSTWORTHY = {"trusted", "reviewed"}


@dataclass
class Binding:
    object_sha256: str
    object_kind: str
    process_index: int | None
    relation: str
    support: str
    reason: str
    evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    review_id: str | None = None

    @property
    def trustworthy(self) -> bool:
        return self.support in TRUSTWORTHY and self.process_index is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_sha256": self.object_sha256,
            "object_kind": self.object_kind,
            "process_index": self.process_index,
            "relation": self.relation,
            "support": self.support,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "limitations": list(self.limitations),
            "review_id": self.review_id,
        }


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return posixpath.basename(path.replace("\\", "/"))


def _artifact_evidence(evidence: ReportEvidence, artifact: ArtifactRecord) -> list[str]:
    """All evidence ids that mention the artifact object."""
    ids = [artifact.evidence_id]
    for fact in evidence.facts:
        if fact.subject_sha256 == artifact.sha256 and artifact.sha256:
            ids.append(fact.evidence_id)
    return list(dict.fromkeys(ids))


def machine_bindings(evidence: ReportEvidence) -> list[Binding]:
    """Weak, explainable machine hints. Never sufficient for ``observed``."""
    bindings: list[Binding] = []
    processes = evidence.processes
    by_pid = {process.process_id: process for process in processes if process.process_id is not None}
    by_name: dict[str, list[ProcessSummary]] = {}
    for process in processes:
        if process.process_name:
            by_name.setdefault(process.process_name.casefold(), []).append(process)

    seen: set[tuple[str, int | None, str]] = set()

    def add(
        object_sha: str | None,
        object_kind: str,
        process: ProcessSummary | None,
        reason: str,
        evidence_ids: Iterable[str],
        limitations: Iterable[str] = (),
    ) -> None:
        if not object_sha:
            return
        index = process.process_index if process is not None else None
        key = (object_sha, index, object_kind)
        if key in seen:
            return
        seen.add(key)
        bindings.append(
            Binding(
                object_sha256=object_sha,
                object_kind=object_kind,
                process_index=index,
                relation="execution",
                support="weak",
                reason=reason,
                evidence_ids=list(dict.fromkeys(evidence_ids)),
                limitations=list(limitations),
            )
        )

    for artifact in evidence.artifacts:
        if not artifact.sha256:
            continue
        ids = _artifact_evidence(evidence, artifact)
        process = by_pid.get(artifact.pid) if artifact.pid is not None else None
        if process is not None and artifact.process_name:
            same_name = (process.process_name or "").casefold() == artifact.process_name.casefold()
            if same_name:
                add(artifact.sha256, artifact.kind, process, "artifact_pid_and_process_name_match", ids)
            else:
                add(
                    artifact.sha256,
                    artifact.kind,
                    None,
                    "artifact_pid_and_process_name_conflict",
                    ids,
                    limitations=["artifact_pid_conflicts_with_process_name"],
                )
            continue
        if artifact.process_name:
            candidates = by_name.get(artifact.process_name.casefold(), [])
            if len(candidates) == 1:
                add(
                    artifact.sha256,
                    artifact.kind,
                    candidates[0],
                    "artifact_process_name_unique_match",
                    ids,
                    limitations=["binding_by_process_name_only"],
                )
            elif len(candidates) > 1:
                add(
                    artifact.sha256,
                    artifact.kind,
                    None,
                    "artifact_process_name_ambiguous",
                    ids,
                    limitations=["artifact_process_name_matches_multiple_processes"],
                )
        guest_paths = {_basename(path) for path in artifact.guest_paths if path}
        if guest_paths:
            for process in processes:
                name = _basename(process.module_path) or process.process_name
                if name and name in guest_paths:
                    add(
                        artifact.sha256,
                        artifact.kind,
                        process,
                        "artifact_guest_path_basename_match",
                        ids,
                        limitations=["binding_by_guest_path_basename_only"],
                    )

    if evidence.target_sha256:
        target_names = {
            item for item in (evidence.target_name, _basename(evidence.target_name)) if item
        }
        for process in processes:
            names = {process.process_name, _basename(process.module_path)}
            if names & target_names:
                add(
                    evidence.target_sha256,
                    "target_sample",
                    process,
                    "target_name_matches_process",
                    [],
                    limitations=["binding_by_filename_only"],
                )

    return bindings


def registry_bindings(
    evidence: ReportEvidence, registry: TrustedRuleRegistry | None
) -> list[Binding]:
    """Trusted bindings derived from an explicit registry rule only."""
    if registry is None or not registry.rules:
        return []
    bindings: list[Binding] = []
    for artifact in evidence.artifacts:
        if not artifact.sha256:
            continue
        matches = list(registry.match_sha256(artifact.sha256))
        matches.extend(registry.match_yara(artifact.yara))
        matches.extend(registry.match_cape_yara(artifact.cape_yara))
        trusted = [match for match in matches if match.rule.trust_level == "trusted_identity"]
        if not trusted:
            continue
        for process in _candidate_processes(evidence, artifact):
            bindings.append(
                Binding(
                    object_sha256=artifact.sha256,
                    object_kind=artifact.kind,
                    process_index=process.process_index,
                    relation="execution",
                    support="trusted",
                    reason=f"registry:{trusted[0].rule.rule_id}",
                    evidence_ids=_artifact_evidence(evidence, artifact),
                    limitations=[],
                )
            )
    return bindings


def _candidate_processes(evidence: ReportEvidence, artifact: ArtifactRecord) -> list[ProcessSummary]:
    if artifact.pid is not None:
        for process in evidence.processes:
            if process.process_id == artifact.pid:
                return [process]
    if artifact.process_name:
        matches = [
            process
            for process in evidence.processes
            if (process.process_name or "").casefold() == artifact.process_name.casefold()
        ]
        if len(matches) == 1:
            return matches
    return []


def bindings_for_process(bindings: Iterable[Binding], index: int) -> list[Binding]:
    return [binding for binding in bindings if binding.process_index == index]


def best_binding(bindings: Iterable[Binding], index: int) -> Binding | None:
    rank = {"reviewed": 3, "trusted": 2, "weak": 1, "unsupported": 0}
    candidates = [binding for binding in bindings if binding.process_index == index]
    if not candidates:
        return None
    return max(candidates, key=lambda binding: rank.get(binding.support, 0))


def trustworthy_process_indices(bindings: Iterable[Binding]) -> set[int]:
    return {binding.process_index for binding in bindings if binding.trustworthy}  # type: ignore[misc]
