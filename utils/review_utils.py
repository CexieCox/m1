"""Review template export, review import and validation.

Reviews are the only supported way to add a human-attested execution binding or strict
event scope. They are versioned, fingerprinted and never override parse errors, checksum
mismatches or identity conflicts. A review whose fingerprint no longer matches is marked
stale instead of being silently re-applied.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .models import HUMAN_DISPOSITIONS
from .io_utils import is_sha256, utc_now_iso
from .attribution_utils import EventScope
from .binding_utils import Binding
from .evidence_utils import ReportEvidence

REVIEW_SCHEMA_VERSION = 1
TOP_LEVEL_KEYS = {
    "review_schema_version",
    "review_id",
    "source_id",
    "report_id",
    "report_content_sha256",
    "analysis_fingerprint",
    "reviewer",
    "reviewed_at",
    "disposition",
    "reason",
    "evidence_ids",
    "bindings",
    "event_scopes",
    "supersedes",
}
BINDING_KEYS = {
    "object_sha256",
    "object_kind",
    "process_index",
    "relation",
    "evidence_ids",
    "reason",
}
SCOPE_KEYS = {
    "role",
    "process_index",
    "call_index_start",
    "call_index_end",
    "exclusivity_reason",
    "evidence_ids",
    "object_sha256",
    "review_id",
}


class ReviewError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class ReviewBinding:
    object_sha256: str
    object_kind: str
    process_index: int
    relation: str
    evidence_ids: list[str]
    reason: str

    def to_binding(self, review_id: str) -> Binding:
        return Binding(
            object_sha256=self.object_sha256,
            object_kind=self.object_kind,
            process_index=self.process_index,
            relation=self.relation,
            support="reviewed",
            reason=self.reason,
            evidence_ids=list(self.evidence_ids),
            review_id=review_id,
        )


@dataclass
class ReviewRecord:
    review_schema_version: int
    review_id: str
    source_id: str
    report_id: str
    report_content_sha256: str
    analysis_fingerprint: str
    reviewer: str
    reviewed_at: str
    disposition: str
    reason: str
    evidence_ids: list[str] = field(default_factory=list)
    bindings: list[ReviewBinding] = field(default_factory=list)
    event_scopes: list[EventScope] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_schema_version": self.review_schema_version,
            "review_id": self.review_id,
            "source_id": self.source_id,
            "report_id": self.report_id,
            "report_content_sha256": self.report_content_sha256,
            "analysis_fingerprint": self.analysis_fingerprint,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "disposition": self.disposition,
            "reason": self.reason,
            "evidence_ids": list(self.evidence_ids),
            "bindings": [
                {
                    "object_sha256": binding.object_sha256,
                    "object_kind": binding.object_kind,
                    "process_index": binding.process_index,
                    "relation": binding.relation,
                    "evidence_ids": list(binding.evidence_ids),
                    "reason": binding.reason,
                }
                for binding in self.bindings
            ],
            "event_scopes": [scope.to_dict() for scope in self.event_scopes],
            "supersedes": list(self.supersedes),
        }


def parse_review(raw: Any, *, where: str = "review") -> ReviewRecord:
    problems: list[str] = []
    if not isinstance(raw, dict):
        raise ReviewError([f"{where} must be a JSON object"])
    unknown = set(raw) - TOP_LEVEL_KEYS
    if unknown:
        problems.append(f"{where} has unknown keys: {sorted(unknown)}")
    if raw.get("review_schema_version") != REVIEW_SCHEMA_VERSION:
        problems.append(f"{where}.review_schema_version must be {REVIEW_SCHEMA_VERSION}")
    for key in (
        "review_id",
        "source_id",
        "report_id",
        "report_content_sha256",
        "analysis_fingerprint",
        "reviewer",
        "reviewed_at",
        "disposition",
        "reason",
    ):
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"{where}.{key} is required and must be a non-empty string")
    if raw.get("disposition") not in HUMAN_DISPOSITIONS:
        problems.append(f"{where}.disposition must be one of {list(HUMAN_DISPOSITIONS)}")
    reviewed_at = raw.get("reviewed_at")
    if isinstance(reviewed_at, str) and reviewed_at.strip():
        try:
            parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                problems.append(f"{where}.reviewed_at must include a timezone offset")
        except ValueError:
            problems.append(f"{where}.reviewed_at is not a valid ISO-8601 timestamp")
    for key in ("report_id", "report_content_sha256"):
        value = raw.get(key)
        if isinstance(value, str) and value and not is_sha256(value):
            problems.append(f"{where}.{key} must be a sha256 hex digest")
    evidence_ids = _string_list(raw.get("evidence_ids"), f"{where}.evidence_ids", problems)
    bindings: list[ReviewBinding] = []
    for index, item in enumerate(_list(raw.get("bindings"), f"{where}.bindings", problems)):
        bindings.append(_parse_binding(item, f"{where}.bindings[{index}]", problems))
    scopes: list[EventScope] = []
    for index, item in enumerate(_list(raw.get("event_scopes"), f"{where}.event_scopes", problems)):
        scopes.append(_parse_scope(item, f"{where}.event_scopes[{index}]", problems))
    supersedes = _string_list(raw.get("supersedes", []), f"{where}.supersedes", problems)
    if problems:
        raise ReviewError(problems)
    return ReviewRecord(
        review_schema_version=REVIEW_SCHEMA_VERSION,
        review_id=raw["review_id"],
        source_id=raw["source_id"],
        report_id=raw["report_id"],
        report_content_sha256=raw["report_content_sha256"],
        analysis_fingerprint=raw["analysis_fingerprint"],
        reviewer=raw["reviewer"],
        reviewed_at=raw["reviewed_at"],
        disposition=raw["disposition"],
        reason=raw["reason"],
        evidence_ids=evidence_ids,
        bindings=bindings,
        event_scopes=scopes,
        supersedes=supersedes,
    )


def _parse_binding(raw: Any, where: str, problems: list[str]) -> ReviewBinding:
    if not isinstance(raw, dict):
        problems.append(f"{where} must be an object")
        return ReviewBinding("", "", -1, "", [], "")
    unknown = set(raw) - BINDING_KEYS
    if unknown:
        problems.append(f"{where} has unknown keys: {sorted(unknown)}")
    if raw.get("relation") != "execution":
        problems.append(f"{where}.relation must be 'execution'")
    if not isinstance(raw.get("object_sha256"), str) or not is_sha256(raw.get("object_sha256")):
        problems.append(f"{where}.object_sha256 must be a sha256 digest")
    if not isinstance(raw.get("object_kind"), str) or not raw.get("object_kind"):
        problems.append(f"{where}.object_kind is required")
    process_index = raw.get("process_index")
    if not isinstance(process_index, int) or isinstance(process_index, bool) or process_index < 0:
        problems.append(f"{where}.process_index must be a non-negative integer")
    evidence_ids = _string_list(raw.get("evidence_ids"), f"{where}.evidence_ids", problems)
    if not evidence_ids:
        problems.append(f"{where}.evidence_ids must not be empty")
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        problems.append(f"{where}.reason is required")
    return ReviewBinding(
        object_sha256=str(raw.get("object_sha256", "")),
        object_kind=str(raw.get("object_kind", "")),
        process_index=process_index if isinstance(process_index, int) else -1,
        relation=str(raw.get("relation", "")),
        evidence_ids=evidence_ids,
        reason=str(reason or ""),
    )


def _parse_scope(raw: Any, where: str, problems: list[str]) -> EventScope:
    if not isinstance(raw, dict):
        problems.append(f"{where} must be an object")
        return EventScope("", -1, 0, -1, "")
    unknown = set(raw) - SCOPE_KEYS
    if unknown:
        problems.append(f"{where} has unknown keys: {sorted(unknown)}")
    for key in ("role", "exclusivity_reason"):
        if not isinstance(raw.get(key), str) or not raw.get(key).strip():
            problems.append(f"{where}.{key} is required")
    process_index = raw.get("process_index")
    if not isinstance(process_index, int) or isinstance(process_index, bool) or process_index < 0:
        problems.append(f"{where}.process_index must be a non-negative integer")
    start = raw.get("call_index_start")
    end = raw.get("call_index_end")
    for key, value in (("call_index_start", start), ("call_index_end", end)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"{where}.{key} must be a non-negative integer")
    if isinstance(start, int) and isinstance(end, int) and end < start:
        problems.append(f"{where}.call_index_end must be >= call_index_start")
    evidence_ids = _string_list(raw.get("evidence_ids"), f"{where}.evidence_ids", problems)
    if not evidence_ids:
        problems.append(f"{where}.evidence_ids must not be empty")
    object_sha = raw.get("object_sha256")
    if object_sha is not None and not is_sha256(object_sha):
        problems.append(f"{where}.object_sha256 must be a sha256 digest")
    return EventScope(
        role=str(raw.get("role", "")),
        process_index=process_index if isinstance(process_index, int) else -1,
        call_index_start=start if isinstance(start, int) else 0,
        call_index_end=end if isinstance(end, int) else -1,
        exclusivity_reason=str(raw.get("exclusivity_reason", "")),
        evidence_ids=evidence_ids,
        review_id=str(raw.get("review_id", "")) or None,
        object_sha256=object_sha,
    )


def _list(value: Any, where: str, problems: list[str]) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        problems.append(f"{where} must be a list")
        return []
    return value


def _string_list(value: Any, where: str, problems: list[str]) -> list[str]:
    items = _list(value, where, problems)
    result: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or not item.strip():
            problems.append(f"{where}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def load_review_file(path: Path | str) -> list[ReviewRecord]:
    path = Path(path)
    records: list[ReviewRecord] = []
    problems: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                problems.append(f"{path.name}:{line_number}: invalid JSON: {exc}")
                continue
            try:
                record = parse_review(raw, where=f"{path.name}:{line_number}")
            except ReviewError as exc:
                problems.extend(exc.problems)
                continue
            records.append(record)
    if problems:
        raise ReviewError(problems)
    return records


@dataclass
class ValidatedReview:
    record: ReviewRecord
    status: str  # applied | stale | invalid | superseded
    problems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "review_id": self.record.review_id,
            "source_id": self.record.source_id,
            "report_id": self.record.report_id,
            "status": self.status,
            "problems": list(self.problems),
            "disposition": self.record.disposition,
            "reviewer": self.record.reviewer,
            "reviewed_at": self.record.reviewed_at,
        }


def validate_reviews(
    records: Iterable[ReviewRecord],
    *,
    analysis_fingerprint: str,
    report_by_source: dict[str, str],
    evidence_ids_by_report: dict[str, set[str]],
    process_indices_by_report: dict[str, set[int]],
) -> list[ValidatedReview]:
    """Fingerprint, source and reference checks. Latest review per id wins."""
    latest: dict[str, ReviewRecord] = {}
    order: list[str] = []
    for record in records:
        if record.review_id not in latest:
            order.append(record.review_id)
        latest[record.review_id] = record

    validated: list[ValidatedReview] = []
    for review_id in order:
        record = latest[review_id]
        problems: list[str] = []
        status = "applied"
        if record.analysis_fingerprint != analysis_fingerprint:
            problems.append("review_stale_fingerprint")
        expected_report = report_by_source.get(record.source_id)
        if expected_report is None:
            problems.append("review_source_unknown")
        elif expected_report != record.report_id:
            problems.append("review_source_report_mismatch")
        if record.report_content_sha256 != record.report_id:
            problems.append("review_report_content_mismatch")
        known = evidence_ids_by_report.get(record.report_id, set())
        for evidence_id in record.evidence_ids:
            if evidence_id not in known:
                problems.append(f"review_evidence_unknown:{evidence_id}")
        for binding in record.bindings:
            if binding.process_index not in process_indices_by_report.get(record.report_id, set()):
                problems.append(f"review_binding_process_unknown:{binding.process_index}")
            for evidence_id in binding.evidence_ids:
                if evidence_id not in known:
                    problems.append(f"review_binding_evidence_unknown:{evidence_id}")
        if record.disposition not in ("accepted_loader",):
            if record.bindings or record.event_scopes:
                problems.append("review_disposition_cannot_attest")
        if problems:
            status = "stale" if any(item.startswith("review_stale") for item in problems) else "invalid"
        validated.append(ValidatedReview(record=record, status=status, problems=problems))

    superseded: set[str] = set()
    for review_id in order:
        for target in latest[review_id].supersedes:
            superseded.add(target)
    for item in validated:
        if item.record.review_id in superseded and item.status == "applied":
            item.status = "superseded"
    return validated


def effective_bindings(validated: Iterable[ValidatedReview]) -> list[Binding]:
    bindings: list[Binding] = []
    for item in validated:
        if item.status != "applied" or item.record.disposition != "accepted_loader":
            continue
        for binding in item.record.bindings:
            bindings.append(binding.to_binding(item.record.review_id))
    return bindings


def effective_scopes(validated: Iterable[ValidatedReview]) -> list[EventScope]:
    scopes: list[EventScope] = []
    for item in validated:
        if item.status != "applied" or item.record.disposition != "accepted_loader":
            continue
        for scope in item.record.event_scopes:
            scope.review_id = item.record.review_id
            scopes.append(scope)
    return scopes


def build_review_template(
    *,
    source_id: str,
    evidence: ReportEvidence,
    analysis_fingerprint: str,
    decision: Any,
    reviewer: str = "REPLACE-ME",
    review_id: str | None = None,
) -> ReviewRecord:
    evidence_ids: list[str] = []
    for observation in getattr(decision, "execution_observations", []):
        evidence_ids.extend(observation.evidence_ids)
    if not evidence_ids:
        evidence_ids = [fact.evidence_id for fact in evidence.facts[:3]]
    return ReviewRecord(
        review_schema_version=REVIEW_SCHEMA_VERSION,
        review_id=review_id or f"review-{source_id[:12]}",
        source_id=source_id,
        report_id=evidence.report_id,
        report_content_sha256=evidence.report_content_sha256,
        analysis_fingerprint=analysis_fingerprint,
        reviewer=reviewer,
        reviewed_at=utc_now_iso(),
        disposition="inconclusive",
        reason="REPLACE WITH THE BASIS FOR IDENTIFICATION AND EXECUTION BINDING",
        evidence_ids=evidence_ids,
        bindings=[],
        event_scopes=[],
        supersedes=[],
    )
