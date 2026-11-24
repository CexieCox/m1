"""Event-scope attribution for reviewed intervals.

CAPE does not expose code ranges or module lifetimes, so conservative-v1 marks the
code-scope method ``unsupported`` and only supports human-attested event intervals. A
reviewed interval is a *human* claim about a process and call range; it never hides the
original facts and never turns a weak machine binding into a trusted one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Fact
from .binding_utils import Binding

CALL_POINTER = re.compile(r"^/behavior/processes/(\d+)/calls/(\d+)$")
SCOPE_ROLES = ("loader", "payload")


def fact_process_call(fact: Fact) -> tuple[int | None, int | None]:
    for pointer in fact.source_json_pointers:
        match = CALL_POINTER.match(pointer)
        if match:
            return int(match.group(1)), int(match.group(2))
    return fact.process_index, None


@dataclass
class EventScope:
    role: str
    process_index: int
    call_index_start: int
    call_index_end: int
    exclusivity_reason: str
    evidence_ids: list[str] = field(default_factory=list)
    review_id: str | None = None
    object_sha256: str | None = None

    def covers(self, process_index: int | None, call_index: int | None) -> bool:
        if process_index != self.process_index or call_index is None:
            return False
        return self.call_index_start <= call_index <= self.call_index_end

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "process_index": self.process_index,
            "call_index_start": self.call_index_start,
            "call_index_end": self.call_index_end,
            "exclusivity_reason": self.exclusivity_reason,
            "evidence_ids": list(self.evidence_ids),
            "review_id": self.review_id,
            "object_sha256": self.object_sha256,
        }


@dataclass
class ScopeConflict:
    process_index: int
    call_index: int
    roles: list[str]
    review_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_index": self.process_index,
            "call_index": self.call_index,
            "roles": list(self.roles),
            "review_ids": list(self.review_ids),
        }


@dataclass
class AttributionResult:
    bucket_by_evidence: dict[str, str]
    method_by_evidence: dict[str, str]
    review_by_evidence: dict[str, str | None]
    conflicts: list[ScopeConflict]
    status: str
    limitations: list[str]

    def bucket_counts(self) -> dict[str, int]:
        counts = {"loader_strict": 0, "payload": 0, "system_context": 0, "mixed_or_unresolved": 0}
        for bucket in self.bucket_by_evidence.values():
            counts[bucket] = counts.get(bucket, 0) + 1
        return counts


def validate_scope(
    scope: EventScope,
    *,
    facts: Iterable[Fact],
    bindings: Iterable[Binding],
) -> list[str]:
    """Return review-scope limitations; an empty list means the scope is usable."""
    problems: list[str] = []
    if scope.role not in SCOPE_ROLES:
        problems.append("review_scope_role_invalid")
    if scope.call_index_start < 0 or scope.call_index_end < scope.call_index_start:
        problems.append("review_scope_range_invalid")
    if not scope.exclusivity_reason:
        problems.append("review_scope_reason_missing")
    if not scope.evidence_ids:
        problems.append("review_scope_evidence_missing")
    known_ids = {fact.evidence_id for fact in facts}
    if any(item not in known_ids for item in scope.evidence_ids):
        problems.append("review_scope_evidence_unknown")
    if scope.role == "loader":
        bound = any(
            binding.process_index == scope.process_index
            and binding.trustworthy
            and (scope.object_sha256 is None or binding.object_sha256 == scope.object_sha256)
            for binding in bindings
        )
        if not bound:
            problems.append("review_scope_unbound")
    covered = [
        fact
        for fact in facts
        if fact_process_call(fact)[0] == scope.process_index
        and fact_process_call(fact)[1] is not None
        and scope.covers(*fact_process_call(fact))
    ]
    if not covered:
        problems.append("review_scope_covers_no_event")
    return problems


def attribute_events(
    facts: Iterable[Fact],
    scopes: Iterable[EventScope],
    bindings: Iterable[Binding],
) -> AttributionResult:
    facts = list(facts)
    bindings = list(bindings)
    usable: list[EventScope] = []
    limitations: list[str] = ["code_scope_attribution_unsupported"]
    for scope in scopes:
        problems = validate_scope(scope, facts=facts, bindings=bindings)
        if problems:
            limitations.extend(problems)
        else:
            usable.append(scope)

    bucket_by_evidence: dict[str, str] = {}
    method: dict[str, str] = {}
    review_id: dict[str, str | None] = {}
    conflicts: list[ScopeConflict] = []

    for fact in facts:
        process_index, call_index = fact_process_call(fact)
        matches = [scope for scope in usable if scope.covers(process_index, call_index)]
        roles = sorted({scope.role for scope in matches})
        if not matches:
            bucket_by_evidence[fact.evidence_id] = "mixed_or_unresolved"
            method[fact.evidence_id] = "no_attribution"
            review_id[fact.evidence_id] = None
            continue
        if len(roles) > 1:
            conflicts.append(
                ScopeConflict(
                    process_index=process_index or -1,
                    call_index=call_index or -1,
                    roles=roles,
                    review_ids=sorted({scope.review_id for scope in matches if scope.review_id}),
                )
            )
            bucket_by_evidence[fact.evidence_id] = "mixed_or_unresolved"
            method[fact.evidence_id] = "conflicting_reviewed_scope"
            review_id[fact.evidence_id] = None
            continue
        bucket = "loader_strict" if roles[0] == "loader" else "payload"
        bucket_by_evidence[fact.evidence_id] = bucket
        method[fact.evidence_id] = "reviewed_interval"
        review_id[fact.evidence_id] = sorted(
            {scope.review_id for scope in matches if scope.review_id}
        )[-1] if any(scope.review_id for scope in matches) else None

    if conflicts:
        status = "mixed_or_unresolved"
    elif not usable:
        status = "not_evaluated"
    elif any(bucket == "loader_strict" for bucket in bucket_by_evidence.values()):
        status = "supported_for_some_events"
    else:
        status = "none_supported"
    if conflicts:
        limitations.append("review_scope_conflict")
    return AttributionResult(
        bucket_by_evidence=bucket_by_evidence,
        method_by_evidence=method,
        review_by_evidence=review_id,
        conflicts=conflicts,
        status=status,
        limitations=list(dict.fromkeys(limitations)),
    )


def strict_event_count(result: AttributionResult) -> int:
    return sum(1 for bucket in result.bucket_by_evidence.values() if bucket == "loader_strict")
