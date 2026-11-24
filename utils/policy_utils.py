"""The conservative-v1 policy: facts first, decisions afterwards.

The predicates implemented here are intentionally hard to satisfy:

    observed          = supported family identity for a specific object
                        AND trustworthy object->execution binding for that object
                        AND runtime execution observed
                        AND no invalidating conflict

    payload_execution = observed AND execution of the linked next stage is observed

Without a registry rule or a valid review there is no trustworthy binding, so
``observed`` stays false and reports go to review instead of being guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Fact, ProcessSummary
from .taxonomy_utils import Taxonomy
from .attribution_utils import AttributionResult, attribute_events, fact_process_call
from .binding_utils import Binding, best_binding, trustworthy_process_indices
from .evidence_utils import ReportEvidence
from .delivery_utils import DeliveryResult, compute_delivery
from .registry_utils import TrustedRuleRegistry

CREATE_FACT_KINDS = ("process_create", "remote_thread")


@dataclass
class ExecutionObservation:
    process_index: int
    evidence_ids: list[str]
    reasons: list[str]


@dataclass
class ReportDecision:
    observed: bool
    payload_execution: bool
    family_identity_status: str
    family: str | None
    family_evidence: list[dict[str, Any]]
    execution_status: str
    execution_observations: list[ExecutionObservation]
    bindings: list[Binding]
    delivery: DeliveryResult
    attribution: AttributionResult
    bucket_counts: dict[str, int]
    machine_decision: str
    machine_reasons: list[str]
    candidate_reasons: list[str]
    needs_review: bool
    quality_flags: list[str]
    observed_objects: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed": self.observed,
            "payload_execution": self.payload_execution,
            "family_identity_status": self.family_identity_status,
            "family": self.family,
            "family_evidence": list(self.family_evidence),
            "execution_status": self.execution_status,
            "execution_observations": [
                {
                    "process_index": item.process_index,
                    "evidence_ids": list(item.evidence_ids),
                    "reasons": list(item.reasons),
                }
                for item in self.execution_observations
            ],
            "bindings": [binding.to_dict() for binding in self.bindings],
            "delivery": self.delivery.to_dict(),
            "attribution": {
                "status": self.attribution.status,
                "limitations": list(self.attribution.limitations),
                "conflicts": [conflict.to_dict() for conflict in self.attribution.conflicts],
            },
            "bucket_counts": dict(self.bucket_counts),
            "machine_decision": self.machine_decision,
            "machine_reasons": list(self.machine_reasons),
            "candidate_reasons": list(self.candidate_reasons),
            "needs_review": self.needs_review,
            "quality_flags": list(self.quality_flags),
            "observed_objects": list(self.observed_objects),
        }


def runtime_execution(
    evidence: ReportEvidence, process_index: int
) -> ExecutionObservation | None:
    """Prove that a bound process actually ran, using create/thread calls only."""
    process = next(
        (item for item in evidence.processes if item.process_index == process_index), None
    )
    if process is None or process.call_count <= 0:
        return None
    evidence_ids: list[str] = []
    reasons: list[str] = []
    for fact in evidence.facts:
        if fact.attributes.get("result") != "success":
            continue
        target = fact.attributes.get("target_pid")
        if fact.kind == "process_create" and target == process.process_id and process.process_id:
            evidence_ids.append(fact.evidence_id)
            reasons.append("process_create_target_pid_succeeded")
        elif fact.kind == "remote_thread" and target == process.process_id and process.process_id:
            evidence_ids.append(fact.evidence_id)
            reasons.append("remote_thread_target_pid_succeeded")
    if not evidence_ids:
        return None
    return ExecutionObservation(
        process_index=process_index,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        reasons=list(dict.fromkeys(reasons)),
    )


def _artifact_matches(
    evidence: ReportEvidence, registry: TrustedRuleRegistry | None, family_hint: str | None
) -> list[dict[str, Any]]:
    """Objects whose identity is supported by an explicit registry rule."""
    matches: list[dict[str, Any]] = []
    if registry is None:
        return matches
    for artifact in evidence.artifacts:
        if not artifact.sha256:
            continue
        found = list(registry.match_sha256(artifact.sha256))
        found.extend(registry.match_yara(artifact.yara))
        found.extend(registry.match_cape_yara(artifact.cape_yara))
        trusted = [item for item in found if item.rule.trust_level == "trusted_identity"]
        if not trusted:
            continue
        for item in trusted:
            matches.append(
                {
                    "object_sha256": artifact.sha256,
                    "object_kind": artifact.kind,
                    "family": item.rule.family,
                    "rule_id": item.rule.rule_id,
                    "rule_version": item.rule.version,
                    "evidence_id": artifact.evidence_id,
                    "source": item.rule.source,
                }
            )
    return matches


def family_identity(
    evidence: ReportEvidence,
    *,
    registry: TrustedRuleRegistry | None,
    label_families: Iterable[str],
    raw_labels: Iterable[str],
    taxonomy: Taxonomy | None,
) -> tuple[str, str | None, list[dict[str, Any]]]:
    evidence_items: list[dict[str, Any]] = []
    object_families: set[str] = set()
    for match in _artifact_matches(evidence, registry, None):
        object_families.add(match["family"])
        evidence_items.append({**match, "basis": "trusted_rule"})
    for detection in evidence.detections:
        family = detection.get("family")
        if not family:
            continue
        if registry is not None:
            trusted = [
                item
                for item in registry.match_detection(family)
                if item.rule.trust_level == "trusted_identity"
            ]
            for item in trusted:
                object_families.add(item.rule.family)
                evidence_items.append(
                    {
                        "family": item.rule.family,
                        "rule_id": item.rule.rule_id,
                        "rule_version": item.rule.version,
                        "basis": "trusted_detection",
                        "raw_value": family,
                    }
                )

    canonical_labels = {value for value in label_families if value}
    if taxonomy is not None:
        for detection in evidence.detections:
            canonical = taxonomy.canonical_for(detection.get("family"))
            if canonical:
                canonical_labels.add(canonical)
        canonical = taxonomy.canonical_for(evidence.avclass_detection)
        if canonical:
            canonical_labels.add(canonical)

    status: str
    family: str | None = None
    if object_families:
        if len(object_families) > 1:
            status = "conflicting"
            family = sorted(object_families)[0]
        else:
            status = "supported"
            family = next(iter(object_families))
    elif len(canonical_labels) > 1:
        status = "conflicting"
        family = sorted(canonical_labels)[0]
    elif len(canonical_labels) == 1:
        status = "provisional"
        family = next(iter(canonical_labels))
    elif any(isinstance(value, str) and value.strip() for value in raw_labels):
        status = "unknown"
    else:
        status = "unknown"
    for value in sorted(canonical_labels):
        evidence_items.append({"family": value, "basis": "label", "support": status})
    return status, family, evidence_items


def _invalidating_conflicts(evidence: ReportEvidence, identity_status: str | None) -> list[str]:
    conflicts: list[str] = []
    if identity_status == "conflict":
        conflicts.append("sample_identity_conflict")
    if "target_sha256_invalid" in evidence.quality_flags:
        conflicts.append("target_sha256_invalid")
    if "duplicate_json_key" in evidence.quality_flags:
        conflicts.append("duplicate_json_key")
    if evidence.target_sha256 is None:
        conflicts.append("target_sha256_missing")
    return conflicts


def decide(
    evidence: ReportEvidence,
    *,
    registry: TrustedRuleRegistry | None = None,
    review_bindings: Iterable[Binding] = (),
    scopes: Iterable[Any] = (),
    label_families: Iterable[str] = (),
    raw_labels: Iterable[str] = (),
    taxonomy: Taxonomy | None = None,
    identity_status: str | None = None,
    extra_bindings: Iterable[Binding] = (),
) -> ReportDecision:
    from .binding_utils import machine_bindings, registry_bindings

    bindings = list(machine_bindings(evidence))
    bindings.extend(registry_bindings(evidence, registry))
    bindings.extend(extra_bindings)
    bindings.extend(review_bindings)

    trusted_indices = trustworthy_process_indices(bindings)
    observations: list[ExecutionObservation] = []
    for index in sorted(trusted_indices):
        observed = runtime_execution(evidence, index)
        if observed is not None:
            observations.append(observed)

    status, family, family_evidence = family_identity(
        evidence,
        registry=registry,
        label_families=label_families,
        raw_labels=raw_labels,
        taxonomy=taxonomy,
    )

    conflicts = _invalidating_conflicts(evidence, identity_status)
    execution_status = "not_evaluated"
    observed = False
    observed_objects: list[dict[str, Any]] = []
    if observations:
        execution_status = "launcher_only_observed"
        for observation in observations:
            binding = best_binding(bindings, observation.process_index)
            if binding is None or not binding.trustworthy:
                continue
            if binding.object_sha256 == evidence.target_sha256:
                execution_status = "loader_execution_observed"
                if status == "supported" and family and not conflicts:
                    observed = True
            elif binding.object_kind in ("cape_payload", "dropped", "procdump"):
                if execution_status != "loader_execution_observed":
                    execution_status = "target_execution_observed"
            observed_objects.append(
                {
                    "object_sha256": binding.object_sha256,
                    "object_kind": binding.object_kind,
                    "process_index": observation.process_index,
                    "binding_support": binding.support,
                    "evidence_ids": observation.evidence_ids,
                }
            )
    elif evidence.facts:
        execution_status = "unresolved"

    executed_pids = {
        process.process_id
        for observation in observations
        for process in evidence.processes
        if process.process_index == observation.process_index and process.process_id
    }
    delivery = compute_delivery(
        facts=evidence.facts,
        processes=evidence.processes,
        actor_indices=trusted_indices,
        artifact_guest_paths=[path for item in evidence.artifacts for path in item.guest_paths],
        artifact_names=[item.name for item in evidence.artifacts if item.name],
        next_stage_executed=executed_pids,
    )

    attribution = attribute_events(evidence.facts, scopes, bindings)
    payload_execution = observed and bool(observations) and any(
        item["object_kind"] != "target_sample" for item in observed_objects
    )

    candidate_reasons: list[str] = []
    seed_families: set[str] = set()
    if taxonomy is not None:
        seed_families = taxonomy.seed_family_normalized
    detection_families: set[str] = set()
    for detection in evidence.detections:
        canonical = taxonomy.canonical_for(detection.get("family")) if taxonomy else None
        raw = detection.get("family")
        if canonical in seed_families or (
            isinstance(raw, str) and raw.strip().casefold() in seed_families
        ):
            detection_families.add(canonical or raw)
    canonical_av = taxonomy.canonical_for(evidence.avclass_detection) if taxonomy else None
    if canonical_av in seed_families:
        detection_families.add(canonical_av)
    raw_loader = bool(detection_families)
    if raw_loader:
        candidate_reasons.append("raw_loader_detection")
    if delivery.flags["delivery_attempt_observed"] or delivery.flags["handoff_api_succeeded"]:
        if not observed:
            candidate_reasons.append("delivery_behavior_review")

    reasons: list[str] = []
    needs_review = False
    if observed:
        machine_decision = "loader_run_observed"
        reasons.append("observed_predicate_satisfied")
    elif conflicts:
        machine_decision = "needs_review"
        reasons.extend(conflicts)
        needs_review = True
    elif status in ("provisional", "conflicting") or raw_loader or candidate_reasons:
        machine_decision = "needs_review"
        reasons.append(f"family_identity_{status}")
        if raw_loader:
            reasons.append("raw_loader_detection")
        if observations:
            reasons.append("execution_observed_without_trusted_binding")
        needs_review = True
    elif any(delivery.flags.values()):
        machine_decision = "needs_review"
        reasons.append("delivery_evidence_without_actor")
        needs_review = True
    else:
        machine_decision = "screened_no_loader_evidence"
        reasons.append("no_loader_evidence")

    quality = list(dict.fromkeys([*evidence.quality_flags, *delivery.limitations, *attribution.limitations]))
    return ReportDecision(
        observed=observed,
        payload_execution=payload_execution,
        family_identity_status=status,
        family=family,
        family_evidence=family_evidence,
        execution_status=execution_status,
        execution_observations=observations,
        bindings=bindings,
        delivery=delivery,
        attribution=attribution,
        bucket_counts=attribution.bucket_counts(),
        machine_decision=machine_decision,
        machine_reasons=reasons,
        candidate_reasons=list(dict.fromkeys(candidate_reasons)),
        needs_review=needs_review,
        quality_flags=quality,
        observed_objects=observed_objects,
    )
