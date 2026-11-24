"""Domain dataclasses shared by the discovery, evidence, policy and export layers.

Tuân thủ Rule 9 (PascalCase class, snake_case fields).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

PROCESSING_STATUSES = (
    "discovered",
    "pending",
    "running",
    "completed",
    "error",
    "resource_limit",
    "unsupported",
    "excluded_by_config",
    "not_scanned",
)

SAMPLE_IDENTITY_STATUSES = (
    "filename_unverified",
    "target_only",
    "filename_target_agree",
    "conflict",
    "unresolved",
)

FAMILY_IDENTITY_STATUSES = (
    "provisional",
    "supported",
    "conflicting",
    "unknown",
)

EXECUTION_STATUSES = (
    "not_evaluated",
    "loader_execution_observed",
    "target_execution_observed",
    "launcher_only_observed",
    "unresolved",
)

DELIVERY_FLAGS = (
    "delivery_attempt_observed",
    "payload_materialized_observed",
    "handoff_api_succeeded",
    "payload_execution_observed",
)

STRICT_ATTRIBUTION_STATUSES = (
    "not_evaluated",
    "supported_for_some_events",
    "none_supported",
    "mixed_or_unresolved",
)

MACHINE_DECISIONS = (
    "invalid_or_unsupported",
    "not_evaluated",
    "needs_review",
    "screened_no_loader_evidence",
    "loader_run_observed",
)

HUMAN_DISPOSITIONS = (
    "unreviewed",
    "accepted_loader",
    "rejected_loader",
    "inconclusive",
)

EVENT_BUCKETS = ("loader_strict", "payload", "system_context", "mixed_or_unresolved")

CANDIDATE_REASONS = (
    "seed_label",
    "trusted_alias",
    "generic_label_review",
    "multirole_family_review",
    "raw_loader_detection",
    "delivery_behavior_review",
    "label_index_conflict",
)

LABEL_PAIR_STATES = (
    "both_missing",
    "one_present",
    "same_canonical_family",
    "different_canonical_families",
    "same_unmapped_label",
    "different_nonmissing_labels",
    "source_conflict",
    "unresolved",
)

IDENTITY_MODES = ("auto", "filename", "report")
ANALYSIS_MODES = ("labels", "evidence")
ANALYSIS_SCOPES = ("candidates", "all")
ROW_ERROR_POLICIES = ("quarantine", "fail")


@dataclass
class IdentityResolution:
    """Identity of the analysed sample, kept separate from the locator identity."""

    sample_sha256_filename: Optional[str] = None
    sample_sha256_target: Optional[str] = None
    sample_sha256: Optional[str] = None
    status: str = "unresolved"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_sha256_filename": self.sample_sha256_filename,
            "sample_sha256_target": self.sample_sha256_target,
            "sample_sha256": self.sample_sha256,
            "sample_identity_status": self.status,
            "notes": list(self.notes),
        }


@dataclass
class LabelObservation:
    """A single label observation for one (source_kind, sample_sha256) pair."""

    source_kind: str
    sample_sha256: str
    raw_label: str
    normalized_label: str
    canonical_family: Optional[str]
    state: str  # present | missing_label | invalid | missing_record
    provenance: str  # mapping | consensus_only | mapping+consensus_agree | mapping+consensus_mismatch
    json_pointer: str
    source_file: str
    source_sha256: str
    duplicate_count: int = 1
    secondary_raw_label: Optional[str] = None
    limitations: list[str] = field(default_factory=list)

    @property
    def is_present(self) -> bool:
        return self.state == "present"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "sample_sha256": self.sample_sha256,
            "raw_label": self.raw_label,
            "normalized_label": self.normalized_label,
            "canonical_family": self.canonical_family,
            "state": self.state,
            "provenance": self.provenance,
            "json_pointer": self.json_pointer,
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "duplicate_count": self.duplicate_count,
            "secondary_raw_label": self.secondary_raw_label,
            "limitations": list(self.limitations),
        }


@dataclass
class SourceRecord:
    """One discovered file locator plus everything decided about it so far."""

    source_id: str
    root_id: str
    relative_path: str
    absolute_path: str
    size_bytes: int
    mtime_ns: int
    processing_status: str = "discovered"
    report_id: Optional[str] = None
    report_content_sha256: Optional[str] = None
    sample_sha256_filename: Optional[str] = None
    sample_sha256_target: Optional[str] = None
    sample_sha256: Optional[str] = None
    sample_identity_status: str = "unresolved"
    family_identity_status: str = "unknown"
    execution_status: str = "not_evaluated"
    strict_attribution_status: str = "not_evaluated"
    delivery_flags: dict[str, bool] = field(default_factory=dict)
    label_pair_state: str = "unresolved"
    candidate_reasons: list[str] = field(default_factory=list)
    is_seed_candidate: bool = False
    is_candidate: bool = False
    machine_decision: str = "not_evaluated"
    machine_decision_reasons: list[str] = field(default_factory=list)
    effective_decision: str = "not_evaluated"
    human_disposition: str = "unreviewed"
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    quality_flags: list[str] = field(default_factory=list)
    secondary_locators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "root_id": self.root_id,
            "relative_path": self.relative_path,
            "absolute_path": self.absolute_path,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
            "processing_status": self.processing_status,
            "report_id": self.report_id,
            "report_content_sha256": self.report_content_sha256,
            "sample_sha256_filename": self.sample_sha256_filename,
            "sample_sha256_target": self.sample_sha256_target,
            "sample_sha256": self.sample_sha256,
            "sample_identity_status": self.sample_identity_status,
            "family_identity_status": self.family_identity_status,
            "execution_status": self.execution_status,
            "strict_attribution_status": self.strict_attribution_status,
            "delivery_flags": dict(self.delivery_flags),
            "label_pair_state": self.label_pair_state,
            "candidate_reasons": list(self.candidate_reasons),
            "is_seed_candidate": self.is_seed_candidate,
            "is_candidate": self.is_candidate,
            "machine_decision": self.machine_decision,
            "machine_decision_reasons": list(self.machine_decision_reasons),
            "effective_decision": self.effective_decision,
            "human_disposition": self.human_disposition,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "quality_flags": list(self.quality_flags),
            "secondary_locators": list(self.secondary_locators),
        }


@dataclass
class Fact:
    """An evidence fact. Facts are observations, never conclusions."""

    evidence_id: str
    report_id: str
    rule_id: str
    rule_version: str
    kind: str
    subject_sha256: Optional[str] = None
    subject_kind: Optional[str] = None
    process_key: Optional[str] = None
    process_index: Optional[int] = None
    event_keys: list[str] = field(default_factory=list)
    source_json_pointers: list[str] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "kind": self.kind,
            "subject_sha256": self.subject_sha256,
            "subject_kind": self.subject_kind,
            "process_key": self.process_key,
            "process_index": self.process_index,
            "event_keys": list(self.event_keys),
            "source_json_pointers": list(self.source_json_pointers),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "limitations": list(self.limitations),
            "attributes": dict(self.attributes),
        }


@dataclass
class ProcessSummary:
    process_index: int
    process_id: Optional[int] = None
    parent_id: Optional[int] = None
    process_name: Optional[str] = None
    module_path: Optional[str] = None
    command_line: Optional[str] = None
    first_seen: Optional[str] = None
    call_count: int = 0
    enhanced_count: int = 0
    api_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    created_child_pids: list[int] = field(default_factory=list)
    remote_write_pids: list[int] = field(default_factory=list)
    remote_thread_pids: list[int] = field(default_factory=list)
    unresolved_handle_pids: list[int] = field(default_factory=list)
    has_network_activity: bool = False
    has_download_api: bool = False
    has_file_create: bool = False
    has_file_write: bool = False
    has_remote_write: bool = False
    has_remote_thread: bool = False
    has_process_create: bool = False
    role_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "process_index": self.process_index,
            "process_id": self.process_id,
            "parent_id": self.parent_id,
            "process_name": self.process_name,
            "module_path": self.module_path,
            "command_line": self.command_line,
            "first_seen": self.first_seen,
            "call_count": self.call_count,
            "enhanced_count": self.enhanced_count,
            "api_counts": dict(self.api_counts),
            "category_counts": dict(self.category_counts),
            "created_child_pids": list(self.created_child_pids),
            "remote_write_pids": list(self.remote_write_pids),
            "remote_thread_pids": list(self.remote_thread_pids),
            "unresolved_handle_pids": list(self.unresolved_handle_pids),
            "has_network_activity": self.has_network_activity,
            "has_download_api": self.has_download_api,
            "has_file_create": self.has_file_create,
            "has_file_write": self.has_file_write,
            "has_remote_write": self.has_remote_write,
            "has_remote_thread": self.has_remote_thread,
            "has_process_create": self.has_process_create,
            "role_hints": list(self.role_hints),
        }


@dataclass
class ReportFacts:
    """Everything the CAPE adapter extracted from one report."""

    report_id: str
    report_content_sha256: str
    size_bytes: int
    target_sha256: Optional[str] = None
    target_name: Optional[str] = None
    target_type: Optional[str] = None
    target_guest_paths: list[str] = field(default_factory=list)
    avclass_detection: Optional[str] = None
    detections: list[dict[str, Any]] = field(default_factory=list)
    cape_payloads: list[dict[str, Any]] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    procdump: list[dict[str, Any]] = field(default_factory=list)
    signature_names: list[str] = field(default_factory=list)
    processes: list[ProcessSummary] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    total_calls: int = 0
    enhanced_count: int = 0
    quality_flags: list[str] = field(default_factory=list)
    coverage_flags: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_content_sha256": self.report_content_sha256,
            "size_bytes": self.size_bytes,
            "target_sha256": self.target_sha256,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "target_guest_paths": list(self.target_guest_paths),
            "avclass_detection": self.avclass_detection,
            "detections": list(self.detections),
            "cape_payloads": list(self.cape_payloads),
            "dropped": list(self.dropped),
            "procdump": list(self.procdump),
            "signature_names": list(self.signature_names),
            "processes": [p.to_dict() for p in self.processes],
            "facts": [f.to_dict() for f in self.facts],
            "total_calls": self.total_calls,
            "enhanced_count": self.enhanced_count,
            "quality_flags": list(self.quality_flags),
            "coverage_flags": list(self.coverage_flags),
            "errors": list(self.errors),
        }
