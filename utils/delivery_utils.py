"""Delivery evidence flags.

Each flag is independent and requires its own evidence. A true flag never implies a
later one, and all flags are gated on having a trustworthy loader actor plus a concrete
next-stage object. Without that gate the flags stay false and the reason is recorded.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Fact, ProcessSummary

DOWNLOAD_APIS = {"URLDownloadToFileW", "URLDownloadToFileA", "InternetOpenUrlW", "InternetOpenUrlA"}
HANDOFF_APIS = {
    "QueueUserAPC",
    "NtQueueApcThread",
    "NtCreateThreadEx",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "RtlCreateUserThread",
}
CREATE_APIS = {
    "CreateProcessInternalW",
    "CreateProcessW",
    "CreateProcessA",
    "NtCreateUserProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "ShellExecuteExW",
    "ShellExecuteExA",
    "WinExec",
    "RtlCreateUserProcess",
}
FILE_MATERIALIZE_APIS = {"NtCreateFile", "NtWriteFile", "WriteFile", "CreateFileW", "CreateFileA"}


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return posixpath.basename(path.replace("\\", "/"))


@dataclass
class DeliveryResult:
    flags: dict[str, bool] = field(
        default_factory=lambda: {
            "delivery_attempt_observed": False,
            "payload_materialized_observed": False,
            "handoff_api_succeeded": False,
            "payload_execution_observed": False,
        }
    )
    evidence_ids: dict[str, list[str]] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    next_stage_pids: set[int] = field(default_factory=set)
    materialized_objects: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivery_flags": dict(self.flags),
            "delivery_evidence_ids": {key: list(value) for key, value in self.evidence_ids.items()},
            "delivery_limitations": list(self.limitations),
            "next_stage_pids": sorted(self.next_stage_pids),
            "materialized_objects": list(self.materialized_objects),
        }


def _add(result: DeliveryResult, flag: str, evidence_id: str) -> None:
    result.flags[flag] = True
    result.evidence_ids.setdefault(flag, [])
    if evidence_id not in result.evidence_ids[flag]:
        result.evidence_ids[flag].append(evidence_id)


def compute_delivery(
    *,
    facts: Iterable[Fact],
    processes: Iterable[ProcessSummary],
    actor_indices: set[int],
    artifact_guest_paths: Iterable[str] = (),
    artifact_names: Iterable[str] = (),
    next_stage_executed: set[int] | None = None,
) -> DeliveryResult:
    """Compute the four independent delivery flags conservatively.

    ``actor_indices`` must already be trustworthy (registry or review). Every branch
    below is unreachable without an actor, which is exactly the point.
    """
    facts = list(facts)
    processes = {process.process_index: process for process in processes}
    result = DeliveryResult()
    if not actor_indices:
        result.limitations.append("delivery_actor_gate_unmet")
        return result

    next_stage_executed = next_stage_executed or set()
    by_process: dict[int | None, list[Fact]] = {}
    for fact in facts:
        by_process.setdefault(fact.process_index, []).append(fact)

    actor_facts = [fact for index in actor_indices for fact in by_process.get(index, [])]
    actor_pids = {
        processes[index].process_id
        for index in actor_indices
        if index in processes and processes[index].process_id is not None
    }

    next_stage_pids: set[int] = set()
    for index in actor_indices:
        process = processes.get(index)
        if process is None:
            continue
        next_stage_pids.update(process.created_child_pids)
        next_stage_pids.update(process.remote_write_pids)
        next_stage_pids.update(process.remote_thread_pids)
    next_stage_pids -= actor_pids
    result.next_stage_pids = next_stage_pids

    intent_evidence: list[str] = []
    for fact in actor_facts:
        api = fact.attributes.get("api")
        if fact.kind == "process_create" and fact.attributes.get("result") == "success":
            intent_evidence.append(fact.evidence_id)
        elif fact.kind == "network" and api in DOWNLOAD_APIS:
            intent_evidence.append(fact.evidence_id)
    if intent_evidence:
        _add(result, "delivery_attempt_observed", intent_evidence[0])

    def _norm(p: str | None) -> str | None:
        if not p:
            return None
        return p.replace("\\", "/").strip().lower()

    norm_artifact_paths = {_norm(path) for path in artifact_guest_paths if path}
    norm_artifact_names = {_norm(name) for name in artifact_names if name}

    for fact in actor_facts:
        if fact.kind != "file" or fact.attributes.get("result") != "success":
            continue
        path = fact.attributes.get("file_path")
        api = fact.attributes.get("api")
        disposition = str(fact.attributes.get("disposition") or "").strip().upper()

        is_materialize_op = False
        if api in ("NtWriteFile", "WriteFile"):
            is_materialize_op = True
        elif api == "NtCreateFile":
            if disposition not in ("1", "FILE_OPEN", ""):
                is_materialize_op = True
        elif api in ("CreateFileW", "CreateFileA"):
            if disposition not in ("3", "OPEN_EXISTING", ""):
                is_materialize_op = True

        if not is_materialize_op:
            continue

        norm_file_path = _norm(path)
        norm_name = _norm(_basename(path))

        matched = False
        if norm_artifact_paths:
            if norm_file_path in norm_artifact_paths:
                matched = True
        elif norm_artifact_names:
            if norm_name in norm_artifact_names:
                matched = True

        if matched:
            _add(result, "payload_materialized_observed", fact.evidence_id)
            result.materialized_objects.append(norm_name or path or "")
            break

    handoff: list[str] = []
    for fact in actor_facts:
        target = fact.attributes.get("target_pid")
        if fact.attributes.get("result") != "success":
            continue
        api = fact.attributes.get("api")
        if fact.kind == "remote_thread" and target in next_stage_pids:
            if api in HANDOFF_APIS:
                handoff.append(fact.evidence_id)
        elif fact.kind == "process_create" and api in CREATE_APIS:
            if target in next_stage_pids and target is not None:
                handoff.append(fact.evidence_id)
    if handoff:
        _add(result, "handoff_api_succeeded", handoff[0])

    if result.flags["payload_materialized_observed"] and result.flags["handoff_api_succeeded"]:
        executed = next_stage_pids & next_stage_executed
        if executed:
            for fact in actor_facts:
                if fact.attributes.get("target_pid") in executed and fact.kind in (
                    "remote_write",
                    "remote_thread",
                    "process_create",
                ):
                    _add(result, "payload_execution_observed", fact.evidence_id)
                    break
        else:
            result.limitations.append("payload_execution_not_observed")
    else:
        if not result.flags["payload_materialized_observed"]:
            result.limitations.append("payload_materialization_not_observed")
        if not result.flags["handoff_api_succeeded"]:
            result.limitations.append("handoff_success_not_observed")
    return result
