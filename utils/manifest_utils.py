"""Manifest rendering.

CSV files are UTF-8 with a BOM and every text cell starting with a spreadsheet formula
character is prefixed with an apostrophe. List/dict values are always serialised as JSON
inside a single cell, never joined with a separator that could appear in the data.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Iterable

from .state_utils import StateStore

SOURCE_COLUMNS = [
    "source_id",
    "root_id",
    "relative_path",
    "absolute_path",
    "size_bytes",
    "processing_status",
    "report_id",
    "report_content_sha256",
    "sample_sha256_filename",
    "sample_sha256_target",
    "sample_sha256",
    "sample_identity_status",
    "label_pair_state",
    "candidate_reasons",
    "is_seed_candidate",
    "is_candidate",
    "family_identity_status",
    "execution_status",
    "strict_attribution_status",
    "delivery_flags",
    "machine_decision",
    "machine_decision_reasons",
    "effective_decision",
    "human_disposition",
    "error_code",
    "error_message",
    "quality_flags",
    "secondary_locators",
]

LABEL_COLUMNS = [
    "avclass_raw_label",
    "avclass_normalized_label",
    "avclass_canonical_family",
    "avclass_state",
    "avclass_provenance",
    "cape_raw_label",
    "cape_normalized_label",
    "cape_canonical_family",
    "cape_state",
    "cape_provenance",
    "consensus_raw_label",
    "consensus_canonical_family",
    "consensus_state",
    "consensus_provenance",
    "label_secondary_raw_label",
    "label_limitations",
]

OBSERVED_COLUMNS = [
    "source_id",
    "report_id",
    "report_content_sha256",
    "sample_sha256",
    "sample_identity_status",
    "family",
    "family_identity_status",
    "execution_status",
    "binding_support",
    "binding_object_sha256",
    "binding_process_index",
    "execution_evidence_ids",
    "delivery_flags",
    "delivery_evidence_ids",
    "observed_object_sha256",
    "observed_object_kind",
    "review_id",
    "effective_decision",
]

PAYLOAD_COLUMNS = [
    "source_id",
    "report_id",
    "object_sha256",
    "object_kind",
    "object_name",
    "object_size",
    "process_index",
    "process_id",
    "process_name",
    "binding_support",
    "execution_evidence_ids",
    "delivery_flags",
    "review_id",
]

REVIEW_QUEUE_COLUMNS = [
    "source_id",
    "report_id",
    "sample_sha256",
    "machine_decision",
    "machine_decision_reasons",
    "candidate_reasons",
    "family_identity_status",
    "execution_status",
    "strict_attribution_status",
    "quality_flags",
]

UNRESOLVED_COLUMNS = [
    "source_id",
    "report_id",
    "area",
    "code",
    "message",
    "machine_decision",
    "processing_status",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def susceptible(value: Any) -> Any:
    if isinstance(value, str) and value[:1] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return susceptible(str(value))


def write_csv(path: Path, columns: list[str], rows: Iterable[dict[str, Any]]) -> int:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(columns)
    count = 0
    for row in rows:
        writer.writerow([csv_cell(row.get(column)) for column in columns])
        count += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\ufeff" + buffer.getvalue(), encoding="utf-8", newline="")
    return count


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def _labels_by_source(store: StateStore, run_id: str, sources: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    for source in sources:
        observations = store.list_label_observations(run_id, source["source_id"])
        row: dict[str, Any] = {}
        provenance: list[str] = []
        limitations: list[str] = []
        for observation in observations:
            kind = observation["source_kind"]
            if kind not in ("avclass", "cape", "consensus"):
                continue
            row[f"{kind}_raw_label"] = observation["raw_label"]
            row[f"{kind}_normalized_label"] = observation["normalized_label"]
            row[f"{kind}_canonical_family"] = observation["canonical_family"]
            row[f"{kind}_state"] = observation["state"]
            row[f"{kind}_provenance"] = observation["provenance"]
            provenance.append(f"{kind}:{observation['provenance']}")
            limitations.extend(observation["limitations"])
            if observation.get("secondary_raw_label"):
                row["label_secondary_raw_label"] = observation["secondary_raw_label"]
        row.setdefault("label_limitations", sorted(set(limitations)))
        labels[source["source_id"]] = row
    return labels


def _candidate_rows(store: StateStore, run_id: str, sources: list[dict[str, Any]], *, seed_only: bool) -> list[dict[str, Any]]:
    labels = _labels_by_source(store, run_id, sources)
    rows: list[dict[str, Any]] = []
    for source in sources:
        if seed_only and not source["is_seed_candidate"]:
            continue
        if not seed_only and not source["is_candidate"]:
            continue
        row = dict(source)
        row.update(labels.get(source["source_id"], {}))
        rows.append(row)
    return rows


def write_manifests(run_dir: Path, store: StateStore, run_id: str) -> dict[str, int]:
    directory = run_dir / "manifest"
    sources = store.list_sources(run_id)
    reports = store.list_report_meta(run_id)
    counts: dict[str, int] = {}

    counts["all_sources"] = write_csv(directory / "all_sources.csv", SOURCE_COLUMNS, sources)
    counts["seed_candidates"] = write_csv(
        directory / "seed_candidates.csv",
        SOURCE_COLUMNS + LABEL_COLUMNS,
        _candidate_rows(store, run_id, sources, seed_only=True),
    )
    counts["candidates"] = write_csv(
        directory / "candidates.csv",
        SOURCE_COLUMNS + LABEL_COLUMNS,
        _candidate_rows(store, run_id, sources, seed_only=False),
    )
    counts["all_reports"] = write_jsonl(directory / "all_reports.jsonl", reports)

    observed_rows: list[dict[str, Any]] = []
    payload_rows: list[dict[str, Any]] = []
    for report in reports:
        if report.get("effective_decision") != "loader_run_observed":
            continue
        for source_id in report.get("source_ids", []):
            observed_rows.append(
                {
                    "source_id": source_id,
                    "report_id": report["report_id"],
                    "report_content_sha256": report.get("report_content_sha256"),
                    "sample_sha256": report.get("sample_sha256"),
                    "sample_identity_status": report.get("sample_identity_status"),
                    "family": report.get("family"),
                    "family_identity_status": report.get("family_identity_status"),
                    "execution_status": report.get("execution_status"),
                    "binding_support": report.get("binding_support"),
                    "binding_object_sha256": report.get("binding_object_sha256"),
                    "binding_process_index": report.get("binding_process_index"),
                    "execution_evidence_ids": report.get("execution_evidence_ids", []),
                    "delivery_flags": report.get("delivery_flags", {}),
                    "delivery_evidence_ids": report.get("delivery_evidence_ids", {}),
                    "observed_object_sha256": report.get("observed_object_sha256"),
                    "observed_object_kind": report.get("observed_object_kind"),
                    "review_id": report.get("review_id"),
                    "effective_decision": report.get("effective_decision"),
                }
            )
        for item in report.get("observed_objects", []):
            if item.get("payload_execution") is not True:
                continue
            payload_rows.append(
                {
                    "source_id": report.get("source_id"),
                    "report_id": report["report_id"],
                    "object_sha256": item.get("object_sha256"),
                    "object_kind": item.get("object_kind"),
                    "object_name": item.get("name"),
                    "object_size": item.get("size"),
                    "process_index": item.get("process_index"),
                    "process_id": item.get("process_id"),
                    "process_name": item.get("process_name"),
                    "binding_support": item.get("binding_support"),
                    "execution_evidence_ids": item.get("execution_evidence_ids", []),
                    "delivery_flags": report.get("delivery_flags", {}),
                    "review_id": report.get("review_id"),
                }
            )

    counts["observed"] = write_csv(directory / "observed.csv", OBSERVED_COLUMNS, observed_rows)
    counts["payload_execution"] = write_csv(directory / "payload_execution.csv", PAYLOAD_COLUMNS, payload_rows)
    counts["review_queue"] = write_csv(
        directory / "review_queue.csv",
        REVIEW_QUEUE_COLUMNS,
        [
            source
            for source in sources
            if source.get("machine_decision") == "needs_review"
            and source.get("human_disposition") not in ("accepted_loader", "rejected_loader")
        ],
    )

    unresolved_rows: list[dict[str, Any]] = []
    for source in sources:
        status = source.get("processing_status")
        if status in ("error", "resource_limit", "unsupported"):
            unresolved_rows.append(
                {
                    "source_id": source["source_id"],
                    "report_id": source.get("report_id"),
                    "area": "processing",
                    "code": source.get("error_code"),
                    "message": source.get("error_message"),
                    "machine_decision": source.get("machine_decision"),
                    "processing_status": status,
                }
            )
        if source.get("sample_identity_status") in ("conflict", "unresolved"):
            unresolved_rows.append(
                {
                    "source_id": source["source_id"],
                    "report_id": source.get("report_id"),
                    "area": "identity",
                    "code": source.get("sample_identity_status"),
                    "message": "sample identity was not resolved to a single value",
                    "machine_decision": source.get("machine_decision"),
                    "processing_status": status,
                }
            )
        if source.get("strict_attribution_status") == "mixed_or_unresolved":
            unresolved_rows.append(
                {
                    "source_id": source["source_id"],
                    "report_id": source.get("report_id"),
                    "area": "attribution",
                    "code": "mixed_or_unresolved",
                    "message": "event attribution contains conflicting or unattributed events",
                    "machine_decision": source.get("machine_decision"),
                    "processing_status": status,
                }
            )
    counts["unresolved"] = write_csv(directory / "unresolved.csv", UNRESOLVED_COLUMNS, unresolved_rows)
    return counts
