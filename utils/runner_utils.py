"""Run orchestration: discovery -> inventory -> evidence -> decision -> manifests -> QA."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .cape_adapter import CapeAdapter, ParseLimits
from .configs import Config
from .discovery_utils import discover
from .errors import ConfigError, EXIT_INTEGRITY, EXIT_OK, EXIT_PARTIAL, IntegrityError, RunLockError
from .evidence_utils import ReportEvidence, collect_report, evidence_dir, read_report_evidence, write_evidence
from .policy_utils import ReportDecision, decide
from .registry_utils import load_registry
from .review_utils import (
    REVIEW_SCHEMA_VERSION,
    ReviewError,
    parse_review,
    ValidatedReview,
    effective_bindings,
    effective_scopes,
    load_review_file,
    validate_reviews,
)
from .identity_utils import resolve_identity, sha256_from_filename
from .inventory_utils import InventoryEntry, build_inventory
from .label_utils import LabelStore
from .locking_utils import RunLock
from .manifest_utils import write_manifests
from .models import SourceRecord
from .qa_utils import comparison_report, run_checks
from .scheduler_utils import ParseScheduler, report_facts_from_dict
from .state_utils import StateStore
from .taxonomy_utils import Taxonomy, load_taxonomy
from .io_utils import atomic_write_text, is_sha256, read_json_strict, sha256_file, sha256_json, utc_now, utc_now_iso, write_json, write_jsonl

SOFTWARE_NAME = "LoaderFilter"
SOFTWARE_VERSION = "0.1.0"
ANALYSIS_VERSION = "conservative-v1"
EVIDENCE_SCHEMA_VERSION = 1
OUTPUT_MARKER = ".loaderfilter-output.json"

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


# ---------------------------------------------------------------------------------------
# layout and configuration snapshots
# ---------------------------------------------------------------------------------------
@dataclass
class RunLayout:
    run_id: str
    run_dir: Path

    @classmethod
    def build(cls, config: Config, run_id: str) -> "RunLayout":
        if not RUN_ID_RE.match(run_id):
            raise ConfigError(f"invalid run id: {run_id!r}")
        return cls(run_id=run_id, run_dir=Path(config.output.root) / run_id)

    @property
    def state_path(self) -> Path:
        return self.run_dir / "state.sqlite"

    @property
    def config_dir(self) -> Path:
        return self.run_dir / "config"

    @property
    def manifest_dir(self) -> Path:
        return self.run_dir / "manifest"

    @property
    def evidence_root(self) -> Path:
        return self.run_dir / "evidence" / "by_report"

    @property
    def reviews_dir(self) -> Path:
        return self.run_dir / "reviews"

    @property
    def qa_dir(self) -> Path:
        return self.run_dir / "qa"

    @property
    def errors_dir(self) -> Path:
        return self.run_dir / "errors"

    @property
    def logs_dir(self) -> Path:
        return self.run_dir / "logs"

    @property
    def lock_path(self) -> Path:
        return self.run_dir / ".run.lock"

    @property
    def run_json(self) -> Path:
        return self.run_dir / "run.json"

    def ensure(self) -> None:
        for directory in (
            self.run_dir,
            self.config_dir,
            self.manifest_dir,
            self.evidence_root,
            self.reviews_dir,
            self.qa_dir,
            self.errors_dir,
            self.logs_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


class RunLog:
    def __init__(self, path: Path):
        self.path = path

    def write(self, level: str, event: str, **fields: Any) -> None:
        line = {"ts": utc_now_iso(), "level": level, "event": event, **fields}
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(line, ensure_ascii=False, sort_keys=True, default=str) + "\n")


@dataclass
class RunOptions:
    run_id: str
    resume: bool = False
    limit: int | None = None
    retry_errors: bool = False
    review_files: list[Path] = field(default_factory=list)


@dataclass
class RunOutcome:
    run_id: str
    run_dir: Path
    exit_code: int
    counters: dict[str, Any]
    qa_status: str
    summary: dict[str, Any]


def generate_run_id(config: Config) -> str:
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    return f"run-{stamp}-{config.semantic_config_hash()[:8]}"


def _label_fingerprints(config: Config) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for kind, path in (
        ("avclass", config.labels.avclass),
        ("cape", config.labels.cape),
        ("consensus", config.labels.consensus),
    ):
        if path is None:
            continue
        stat = Path(path).stat()
        result[kind] = {
            "path": str(path),
            "size_bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "content_sha256": sha256_file(Path(path))[0],
        }
    return result


def compute_analysis_fingerprint(config: Config, taxonomy: Taxonomy, registry_sha256: str | None) -> str:
    return sha256_json(
        {
            "software": SOFTWARE_VERSION,
            "analysis_version": ANALYSIS_VERSION,
            "adapter": {"name": CapeAdapter.name, "version": CapeAdapter.version},
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "review_schema_version": REVIEW_SCHEMA_VERSION,
            "semantic_config": config.semantic_config_hash(),
            "taxonomy_sha256": taxonomy.content_sha256,
            "registry_sha256": registry_sha256,
        }
    )


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------
def _peek_target_sha256(path: Path, max_bytes: int) -> str | None:
    """Read target sha256 from a CAPE report; never used as evidence."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        import ijson

        with path.open("rb") as stream:
            for prefix, event, value in ijson.parse(stream):
                if prefix in ("target.file.sha256", "target.sha256") and event == "string" and isinstance(value, str):
                    if is_sha256(value):
                        return value.lower()
                if prefix == "target" and event == "end_map":
                    return None
    except Exception:  # noqa: BLE001 - identity pre-read is best effort only
        return None
    return None


def _needs_target_prefetch(config: Config, absolute_path: str) -> bool:
    mode = config.discovery.identity
    if mode == "report":
        return True
    if mode == "auto":
        return sha256_from_filename(Path(absolute_path)) is None
    return False


def _label_inputs(entry: InventoryEntry) -> tuple[list[str], list[str]]:
    families: list[str] = []
    raw: list[str] = []
    for observation in entry.observations:
        raw.append(observation.raw_label)
        if observation.canonical_family and observation.canonical_family not in families:
            families.append(observation.canonical_family)
    return families, raw


def _review_binding_for_source(validated: Iterable[ValidatedReview], source_id: str) -> list[Any]:
    selected = [item for item in validated if item.record.source_id == source_id and item.status == "applied"]
    return effective_bindings(selected)


def _review_scopes_for_source(validated: Iterable[ValidatedReview], source_id: str) -> list[Any]:
    selected = [item for item in validated if item.record.source_id == source_id and item.status == "applied"]
    return effective_scopes(selected)


def _human_effective_decision(decision: ReportDecision, human: str | None) -> str:
    if human == "rejected_loader":
        return "rejected_loader"
    if human == "inconclusive":
        return "needs_review"
    if decision.observed:
        return "loader_run_observed"
    return decision.machine_decision


def _observed_binding(decision: ReportDecision) -> Any:
    trustworthy = [binding for binding in decision.bindings if binding.trustworthy]
    if not trustworthy:
        return None
    indices = [observation.process_index for observation in decision.execution_observations]
    for binding in trustworthy:
        if binding.process_index in indices:
            return binding
    return trustworthy[0]


def _enrich_observed_objects(decision: ReportDecision, evidence: ReportEvidence) -> list[dict[str, Any]]:
    by_sha = {artifact.sha256: artifact for artifact in evidence.artifacts if artifact.sha256}
    by_process = {process.process_index: process for process in evidence.processes}
    objects: list[dict[str, Any]] = []
    for item in decision.observed_objects:
        artifact = by_sha.get(item.get("object_sha256"))
        process = by_process.get(item.get("process_index"))
        is_target = item.get("object_kind") == "target_sample"
        objects.append(
            {
                **item,
                "name": artifact.name if artifact else (evidence.target_name if is_target else None),
                "size": artifact.size if artifact else (evidence.size_bytes if is_target else None),
                "process_id": process.process_id if process else None,
                "process_name": process.process_name if process else None,
                "payload_execution": bool(decision.payload_execution and not is_target),
            }
        )
    return objects


def _merge_report_meta(
    report_id: str,
    evidence: ReportEvidence,
    decisions: list[tuple[SourceRecord, ReportDecision]],
) -> dict[str, Any]:
    first_source, first_decision = decisions[0]
    binding = _observed_binding(first_decision)
    observations = first_decision.execution_observations
    execution_ids: list[str] = []
    for observation in observations:
        execution_ids.extend(observation.evidence_ids)
    effective = first_source.effective_decision
    machine = first_source.machine_decision
    reasons = list(first_source.machine_decision_reasons)
    source_ids = [source.source_id for source, _ in decisions]
    if len({source.effective_decision for source, _ in decisions}) > 1:
        effective = "needs_review"
        machine = "needs_review"
        if "source_decisions_diverge" not in reasons:
            reasons.append("source_decisions_diverge")
    return {
        "report_id": report_id,
        "source_id": first_source.source_id,
        "source_ids": source_ids,
        "report_content_sha256": evidence.report_content_sha256,
        "size_bytes": evidence.size_bytes,
        "sample_sha256": first_source.sample_sha256,
        "sample_identity_status": first_source.sample_identity_status,
        "family": first_decision.family,
        "family_identity_status": first_decision.family_identity_status,
        "execution_status": first_decision.execution_status,
        "binding_support": binding.support if binding else "unsupported",
        "binding_object_sha256": binding.object_sha256 if binding else None,
        "binding_process_index": binding.process_index if binding else None,
        "execution_evidence_ids": list(dict.fromkeys(execution_ids)),
        "delivery_flags": dict(first_decision.delivery.flags),
        "delivery_evidence_ids": dict(first_decision.delivery.evidence_ids),
        "observed_object_sha256": binding.object_sha256 if binding else None,
        "observed_object_kind": binding.object_kind if binding else None,
        "observed_objects": _enrich_observed_objects(first_decision, evidence),
        "observed": first_decision.observed,
        "payload_execution": first_decision.payload_execution,
        "bucket_counts": dict(first_decision.bucket_counts),
        "machine_decision": machine,
        "machine_decision_reasons": reasons,
        "effective_decision": effective,
        "human_disposition": first_source.human_disposition,
        "review_id": binding.review_id if binding else None,
        "quality_flags": list(dict.fromkeys(first_decision.quality_flags)),
        "strict_attribution_status": first_decision.attribution.status,
    }


def _error_status(error_code: str | None) -> tuple[str, str]:
    code = error_code or "unknown_error"
    if code == "resource_limit":
        return "resource_limit", "invalid_or_unsupported"
    if code in ("not_cape_report", "unsupported_schema", "invalid_json"):
        return "unsupported", "invalid_or_unsupported"
    return "error", "invalid_or_unsupported"


# ---------------------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------------------
def run(config: Config, options: RunOptions) -> RunOutcome:
    layout = RunLayout.build(config, options.run_id)
    layout.ensure()
    lock = RunLock(layout.lock_path)
    if not lock.acquire():
        raise RunLockError(f"run is locked by another process: {layout.lock_path}")
    try:
        return _run_locked(config, options, layout)
    finally:
        lock.release()


def _run_locked(config: Config, options: RunOptions, layout: RunLayout) -> RunOutcome:
    started = time.monotonic()
    log = RunLog(layout.logs_dir / "run.jsonl")
    log.write("info", "run_start", run_id=layout.run_id, resume=options.resume)

    if config.taxonomy is None:
        raise ConfigError("a taxonomy is required for every analysis")
    taxonomy = load_taxonomy(config.taxonomy)
    registry = load_registry(config.analysis.trusted_rule_registry)
    registry_sha = getattr(registry, "content_sha256", None)
    fingerprint = compute_analysis_fingerprint(config, taxonomy, registry_sha)

    store = StateStore(layout.state_path)
    try:
        return _run_impl(
            config, options, layout, started, log, taxonomy, registry, registry_sha, fingerprint, store
        )
    finally:
        store.close()


def _run_impl(
    config: Config,
    options: RunOptions,
    layout: RunLayout,
    started: float,
    log: RunLog,
    taxonomy: Taxonomy,
    registry: Any,
    registry_sha: str | None,
    fingerprint: str,
    store: StateStore,
) -> RunOutcome:
    store.begin()
    existing_run = store.get_run(layout.run_id)
    if existing_run is None:
        if options.resume:
            raise ConfigError(f"no run to resume at {layout.run_dir}")
        store.create_run(
            run_id=layout.run_id,
            mode=config.analysis.mode,
            scope=config.analysis.scope,
            policy=config.analysis.policy,
            semantic_config_hash=config.semantic_config_hash(),
            analysis_fingerprint=fingerprint,
            config_path=str(config.config_path) if config.config_path else None,
            effective_config=config.to_dict(),
        )
    else:
        if not options.resume:
            raise ConfigError(
                f"run directory already contains run {layout.run_id!r}; use --resume or a different --run-id"
            )
        if existing_run.semantic_config_hash != config.semantic_config_hash():
            raise ConfigError("configuration changed since the run was created; semantic settings must match")
        if existing_run.analysis_fingerprint != fingerprint:
            raise ConfigError("analysis fingerprint changed (adapter/taxonomy/registry); start a new run")

    label_store = LabelStore(taxonomy)
    label_paths = config.label_source_paths()
    label_metrics: dict[str, Any] = {}
    if label_paths:
        label_store.load(
            config.labels.avclass,
            config.labels.cape,
            config.labels.consensus,
            config.labels.row_errors,
        )
        label_metrics = label_store.to_dict()
    log.write("info", "labels_loaded", **label_metrics)

    discovery = discover(config, limit=options.limit)
    log.write(
        "info",
        "discovery",
        files=len(discovery.files),
        coverage_limited=discovery.coverage_limited,
        stats=discovery.stats,
    )

    target_shas: dict[str, str] = {}
    prefetch = [item for item in discovery.files if _needs_target_prefetch(config, item.absolute_path)]
    for item in prefetch:
        sha = _peek_target_sha256(Path(item.absolute_path), config.resources.max_file_bytes)
        if sha:
            target_shas[item.source_id] = sha
    log.write("info", "identity_prefetch", considered=len(prefetch), resolved=len(target_shas))

    inventory = build_inventory(
        discovery.files,
        label_store,
        taxonomy,
        target_sha256_by_source=target_shas,
        identity_mode=config.discovery.identity,
    )
    log.write("info", "inventory", **inventory.counters)

    _write_config_snapshot(layout, config, taxonomy, label_metrics, fingerprint, label_paths, registry_sha)
    _write_label_errors(layout, label_store)

    entries_by_source: dict[str, InventoryEntry] = {}
    previous = {row["source_id"]: row for row in store.list_sources(layout.run_id)}
    terminal_errors = {"error", "resource_limit", "unsupported"}
    for entry in inventory.entries:
        record = entry.source
        prior = previous.get(record.source_id)
        if prior is not None:
            record.effective_decision = prior.get("effective_decision") or "not_evaluated"
            record.human_disposition = prior.get("human_disposition") or "unreviewed"
            if prior.get("processing_status") in terminal_errors and options.resume and not options.retry_errors:
                record.processing_status = prior.get("processing_status")
                record.error_code = prior.get("error_code")
                record.error_message = prior.get("error_message")
            if prior.get("processing_status") == "completed":
                source_path = Path(record.absolute_path)
                if not source_path.is_file():
                    record.processing_status = "error"
                    record.error_code = "source_missing"
                    record.error_message = f"source file missing on resume: {source_path}"
                elif config.analysis.mode == "evidence":
                    current_sha, current_size = sha256_file(source_path)
                    if current_sha != prior.get("report_content_sha256"):
                        record.processing_status = "discovered"
                        record.report_id = None
                        record.report_content_sha256 = None
                        record.size_bytes = current_size
                    else:
                        record.processing_status = "completed"
                        record.report_id = prior.get("report_id")
                        record.report_content_sha256 = prior.get("report_content_sha256")
                        record.sample_sha256_filename = prior.get("sample_sha256_filename")
                        record.sample_sha256_target = prior.get("sample_sha256_target")
                        record.sample_sha256 = prior.get("sample_sha256")
                        record.sample_identity_status = prior.get("sample_identity_status")
                        record.size_bytes = prior.get("size_bytes") or record.size_bytes
                else:
                    record.processing_status = "completed"
                    record.report_id = prior.get("report_id")
                    record.report_content_sha256 = prior.get("report_content_sha256")
                    record.sample_sha256_filename = prior.get("sample_sha256_filename")
                    record.sample_sha256_target = prior.get("sample_sha256_target")
                    record.sample_sha256 = prior.get("sample_sha256")
                    record.sample_identity_status = prior.get("sample_identity_status")
                    record.size_bytes = prior.get("size_bytes") or record.size_bytes
        entries_by_source[record.source_id] = entry

    in_scope = [
        entry
        for entry in inventory.entries
        if config.analysis.scope == "all" or entry.source.is_candidate
    ]
    in_scope_ids = {entry.source.source_id for entry in in_scope}
    for entry in inventory.entries:
        record = entry.source
        if record.source_id not in in_scope_ids:
            record.processing_status = "not_scanned"
            record.machine_decision = "not_evaluated"
            record.effective_decision = "not_evaluated"
        store.upsert_source(layout.run_id, record)
        observations = [
            {
                "source_kind": observation.source_kind,
                "sample_sha256": observation.sample_sha256,
                "raw_label": observation.raw_label,
                "normalized_label": observation.normalized_label,
                "canonical_family": observation.canonical_family,
                "state": observation.state,
                "provenance": observation.provenance,
                "json_pointer": observation.json_pointer,
                "source_file": observation.source_file,
                "source_sha256": observation.source_sha256,
                "duplicate_count": observation.duplicate_count,
                "secondary_raw_label": observation.secondary_raw_label,
                "limitations": list(observation.limitations),
            }
            for observation in entry.observations
        ]
        if observations:
            store.upsert_label_observations(layout.run_id, record.source_id, observations)
        if record.source_id not in in_scope_ids:
            job_status = "skipped"
        elif record.processing_status == "completed":
            job_status = "completed"
        elif record.processing_status in terminal_errors and options.resume and not options.retry_errors:
            job_status = record.processing_status
        else:
            job_status = "pending"
        store.set_job(layout.run_id, record.source_id, job_status)
    store.commit()
    log.write("info", "inventory_persisted", sources=len(inventory.entries), in_scope=len(in_scope))

    if config.analysis.mode == "labels":
        for entry in inventory.entries:
            record = entry.source
            if not record.report_id:
                content_sha, _ = sha256_file(Path(record.absolute_path))
                record.report_id = content_sha
                record.report_content_sha256 = content_sha
            record.machine_decision = "not_evaluated"
            record.effective_decision = "not_evaluated"
            record.execution_status = "not_evaluated"
            record.strict_attribution_status = "not_evaluated"
            record.processing_status = "completed"
            store.upsert_source(layout.run_id, record)
            store.set_job(layout.run_id, record.source_id, "completed", increment_attempts=True)
        store.commit()
        manifest_counts = write_manifests(layout.run_dir, store, layout.run_id)
        store.commit()
        qa_summary = run_checks(layout.run_dir, store, layout.run_id, config)
        write_json(layout.qa_dir / "summary.json", qa_summary)
        write_jsonl(layout.qa_dir / "checks.jsonl", qa_summary["checks"])
        comparison = comparison_report(layout.run_dir, store, layout.run_id)
        write_json(layout.qa_dir / "run_summary.json", comparison)
        log.write("info", "manifest", **manifest_counts)
        log.write("info", "qa", status=qa_summary["status"], counts=qa_summary["counts"])
        counters = _build_counters(config, layout, store, inventory, discovery, manifest_counts, comparison, 0, started)
        status = "completed" if qa_summary["status"] != "fail" else "completed"
        exit_code = EXIT_OK if qa_summary["status"] != "fail" else EXIT_INTEGRITY
        store.update_run_status(layout.run_id, status, counters)
        store.commit()
        summary = {
            "run_id": layout.run_id,
            "status": status,
            "created_at": existing_run.created_at if existing_run else utc_now_iso(),
            "finished_at": utc_now_iso(),
            "software": {"name": SOFTWARE_NAME, "version": SOFTWARE_VERSION},
            "analysis_version": ANALYSIS_VERSION,
            "config_path": str(config.config_path) if config.config_path else None,
            "semantic_config_sha256": config.semantic_config_hash(),
            "analysis_fingerprint": fingerprint,
            "taxonomy": {"path": str(config.taxonomy), "content_sha256": taxonomy.content_sha256, "version": taxonomy.version},
            "inputs": [{"id": spec.id, "path": str(Path(spec.path).resolve())} for spec in config.inputs],
            "scope": config.analysis.scope,
            "evidence_scope": "not_applicable",
            "mode": config.analysis.mode,
            "policy": config.analysis.policy,
            "counters": counters,
            "qa": {"status": qa_summary["status"], "counts": qa_summary["counts"], "path": str(layout.qa_dir / "summary.json")},
            "exit_code": exit_code,
            "run_summary_path": str(layout.qa_dir / "run_summary.json"),
        }
        write_json(layout.run_json, summary)
        atomic_write_text(
            layout.run_dir / OUTPUT_MARKER,
            json.dumps({"run_id": layout.run_id, "software": SOFTWARE_NAME, "version": SOFTWARE_VERSION}) + "\n",
        )
        log.write("info", "run_finish", status=status, exit_code=exit_code)
        store.close()
        return RunOutcome(
            run_id=layout.run_id,
            run_dir=layout.run_dir,
            exit_code=exit_code,
            counters=counters,
            qa_status=qa_summary["status"],
            summary=summary,
        )

    limits = ParseLimits(
        max_file_bytes=config.resources.max_file_bytes,
        max_call_record_bytes=config.resources.max_call_record_bytes,
        max_json_depth=config.resources.max_json_depth,
        timeout_seconds=config.resources.report_timeout_seconds,
    )

    groups: dict[str, list[InventoryEntry]] = {}
    for entry in in_scope:
        if options.resume and _evidence_is_complete(layout, store, layout.run_id, entry.source):
            continue
        if (
            options.resume
            and not options.retry_errors
            and entry.source.processing_status in terminal_errors
            and entry.source.report_id is None
        ):
            continue
        groups.setdefault(entry.source.absolute_path, []).append(entry)

    error_rows: list[dict[str, object]] = []
    failed = 0
    with ParseScheduler(
        workers=config.resources.workers,
        timeout_seconds=config.resources.report_timeout_seconds,
        limits=limits,
    ) as scheduler:
        tasks = [(path, Path(path)) for path in sorted(groups)]
        for path, result in scheduler.map(tasks):
            group = groups[path]
            facts_payload = result.get("facts")
            if facts_payload is None:
                failed += 1
                status, machine_decision = _error_status(result.get("error_code"))
                for entry in group:
                    record = entry.source
                    record.processing_status = status
                    record.error_code = result.get("error_code") or "unknown_error"
                    record.error_message = result.get("error_message")
                    record.machine_decision = machine_decision
                    record.machine_decision_reasons = [record.error_code]
                    record.effective_decision = "invalid_or_unsupported"
                    error_rows.append(
                        {
                            "source_id": record.source_id,
                            "source_path": record.absolute_path,
                            "error_code": record.error_code,
                            "error_message": record.error_message,
                            "processing_status": status,
                        }
                    )
                    store.upsert_source(layout.run_id, record)
                    store.set_job(
                        layout.run_id,
                        record.source_id,
                        status,
                        error_code=record.error_code,
                        error_message=record.error_message,
                        increment_attempts=True,
                    )
                log.write("warning", "parse_failed", path=path, code=result.get("error_code"), message=result.get("error_message"))
                store.commit()
                continue

            facts = report_facts_from_dict(facts_payload)
            if result.get("content_sha256") and facts.report_content_sha256 != result["content_sha256"]:
                raise IntegrityError(
                    f"adapter content hash disagrees with streamed hash for {path}",
                    details={"expected": result["content_sha256"], "actual": facts.report_content_sha256},
                )
            report_id = facts.report_content_sha256
            evidence = collect_report(facts, report_id=report_id)
            fact_count = len(evidence.facts)
            checksums = write_evidence(evidence_dir(layout.run_dir, report_id), evidence)
            del evidence
            for kind, suffix in (("evidence_facts", "facts.jsonl"), ("evidence_processes", "processes.jsonl"), ("evidence_report", "report.json")):
                artifact_path = evidence_dir(layout.run_dir, report_id) / suffix
                store.add_artifact(
                    layout.run_id,
                    artifact_id=f"{kind}:{report_id}",
                    kind=kind,
                    path=str(artifact_path),
                    sha256=checksums.get(f"{kind.split('_', 1)[1]}_sha256"),
                    size_bytes=artifact_path.stat().st_size,
                )

            for entry in group:
                record = entry.source
                filename_sha = sha256_from_filename(Path(record.absolute_path))
                identity = resolve_identity(
                    record.source_id,
                    filename_sha256=filename_sha,
                    target_sha256=facts.target_sha256,
                )
                record.report_id = report_id
                record.report_content_sha256 = facts.report_content_sha256
                record.sample_sha256_filename = identity.filename_sha256
                record.sample_sha256_target = identity.target_sha256
                record.sample_sha256 = identity.sample_sha256
                record.sample_identity_status = identity.status
                record.size_bytes = facts.size_bytes
                record.processing_status = "parsed"
                store.upsert_source(layout.run_id, record)
                store.upsert_report(
                    layout.run_id,
                    report_id=report_id,
                    source_id=record.source_id,
                    content_sha256=facts.report_content_sha256,
                    size_bytes=facts.size_bytes,
                    adapter_version=CapeAdapter.version,
                    analysis_fingerprint=fingerprint,
                    facts_path=str(evidence_dir(layout.run_dir, report_id) / "facts.jsonl"),
                    processes_path=str(evidence_dir(layout.run_dir, report_id) / "processes.jsonl"),
                    strict_count=0,
                    bucket_counts={},
                    status="ok",
                )
                store.set_job(
                    layout.run_id,
                    record.source_id,
                    "parsed",
                    increment_attempts=True,
                )
            log.write("info", "parsed", path=path, report_id=report_id, facts=fact_count)
            store.commit()

    store.commit()
    write_jsonl(layout.errors_dir / "reports.jsonl", error_rows)

    decisions_by_report: dict[str, list[tuple[SourceRecord, ReportDecision]]] = {}

    validated_reviews = _prepare_reviews(config, options, layout, store, fingerprint, in_scope)
    dispositions = {
        item.record.source_id: item.record.disposition
        for item in validated_reviews
        if item.status == "applied"
    }
    for entry in in_scope:
        if entry.source.source_id in dispositions:
            entry.source.human_disposition = dispositions[entry.source.source_id]
    for item in validated_reviews:
        store.add_review_revision(
            layout.run_id,
            review_id=item.record.review_id,
            source_id=item.record.source_id,
            revision=1,
            disposition=item.record.disposition,
            payload=item.record.to_dict(),
            analysis_fingerprint=item.record.analysis_fingerprint,
        )
    if validated_reviews:
        write_jsonl(
            layout.reviews_dir / "history.jsonl",
            [
                {
                    **item.to_dict(),
                    "record": item.record.to_dict(),
                }
                for item in validated_reviews
            ],
        )

    for entry in in_scope:
        record = entry.source
        if record.processing_status not in ("completed", "parsed") and record.report_id is None:
            continue
        report_id = record.report_id
        if not report_id:
            continue
        evidence = read_report_evidence(evidence_dir(layout.run_dir, report_id))
        if evidence is None:
            continue
        families, raw_labels = _label_inputs(entry)
        decision = decide(
            evidence,
            registry=registry,
            review_bindings=_review_binding_for_source(validated_reviews, record.source_id),
            scopes=_review_scopes_for_source(validated_reviews, record.source_id),
            label_families=families,
            raw_labels=raw_labels,
            taxonomy=taxonomy,
            identity_status=record.sample_identity_status,
        )
        record.family_identity_status = decision.family_identity_status
        record.execution_status = decision.execution_status
        record.strict_attribution_status = decision.attribution.status
        record.delivery_flags = dict(decision.delivery.flags)
        record.machine_decision = decision.machine_decision
        record.machine_decision_reasons = list(decision.machine_reasons)
        reasons = list(record.candidate_reasons)
        for reason in decision.candidate_reasons:
            if reason not in reasons:
                reasons.append(reason)
        record.candidate_reasons = reasons
        record.is_candidate = bool(record.is_candidate or reasons)
        record.quality_flags = list(dict.fromkeys([*record.quality_flags, *decision.quality_flags]))
        record.effective_decision = _human_effective_decision(decision, record.human_disposition)
        record.processing_status = "completed"
        record.error_code = None
        record.error_message = None
        store.record_machine_decision(
            layout.run_id,
            record.source_id,
            decision.machine_decision,
            list(decision.machine_reasons),
            fingerprint,
        )
        store.upsert_source(layout.run_id, record)
        store.upsert_report(
            layout.run_id,
            report_id=report_id,
            source_id=record.source_id,
            content_sha256=evidence.report_content_sha256,
            size_bytes=evidence.size_bytes,
            adapter_version=CapeAdapter.version,
            analysis_fingerprint=fingerprint,
            facts_path=str(evidence_dir(layout.run_dir, report_id) / "facts.jsonl"),
            processes_path=str(evidence_dir(layout.run_dir, report_id) / "processes.jsonl"),
            strict_count=decision.bucket_counts.get("loader_strict", 0),
            bucket_counts=dict(decision.bucket_counts),
            status="ok",
        )
        store.set_job(layout.run_id, record.source_id, "completed", increment_attempts=True)
        decisions_by_report.setdefault(report_id, []).append((record, decision))

    store.commit()

    for report_id, decisions in decisions_by_report.items():
        evidence = read_report_evidence(evidence_dir(layout.run_dir, report_id))
        if evidence is None:
            continue
        meta = _merge_report_meta(report_id, evidence, decisions)
        meta["facts_path"] = str(evidence_dir(layout.run_dir, report_id) / "facts.jsonl")
        store.upsert_report_meta(layout.run_id, report_id, meta)
    store.commit()

    manifest_counts = write_manifests(layout.run_dir, store, layout.run_id)
    store.commit()

    qa_summary = run_checks(layout.run_dir, store, layout.run_id, config)
    write_json(layout.qa_dir / "summary.json", qa_summary)
    write_jsonl(layout.qa_dir / "checks.jsonl", qa_summary["checks"])

    comparison = comparison_report(layout.run_dir, store, layout.run_id)
    write_json(layout.qa_dir / "run_summary.json", comparison)

    log.write("info", "manifest", **manifest_counts)
    log.write("info", "qa", status=qa_summary["status"], counts=qa_summary["counts"])

    counters = _build_counters(config, layout, store, inventory, discovery, manifest_counts, comparison, failed, started)
    partial = counters["partial"]
    if qa_summary["status"] == "fail":
        status = "completed"
        exit_code = EXIT_INTEGRITY
    elif partial:
        status = "partial"
        exit_code = EXIT_PARTIAL
    else:
        status = "completed"
        exit_code = EXIT_OK
    store.update_run_status(layout.run_id, status, counters)
    store.commit()

    summary = {
        "run_id": layout.run_id,
        "status": status,
        "created_at": existing_run.created_at if existing_run else utc_now_iso(),
        "finished_at": utc_now_iso(),
        "software": {"name": SOFTWARE_NAME, "version": SOFTWARE_VERSION},
        "analysis_version": ANALYSIS_VERSION,
        "config_path": str(config.config_path) if config.config_path else None,
        "semantic_config_sha256": config.semantic_config_hash(),
        "analysis_fingerprint": fingerprint,
        "taxonomy": {"path": str(config.taxonomy), "content_sha256": taxonomy.content_sha256, "version": taxonomy.version},
        "inputs": [{"id": spec.id, "path": str(Path(spec.path).resolve())} for spec in config.inputs],
        "scope": config.analysis.scope,
        "evidence_scope": "not_applicable" if config.analysis.mode == "labels" else config.analysis.scope,
        "mode": config.analysis.mode,
        "policy": config.analysis.policy,
        "counters": counters,
        "qa": {"status": qa_summary["status"], "counts": qa_summary["counts"], "path": str(layout.qa_dir / "summary.json")},
        "exit_code": exit_code,
        "run_summary_path": str(layout.qa_dir / "run_summary.json"),
    }
    write_json(layout.run_json, summary)
    atomic_write_text(
        layout.run_dir / OUTPUT_MARKER,
        json.dumps({"run_id": layout.run_id, "software": SOFTWARE_NAME, "version": SOFTWARE_VERSION}) + "\n",
    )
    log.write("info", "run_finish", status=status, exit_code=exit_code)
    store.close()
    return RunOutcome(
        run_id=layout.run_id,
        run_dir=layout.run_dir,
        exit_code=exit_code,
        counters=counters,
        qa_status=qa_summary["status"],
        summary=summary,
    )


# ---------------------------------------------------------------------------------------
# persistence helpers
# ---------------------------------------------------------------------------------------
def _write_config_snapshot(
    layout: RunLayout,
    config: Config,
    taxonomy: Taxonomy,
    label_metrics: dict[str, Any],
    fingerprint: str,
    label_paths: list[Path],
    registry_sha256: str | None,
) -> None:
    document = config.to_dict()
    config_path = document.pop("config_path", None)
    value_sources = document.pop("value_sources", None)
    effective = {
        "software": {"name": SOFTWARE_NAME, "version": SOFTWARE_VERSION},
        "analysis_version": ANALYSIS_VERSION,
        "config": document,
        "config_path": config_path,
        "value_sources": value_sources,
        "semantic_settings": config.semantic_settings(),
        "semantic_config_sha256": config.semantic_config_hash(),
        "analysis_fingerprint": fingerprint,
        "label_metrics": label_metrics,
    }
    write_json(layout.config_dir / "effective.json", effective)
    write_json(layout.config_dir / "taxonomy.json", taxonomy.to_dict())
    write_json(
        layout.config_dir / "source_fingerprints.json",
        {
            "label_sources": _label_fingerprints(config),
            "taxonomy": {
                "path": str(taxonomy.path),
                "content_sha256": taxonomy.content_sha256,
            },
            "registry": {"configured": bool(config.analysis.trusted_rule_registry), "content_sha256": registry_sha256},
            "label_paths": [str(path) for path in label_paths],
        },
    )


def _write_label_errors(layout: RunLayout, label_store: LabelStore) -> None:
    rows = list(getattr(label_store, "quarantined_rows", []) or [])
    write_jsonl(layout.errors_dir / "label_rows.jsonl", rows)


def _evidence_is_complete(layout: RunLayout, store: StateStore, run_id: str, record: SourceRecord) -> bool:
    row = store.get_source(run_id, record.source_id) or {}
    if row.get("processing_status") != "completed" or not row.get("report_id"):
        return False
    source_path = Path(record.absolute_path)
    if not source_path.is_file():
        return False
    if sha256_file(source_path)[0] != row.get("report_content_sha256"):
        return False
    directory = evidence_dir(layout.run_dir, row["report_id"])
    evidence = read_report_evidence(directory)
    if evidence is None:
        return False
    for artifact in store.list_artifacts(run_id):
        if artifact["artifact_id"].endswith(f":{row['report_id']}") and artifact["sha256"]:
            art_path = Path(artifact["path"])
            if not art_path.is_file() or sha256_file(art_path)[0] != artifact["sha256"]:
                return False
    return True


def _load_cached_evidence(
    layout: RunLayout, store: StateStore, run_id: str, entries: list[InventoryEntry]
) -> dict[str, ReportEvidence]:
    result: dict[str, ReportEvidence] = {}
    for entry in entries:
        report_id = entry.source.report_id
        if not report_id or report_id in result:
            continue
        evidence = read_report_evidence(evidence_dir(layout.run_dir, report_id))
        if evidence is not None:
            result[report_id] = evidence
    return result


def _prepare_reviews(
    config: Config,
    options: RunOptions,
    layout: RunLayout,
    store: StateStore,
    fingerprint: str,
    entries: list[InventoryEntry],
) -> list[ValidatedReview]:
    records = []
    history = layout.reviews_dir / "history.jsonl"
    if history.is_file():
        import json as _json

        with history.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = _json.loads(line)
                record = payload.get("record")
                if record:
                    try:
                        records.append(parse_review(record, where="history"))
                    except ReviewError as exc:
                        raise IntegrityError(
                            f"invalid review record in history: {'; '.join(exc.problems)}"
                        ) from exc
    paths = list(options.review_files)
    if not paths:
        if not records:
            return []
    for path in paths:
        try:
            records.extend(load_review_file(path))
        except ReviewError as exc:
            raise ConfigError(f"invalid review file {path}: {'; '.join(exc.problems)}") from exc
    report_by_source: dict[str, str] = {}
    for entry in entries:
        if entry.source.report_id:
            report_by_source[entry.source.source_id] = entry.source.report_id
    evidence_ids_by_report: dict[str, set[str]] = {}
    process_indices_by_report: dict[str, set[int]] = {}
    for report_id in sorted(set(report_by_source.values())):
        evidence = read_report_evidence(evidence_dir(layout.run_dir, report_id))
        if evidence is None:
            continue
        evidence_ids_by_report[report_id] = {fact.evidence_id for fact in evidence.facts}
        process_indices_by_report[report_id] = {process.process_index for process in evidence.processes}
    return validate_reviews(
        records,
        analysis_fingerprint=fingerprint,
        report_by_source=report_by_source,
        evidence_ids_by_report=evidence_ids_by_report,
        process_indices_by_report=process_indices_by_report,
    )


def _build_counters(
    config: Config,
    layout: RunLayout,
    store: StateStore,
    inventory: Any,
    discovery: Any,
    manifest_counts: dict[str, int],
    comparison: dict[str, Any],
    failed: int,
    started: float,
) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    for row in store.list_sources(layout.run_id):
        status = row.get("processing_status") or "unknown"
        statuses[status] = statuses.get(status, 0) + 1
    reports = store.list_reports(layout.run_id)
    partial_states = {"error", "resource_limit", "unsupported"}
    partial = bool(discovery.coverage_limited) or any(status in partial_states for status in statuses)
    return {
        "source_files": inventory.counters.get("source_files", 0),
        "report_files": len(reports),
        "failed_reports": failed,
        "status_counts": dict(sorted(statuses.items())),
        "seed_candidate_count": manifest_counts.get("seed_candidates", 0),
        "candidate_count": manifest_counts.get("candidates", 0),
        "observed_count": manifest_counts.get("observed", 0),
        "payload_execution_count": manifest_counts.get("payload_execution", 0),
        "review_queue_count": manifest_counts.get("review_queue", 0),
        "unresolved_count": manifest_counts.get("unresolved", 0),
        "manifest_counts": manifest_counts,
        "delivery_flag_counts": comparison.get("delivery_flag_counts", {}),
        "inventory": inventory.counters,
        "discovery": discovery.stats,
        "coverage_limited": bool(discovery.coverage_limited),
        "evidence_scope": "not_applicable" if config.analysis.mode == "labels" else config.analysis.scope,
        "partial": partial,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "policy": config.analysis.policy,
    }
