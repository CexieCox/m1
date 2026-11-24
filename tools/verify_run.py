"""Independent verification of a run directory and its published exports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from utils.configs import build_config
from utils.errors import ConfigError
from utils.evidence_utils import read_report_evidence
from utils.qa_utils import run_checks
from utils.state_utils import StateStore
from utils.io_utils import read_json_strict, read_jsonl, sha256_file, to_safe_path


def _check(checks: list[dict[str, Any]], check_id: str, ok: bool, message: str, **details: Any) -> bool:
    checks.append({"check_id": check_id, "status": "pass" if ok else "fail", "message": message, **details})
    return ok


def verify_run(run_dir: Path, exports: Path | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir).resolve()
    checks: list[dict[str, Any]] = []
    problems: list[str] = []

    run_json_path = run_dir / "run.json"
    state_path = run_dir / "state.sqlite"
    _check(checks, "V-01", run_json_path.is_file(), "run.json exists")
    _check(checks, "V-02", state_path.is_file(), "state.sqlite exists")
    if not run_json_path.is_file() or not state_path.is_file():
        return {"status": "fail", "checks": checks, "problems": ["run is incomplete: missing run.json or state.sqlite"]}
    try:
        summary = read_json_strict(run_json_path)
    except Exception as exc:  # noqa: BLE001
        summary = {}
        problems.append(f"run.json is not valid JSON: {exc}")

    run_id = summary.get("run_id")
    store = StateStore(state_path)
    try:
        run_row = store.get_run(run_id) if run_id else None
        _check(checks, "V-03", run_row is not None, "run record exists in the database", run_id=run_id)
        if run_row is None:
            return {"status": "fail", "checks": checks, "problems": problems + ["run record missing"]}

        if not _check(
            checks,
            "V-04",
            run_row.semantic_config_hash == summary.get("semantic_config_sha256"),
            "run.json and database agree on the semantic config hash",
        ):
            problems.append("run.json and database disagree on the semantic config hash")
        if not _check(
            checks,
            "V-05",
            run_row.analysis_fingerprint == summary.get("analysis_fingerprint"),
            "run.json and database agree on the analysis fingerprint",
        ):
            problems.append("run.json and database disagree on the analysis fingerprint")

        # QA needs the recorded configuration; rebuild it from the effective snapshot.
        config = None
        try:
            effective = read_json_strict(run_dir / "config" / "effective.json")
            document = dict(effective["config"])
            document.pop("config_path", None)
            document.pop("value_sources", None)
            config = build_config(document, base=run_dir, config_path=None)
        except (OSError, KeyError, ConfigError) as exc:
            problems.append(f"cannot rebuild configuration for QA: {exc}")

        if config is not None:
            qa = run_checks(run_dir, store, run_id, config)
            _check(checks, "V-06", qa["status"] != "fail", "QA checks pass", qa_status=qa["status"], counts=qa["counts"])
            for line in qa["checks"]:
                if line["status"] in ("fail", "error"):
                    problems.append(f"{line['check_id']}: {line['message']}")
        else:
            _check(checks, "V-06", False, "QA checks could not be recomputed")

        sources = store.list_sources(run_id)
        reports = store.list_reports(run_id)
        observed = [row for row in sources if row.get("effective_decision") == "loader_run_observed"]
        for row in sources:
            if row.get("processing_status") == "completed" and not row.get("report_id"):
                problems.append(f"completed source without a report id: {row['source_id']}")

        accounting_ok = True
        for report in reports:
            if report["status"] == "ok":
                if report["strict_count"] > 0:
                    matching = [row for row in sources if row["source_id"] == report["source_id"]]
                    if not matching or matching[0].get("effective_decision") != "loader_run_observed":
                        accounting_ok = False
                        problems.append(f"strict events without effective observed: {report['report_id']}")
                evidence_dir = run_dir / "evidence" / "by_report" / report["report_id"]
                if read_report_evidence(evidence_dir) is None:
                    accounting_ok = False
                    problems.append(f"evidence missing for report {report['report_id']}")
        _check(checks, "V-07", accounting_ok, "strict events imply effective observed and evidence exists")

        missing_sources = []
        for row in sources:
            if row.get("processing_status") not in ("completed",):
                continue
            path = Path(row["absolute_path"])
            if not path.is_file():
                missing_sources.append(str(path))
                continue
            if row.get("report_id") and sha256_file(path)[0] != row["report_id"]:
                missing_sources.append(str(path))
        _check(
            checks,
            "V-08",
            not missing_sources,
            "source reports are present and unchanged",
            missing=missing_sources[:10],
        )
        if missing_sources:
            problems.extend(f"source changed or missing: {path}" for path in missing_sources[:10])

        if not _check(checks, "V-09", (run_dir / "manifest" / "observed.csv").is_file(), "observed manifest exists"):
            problems.append("observed manifest is missing")
        if not _check(checks, "V-10", (run_dir / "qa" / "summary.json").is_file(), "QA summary exists"):
            problems.append("QA summary is missing")

        export_status = None
        if exports is not None:
            export_status, export_problems = _verify_export(Path(exports), summary, checks)
            problems.extend(export_problems)
    finally:
        store.close()
    status = "pass" if not problems else "fail"
    return {
        "status": status,
        "checks": checks,
        "problems": problems,
        "counters": {
            "sources": len(sources),
            "reports": len(reports),
            "observed": len(observed),
        },
        "exports": export_status,
    }


def _verify_export(exports: Path, summary: dict[str, Any], checks: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[str]]:
    problems: list[str] = []
    export_json = exports / "export.json"
    checksums_path = exports / "checksums.json"
    manifest_path = exports / "manifest.jsonl"
    _check(checks, "V-11", export_json.is_file(), "export.json exists")
    _check(checks, "V-12", checksums_path.is_file(), "checksums.json exists")
    if not export_json.is_file() or not checksums_path.is_file():
        return None, ["export directory is missing export.json or checksums.json"]
    try:
        metadata = read_json_strict(export_json)
        checksums = read_json_strict(checksums_path)
    except Exception as exc:  # noqa: BLE001
        return None, [f"export metadata is not valid JSON: {exc}"]

    if metadata.get("run_id") != summary.get("run_id"):
        problems.append("export belongs to a different run")

    counts = metadata.get("counts") or {}
    files = checksums.get("files") or {}
    has_content = (
        counts.get("events_exported", 0) > 0
        or counts.get("reports_copied", 0) > 0
        or metadata.get("format") == "manifest"
    )
    if has_content and not files:
        problems.append("checksums.json has no file entries for non-empty export")

    mismatched = []
    for relative, expected in files.items():
        path = to_safe_path(exports / relative)
        if not path.is_file():
            mismatched.append(relative)
            continue
        if sha256_file(path)[0] != expected:
            mismatched.append(relative)
    _check(checks, "V-13", not mismatched and not (has_content and not files), "export files match checksums.json", mismatched=mismatched[:10])
    if mismatched:
        problems.extend(f"export file changed or missing: {name}" for name in mismatched[:10])

    if metadata.get("format") == "events":
        scanned = counts.get("scanned_calls", 0)
        exported = counts.get("events_exported", 0)
        omitted = counts.get("events_omitted", 0)
        bucket_counts = counts.get("bucket_counts") or {}
        accounting = (scanned == exported + omitted) and (scanned == sum(bucket_counts.values()))
        _check(checks, "V-14", accounting, "event accounting balances", scanned=scanned, exported=exported, omitted=omitted)
        if not accounting:
            problems.append("event export accounting does not balance")

        # Check actual event files and actual rows on disk
        event_files_on_disk = list((exports / "events").rglob("*.jsonl")) if (exports / "events").is_dir() else []
        actual_rows = 0
        for p in event_files_on_disk:
            rel = str(p.relative_to(exports)).replace(os.sep, "/")
            if rel not in files:
                problems.append(f"unrecorded export file on disk: {rel}")
            actual_rows += len(read_jsonl(p))
        if exported > 0 and not event_files_on_disk:
            problems.append("expected exported event files on disk but found none")
        if actual_rows != exported:
            problems.append(f"actual event rows on disk ({actual_rows}) does not match metadata ({exported})")

    manifest = read_jsonl(manifest_path) if manifest_path.is_file() else []
    expected_rows = (
        counts.get("reports_copied", 0)
        if metadata.get("format") == "reports"
        else counts.get("reports_selected", counts.get("locators_selected", 0))
    )
    covered = len(manifest) >= expected_rows
    _check(checks, "V-15", covered and manifest_path.is_file(), "manifest covers the exported selection", rows=len(manifest))
    if not covered or not manifest_path.is_file():
        problems.append("manifest does not cover the exported selection")

    return metadata, problems
