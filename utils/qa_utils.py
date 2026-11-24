"""Quality assurance checks and run comparison.

Every check is independent: an exception inside a check is recorded as ``error`` instead of
aborting the run, so the user still gets a QA report describing a broken run.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from .configs import Config
from .state_utils import StateStore
from .io_utils import read_json_strict, read_jsonl, sha256_file, sha256_json

CSV_FILES = [
    "all_sources.csv",
    "seed_candidates.csv",
    "candidates.csv",
    "observed.csv",
    "payload_execution.csv",
    "review_queue.csv",
    "unresolved.csv",
]
JSONL_FILES = ["all_reports.jsonl"]

COMPARE_FIELDS = [
    "semantic_config_sha256",
    "source_count",
    "report_count",
    "status_counts",
    "seed_candidate_count",
    "candidate_count",
    "observed_count",
    "payload_execution_count",
    "review_queue_count",
    "unresolved_count",
    "delivery_flag_counts",
    "manifest_sha256",
]

_POINTER_KEY_RE = re.compile(r"^/(?:[^/~]|~[01])*(?:/(?:[^/~]|~[01])*)*$")


class CheckLog:
    def __init__(self) -> None:
        self.lines: list[dict[str, Any]] = []

    def add(
        self,
        check_id: str,
        area: str,
        status: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.lines.append(
            {
                "check_id": check_id,
                "area": area,
                "status": status,
                "severity": severity,
                "message": message,
                "details": details or {},
            }
        )

    def run(self, check_id: str, area: str, severity: str, function: Callable[[], tuple[str, str, dict[str, Any]]]) -> None:
        try:
            status, message, details = function()
        except Exception as exc:  # noqa: BLE001 - a broken check must not abort QA
            self.add(check_id, area, "error", severity, f"check raised {type(exc).__name__}: {exc}")
        else:
            self.add(check_id, area, status, severity, message, details)

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for line in self.lines:
            counts[line["status"]] = counts.get(line["status"], 0) + 1
        if counts.get("fail"):
            status = "fail"
        elif counts.get("warn") or counts.get("error"):
            status = "warn"
        else:
            status = "pass"
        return {
            "status": status,
            "counts": counts,
            "checks": [line["check_id"] for line in self.lines],
        }


def _read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    raw = path.read_bytes()
    if not raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("missing UTF-8 BOM")
    text = raw.decode("utf-8-sig")
    rows = list(csv.reader(text.splitlines()))
    if not rows:
        raise ValueError("empty CSV")
    header, body = rows[0], rows[1:]
    for index, row in enumerate(body, start=2):
        if len(row) != len(header):
            raise ValueError(f"line {index} has {len(row)} cells, expected {len(header)}")
    return header, body


def _manifest_sha(directory: Path) -> dict[str, str]:
    return {name: sha256_file(directory / name)[0] for name in CSV_FILES}


def _row_counts(directory: Path) -> dict[str, int]:
    counts = {}
    for name in CSV_FILES:
        header, body = _read_csv(directory / name)
        counts[name.removesuffix(".csv")] = len(body)
    for name in JSONL_FILES:
        counts[name.removesuffix(".jsonl")] = len(read_jsonl(directory / name))
    return counts


def run_checks(run_dir: Path, store: StateStore, run_id: str, config: Config) -> dict[str, Any]:
    log = CheckLog()
    manifest_dir = run_dir / "manifest"
    sources = store.list_sources(run_id)
    reports = store.list_reports(run_id)
    meta = store.list_report_meta(run_id)

    def config_hash() -> tuple[str, str, dict[str, Any]]:
        effective = read_json_strict(run_dir / "config" / "effective.json")
        settings = effective.get("semantic_settings")
        recorded = effective.get("semantic_config_sha256")
        recomputed = config.semantic_config_hash()
        if not isinstance(settings, dict) or not recorded:
            return "fail", "effective config does not embed semantic settings", {}
        if sha256_json(settings) != recorded:
            return "fail", "embedded semantic settings do not match their recorded hash", {"recorded": recorded}
        run = store.get_run(run_id)
        if run is None or run.semantic_config_hash != recorded:
            return "fail", "run record disagrees with the effective semantic hash", {"run": None if run is None else run.semantic_config_hash}
        if recomputed != recorded:
            return "fail", "current configuration differs from the recorded semantic settings", {"recorded": recorded, "recomputed": recomputed}
        return "pass", "semantic config hash matches", {"sha256": recomputed}

    def taxonomy_sha() -> tuple[str, str, dict[str, Any]]:
        snapshot = read_json_strict(run_dir / "config" / "taxonomy.json")
        recorded = snapshot.get("content_sha256")
        actual = sha256_file(Path(config.taxonomy))[0]
        if recorded != actual:
            return "fail", "taxonomy file changed after configuration", {"recorded": recorded, "actual": actual}
        return "pass", "taxonomy file unchanged", {"sha256": actual}

    def label_files() -> tuple[str, str, dict[str, Any]]:
        snapshot = read_json_strict(run_dir / "config" / "source_fingerprints.json")
        fingerprints = snapshot.get("label_sources") or {}
        changed = []
        for key, fingerprint in fingerprints.items():
            actual = sha256_file(Path(fingerprint["path"]))[0]
            if actual != fingerprint.get("content_sha256"):
                changed.append({"source": key, "path": fingerprint["path"], "recorded": fingerprint.get("content_sha256"), "actual": actual})
        if changed:
            return "fail", "label source files changed after configuration", {"changed": changed}
        return "pass", "label source files unchanged", {"count": len(fingerprints)}

    def unique_source_ids() -> tuple[str, str, dict[str, Any]]:
        ids = [source["source_id"] for source in sources]
        duplicates = sorted({value for value in ids if ids.count(value) > 1})
        if duplicates:
            return "fail", "duplicate source ids", {"source_ids": duplicates[:20]}
        return "pass", "source ids are unique", {"count": len(ids)}

    def source_id_derivation() -> tuple[str, str, dict[str, Any]]:
        mismatched = []
        for source in sources:
            expected = hashlib.sha256(f"{source['root_id']}\0{source['relative_path']}".encode("utf-8")).hexdigest()
            if expected != source["source_id"]:
                mismatched.append({"source_id": source["source_id"], "expected": expected})
        if mismatched:
            return "fail", "source ids do not match root_id+relative_path", {"examples": mismatched[:10]}
        return "pass", "source ids derive from root_id and relative path", {"count": len(sources)}

    def report_mapping() -> tuple[str, str, dict[str, Any]]:
        by_report: dict[str, set[str]] = {}
        for source in sources:
            if source.get("report_id"):
                by_report.setdefault(source["report_id"], set()).add(source["report_content_sha256"] or "")
        conflicts = {report_id: sorted(hashes) for report_id, hashes in by_report.items() if len(hashes) > 1}
        if conflicts:
            return "fail", "one report id maps to multiple content hashes", {"conflicts": list(conflicts)[:10]}
        return "pass", "report ids map to a single content hash", {"reports": len(by_report)}

    def evidence_artifacts() -> tuple[str, str, dict[str, Any]]:
        missing = []
        mismatched = []
        artifacts = store.list_artifacts(run_id)
        evidence_list = [
            a for a in artifacts
            if a["kind"] in ("evidence", "evidence_facts", "evidence_processes", "evidence_report")
        ]
        for artifact in evidence_list:
            path = Path(artifact["path"])
            if not path.is_file():
                missing.append(artifact["path"])
                continue
            if artifact["sha256"] and sha256_file(path)[0] != artifact["sha256"]:
                mismatched.append(artifact["path"])
        if missing or mismatched:
            return "fail", "evidence artifacts are missing or changed", {"missing": missing[:10], "mismatched": mismatched[:10]}
        return "pass", "evidence artifacts match recorded checksums", {"count": len(evidence_list)}

    def evidence_content() -> tuple[str, str, dict[str, Any]]:
        problems = []
        checked = 0
        for report in reports:
            if report["status"] not in ("ok", "partial"):
                continue
            facts_path = report.get("facts_path")
            if not facts_path:
                continue
            path = Path(facts_path)
            if not path.is_file():
                problems.append({"report_id": report["report_id"], "problem": "facts artifact missing"})
                continue
            facts = read_jsonl(path)
            checked += 1
            ids = [fact.get("evidence_id") for fact in facts]
            if len(ids) != len(set(ids)):
                problems.append({"report_id": report["report_id"], "problem": "duplicate evidence ids"})
            known = set(ids)
            for fact in facts:
                for supporting in fact.get("supporting_evidence_ids") or []:
                    if supporting not in known:
                        problems.append({"report_id": report["report_id"], "problem": f"unresolved supporting id {supporting}"})
                for pointer in fact.get("source_json_pointers") or []:
                    if not isinstance(pointer, str) or not _POINTER_KEY_RE.match(pointer):
                        problems.append({"report_id": report["report_id"], "problem": f"invalid pointer {pointer!r}"})
                        break
        if problems:
            return "fail", "evidence content failed integrity checks", {"problems": problems[:20], "count": len(problems)}
        return "pass", "evidence content is internally consistent", {"reports_checked": checked}

    def observed_requires_binding() -> tuple[str, str, dict[str, Any]]:
        bad = []
        for entry in meta:
            if entry.get("effective_decision") != "loader_run_observed":
                continue
            if entry.get("binding_support") not in ("trusted", "reviewed"):
                bad.append({"report_id": entry["report_id"], "binding_support": entry.get("binding_support")})
            if not entry.get("execution_evidence_ids"):
                bad.append({"report_id": entry["report_id"], "problem": "missing execution evidence ids"})
        if bad:
            return "fail", "observed rows lack trustworthy bindings or evidence", {"rows": bad[:10]}
        return "pass", "every observed row has a trustworthy binding and evidence", {}

    def strict_requires_observed() -> tuple[str, str, dict[str, Any]]:
        bad = [
            source["source_id"]
            for source in sources
            if source.get("strict_attribution_status") == "supported_for_some_events"
            and source.get("effective_decision") != "loader_run_observed"
        ]
        if bad:
            return "fail", "strict attribution implies observed execution", {"source_ids": bad[:10]}
        return "pass", "strict attribution never appears without observed execution", {}

    def manifest_counts() -> tuple[str, str, dict[str, Any]]:
        counts = _row_counts(manifest_dir)
        seed = sum(1 for source in sources if source["is_seed_candidate"])
        candidate = sum(1 for source in sources if source["is_candidate"])
        review = sum(
            1
            for source in sources
            if source.get("machine_decision") == "needs_review"
            and source.get("human_disposition") not in ("accepted_loader", "rejected_loader")
        )
        expected = {"seed_candidates": seed, "candidates": candidate, "review_queue": review}
        mismatch = {name: {"manifest": counts[name], "database": value} for name, value in expected.items() if counts[name] != value}
        if mismatch:
            return "fail", "manifest row counts disagree with the database", {"mismatch": mismatch}
        if counts["all_reports"] != len(meta):
            return "fail", "report manifest count disagrees with the database", {"manifest": counts["all_reports"], "database": len(meta)}
        return "pass", "manifest row counts match the database", {"counts": counts}

    def csv_layout() -> tuple[str, str, dict[str, Any]]:
        problems = []
        for name in CSV_FILES:
            try:
                _read_csv(manifest_dir / name)
            except Exception as exc:  # noqa: BLE001
                problems.append({"file": name, "problem": str(exc)})
        for name in CSV_FILES:
            raw = (manifest_dir / name).read_bytes()
            if b"\r\n" not in raw:
                problems.append({"file": name, "problem": "expected CRLF line endings"})
        if problems:
            return "fail", "CSV manifests are malformed", {"problems": problems}
        return "pass", "CSV manifests are well formed", {"files": len(CSV_FILES)}

    def jsonl_layout() -> tuple[str, str, dict[str, Any]]:
        problems = []
        for name in JSONL_FILES:
            try:
                for index, line in enumerate((manifest_dir / name).read_text(encoding="utf-8").splitlines(), start=1):
                    if not line.strip():
                        continue
                    json.loads(line)
            except Exception as exc:  # noqa: BLE001
                problems.append({"file": name, "problem": str(exc), "line": index})
        if problems:
            return "fail", "JSONL manifests are malformed", {"problems": problems}
        return "pass", "JSONL manifests are well formed", {}

    def error_partition() -> tuple[str, str, dict[str, Any]]:
        failed = {source["source_id"] for source in sources if source.get("processing_status") in ("error", "resource_limit", "unsupported")}
        error_path = run_dir / "errors" / "reports.jsonl"
        rows = read_jsonl(error_path) if error_path.is_file() else []
        logged = {row.get("source_id") for row in rows}
        missing = sorted(failed - logged)
        if missing:
            return "warn", "some failed sources have no error record", {"source_ids": missing[:10]}
        return "pass", "failed sources have error records", {"errors": len(rows)}

    def source_status_values() -> tuple[str, str, dict[str, Any]]:
        from .models import PROCESSING_STATUSES

        invalid = sorted({source["processing_status"] for source in sources if source["processing_status"] not in PROCESSING_STATUSES})
        if invalid:
            return "fail", "unknown processing status values", {"values": invalid}
        return "pass", "processing status values are valid", {}

    log.run("QC-01", "config", "fatal", config_hash)
    log.run("QC-02", "taxonomy", "fatal", taxonomy_sha)
    log.run("QC-03", "labels", "fatal", label_files)
    log.run("QC-04", "inventory", "fatal", unique_source_ids)
    log.run("QC-05", "inventory", "fatal", source_id_derivation)
    log.run("QC-06", "reports", "fatal", report_mapping)
    log.run("QC-07", "evidence", "fatal", evidence_artifacts)
    log.run("QC-08", "evidence", "fatal", evidence_content)
    log.run("QC-09", "evidence", "fatal", observed_requires_binding)
    log.run("QC-10", "evidence", "fatal", strict_requires_observed)
    log.run("QC-11", "manifest", "fatal", manifest_counts)
    log.run("QC-12", "manifest", "fatal", csv_layout)
    log.run("QC-13", "manifest", "fatal", jsonl_layout)
    log.run("QC-14", "errors", "warning", error_partition)
    log.run("QC-15", "inventory", "fatal", source_status_values)

    summary = log.summary()
    summary["checks"] = log.lines
    summary["run_id"] = run_id
    return summary


def comparison_report(run_dir: Path, store: StateStore, run_id: str) -> dict[str, Any]:
    run = store.get_run(run_id)
    sources = store.list_sources(run_id)
    reports = store.list_reports(run_id)
    status_counts: dict[str, int] = {}
    delivery_counts: dict[str, int] = {}
    for source in sources:
        status = source.get("processing_status") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1
        for flag, value in (source.get("delivery_flags") or {}).items():
            if value:
                delivery_counts[flag] = delivery_counts.get(flag, 0) + 1
    counts = _row_counts(run_dir / "manifest")
    return {
        "run_id": run_id,
        "semantic_config_sha256": None if run is None else run.semantic_config_hash,
        "source_count": len(sources),
        "report_count": len(reports),
        "status_counts": dict(sorted(status_counts.items())),
        "seed_candidate_count": counts["seed_candidates"],
        "candidate_count": counts["candidates"],
        "observed_count": counts["observed"],
        "payload_execution_count": counts["payload_execution"],
        "review_queue_count": counts["review_queue"],
        "unresolved_count": counts["unresolved"],
        "delivery_flag_counts": dict(sorted(delivery_counts.items())),
        "manifest_sha256": _manifest_sha(run_dir / "manifest"),
    }


def compare_reports(baseline: dict[str, Any], current: dict[str, Any], *, allow_host_rebuild: bool) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for field in COMPARE_FIELDS:
        old = baseline.get(field)
        new = current.get(field)
        if old == new:
            continue
        if field == "semantic_config_sha256" and allow_host_rebuild:
            continue
        differences.append({"field": field, "baseline": old, "current": new})
    return differences
