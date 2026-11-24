"""Export a selection from a completed run.

Exports always write a fresh ``EXPORT_DEST`` layout (export.json, manifest.jsonl,
checksums.json) and never modify the run directory. Raw reports are copied byte-for-byte
through a temporary file, hashed and atomically renamed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from utils.errors import ConfigError, IntegrityError, UsageError
from utils.attribution_utils import EventScope, attribute_events
from utils.binding_utils import Binding
from utils.evidence_utils import read_report_evidence
from utils.review_utils import load_review_file
from utils.state_utils import StateStore
from utils.io_utils import atomic_write_text, read_json_strict, read_jsonl, sha256_file, utc_now_iso, write_json, write_jsonl

EXPORT_SCHEMA_VERSION = 1
SELECTIONS = ("seed-candidates", "candidates", "observed", "payload-execution")
FORMATS = ("manifest", "reports", "events")
BUCKETS = ("loader_strict", "payload", "system_context", "mixed_or_unresolved")

_CSV_BY_SELECTION = {
    "seed-candidates": "seed_candidates.csv",
    "candidates": "candidates.csv",
    "observed": "observed.csv",
    "payload-execution": "payload_execution.csv",
}


@dataclass
class ExportOptions:
    run_dir: Path
    dest: Path
    selection: str = "candidates"
    format: str = "manifest"
    buckets: list[str] = field(default_factory=list)
    group_by_year: bool = False


@dataclass
class ExportResult:
    dest: Path
    counts: dict[str, Any]
    metadata: dict[str, Any]


def _select_sources(store: StateStore, run_id: str, selection: str) -> list[dict[str, Any]]:
    sources = store.list_sources(run_id)
    if selection == "seed-candidates":
        return [row for row in sources if row["is_seed_candidate"]]
    if selection == "candidates":
        return [row for row in sources if row["is_candidate"]]
    if selection == "observed":
        return [row for row in sources if row.get("effective_decision") == "loader_run_observed"]
    payload_sources: set[str] = set()
    for meta in store.list_report_meta(run_id):
        if meta.get("effective_decision") == "loader_run_observed" and meta.get("payload_execution"):
            payload_sources.update(meta.get("source_ids") or [])
    return [row for row in sources if row["source_id"] in payload_sources]


def _require_sha(path: Path, expected: str) -> None:
    actual, _size = sha256_file(path)
    if actual != expected:
        raise IntegrityError(
            f"source bytes changed since the run was created: {path}",
            details={"expected": expected, "actual": actual},
        )


_EXEC_TS_RE = re.compile(rb'"(?:first_seen|timestamp)":\s*"(20\d\d|19\d\d)-\d\d-\d\d \d\d:\d\d:\d\d[,\.]\d+"')
_INFO_TS_RE = re.compile(rb'"(?:started|ended)":\s*"(20\d\d|19\d\d)')


def _extract_report_year(run_dir: Path | None, report_id: str | None, source_path: Path) -> str | None:
    # 1. Try reading from evidence facts if available
    if run_dir and report_id:
        facts_path = run_dir / "evidence" / "by_report" / report_id / "facts.jsonl"
        if facts_path.is_file():
            try:
                with facts_path.open("r", encoding="utf-8-sig") as stream:
                    for line in stream:
                        item = json.loads(line)
                        ts = item.get("attributes", {}).get("timestamp")
                        if ts:
                            m = re.search(r"(20\d\d|19\d\d)", str(ts))
                            if m:
                                y = int(m.group(1))
                                if 1995 <= y <= 2035:
                                    return str(y)
            except Exception:
                pass

    # 2. Try fast stream scan on source_path specifically for dynamic execution timestamps:
    # - info.started / info.ended (CAPE task execution time)
    # - behavior.processes[].calls[].timestamp or first_seen (dynamic API trace timestamps, containing milliseconds)
    # This prevents PE header compile timestamps (e.g. pe.timestamp: 2004-10-13 05:27:30) from overriding
    # the true sandbox execution time (2024-08-02 10:29:31,999).
    try:
        with source_path.open("rb") as stream:
            chunk = stream.read(8 * 1024 * 1024)
            m = _INFO_TS_RE.search(chunk)
            if m:
                y = int(m.group(1).decode("ascii"))
                if 1995 <= y <= 2035:
                    return str(y)
            m = _EXEC_TS_RE.search(chunk)
            if m:
                y = int(m.group(1).decode("ascii"))
                if 1995 <= y <= 2035:
                    return str(y)

            # If not in the first 8MB (e.g. large static procdump before behavior), read subsequent chunks
            while True:
                chunk = stream.read(8 * 1024 * 1024)
                if not chunk:
                    break
                m = _INFO_TS_RE.search(chunk) or _EXEC_TS_RE.search(chunk)
                if m:
                    y = int(m.group(1).decode("ascii"))
                    if 1995 <= y <= 2035:
                        return str(y)
    except Exception:
        pass

    # 3. Fallback to parsing json if small enough
    try:
        if source_path.stat().st_size <= 25 * 1024 * 1024:
            with source_path.open("r", encoding="utf-8-sig") as stream:
                doc = json.load(stream)
            info = doc.get("info")
            if isinstance(info, dict):
                for k in ("started", "ended", "timestamp"):
                    if info.get(k):
                        m = re.search(r"(20\d\d|19\d\d)", str(info[k]))
                        if m:
                            y = int(m.group(1))
                            if 1995 <= y <= 2035:
                                return str(y)
            behavior = doc.get("behavior")
            if isinstance(behavior, dict):
                for proc in behavior.get("processes", []):
                    if isinstance(proc, dict):
                        for call in proc.get("calls", []):
                            if isinstance(call, dict) and call.get("timestamp"):
                                m = re.search(r"(20\d\d|19\d\d)", str(call["timestamp"]))
                                if m:
                                    y = int(m.group(1))
                                    if 1995 <= y <= 2035:
                                        return str(y)
    except Exception:
        pass

    return None


def _copy_report(path: Path, destination: Path, expected_sha: str) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".tmp")
    with path.open("rb") as reader, temp.open("wb") as writer:
        digest = hashlib.sha256()
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(chunk)
            writer.write(chunk)
    if digest.hexdigest() != expected_sha:
        temp.unlink(missing_ok=True)
        raise IntegrityError(
            f"copied report hash does not match the run record: {path}",
            details={"expected": expected_sha, "actual": digest.hexdigest()},
        )
    os.replace(temp, destination)
    return digest.hexdigest()


def _scopes_from_history(run_dir: Path) -> tuple[dict[str, list[Any]], dict[str, list[Binding]]]:
    history = run_dir / "reviews" / "history.jsonl"
    scopes: dict[str, list[Any]] = {}
    bindings: dict[str, list[Binding]] = {}
    if not history.is_file():
        return scopes, bindings
    for row in read_jsonl(history):
        if row.get("status") != "applied":
            continue
        record = row.get("record") or {}
        report_id = record.get("report_id")
        if not report_id:
            continue
        for raw_scope in record.get("event_scopes") or []:
            scopes.setdefault(report_id, []).append(
                EventScope(
                    role=raw_scope["role"],
                    process_index=raw_scope["process_index"],
                    call_index_start=raw_scope["call_index_start"],
                    call_index_end=raw_scope["call_index_end"],
                    exclusivity_reason=raw_scope["exclusivity_reason"],
                    evidence_ids=list(raw_scope.get("evidence_ids") or []),
                    review_id=row.get("review_id"),
                    object_sha256=raw_scope.get("object_sha256"),
                )
            )
        for raw_binding in record.get("bindings") or []:
            bindings.setdefault(report_id, []).append(
                Binding(
                    object_sha256=raw_binding["object_sha256"],
                    object_kind=raw_binding["object_kind"],
                    process_index=raw_binding["process_index"],
                    relation=raw_binding["relation"],
                    support="reviewed",
                    reason=raw_binding["reason"],
                    evidence_ids=list(raw_binding.get("evidence_ids") or []),
                    review_id=row.get("review_id"),
                )
            )
    return scopes, bindings


def _iter_raw_calls(path: Path) -> Iterable[tuple[int, int, dict[str, Any]]]:
    import ijson

    with path.open("rb") as stream:
        builder = None
        proc_idx = -1
        call_idx = -1
        for prefix, event, value in ijson.parse(stream):
            if prefix == "behavior.processes.item" and event == "start_map":
                proc_idx += 1
                call_idx = -1
            elif prefix == "behavior.processes.item.calls.item":
                if event == "start_map":
                    call_idx += 1
                    builder = ijson.common.ObjectBuilder()
                if builder is not None:
                    builder.event(event, value)
                if event == "end_map" and builder is not None:
                    yield proc_idx, call_idx, builder.value
                    builder = None
            elif builder is not None:
                builder.event(event, value)


def export_run(options: ExportOptions) -> ExportResult:
    if options.selection not in SELECTIONS:
        raise UsageError(f"unknown selection {options.selection!r}; choose from {list(SELECTIONS)}")
    if options.format not in FORMATS:
        raise UsageError(f"unknown format {options.format!r}; choose from {list(FORMATS)}")
    if options.format == "events":
        if not options.buckets:
            raise UsageError("--bucket is required when --format events")
        unknown = [bucket for bucket in options.buckets if bucket not in BUCKETS and bucket != "all"]
        if unknown:
            raise UsageError(f"unknown bucket {unknown[0]!r}; choose from {list(BUCKETS)} or all")
    elif options.buckets:
        raise UsageError("--bucket is only valid with --format events")

    run_dir = options.run_dir.resolve()
    state_path = run_dir / "state.sqlite"
    if not state_path.is_file():
        raise ConfigError(f"not a run directory (state.sqlite missing): {run_dir}")
    summary = read_json_strict(run_dir / "run.json") if (run_dir / "run.json").is_file() else {}

    dest = options.dest.resolve()

    def _is_relative_to_or_equal(p1: Path, p2: Path) -> bool:
        try:
            p1.relative_to(p2)
            return True
        except ValueError:
            return False

    if _is_relative_to_or_equal(dest, run_dir) or _is_relative_to_or_equal(run_dir, dest):
        raise UsageError(
            f"export destination cannot be the run directory, inside the run directory, or an ancestor of the run directory: {dest}"
        )

    effective_path = run_dir / "config" / "effective.json"
    if effective_path.is_file():
        try:
            eff_cfg = read_json_strict(effective_path)
            for inp in eff_cfg.get("inputs", []):
                inp_path = Path(inp["path"]).resolve()
                if _is_relative_to_or_equal(dest, inp_path) or _is_relative_to_or_equal(inp_path, dest):
                    raise UsageError(f"export destination cannot overlap input root: {inp_path}")
            out_root = Path(eff_cfg.get("output", {}).get("root", "")).resolve()
            if dest == out_root:
                raise UsageError(f"export destination cannot be the output root: {out_root}")
        except UsageError:
            raise
        except Exception:
            pass

    if dest.exists() and any(dest.iterdir()):
        marker = dest / "export.json"
        if not marker.is_file():
            raise UsageError(f"destination is not empty and is not an export directory: {dest}")
        previous = read_json_strict(marker)
        if previous.get("run_id") != summary.get("run_id"):
            raise UsageError("destination already contains an export from a different run")

    import secrets
    staging_dir = dest.parent / f".staging-{dest.name}-{secrets.token_hex(4)}"
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        store = StateStore(state_path)
        run_id = summary.get("run_id")
        if not run_id:
            raise ConfigError("run.json is missing or incomplete; cannot determine the run id")
        sources = _select_sources(store, run_id, options.selection)
        by_report: dict[str, dict[str, Any]] = {}
        for row in sources:
            report_id = row.get("report_id")
            if not report_id:
                continue
            by_report.setdefault(report_id, row)

        manifest_rows: list[dict[str, Any]] = []
        checksums: dict[str, str] = {}
        counts: dict[str, Any] = {
            "locators_selected": len(sources),
            "reports_selected": len(by_report),
            "reports_copied": 0,
            "events_exported": 0,
            "events_omitted": 0,
            "scanned_calls": 0,
            "enhanced_context_records": 0,
        }
        notes: list[str] = []

        if options.format == "manifest":
            source_name = _CSV_BY_SELECTION[options.selection]
            source_csv = run_dir / "manifest" / source_name
            if not source_csv.is_file():
                raise ConfigError(f"run has no {source_name}; rebuild manifests first")
            import csv as _csv
            import io as _io

            selected_ids = {row["source_id"] for row in sources}
            text = source_csv.read_text(encoding="utf-8-sig")
            rows = list(_csv.reader(_io.StringIO(text)))
            header = rows[0]
            body = [row for row in rows[1:] if row and row[0] in selected_ids]
            buffer = _io.StringIO()
            writer = _csv.writer(buffer, lineterminator="\r\n")
            writer.writerow(header)
            writer.writerows(body)
            target = staging_dir / "manifest.csv"
            atomic_write_text(target, "\ufeff" + buffer.getvalue())
            checksums["manifest.csv"] = sha256_file(target)[0]
            manifest_rows = [{"source_id": row["source_id"], "report_id": row.get("report_id")} for row in sources]

        elif options.format == "reports":
            for report_id, row in sorted(by_report.items()):
                source_path = Path(row["absolute_path"])
                if not source_path.is_file():
                    raise IntegrityError(f"source report is missing: {source_path}")
                _require_sha(source_path, report_id)
                year = None
                if options.group_by_year:
                    year = _extract_report_year(run_dir, report_id, source_path) or "unknown"
                    rel_target = f"raw_reports/{year}/{report_id}.json"
                else:
                    rel_target = f"raw_reports/{report_id}.json"
                target = staging_dir / rel_target
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = _copy_report(source_path, target, report_id)
                checksums[rel_target] = digest
                counts["reports_copied"] += 1
                manifest_row = {
                    "source_id": row["source_id"],
                    "report_id": report_id,
                    "report_content_sha256": digest,
                    "relative_path": row["relative_path"],
                    "sample_sha256": row.get("sample_sha256"),
                    "effective_decision": row.get("effective_decision"),
                }
                if options.group_by_year:
                    manifest_row["year"] = year
                manifest_rows.append(manifest_row)

        else:  # events
            wanted_buckets = set(BUCKETS) if "all" in options.buckets else set(options.buckets)
            scopes_by_report, bindings_by_report = _scopes_from_history(run_dir)
            selected_buckets: dict[str, int] = {bucket: 0 for bucket in BUCKETS}
            from utils.attribution_utils import validate_scope

            for report_id, row in sorted(by_report.items()):
                evidence = read_report_evidence(run_dir / "evidence" / "by_report" / report_id)
                if evidence is None:
                    raise IntegrityError(f"run has no complete evidence for report {report_id}")
                scopes = scopes_by_report.get(report_id, [])
                bindings = bindings_by_report.get(report_id, [])
                usable_scopes = [s for s in scopes if not validate_scope(s, facts=evidence.facts, bindings=bindings)]

                source_path = Path(row["absolute_path"])
                if not source_path.is_file():
                    raise IntegrityError(f"source report is missing: {source_path}")
                _require_sha(source_path, report_id)

                facts_by_call: dict[tuple[int, int], list[Any]] = {}
                for fact in evidence.facts:
                    for pointer in fact.source_json_pointers:
                        parts = pointer.strip("/").split("/")
                        if len(parts) == 5 and parts[0] == "behavior" and parts[1] == "processes" and parts[3] == "calls":
                            try:
                                proc_idx = int(parts[2])
                                call_idx = int(parts[4])
                                facts_by_call.setdefault((proc_idx, call_idx), []).append(fact)
                            except ValueError:
                                continue

                proc_by_index = {p.process_index: p for p in evidence.processes}
                rows_by_bucket: dict[str, list[dict[str, Any]]] = {}

                for process_index, call_index, call_data in _iter_raw_calls(source_path):
                    matches = [s for s in usable_scopes if s.covers(process_index, call_index)]
                    roles = sorted({s.role for s in matches})
                    if not matches:
                        bucket = "mixed_or_unresolved"
                        method = "no_attribution"
                        rev_id = None
                    elif len(roles) > 1:
                        bucket = "mixed_or_unresolved"
                        method = "conflicting_reviewed_scope"
                        rev_id = None
                    else:
                        bucket = "loader_strict" if roles[0] == "loader" else "payload"
                        method = "reviewed_interval"
                        rev_id = (
                            sorted({s.review_id for s in matches if s.review_id})[-1]
                            if any(s.review_id for s in matches)
                            else None
                        )

                    selected_buckets[bucket] = selected_buckets.get(bucket, 0) + 1
                    counts["scanned_calls"] += 1

                    if bucket not in wanted_buckets:
                        counts["events_omitted"] += 1
                        continue

                    call_facts = facts_by_call.get((process_index, call_index), [])
                    evidence_ids = [f.evidence_id for f in call_facts]
                    proc = proc_by_index.get(process_index)
                    rule_ids = list(dict.fromkeys(r for f in call_facts for r in f.attributes.get("rule_ids", [])))
                    limitations = list(dict.fromkeys(l for f in call_facts for l in f.limitations))
                    pointer = f"/behavior/processes/{process_index}/calls/{call_index}"
                    event_key = f"{report_id}:{process_index}:{call_index}"
                    killchain = call_facts[0].attributes.get("category") if call_facts else None

                    rows_by_bucket.setdefault(bucket, []).append(
                        {
                            "event_key": event_key,
                            "evidence_id": evidence_ids[0] if evidence_ids else None,
                            "evidence_ids": evidence_ids,
                            "report_id": report_id,
                            "sample_sha256": evidence.target_sha256,
                            "source_id": row["source_id"],
                            "process_index": process_index,
                            "process_id": proc.process_id if proc else None,
                            "parent_id": proc.parent_id if proc else None,
                            "killchain": killchain,
                            "call_index": call_index,
                            "call": call_data,
                            "source_json_pointer": pointer,
                            "bucket": bucket,
                            "attribution_method": method,
                            "review_id": rev_id,
                            "rule_ids": rule_ids,
                            "fact_kind": call_facts[0].kind if call_facts else None,
                            "attributes": call_facts[0].attributes if call_facts else {},
                            "limitations": limitations,
                        }
                    )

                for bucket, rows in rows_by_bucket.items():
                    target = staging_dir / "events" / bucket / row["source_id"] / f"{report_id}.jsonl"
                    write_jsonl(target, rows)
                    checksums[str(target.relative_to(staging_dir)).replace(os.sep, "/")] = sha256_file(target)[0]
                    counts["events_exported"] += len(rows)
                counts["enhanced_context_records"] += evidence.enhanced_count
                manifest_rows.append(
                    {
                        "source_id": row["source_id"],
                        "report_id": report_id,
                        "sample_sha256": evidence.target_sha256,
                        "effective_decision": row.get("effective_decision"),
                    }
                )
            counts["bucket_counts"] = selected_buckets
            if not counts["events_exported"]:
                notes.append("no_strict_attribution" if "loader_strict" in wanted_buckets else "no_matching_events")

        manifest_path = staging_dir / "manifest.jsonl"
        write_jsonl(manifest_path, manifest_rows)
        checksums["manifest.jsonl"] = sha256_file(manifest_path)[0]

        metadata = {
            "export_schema_version": EXPORT_SCHEMA_VERSION,
            "export_id": f"{summary.get('run_id')}-{options.selection}-{options.format}-{utc_now_iso().replace(':', '')}",
            "created_at": utc_now_iso(),
            "run_id": summary.get("run_id"),
            "run_dir": str(run_dir),
            "selection": options.selection,
            "format": options.format,
            "buckets": options.buckets or None,
            "group_by_year": options.group_by_year,
            "semantic_config_sha256": summary.get("semantic_config_sha256"),
            "analysis_fingerprint": summary.get("analysis_fingerprint"),
            "counts": counts,
            "notes": notes,
            "attribution_quality": "reviewed_intervals_only; code-scope attribution unsupported by the CAPE adapter",
        }
        write_json(staging_dir / "export.json", metadata)
        _write_readme(staging_dir, metadata)
        write_json(staging_dir / "checksums.json", {"generated_at": utc_now_iso(), "files": dict(sorted(checksums.items()))})
        store.close()

        # Publish from staging_dir to dest
        if dest.exists():
            for child in dest.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        else:
            dest.mkdir(parents=True, exist_ok=True)
        for item in staging_dir.iterdir():
            shutil.move(str(item), str(dest / item.name))

        return ExportResult(dest=dest, counts=counts, metadata=metadata)
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def _write_readme(dest: Path, metadata: dict[str, Any]) -> None:
    lines = [
        "# LoaderFilter export",
        "",
        f"- Run: `{metadata['run_id']}`",
        f"- Selection: `{metadata['selection']}`",
        f"- Format: `{metadata['format']}`",
        f"- Created: {metadata['created_at']}",
        "",
        "## Phạm vi và giới hạn",
        "",
        "- `candidates`/`seed-candidates` chỉ là tín hiệu ứng viên từ metadata, không phải kết luận.",
        "- `observed` chỉ xuất khi có binding tin cậy (registry hoặc review hợp lệ) và execution được chứng minh.",
        "- Attribution sự kiện chỉ dựa trên review interval; phương pháp code-scope không được CAPE adapter hỗ trợ.",
        "- Events giữ nguyên raw call cho các pointer có thể đọc lại; trường thiếu được để `null`, không suy diễn.",
        "",
        "## Kiểm tra",
        "",
        "```",
        "loaderfilter verify --run <RUN_DIR> --exports <THIS_DIR>",
        "```",
    ]
    atomic_write_text(dest / "README.md", "\n".join(lines) + "\n")


def organize_directory_by_year(target_dir: Path, out_dir: Path | None = None, mode: str = "move") -> dict[str, Any]:
    target_dir = Path(target_dir).resolve()
    if not target_dir.is_dir():
        raise UsageError(f"directory does not exist: {target_dir}")
    dest_base = Path(out_dir).resolve() if out_dir else target_dir
    counts: dict[str, int] = {}
    total = 0
    ignored_names = {"export.json", "checksums.json", "run.json", "effective.json", "metadata.json"}

    # Collect all json reports (supports re-organizing existing subdirectories)
    files: list[Path] = []
    for p in target_dir.rglob("*.json"):
        if not p.is_file() or p.name in ignored_names:
            continue
        if ".staging" in str(p):
            continue
        files.append(p)

    for file_path in sorted(files):
        year = _extract_report_year(None, None, file_path) or "unknown"
        year_folder = dest_base / year
        dest_file = year_folder / file_path.name

        if file_path.resolve() == dest_file.resolve():
            counts[year] = counts.get(year, 0) + 1
            total += 1
            continue

        year_folder.mkdir(parents=True, exist_ok=True)
        if mode == "copy":
            shutil.copyfile(file_path, dest_file)
        else:
            shutil.move(str(file_path), str(dest_file))
        counts[year] = counts.get(year, 0) + 1
        total += 1

    # In move mode, clean up any now-empty subdirectories in target_dir
    if mode == "move":
        for child in sorted(target_dir.iterdir(), reverse=True):
            if child.is_dir() and child.name not in ("evidence", "manifest", "qa", "config"):
                try:
                    if not any(child.iterdir()):
                        child.rmdir()
                except OSError:
                    pass

    return {
        "total_organized": total,
        "by_year": dict(sorted(counts.items())),
        "mode": mode,
        "directory": str(dest_base),
        "source_directory": str(target_dir),
        "destination_directory": str(dest_base),
    }

