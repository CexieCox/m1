"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any

__version__ = '0.1.0'
from utils.configs import UsageError, apply_cli_overrides, build_config, load_config_file
from utils.errors import EXIT_INTEGRITY, EXIT_INTERRUPT, EXIT_OK, EXIT_USAGE, LoaderFilterError
from utils.evidence_utils import read_report_evidence
from utils.policy_utils import ReportDecision
from utils.review_utils import ReviewError, build_review_template, load_review_file
from tools.export_run import ExportOptions, export_run
from utils.runner_utils import RunLayout, RunOptions, generate_run_id, run
from utils.state_utils import StateStore
from utils.io_utils import read_json_strict, read_jsonl, write_jsonl
from tools.verify_run import verify_run


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - argparse plumbing
        raise UsageError(message)


def _emit(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n")


def _load_config(args: argparse.Namespace) -> Config:
    if args.config:
        config = load_config_file(Path(args.config))
    else:
        config = build_config({}, base=Path.cwd())
    overrides = {
        "inputs": _parse_inputs(args.input) if args.input else None,
        "output": args.output,
        "labels_dir": getattr(args, "labels_dir", None),
        "avclass_map": getattr(args, "avclass_map", None),
        "cape_map": getattr(args, "cape_map", None),
        "consensus_map": getattr(args, "consensus_map", None),
        "no_labels": getattr(args, "no_labels", False),
        "taxonomy": getattr(args, "taxonomy", None),
        "registry": getattr(args, "registry", None),
        "mode": getattr(args, "mode", None),
        "scope": getattr(args, "scope", None),
        "recursive": getattr(args, "recursive", None),
        "identity": getattr(args, "identity", None),
        "workers": getattr(args, "workers", None),
        "max_pending": getattr(args, "max_pending", None),
    }
    return apply_cli_overrides(config, overrides, cwd=Path.cwd())


def _parse_inputs(values: list[str]):
    from utils.configs import InputSpec, INPUT_ID_RE

    specs = []
    for value in values:
        if "=" not in value:
            raise UsageError(f"--input must be ID=PATH, got {value!r}")
        identifier, path = value.split("=", 1)
        if not INPUT_ID_RE.match(identifier):
            raise UsageError(f"invalid input id {identifier!r}")
        specs.append(InputSpec(id=identifier, path=Path(path)))
    return specs


def _cmd_validate(args: argparse.Namespace) -> int:
    config = _load_config(args)
    from utils.taxonomy_utils import load_taxonomy
    from utils.label_utils import LabelStore
    from utils.io_utils import sha256_file

    taxonomy = load_taxonomy(config.taxonomy) if config.taxonomy else None
    labels = LabelStore(taxonomy) if taxonomy else None
    metrics = {}
    if labels is not None and config.label_source_paths():
        labels.load(config.labels.avclass, config.labels.cape, config.labels.consensus, config.labels.row_errors)
        metrics = labels.to_dict()
    _emit(
        {
            "status": "ok",
            "config_path": str(config.config_path) if config.config_path else None,
            "semantic_config_sha256": config.semantic_config_hash(),
            "taxonomy": taxonomy.to_dict() if taxonomy else None,
            "labels": metrics,
            "inputs": [{"id": spec.id, "path": str(spec.path)} for spec in config.inputs],
            "label_files": {
                kind: {"path": str(path), "sha256": sha256_file(path)[0]}
                for kind, path in (
                    ("avclass", config.labels.avclass),
                    ("cape", config.labels.cape),
                    ("consensus", config.labels.consensus),
                )
                if path is not None
            },
        }
    )
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    config = _load_config(args)
    if args.resume:
        run_dir = Path(args.resume).resolve()
        options = RunOptions(
            run_id=run_dir.name,
            resume=True,
            limit=args.limit,
            retry_errors=args.retry_errors,
            review_files=[Path(item) for item in args.review or []],
        )
        config = _rebase_config_for_run(config, run_dir.parent)
    else:
        run_id = args.run_id or generate_run_id(config)
        options = RunOptions(
            run_id=run_id,
            resume=False,
            limit=args.limit,
            retry_errors=args.retry_errors,
            review_files=[Path(item) for item in args.review or []],
        )
    layout = RunLayout.build(config, options.run_id)
    sys.stderr.write(f"run directory: {layout.run_dir}\n")
    outcome = run(config, options)
    _emit(
        {
            "run_id": outcome.run_id,
            "run_dir": str(outcome.run_dir),
            "status": outcome.summary.get("status"),
            "qa": outcome.qa_status,
            "counters": outcome.counters,
            "exit_code": outcome.exit_code,
        }
    )
    return outcome.exit_code


def _rebase_config_for_run(config: Config, output_root: Path) -> Config:
    from dataclasses import replace

    return replace(config, output=replace(config.output, root=output_root))


def _cmd_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    summary = read_json_strict(run_dir / "run.json")
    state_path = run_dir / "state.sqlite"
    payload: dict[str, Any] = {"run": summary}
    if state_path.is_file():
        store = StateStore(state_path)
        run_row = store.get_run(summary.get("run_id"))
        payload["database"] = {
            "status": run_row.status if run_row else None,
            "counters": run_row.counters if run_row else None,
        }
        payload["status_counts"] = _status_counts(store.list_sources(summary.get("run_id")))
        store.close()
    qa_path = run_dir / "qa" / "summary.json"
    if qa_path.is_file():
        payload["qa"] = read_json_strict(qa_path)
    _emit(payload)
    return EXIT_OK


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = row.get("processing_status") or "unknown"
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _cmd_explain(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    summary = read_json_strict(run_dir / "run.json")
    run_id = summary.get("run_id")
    store = StateStore(run_dir / "state.sqlite")
    if args.source_id:
        source = store.get_source(run_id, args.source_id)
        if source is None:
            raise UsageError(f"unknown source id: {args.source_id}")
        payload: dict[str, Any] = {
            "source": source,
            "labels": store.list_label_observations(run_id, args.source_id),
            "machine_decision": [
                row for row in store.list_machine_decisions(run_id) if row["source_id"] == args.source_id
            ],
            "job": [row for row in store.list_jobs(run_id) if row["source_id"] == args.source_id],
        }
        report_id = source.get("report_id")
    elif args.report_id:
        report_id = args.report_id
        payload = {"report_id": report_id, "meta": store.get_report_meta(run_id, report_id)}
        payload["reports"] = [row for row in store.list_reports(run_id) if row["report_id"] == report_id]
    else:
        raise UsageError("explain requires --source-id or --report-id")

    if report_id:
        evidence = read_report_evidence(run_dir / "evidence" / "by_report" / report_id)
        if evidence is not None:
            payload["evidence"] = {
                "report_id": evidence.report_id,
                "target_sha256": evidence.target_sha256,
                "facts_total": len(evidence.facts),
                "processes": [process.to_dict() for process in evidence.processes],
                "facts": [fact.to_dict() for fact in evidence.facts[: args.max_facts]],
                "artifacts": [item.to_dict() for item in evidence.artifacts],
                "quality_flags": evidence.quality_flags,
                "coverage_flags": evidence.coverage_flags,
            }
    store.close()
    _emit(payload)
    return EXIT_OK


def _cmd_review_export(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    summary = read_json_strict(run_dir / "run.json")
    run_id = summary.get("run_id")
    store = StateStore(run_dir / "state.sqlite")
    fingerprint = summary.get("analysis_fingerprint") or ""
    rows: list[dict[str, Any]] = []
    for source in store.list_sources(run_id):
        if source.get("machine_decision") != "needs_review":
            continue
        report_id = source.get("report_id")
        if not report_id:
            continue
        evidence = read_report_evidence(run_dir / "evidence" / "by_report" / report_id)
        if evidence is None:
            continue
        decision = ReportDecision(
            observed=False,
            payload_execution=False,
            family_identity_status=source.get("family_identity_status") or "unknown",
            family=None,
            family_evidence=[],
            execution_status=source.get("execution_status") or "not_evaluated",
            execution_observations=[],
            bindings=[],
            delivery=None,
            attribution=None,
            bucket_counts={},
            machine_decision=source.get("machine_decision") or "needs_review",
            machine_reasons=list(source.get("machine_decision_reasons") or []),
            candidate_reasons=list(source.get("candidate_reasons") or []),
            needs_review=True,
            quality_flags=list(source.get("quality_flags") or []),
        )
        template = build_review_template(
            source_id=source["source_id"],
            evidence=evidence,
            analysis_fingerprint=fingerprint,
            decision=decision,
            reviewer=args.reviewer,
        )
        rows.append(template.to_dict())
    store.close()
    write_jsonl(Path(args.out), rows)
    _emit({"review_items": len(rows), "out": str(Path(args.out).resolve())})
    return EXIT_OK


def _cmd_review_import(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    review_path = Path(args.file).resolve()
    try:
        records = load_review_file(review_path)
    except ReviewError as exc:
        raise UsageError(f"invalid review file: {'; '.join(exc.problems)}") from exc
    effective = read_json_strict(run_dir / "config" / "effective.json")
    config = build_config(effective["config"], base=run_dir, config_path=None)
    config = _rebase_config_for_run(config, run_dir.parent)
    sys.stderr.write(f"run directory: {run_dir}\n")
    outcome = run(config, RunOptions(run_id=run_dir.name, resume=True, review_files=[review_path]))
    history = read_jsonl(run_dir / "reviews" / "history.jsonl") if (run_dir / "reviews" / "history.jsonl").is_file() else []
    _emit(
        {
            "review_records": len(records),
            "history": [
                {"review_id": row.get("review_id"), "status": row.get("status"), "problems": row.get("problems", [])}
                for row in history
            ],
            "run_id": outcome.run_id,
            "status": outcome.summary.get("status"),
            "exit_code": outcome.exit_code,
        }
    )
    return outcome.exit_code


def _cmd_export(args: argparse.Namespace) -> int:
    buckets = args.bucket or []
    result = export_run(
        ExportOptions(
            run_dir=Path(args.run),
            dest=Path(args.dest),
            selection=args.selection,
            format=args.format,
            buckets=list(buckets),
            group_by_year=bool(getattr(args, "group_by_year", False)),
        )
    )
    _emit({"dest": str(result.dest), "counts": result.counts, "notes": result.metadata.get("notes", [])})
    return EXIT_OK


def _cmd_organize_by_year(args: argparse.Namespace) -> int:
    from tools.export_run import organize_directory_by_year

    out_dir = Path(args.out) if getattr(args, "out", None) else None
    result = organize_directory_by_year(Path(args.dir), out_dir=out_dir, mode=args.mode)
    _emit(result)
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify_run(Path(args.run), Path(args.exports) if args.exports else None)
    _emit(result)
    return EXIT_OK if result["status"] == "pass" else EXIT_INTEGRITY


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="loaderfilter", description="Conservative payload-delivery triage for sandbox reports.")
    parser.add_argument("--version", action="version", version=f"loaderfilter {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    def add_config_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--config", help="JSON configuration file")
        sub.add_argument("--input", action="append", metavar="ID=PATH", help="input root (repeatable; replaces config inputs)")
        sub.add_argument("--output", metavar="PATH", help="output root (replaces output.root)")
        sub.add_argument("--labels-dir", help="directory with the three label mapping files")
        sub.add_argument("--avclass-map")
        sub.add_argument("--cape-map")
        sub.add_argument("--consensus-map")
        sub.add_argument("--no-labels", action="store_true")
        sub.add_argument("--taxonomy")
        sub.add_argument("--registry", help="trusted rule registry JSON")

    scan = subparsers.add_parser("scan", help="discover, parse and decide a dataset")
    add_config_options(scan)
    scan.add_argument("--mode", choices=["labels", "evidence"])
    scan.add_argument("--scope", choices=["candidates", "all"])
    scan.add_argument("--recursive", dest="recursive", action="store_true", default=None)
    scan.add_argument("--no-recursive", dest="recursive", action="store_false")
    scan.add_argument("--identity", choices=["auto", "filename", "report"])
    scan.add_argument("--workers", type=int)
    scan.add_argument("--max-pending", type=int)
    scan.add_argument("--limit", type=int)
    scan.add_argument("--run-id")
    scan.add_argument("--resume", metavar="RUN_DIR")
    scan.add_argument("--retry-errors", action="store_true")
    scan.add_argument("--review", action="append", metavar="FILE", help="review JSONL applied to this run")
    scan.set_defaults(handler=_cmd_scan)

    validate = subparsers.add_parser("validate", help="validate configuration, taxonomy and label files")
    add_config_options(validate)
    validate.set_defaults(handler=_cmd_validate)

    status = subparsers.add_parser("status", help="print run status")
    status.add_argument("--run", required=True)
    status.set_defaults(handler=_cmd_status)

    explain = subparsers.add_parser("explain", help="explain one source or report")
    explain.add_argument("--run", required=True)
    explain.add_argument("--source-id")
    explain.add_argument("--report-id")
    explain.add_argument("--max-facts", type=int, default=200)
    explain.set_defaults(handler=_cmd_explain)

    review = subparsers.add_parser("review", help="export or import review items")
    review_sub = review.add_subparsers(dest="review_command", required=True, parser_class=_Parser)
    review_export = review_sub.add_parser("export")
    review_export.add_argument("--run", required=True)
    review_export.add_argument("--out", required=True)
    review_export.add_argument("--reviewer", default="REPLACE-ME")
    review_export.set_defaults(handler=_cmd_review_export)
    review_import = review_sub.add_parser("import")
    review_import.add_argument("--run", required=True)
    review_import.add_argument("--file", required=True)
    review_import.set_defaults(handler=_cmd_review_import)

    export = subparsers.add_parser("export", help="export a selection from a run")
    export.add_argument("--run", required=True)
    export.add_argument("--selection", default="candidates", choices=["seed-candidates", "candidates", "observed", "payload-execution"])
    export.add_argument("--format", default="manifest", choices=["manifest", "reports", "events"])
    export.add_argument(
        "--bucket",
        action="append",
        choices=["loader_strict", "payload", "system_context", "mixed_or_unresolved", "all"],
        help="event bucket (repeatable; required for --format events)",
    )
    export.add_argument("--dest", required=True)
    export.add_argument(
        "--group-by-year",
        action="store_true",
        help="partition raw reports into subdirectories by year (e.g. 2023, 2024)",
    )
    export.set_defaults(handler=_cmd_export)

    organize = subparsers.add_parser(
        "organize-by-year",
        help="read all json reports in a directory and partition them into subdirectories by year",
    )
    organize.add_argument("--dir", required=True, help="directory containing json reports to organize")
    organize.add_argument(
        "--out",
        help="destination directory (optional; if omitted, organizes in-place inside --dir)",
    )
    organize.add_argument(
        "--mode",
        choices=["move", "copy"],
        default="move",
        help="move or copy reports into year folders (default: move)",
    )
    organize.set_defaults(handler=_cmd_organize_by_year)

    verify = subparsers.add_parser("verify", help="recompute QA, references and checksums")
    verify.add_argument("--run", required=True)
    verify.add_argument("--exports")
    verify.set_defaults(handler=_cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_USAGE
    try:
        return int(args.handler(args))
    except LoaderFilterError as exc:
        sys.stderr.write(f"error: {exc}\n")
        if exc.details:
            sys.stderr.write(json.dumps(exc.details, ensure_ascii=False, indent=2, default=str) + "\n")
        return exc.exit_code
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return EXIT_INTERRUPT
    except Exception as exc:  # noqa: BLE001 - report the failure, never fake success
        traceback.print_exc()
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return EXIT_INTEGRITY


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
