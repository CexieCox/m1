from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from utils.configs import build_config
from tools.export_run import ExportOptions, export_run
from utils.runner_utils import RunOptions, generate_run_id, run
from utils.io_utils import read_jsonl, write_jsonl
from tools.verify_run import verify_run

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "cape_small.json"
TAXONOMY = Path(__file__).resolve().parent.parent.parent / "configs" / "taxonomy.seed.json"


def _make_dataset(root: Path) -> Path:
    data = root / "data"
    data.mkdir(parents=True)
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    target = str(fixture["target"]["file"]["sha256"]).lower()
    shutil.copyfile(FIXTURE, data / f"{target}.json")
    conflicting = json.loads(json.dumps(fixture))
    conflicting["target"]["file"]["sha256"] = "c" * 64
    (data / f"{'b' * 64}.json").write_text(json.dumps(conflicting), encoding="utf-8")
    (data / "broken.json").write_text("{", encoding="utf-8")
    (data / "notes.json").write_text("[]", encoding="utf-8")
    return data


def _config(root: Path, data: Path):
    raw = {
        "config_schema_version": 1,
        "inputs": [{"id": "test", "path": str(data)}],
        "discovery": {"recursive": True, "include": ["*.json"], "exclude": [], "follow_links": False, "identity": "auto"},
        "labels": {
            "avclass": None,
            "cape": None,
            "consensus": None,
            "row_errors": "quarantine",
            "require_full_coverage": False,
        },
        "taxonomy": str(TAXONOMY),
        "analysis": {"mode": "evidence", "scope": "all", "policy": "conservative-v1", "trusted_rule_registry": None},
        "resources": {
            "workers": 1,
            "max_pending": 2,
            "max_file_bytes": 1048576,
            "max_call_record_bytes": 1048576,
            "max_json_depth": 128,
            "report_timeout_seconds": 60,
        },
        "output": {"root": str(root / "out"), "keep_fact_cache": True},
        "logging": {"level": "WARNING", "progress_interval_seconds": 5},
    }
    return build_config(raw, base=root)


def test_end_to_end_scan_export_verify_and_review(tmp_path: Path) -> None:
    data = _make_dataset(tmp_path)
    config = _config(tmp_path, data)
    run_id = generate_run_id(config)
    outcome = run(config, RunOptions(run_id=run_id))
    run_dir = outcome.run_dir
    assert outcome.summary["status"] == "partial"
    assert outcome.exit_code == 3
    assert outcome.qa_status == "pass"
    assert outcome.counters["report_files"] == 2
    assert outcome.counters["failed_reports"] == 2
    assert outcome.counters["review_queue_count"] == 1
    for name in ("all_sources.csv", "seed_candidates.csv", "candidates.csv", "all_reports.jsonl", "unresolved.csv"):
        assert (run_dir / "manifest" / name).is_file()

    export = export_run(
        ExportOptions(
            run_dir=run_dir,
            dest=tmp_path / "export",
            selection="candidates",
            format="manifest",
        )
    )
    assert export.counts["locators_selected"] == 0
    verification = verify_run(run_dir, tmp_path / "export")
    assert verification["status"] == "pass", verification["problems"]

    queue = list(__import__("csv").DictReader((run_dir / "manifest" / "review_queue.csv").open(encoding="utf-8-sig")))
    assert len(queue) == 1
    source_id = queue[0]["source_id"]
    review_row = {
        "review_schema_version": 1,
        "review_id": "review-test-1",
        "source_id": source_id,
        "report_id": queue[0]["report_id"],
        "report_content_sha256": queue[0]["report_id"],
        "analysis_fingerprint": outcome.summary["analysis_fingerprint"],
        "reviewer": "pytest",
        "reviewed_at": "2026-01-01T00:00:00+00:00",
        "disposition": "rejected_loader",
        "reason": "fixture has no trustworthy execution binding",
        "evidence_ids": [],
        "bindings": [],
        "event_scopes": [],
        "supersedes": [],
    }
    review_path = tmp_path / "review.jsonl"
    write_jsonl(review_path, [review_row])
    resumed = run(config, RunOptions(run_id=run_id, resume=True, review_files=[review_path]))
    assert resumed.exit_code == 3
    assert resumed.counters["review_queue_count"] == 0
    history = read_jsonl(run_dir / "reviews" / "history.jsonl")
    assert any(item["status"] == "applied" for item in history)
    verification = verify_run(run_dir)
    assert verification["status"] == "pass", verification["problems"]

    again = run(config, RunOptions(run_id=run_id, resume=True))
    assert again.counters["review_queue_count"] == 0
    verification = verify_run(run_dir)
    assert verification["status"] == "pass", verification["problems"]


def test_verify_fails_when_manifest_is_missing(tmp_path: Path) -> None:
    data = _make_dataset(tmp_path)
    config = _config(tmp_path, data)
    outcome = run(config, RunOptions(run_id=generate_run_id(config)))
    (outcome.run_dir / "manifest" / "observed.csv").unlink()
    verification = verify_run(outcome.run_dir)
    assert verification["status"] == "fail"
    assert any(check["check_id"] == "V-09" and check["status"] == "fail" for check in verification["checks"])
