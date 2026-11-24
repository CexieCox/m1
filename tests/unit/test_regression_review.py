from __future__ import annotations

import csv
import io
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from utils.cape_adapter import CapeAdapter, ParseLimits, _Collector, UNCOLLECTED_ARRAYS
from utils.configs import build_config
from Code.step1_discover_sources import discover
from utils.errors import UsageError
from utils.evidence_utils import collect_report
from utils.delivery_utils import compute_delivery
from utils.policy_utils import decide
from utils.registry_utils import load_registry
from utils.review_utils import parse_review, validate_reviews
from tools.export_run import ExportOptions, export_run
from tools.organize_by_year import organize_directory_by_year
from Code.step2_build_inventory import build_inventory
from utils.label_utils import LabelStore
from utils.runner_utils import RunOptions, _human_effective_decision, _peek_target_sha256, run
from utils.taxonomy_utils import load_taxonomy
from utils.io_utils import read_jsonl, sha256_file
from tools.verify_run import verify_run

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TAXONOMY_PATH = PROJECT_ROOT / "configs" / "taxonomy.seed.json"
FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "cape_small.json"

DUMMY_SHA = "a" * 64


def _make_call(api: str, args: tuple = (), status: bool = True, result: str = "0x00000000"):
    return {
        "api": api,
        "status": status,
        "return": result,
        "arguments": [{"name": k, "value": v} for k, v in args],
    }


def _make_report(calls: list[dict], sha: str = DUMMY_SHA, **other):
    return {
        "target": {"file": {"sha256": sha, "name": "sample.exe"}},
        "behavior": {
            "processes": [
                {"process_id": 1000, "process_name": "sample.exe", "calls": calls}
            ]
        },
        **other,
    }


def _write_guloader_labels(path: Path, sha: str, report_filename: str) -> None:
    path.write_text(
        json.dumps({
            "n_reports": 1,
            "Guloader": {
                "n_reports": 1,
                "reports": [{"sha256": sha, "report": report_filename}],
            },
        }),
        encoding="utf-8",
    )


def _base_config_data(data_dir: Path, out_dir: Path, **overrides):
    base = {
        "config_schema_version": 1,
        "inputs": [{"id": "test", "path": str(data_dir)}],
        "discovery": {
            "recursive": True,
            "include": ["*.json"],
            "exclude": [],
            "follow_links": False,
            "identity": "auto",
        },
        "labels": {
            "avclass": None,
            "cape": None,
            "consensus": None,
            "row_errors": "quarantine",
            "require_full_coverage": False,
        },
        "taxonomy": str(TAXONOMY_PATH),
        "analysis": {
            "mode": "evidence",
            "scope": "all",
            "policy": "conservative-v1",
            "trusted_rule_registry": None,
        },
        "resources": {
            "workers": 1,
            "max_pending": 2,
            "max_file_bytes": 10485760,
            "max_call_record_bytes": 1048576,
            "max_json_depth": 128,
            "report_timeout_seconds": 60,
        },
        "output": {"root": str(out_dir), "keep_fact_cache": True},
        "logging": {"level": "WARNING", "progress_interval_seconds": 5},
    }
    base.update(overrides)
    return base


def _csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


# ---------------------------------------------------------------------------
# F01: Event streaming & raw call completeness
# ---------------------------------------------------------------------------
def test_f01_event_streaming_and_raw_call_completeness(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    calls_p0 = [
        _make_call("GetTickCount", result="123"),
        _make_call("LdrLoadDll"),
        _make_call("NtClose", [("Handle", "0x10")]),
    ]
    calls_p1 = [
        _make_call("VirtualAlloc", [("lpAddress", "0x00"), ("dwSize", "4096")]),
        _make_call("RegQueryValueExA"),
    ]
    raw = {
        "target": {"file": {"sha256": DUMMY_SHA, "name": "sample.exe"}},
        "behavior": {
            "processes": [
                {"process_id": 1000, "process_name": "proc0.exe", "calls": calls_p0},
                {"process_id": 2000, "process_name": "proc1.exe", "calls": calls_p1},
            ]
        },
    }
    source_name = f"{DUMMY_SHA}.json"
    (data_dir / source_name).write_text(json.dumps(raw), encoding="utf-8")

    labels_file = tmp_path / "labels.json"
    _write_guloader_labels(labels_file, DUMMY_SHA, source_name)

    cfg = build_config(
        _base_config_data(
            data_dir,
            out_dir,
            labels={"avclass": str(labels_file), "cape": None, "consensus": None, "row_errors": "quarantine", "require_full_coverage": False},
        ),
        base=tmp_path,
    )
    outcome = run(cfg, RunOptions(run_id="f01-run"))
    assert outcome.exit_code == 0

    dest = tmp_path / "events_all"
    exported = export_run(
        ExportOptions(
            run_dir=outcome.run_dir,
            dest=dest,
            selection="candidates",
            format="events",
            buckets=["all"],
        )
    )

    event_files = list((dest / "events").rglob("*.jsonl"))
    assert len(event_files) > 0
    all_events = [row for p in event_files for row in read_jsonl(p)]

    expected_positions = {
        (0, 0), (0, 1), (0, 2),
        (1, 0), (1, 1),
    }
    actual_positions = {
        (row["process_index"], row["call_index"])
        for row in all_events
        if row.get("call_index") is not None
    }
    assert actual_positions == expected_positions
    assert len(all_events) == 5
    assert exported.counts["scanned_calls"] == 5
    assert exported.counts["enhanced_context_records"] == 0

    verification = verify_run(outcome.run_dir, dest)
    assert verification["status"] == "pass"


# ---------------------------------------------------------------------------
# F02: Accepted loader without execution binding remains needs_review
# ---------------------------------------------------------------------------
def test_f02_accepted_loader_without_execution_binding(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    payload = _make_report([
        _make_call("GetTickCount", result="123"),
        _make_call("LdrLoadDll"),
        _make_call("NtClose", [("Handle", "0x10")]),
    ])
    source_name = f"{DUMMY_SHA}.json"
    (data_dir / source_name).write_text(json.dumps(payload), encoding="utf-8")

    labels_file = tmp_path / "labels.json"
    _write_guloader_labels(labels_file, DUMMY_SHA, source_name)

    cfg = build_config(
        _base_config_data(
            data_dir,
            out_dir,
            labels={"avclass": str(labels_file), "cape": None, "consensus": None, "row_errors": "quarantine", "require_full_coverage": False},
        ),
        base=tmp_path,
    )
    outcome = run(cfg, RunOptions(run_id="f02-run"))
    summary = json.loads((outcome.run_dir / "run.json").read_text(encoding="utf-8"))
    source_row = _csv_rows(outcome.run_dir / "manifest/all_sources.csv")[0]
    report_id = source_row["report_id"]

    review = {
        "review_schema_version": 1,
        "review_id": "review-no-binding",
        "source_id": source_row["source_id"],
        "report_id": report_id,
        "report_content_sha256": report_id,
        "analysis_fingerprint": summary["analysis_fingerprint"],
        "reviewer": "test-reviewer",
        "reviewed_at": "2026-10-23T10:00:00+07:00",
        "disposition": "accepted_loader",
        "reason": "Synthetic acceptance without execution binding",
        "evidence_ids": [],
        "bindings": [],
        "event_scopes": [],
        "supersedes": [],
    }
    rev_path = tmp_path / "review.jsonl"
    rev_path.write_text(json.dumps(review) + "\n", encoding="utf-8")

    resumed = run(
        cfg,
        RunOptions(run_id="f02-run", resume=True, review_files=[rev_path]),
    )
    assert resumed.exit_code == 0

    manifest_rows = _csv_rows(outcome.run_dir / "manifest/all_sources.csv")
    row = manifest_rows[0]
    # Human accepted_loader without binding must NOT promote effective_decision to loader_run_observed
    assert row["effective_decision"] != "loader_run_observed"
    assert row["effective_decision"] == row["machine_decision"]

    observed_rows = _csv_rows(outcome.run_dir / "manifest/observed.csv")
    assert len(observed_rows) == 0

    dest_obs = tmp_path / "observed_export"
    exported = export_run(
        ExportOptions(
            run_dir=outcome.run_dir,
            dest=dest_obs,
            selection="observed",
            format="reports",
        )
    )
    assert exported.counts["reports_copied"] == 0


# ---------------------------------------------------------------------------
# F03: Changed source file bytes on resume triggers re-parse
# ---------------------------------------------------------------------------
def test_f03_changed_source_bytes_on_resume(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    source_file = data_dir / f"{DUMMY_SHA}.json"
    raw = _make_report([_make_call("LdrLoadDll")])
    source_file.write_text(json.dumps(raw), encoding="utf-8")
    initial_sha = sha256_file(source_file)[0]

    cfg = build_config(_base_config_data(data_dir, out_dir), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f03-run"))
    assert outcome.exit_code == 0

    # Mutate the source file by adding whitespace
    source_file.write_bytes(source_file.read_bytes() + b"\n\n  \n")
    mutated_sha = sha256_file(source_file)[0]
    assert mutated_sha != initial_sha

    resumed = run(cfg, RunOptions(run_id="f03-run", resume=True))
    assert resumed.exit_code == 0

    row = _csv_rows(outcome.run_dir / "manifest/all_sources.csv")[0]
    assert row["report_id"] == mutated_sha
    assert (outcome.run_dir / "evidence" / "by_report" / mutated_sha).is_dir()

    verify = verify_run(outcome.run_dir)
    assert verify["status"] == "pass"


# ---------------------------------------------------------------------------
# F04: Scoped review persistence across resume and parse_review roundtrip
# ---------------------------------------------------------------------------
def test_f04_scoped_review_persistence_and_roundtrip(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    shutil.copyfile(FIXTURE_PATH, data_dir / f"{DUMMY_SHA}.json")

    cfg = build_config(_base_config_data(data_dir, out_dir), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f04-run"))
    summary = json.loads((outcome.run_dir / "run.json").read_text(encoding="utf-8"))
    source_row = _csv_rows(outcome.run_dir / "manifest/all_sources.csv")[0]
    report_id = source_row["report_id"]

    facts = read_jsonl(outcome.run_dir / "evidence" / "by_report" / report_id / "facts.jsonl")
    assert len(facts) > 0

    review = {
        "review_schema_version": 1,
        "review_id": "scoped-review-1",
        "source_id": source_row["source_id"],
        "report_id": report_id,
        "report_content_sha256": report_id,
        "analysis_fingerprint": summary["analysis_fingerprint"],
        "reviewer": "test-reviewer",
        "reviewed_at": "2026-10-23T10:00:00+07:00",
        "disposition": "inconclusive",
        "reason": "Synthetic scoped review",
        "evidence_ids": [facts[0]["evidence_id"]],
        "bindings": [],
        "event_scopes": [
            {
                "role": "loader",
                "process_index": 0,
                "call_index_start": 0,
                "call_index_end": 0,
                "exclusivity_reason": "Testing review_id in SCOPE_KEYS",
                "evidence_ids": [facts[0]["evidence_id"]],
                "object_sha256": DUMMY_SHA,
            }
        ],
        "supersedes": [],
    }

    # Verify parse_review(scoped.to_dict()) roundtrip works cleanly
    parsed = parse_review(review)
    roundtripped = parse_review(parsed.to_dict())
    assert roundtripped.review_id == "scoped-review-1"
    assert len(roundtripped.event_scopes) == 1

    rev_path = tmp_path / "review.jsonl"
    rev_path.write_text(json.dumps(review) + "\n", encoding="utf-8")

    # Ingest review
    run(cfg, RunOptions(run_id="f04-run", resume=True, review_files=[rev_path]))
    history1 = read_jsonl(outcome.run_dir / "reviews" / "history.jsonl")
    assert len(history1) == 1
    assert history1[0]["review_id"] == "scoped-review-1"

    # Resume without review files, ensure reviews are loaded from DB and history intact
    run(cfg, RunOptions(run_id="f04-run", resume=True))
    history2 = read_jsonl(outcome.run_dir / "reviews" / "history.jsonl")
    assert len(history2) == 1
    assert history2[0]["review_id"] == "scoped-review-1"


# ---------------------------------------------------------------------------
# F05: Generic report filename prefetch & candidate matching
# ---------------------------------------------------------------------------
def test_f05_generic_report_filename_prefetch_and_labels_match(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    # Generic report filename, not a hex hash
    generic_file = data_dir / "report.json"
    raw = _make_report([_make_call("LdrLoadDll")], sha=DUMMY_SHA)
    generic_file.write_text(json.dumps(raw), encoding="utf-8")

    labels_file = tmp_path / "labels.json"
    labels_file.write_text(
        json.dumps({
            "n_reports": 1,
            "Guloader": {
                "n_reports": 1,
                "reports": [{"sha256": DUMMY_SHA, "report": "report.json"}],
            },
        }),
        encoding="utf-8",
    )

    # Verify _peek_target_sha256 retrieves the SHA
    peeked = _peek_target_sha256(generic_file, 1024 * 1024)
    assert peeked == DUMMY_SHA

    overrides = {
        "labels": {
            "avclass": str(labels_file),
            "cape": None,
            "consensus": None,
            "row_errors": "quarantine",
            "require_full_coverage": False,
        },
        "analysis": {
            "mode": "evidence",
            "scope": "candidates",
            "policy": "conservative-v1",
            "trusted_rule_registry": None,
        },
    }
    cfg = build_config(_base_config_data(data_dir, out_dir, **overrides), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f05-run"))
    assert outcome.exit_code == 0
    assert outcome.counters["candidate_count"] == 1
    assert outcome.counters["report_files"] == 1

    row = _csv_rows(outcome.run_dir / "manifest" / "all_sources.csv")[0]
    assert row["is_candidate"].lower() == "true"
    assert row["processing_status"] == "completed"


# ---------------------------------------------------------------------------
# F06: Tampered evidence detected by verifier
# ---------------------------------------------------------------------------
def test_f06_tampered_evidence_detected_by_verifier(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    shutil.copyfile(FIXTURE_PATH, data_dir / f"{DUMMY_SHA}.json")

    cfg = build_config(_base_config_data(data_dir, out_dir), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f06-run"))
    assert outcome.exit_code == 0

    # Initial verification passes
    v1 = verify_run(outcome.run_dir)
    assert v1["status"] == "pass"

    source_row = _csv_rows(outcome.run_dir / "manifest/all_sources.csv")[0]
    report_id = source_row["report_id"]

    # Modify facts.jsonl in evidence artifact directory
    facts_path = outcome.run_dir / "evidence" / "by_report" / report_id / "facts.jsonl"
    facts = read_jsonl(facts_path)
    facts[0]["attributes"]["tampered"] = True
    facts_path.write_text("".join(json.dumps(r) + "\n" for r in facts), encoding="utf-8")

    # Verification must detect the checksum mismatch (QC-07)
    v2 = verify_run(outcome.run_dir)
    assert v2["status"] == "fail"
    assert any("evidence artifacts are missing or changed" in p for p in v2["problems"])


# ---------------------------------------------------------------------------
# F07: Exporter ancestor and overlap guard
# ---------------------------------------------------------------------------
def test_f07_exporter_ancestor_and_overlap_guard(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    raw = _make_report([_make_call("LdrLoadDll")])
    (data_dir / f"{DUMMY_SHA}.json").write_text(json.dumps(raw), encoding="utf-8")

    cfg = build_config(_base_config_data(data_dir, out_dir), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f07-run"))
    run_dir = outcome.run_dir

    # Case A: dest is run_dir parent (ancestor)
    ancestor = run_dir.parent
    with pytest.raises(UsageError, match="ancestor of the run directory"):
        with patch("tools.export_run.shutil.rmtree") as mock_rm:
            export_run(
                ExportOptions(
                    run_dir=run_dir,
                    dest=ancestor,
                    selection="candidates",
                    format="manifest",
                )
            )
            mock_rm.assert_not_called()

    # Case B: dest is inside run_dir
    inside = run_dir / "sub_export"
    with pytest.raises(UsageError, match="inside the run directory"):
        export_run(
            ExportOptions(
                run_dir=run_dir,
                dest=inside,
                selection="candidates",
                format="manifest",
            )
        )

    # State DB still intact
    assert (run_dir / "state.sqlite").is_file()


# ---------------------------------------------------------------------------
# F08: Registry load schema version 1
# ---------------------------------------------------------------------------
def test_f08_registry_load_schema_version_1(tmp_path: Path) -> None:
    reg_path = tmp_path / "registry.json"
    reg_path.write_text(
        json.dumps({"registry_schema_version": 1, "rules": []}),
        encoding="utf-8",
    )
    registry = load_registry(reg_path)
    assert registry is not None
    assert registry.content_sha256 is not None
    assert len(registry.rules) == 0


# ---------------------------------------------------------------------------
# F09: Streaming collector does not retain raw calls in process metadata
# ---------------------------------------------------------------------------
def test_f09_streaming_collector_and_runner_memory_bounded(tmp_path: Path) -> None:
    calls = [_make_call(f"Api_{i}", result=str(i)) for i in range(1000)]
    payload = _make_report(calls)

    collector = _Collector(ParseLimits())
    collector.feed(io.BytesIO(json.dumps(payload).encode()))
    collector.finish()

    assert len(collector.processes) == 1
    proc = collector.processes[0]
    # Raw calls must NOT be retained in process metadata
    assert proc.meta.get("calls") is None
    assert ("behavior", "processes", "*", "calls") in UNCOLLECTED_ARRAYS

    # End-to-end memory check: coordinator runs without in-memory evidence accumulation
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for idx in range(3):
        sha = f"{idx:02x}" * 32
        sample_calls = [_make_call(f"Api_{idx}_{j}", result=str(j)) for j in range(500)]
        (data_dir / f"{sha}.json").write_text(json.dumps(_make_report(sample_calls, sha=sha)), encoding="utf-8")

    cfg = build_config(_base_config_data(data_dir, tmp_path / "out"), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f09-run"))
    assert outcome.exit_code == 0
    assert outcome.counters["report_files"] == 3


# ---------------------------------------------------------------------------
# F10: Labels mode skips evidence parsing
# ---------------------------------------------------------------------------
def test_f10_labels_mode_skips_evidence_parsing(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    raw = _make_report([_make_call("LdrLoadDll")])
    (data_dir / f"{DUMMY_SHA}.json").write_text(json.dumps(raw), encoding="utf-8")

    overrides = {
        "analysis": {
            "mode": "labels",
            "scope": "all",
            "policy": "conservative-v1",
            "trusted_rule_registry": None,
        }
    }
    cfg = build_config(_base_config_data(data_dir, out_dir, **overrides), base=tmp_path)
    outcome = run(cfg, RunOptions(run_id="f10-run"))
    assert outcome.exit_code == 0
    assert outcome.counters["report_files"] == 0

    summary = json.loads((outcome.run_dir / "run.json").read_text(encoding="utf-8"))
    assert summary["evidence_scope"] == "not_applicable"

    # Evidence directory should have no report evidence directories
    evidence_by_report = outcome.run_dir / "evidence" / "by_report"
    assert not evidence_by_report.exists() or len(list(evidence_by_report.iterdir())) == 0

    verify = verify_run(outcome.run_dir)
    assert verify["status"] == "pass"


# ---------------------------------------------------------------------------
# F11: Conflicting mapping family order invariance
# ---------------------------------------------------------------------------
def test_f11_conflicting_mapping_family_order_invariance(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / f"{DUMMY_SHA}.json").write_text(json.dumps(_make_report([])), encoding="utf-8")

    taxonomy = load_taxonomy(TAXONOMY_PATH)
    results = []

    for families in [("Redline", "Guloader"), ("Guloader", "Redline")]:
        doc = {"n_reports": 2}
        for family in families:
            doc[family] = {
                "n_reports": 1,
                "reports": [{"sha256": DUMMY_SHA, "report": f"{DUMMY_SHA}.json"}],
            }
        lbl_file = tmp_path / f"labels_{families[0]}.json"
        lbl_file.write_text(json.dumps(doc), encoding="utf-8")

        store = LabelStore(taxonomy)
        store.load(lbl_file, None, None, "quarantine")

        cfg = build_config(_base_config_data(data_dir, tmp_path / "out"), base=tmp_path)
        discovered = discover(cfg).files
        inventory = build_inventory(discovered, store, taxonomy)
        entry = next(item for item in inventory.entries if item.source.relative_path == f"{DUMMY_SHA}.json")
        results.append({
            "is_candidate": entry.source.is_candidate,
            "is_seed_candidate": entry.source.is_seed_candidate,
            "pair_state": entry.source.label_pair_state,
        })

    assert results[0]["is_candidate"] == results[1]["is_candidate"]
    assert results[0]["is_seed_candidate"] == results[1]["is_seed_candidate"]
    assert results[0]["pair_state"] == results[1]["pair_state"]
    assert results[0]["is_candidate"] is True
    assert results[0]["is_seed_candidate"] is True


# ---------------------------------------------------------------------------
# F12: Discovery recursive=false stops descent into subdirectories
# ---------------------------------------------------------------------------
def test_f12_discovery_recursive_false_stops_descent(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "root.json").write_text("{}", encoding="utf-8")

    child_dir = data_dir / "child"
    child_dir.mkdir()
    (child_dir / "child.json").write_text("{}", encoding="utf-8")

    cfg_rec = build_config(
        _base_config_data(data_dir, tmp_path / "out", discovery={"recursive": True, "include": ["*.json"], "exclude": [], "follow_links": False, "identity": "auto"}),
        base=tmp_path,
    )
    discovered_rec = [f.relative_path for f in discover(cfg_rec).files]
    assert len(discovered_rec) == 2

    cfg_non_rec = build_config(
        _base_config_data(data_dir, tmp_path / "out", discovery={"recursive": False, "include": ["*.json"], "exclude": [], "follow_links": False, "identity": "auto"}),
        base=tmp_path,
    )
    discovered_non_rec = [f.relative_path for f in discover(cfg_non_rec).files]
    assert discovered_non_rec == ["root.json"]


# ---------------------------------------------------------------------------
# F13: Delivery handoff and materialization rules
# ---------------------------------------------------------------------------
def test_f13_delivery_handoff_and_materialization_rules(tmp_path: Path) -> None:
    # Subtest 1: Remote write only does not constitute handoff (no execution control transfer)
    remote_write_report = _make_report([
        _make_call("NtOpenProcess", [("ProcessHandle", "0x10"), ("ProcessId", "2000")]),
        _make_call("NtWriteVirtualMemory", [("ProcessHandle", "0x10"), ("BaseAddress", "0x400000")]),
    ])
    p1 = tmp_path / "remote.json"
    p1.write_text(json.dumps(remote_write_report), encoding="utf-8")
    outcome1 = CapeAdapter().parse(p1, ParseLimits())
    assert outcome1.ok
    ev1 = collect_report(outcome1.facts)
    deliv1 = compute_delivery(facts=ev1.facts, processes=ev1.processes, actor_indices={0})
    assert deliv1.flags["handoff_api_succeeded"] is False

    # Subtest 2: Opening existing file at a different path does not materialize payload
    open_report = _make_report([
        _make_call(
            "NtCreateFile",
            [("FileName", r"C:\unrelated\payload.exe"), ("CreateDisposition", "1")],  # 1 = FILE_OPEN
        )
    ])
    p2 = tmp_path / "open.json"
    p2.write_text(json.dumps(open_report), encoding="utf-8")
    outcome2 = CapeAdapter().parse(p2, ParseLimits())
    assert outcome2.ok
    ev2 = collect_report(outcome2.facts)
    deliv2 = compute_delivery(
        facts=ev2.facts,
        processes=ev2.processes,
        actor_indices={0},
        artifact_guest_paths=[r"C:\actual_payload\payload.exe"],
    )
    assert deliv2.flags["payload_materialized_observed"] is False

    # Subtest 3: Creation of file matching artifact path materializes payload
    create_report = _make_report([
        _make_call(
            "NtCreateFile",
            [("FileName", r"C:\actual_payload\payload.exe"), ("CreateDisposition", "2")],  # 2 = FILE_CREATE
        )
    ])
    p3 = tmp_path / "create.json"
    p3.write_text(json.dumps(create_report), encoding="utf-8")
    outcome3 = CapeAdapter().parse(p3, ParseLimits())
    assert outcome3.ok
    ev3 = collect_report(outcome3.facts)
    deliv3 = compute_delivery(
        facts=ev3.facts,
        processes=ev3.processes,
        actor_indices={0},
        artifact_guest_paths=[r"C:\actual_payload\payload.exe"],
    )
    assert deliv3.flags["payload_materialized_observed"] is True


# ---------------------------------------------------------------------------
# F14: Verifier rejects empty checksums and row mismatch
# ---------------------------------------------------------------------------
def test_f14_verifier_rejects_empty_checksums_and_row_mismatch(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    raw = _make_report([_make_call("LdrLoadDll")])
    source_name = f"{DUMMY_SHA}.json"
    (data_dir / source_name).write_text(json.dumps(raw), encoding="utf-8")

    labels_file = tmp_path / "labels.json"
    _write_guloader_labels(labels_file, DUMMY_SHA, source_name)

    cfg = build_config(
        _base_config_data(
            data_dir,
            out_dir,
            labels={"avclass": str(labels_file), "cape": None, "consensus": None, "row_errors": "quarantine", "require_full_coverage": False},
        ),
        base=tmp_path,
    )
    outcome = run(cfg, RunOptions(run_id="f14-run"))
    dest = tmp_path / "exported"
    export_run(
        ExportOptions(
            run_dir=outcome.run_dir,
            dest=dest,
            selection="candidates",
            format="events",
            buckets=["all"],
        )
    )

    # Initial verification passes
    v1 = verify_run(outcome.run_dir, dest)
    assert v1["status"] == "pass"

    # Case 1: Empty checksums when export files exist
    checksums_path = dest / "checksums.json"
    orig_checksums = checksums_path.read_text(encoding="utf-8")
    checksums_path.write_text(json.dumps({"files": {}}), encoding="utf-8")
    v2 = verify_run(outcome.run_dir, dest)
    assert v2["status"] == "fail"
    assert any("checksums.json has no file entries" in p for p in v2["problems"])
    checksums_path.write_text(orig_checksums, encoding="utf-8")

    # Case 2: Row count mismatch in export metadata
    meta_path = dest / "export.json"
    orig_meta = meta_path.read_text(encoding="utf-8")
    meta = json.loads(orig_meta)
    meta["counts"]["events_exported"] += 999
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    v3 = verify_run(outcome.run_dir, dest)
    assert v3["status"] == "fail"
    assert any("does not match metadata" in p for p in v3["problems"])


def test_export_group_by_year(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "out"

    raw = _make_report(
        calls=[_make_call("LdrLoadDll")],
        sha=DUMMY_SHA,
        info={"started": "2024-03-15 10:00:00", "ended": "2024-03-15 10:02:00"},
    )
    source_name = f"{DUMMY_SHA}.json"
    source_file = data_dir / source_name
    source_file.write_text(json.dumps(raw), encoding="utf-8")
    report_sha, _ = sha256_file(source_file)

    labels_file = tmp_path / "labels.json"
    _write_guloader_labels(labels_file, DUMMY_SHA, source_name)

    cfg = build_config(
        _base_config_data(
            data_dir,
            out_dir,
            labels={"avclass": str(labels_file), "cape": None, "consensus": None, "row_errors": "quarantine", "require_full_coverage": False},
        ),
        base=tmp_path,
    )
    outcome = run(cfg, RunOptions(run_id="test-year-run"))
    dest = tmp_path / "exported_by_year"
    res = export_run(
        ExportOptions(
            run_dir=outcome.run_dir,
            dest=dest,
            selection="candidates",
            format="reports",
            group_by_year=True,
        )
    )
    assert (dest / "raw_reports" / "2024" / f"{report_sha}.json").is_file()
    v = verify_run(outcome.run_dir, dest)
    assert v["status"] == "pass"


def test_organize_directory_by_year(tmp_path: Path) -> None:
    test_dir = tmp_path / "reports_to_organize"
    test_dir.mkdir()

    r2022 = test_dir / "sample_2022.json"
    r2022.write_text(json.dumps({"info": {"started": "2022-01-01 00:00:00"}}), encoding="utf-8")

    r2023 = test_dir / "sample_2023.json"
    r2023.write_text(json.dumps({"info": {"started": "2023-05-10 12:00:00"}}), encoding="utf-8")

    meta = test_dir / "export.json"
    meta.write_text(json.dumps({"type": "export_meta"}), encoding="utf-8")

    res = organize_directory_by_year(test_dir, mode="move")
    assert res["total_organized"] == 2
    assert res["by_year"] == {"2022": 1, "2023": 1}
    assert (test_dir / "2022" / "sample_2022.json").is_file()
    assert (test_dir / "2023" / "sample_2023.json").is_file()
    assert not r2022.is_file()
    assert not r2023.is_file()
    assert meta.is_file()  # export.json is preserved in root


def test_pe_timestamp_does_not_override_execution_year(tmp_path: Path) -> None:
    from tools.export_run import _extract_report_year

    report_path = tmp_path / "pe_2004_call_2024.json"
    doc = {
        "target": {
            "file": {
                "pe": {
                    "timestamp": "2004-10-13 05:27:30"  # Compile / stomped timestamp
                }
            }
        },
        "behavior": {
            "processes": [
                {
                    "process_name": "sample.exe",
                    "first_seen": "2024-08-02 10:29:30,123",
                    "calls": [
                        {
                            "api": "NtProtectVirtualMemory",
                            "timestamp": "2024-08-02 10:29:31,999",
                        }
                    ],
                }
            ]
        },
    }
    report_path.write_text(json.dumps(doc), encoding="utf-8")
    year = _extract_report_year(None, None, report_path)
    assert year == "2024"  # Sandbox execution year, not PE 2004


