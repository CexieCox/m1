"""Unit tests for the CAPE adapter (synthetic fixtures only)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from utils.cape_adapter import CapeAdapter, ParseLimits
from utils.errors import ResourceLimitError

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture()
def outcome():
    return CapeAdapter().parse(FIXTURES / "cape_small.json", ParseLimits())


def test_target_and_regions(outcome):
    assert outcome.ok
    facts = outcome.facts
    assert facts.target_sha256 == "a" * 64
    assert facts.target_name == "loader.exe"
    assert facts.target_guest_paths == ["C:\\Users\\user\\loader.exe", "C:\\Temp\\l.exe"]
    assert facts.avclass_detection == "emotet"
    assert [d["family"] for d in facts.detections] == ["emotet"]
    assert facts.signature_names == ["antivm"]
    assert len(facts.cape_payloads) == 2
    assert len([item for item in facts.cape_payloads if item["sha256"]]) == 1
    assert len(facts.dropped) == 1
    assert len(facts.procdump) == 1
    assert facts.total_calls == 9
    assert facts.enhanced_count == 2


def test_invalid_artifact_hash_is_dropped_and_flagged(outcome):
    facts = outcome.facts
    bad = [item for item in facts.cape_payloads + facts.dropped + facts.procdump if item["name"] == "bad.bin"]
    assert len(bad) == 1
    assert bad[0]["sha256"] is None
    assert "cape_payload_sha256_invalid" in facts.quality_flags


def test_handle_tracking_and_self_filter(outcome):
    facts = outcome.facts
    loader = facts.processes[0]
    assert loader.process_id == 1000
    assert loader.remote_write_pids == [2000]
    assert loader.remote_thread_pids == [2000]
    assert loader.has_remote_write and loader.has_remote_thread
    assert loader.created_child_pids == [2000, 3000]
    assert loader.has_process_create and loader.has_network_activity and loader.has_download_api
    assert loader.has_file_create


def test_write_after_close_is_unresolved(outcome):
    facts = outcome.facts
    late = [
        fact
        for fact in facts.facts
        if fact.kind == "remote_write" and fact.attributes.get("base_address") == "0x401000"
    ]
    assert len(late) == 1
    assert "handle_not_open_at_call_time" in late[0].limitations
    assert "target_pid" not in late[0].attributes


def test_self_handle_is_negative_one(outcome):
    facts = outcome.facts
    self_write = [
        fact
        for fact in facts.facts
        if fact.kind == "remote_write" and fact.attributes.get("base_address") == "0x500000"
    ]
    assert self_write and self_write[0].attributes["target_pid"] == -1
    assert facts.processes[0].remote_write_pids == [2000]


def test_handle_open_fact_carries_target(outcome):
    opened = [fact for fact in outcome.facts.facts if fact.kind == "handle"]
    assert opened and opened[0].attributes["target_pid"] == 2000


def test_coverage_flags_are_curated(outcome):
    flags = outcome.facts.coverage_flags
    assert "present:target.file" in flags
    assert "present:behavior.processes" in flags
    assert "present:procdump" in flags
    assert not any(flag.startswith("present:/") for flag in flags)


def test_duplicate_json_key(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text('{"target": {"file": {"sha256": "a"}}, "target": {"file": {}}}', encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits())
    assert out.error_code == "duplicate_json_key"
    assert not out.ok


def test_invalid_json(tmp_path):
    path = tmp_path / "trunc.json"
    path.write_text('{"target": {"file": {"name": "x"', encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits())
    assert out.error_code == "invalid_json"


def test_non_cape_json(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits())
    assert out.error_code == "unsupported_schema"


def test_top_level_array_is_rejected(tmp_path):
    path = tmp_path / "array.json"
    path.write_text("[]", encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits())
    assert out.error_code == "unsupported_schema"


def test_max_file_bytes(tmp_path):
    path = tmp_path / "big.json"
    path.write_text("{}", encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits(max_file_bytes=1))
    assert out.error_code == "resource_limit"
    assert out.diagnostics["limit"] == "max_file_bytes"


def test_max_json_depth(tmp_path):
    payload = {"target": {"file": {"name": "x", "nested": {"a": {"b": {"c": 1}}}}}}
    path = tmp_path / "deep.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits(max_json_depth=4))
    assert out.error_code == "resource_limit"
    assert out.diagnostics["limit"] == "max_json_depth"


def test_max_call_record_bytes(tmp_path):
    payload = {
        "target": {"file": {"name": "x"}},
        "behavior": {
            "processes": [
                {
                    "process_id": 1,
                    "calls": [
                        {"api": "NtClose", "arguments": [{"name": "Handle", "pretty_value": "0x" * 4000}]}
                    ],
                }
            ]
        },
    }
    path = tmp_path / "big_call.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    out = CapeAdapter().parse(path, ParseLimits(max_call_record_bytes=256))
    assert out.error_code == "resource_limit"
    assert out.diagnostics["limit"] == "max_call_record_bytes"


def test_source_changed_detected(tmp_path, monkeypatch):
    path = tmp_path / "changing.json"
    path.write_text(json.dumps({"target": {"file": {"name": "x"}}}), encoding="utf-8")
    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(target, *args, **kwargs):
        result = real_stat(target, *args, **kwargs)
        calls["n"] += 1
        if calls["n"] > 1:
            return os.stat_result(
                (
                    result.st_mode,
                    result.st_ino,
                    result.st_dev,
                    result.st_nlink,
                    result.st_uid,
                    result.st_gid,
                    result.st_size,
                    result.st_atime,
                    result.st_mtime + 5,
                    result.st_ctime,
                )
            )
        return result

    monkeypatch.setattr("utils.cape_adapter.os.stat", fake_stat)
    out = CapeAdapter().parse(path, ParseLimits())
    assert out.error_code == "source_changed"


def test_missing_source(tmp_path):
    out = CapeAdapter().parse(tmp_path / "absent.json", ParseLimits())
    assert out.error_code == "source_missing"


def test_content_sha256_matches_bytes(outcome):
    import hashlib

    raw = (FIXTURES / "cape_small.json").read_bytes()
    assert outcome.content_sha256 == hashlib.sha256(raw).hexdigest()
    assert outcome.size_bytes == len(raw)


def test_resource_limit_type_is_importable():
    assert issubclass(ResourceLimitError, Exception)
