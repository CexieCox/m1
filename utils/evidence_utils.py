"""Turn adapter output into compact, addressable evidence records.

Facts are observations with a stable ``evidence_id``. Nothing in this module decides
whether a sample is a loader; it only makes the raw observations referenceable by
reviews, delivery rules and attribution.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Fact, ProcessSummary, ReportFacts
from .io_utils import atomic_write_text, read_jsonl, sha256_bytes, sha256_json

FACTS_FILE = "facts.jsonl"
PROCESSES_FILE = "processes.jsonl"
META_FILE = "report.json"
EVIDENCE_SCHEMA_VERSION = 1

ARTIFACT_KINDS = {
    "cape_payload": "cape_payload",
    "procdump": "procdump",
    "dropped": "dropped",
}


def _evidence_id(report_id: str, kind: str, *parts: object) -> str:
    return sha256_bytes(sha256_json([report_id, kind, *parts]).encode("utf-8"))[:24]


@dataclass
class ArtifactRecord:
    evidence_id: str
    kind: str
    sha256: str | None
    name: str | None
    type: str | None
    size: int | None
    guest_paths: list[str] = field(default_factory=list)
    pid: int | None = None
    process_name: str | None = None
    cape_type: str | None = None
    yara: list[str] = field(default_factory=list)
    cape_yara: list[str] = field(default_factory=list)

    @property
    def resolvable(self) -> bool:
        return bool(self.sha256)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "name": self.name,
            "type": self.type,
            "size": self.size,
            "guest_paths": list(self.guest_paths),
            "pid": self.pid,
            "process_name": self.process_name,
            "cape_type": self.cape_type,
            "yara": list(self.yara),
            "cape_yara": list(self.cape_yara),
        }


@dataclass
class ReportEvidence:
    report_id: str
    report_content_sha256: str
    size_bytes: int
    facts: list[Fact]
    processes: list[ProcessSummary]
    artifacts: list[ArtifactRecord]
    target_sha256: str | None
    target_name: str | None
    avclass_detection: str | None
    detections: list[dict[str, Any]]
    signature_names: list[str]
    quality_flags: list[str]
    coverage_flags: list[str]
    total_calls: int
    enhanced_count: int

    def by_kind(self, kind: str) -> list[Fact]:
        return [fact for fact in self.facts if fact.kind == kind]

    def fact(self, evidence_id: str) -> Fact | None:
        for fact in self.facts:
            if fact.evidence_id == evidence_id:
                return fact
        return None

    def artifact(self, evidence_id: str) -> ArtifactRecord | None:
        for item in self.artifacts:
            if item.evidence_id == evidence_id:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
            "report_id": self.report_id,
            "report_content_sha256": self.report_content_sha256,
            "size_bytes": self.size_bytes,
            "target_sha256": self.target_sha256,
            "target_name": self.target_name,
            "avclass_detection": self.avclass_detection,
            "detections": list(self.detections),
            "signature_names": list(self.signature_names),
            "total_calls": self.total_calls,
            "enhanced_count": self.enhanced_count,
            "quality_flags": list(self.quality_flags),
            "coverage_flags": list(self.coverage_flags),
            "facts": [fact.to_dict() for fact in self.facts],
            "processes": [process.to_dict() for process in self.processes],
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


def _artifact_fact(record: ArtifactRecord, report_id: str) -> Fact:
    return Fact(
        evidence_id=record.evidence_id,
        report_id=report_id,
        rule_id=f"cape.artifact.{record.kind}.v1",
        rule_version="1",
        kind="artifact",
        subject_sha256=record.sha256,
        subject_kind=record.kind,
        event_keys=[],
        source_json_pointers=[],
        limitations=[] if record.resolvable else ["artifact_hash_unavailable"],
        attributes=record.to_dict(),
    )


def collect_report(report: ReportFacts, *, report_id: str | None = None) -> ReportEvidence:
    """Re-key adapter facts so ids are unique per report and add artifact facts."""
    report_id = report_id or report.report_content_sha256
    facts: list[Fact] = []
    rekeyed: dict[str, str] = {}
    for fact in report.facts:
        old_id = fact.evidence_id
        new_id = _evidence_id(report_id, "fact", old_id)
        rekeyed[old_id] = new_id
        fact.evidence_id = new_id
        fact.report_id = report_id
        if fact.process_index is not None:
            fact.process_key = f"{report_id}:{fact.process_index}"
        if fact.subject_sha256 is None and report.target_sha256:
            fact.subject_sha256 = report.target_sha256
            fact.subject_kind = "target_sample"
        facts.append(fact)
    for fact in facts:
        fact.supporting_evidence_ids = [
            rekeyed.get(item, item) for item in fact.supporting_evidence_ids
        ]

    artifacts: list[ArtifactRecord] = []
    for source in report.cape_payloads:
        artifacts.append(_artifact(source, "cape_payload", report_id))
    for source in report.dropped:
        artifacts.append(_artifact(source, "dropped", report_id))
    for source in report.procdump:
        artifacts.append(_artifact(source, "procdump", report_id))

    for record in artifacts:
        facts.append(_artifact_fact(record, report_id))

    return ReportEvidence(
        report_id=report_id,
        report_content_sha256=report.report_content_sha256,
        size_bytes=report.size_bytes,
        facts=facts,
        processes=list(report.processes),
        artifacts=artifacts,
        target_sha256=report.target_sha256,
        target_name=report.target_name,
        avclass_detection=report.avclass_detection,
        detections=list(report.detections),
        signature_names=list(report.signature_names),
        quality_flags=list(report.quality_flags),
        coverage_flags=list(report.coverage_flags),
        total_calls=report.total_calls,
        enhanced_count=report.enhanced_count,
    )


def _artifact(source: dict[str, Any], kind: str, report_id: str) -> ArtifactRecord:
    sha = source.get("sha256")
    return ArtifactRecord(
        evidence_id=_evidence_id(report_id, "artifact", kind, sha, source.get("name")),
        kind=kind,
        sha256=sha,
        name=source.get("name"),
        type=source.get("type"),
        size=source.get("size"),
        guest_paths=list(source.get("guest_paths") or []),
        pid=source.get("pid"),
        process_name=source.get("process_name"),
        cape_type=source.get("cape_type"),
        yara=list(source.get("yara") or []),
        cape_yara=list(source.get("cape_yara") or []),
    )


def _write_jsonl_stream(path: Path, rows) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as stream:
        for row in rows:
            data = (_json_line(row)).encode("utf-8")
            digest.update(data)
            stream.write(data)
            size += len(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return digest.hexdigest(), size


def write_evidence(directory: Path, evidence: ReportEvidence) -> dict[str, str]:
    """Write report.json, facts.jsonl and processes.jsonl; return checksums."""
    directory.mkdir(parents=True, exist_ok=True)
    facts_path = directory / FACTS_FILE
    processes_path = directory / PROCESSES_FILE
    facts_hash, facts_bytes = _write_jsonl_stream(facts_path, (fact.to_dict() for fact in evidence.facts))
    processes_hash, processes_bytes = _write_jsonl_stream(
        processes_path, (process.to_dict() for process in evidence.processes)
    )
    meta = {key: value for key, value in evidence.to_dict().items() if key not in ("facts", "processes")}
    meta["facts_sha256"] = facts_hash
    meta["processes_sha256"] = processes_hash
    meta_hash = atomic_write_text(directory / META_FILE, json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n")
    return {
        "facts_sha256": facts_hash,
        "processes_sha256": processes_hash,
        "report_sha256": meta_hash,
        "facts_bytes": str(facts_bytes),
        "processes_bytes": str(processes_bytes),
    }


def read_report_evidence(directory: Path) -> ReportEvidence | None:
    """Reload a persisted evidence record, verifying its own checksums."""
    import json

    meta_path = directory / META_FILE
    if not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    facts = [Fact(**item) for item in read_jsonl(directory / FACTS_FILE)]
    processes = [ProcessSummary(**item) for item in read_jsonl(directory / PROCESSES_FILE)]
    artifacts = [ArtifactRecord(**item) for item in meta.get("artifacts") or []]
    return ReportEvidence(
        report_id=meta["report_id"],
        report_content_sha256=meta["report_content_sha256"],
        size_bytes=meta["size_bytes"],
        facts=facts,
        processes=processes,
        artifacts=artifacts,
        target_sha256=meta.get("target_sha256"),
        target_name=meta.get("target_name"),
        avclass_detection=meta.get("avclass_detection"),
        detections=list(meta.get("detections") or []),
        signature_names=list(meta.get("signature_names") or []),
        quality_flags=list(meta.get("quality_flags") or []),
        coverage_flags=list(meta.get("coverage_flags") or []),
        total_calls=int(meta.get("total_calls") or 0),
        enhanced_count=int(meta.get("enhanced_count") or 0),
    )


def read_evidence(directory: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    facts = read_jsonl(directory / FACTS_FILE) if (directory / FACTS_FILE).exists() else []
    processes = read_jsonl(directory / PROCESSES_FILE) if (directory / PROCESSES_FILE).exists() else []
    return facts, processes


def evidence_dir(root: Path, report_id: str) -> Path:
    if not report_id or any(ch in report_id for ch in (".", "/", "\\")):
        raise ValueError("report_id must be a hex digest")
    return root / "evidence" / "by_report" / report_id


def _json_line(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
