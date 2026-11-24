"""SQLite run state.

The database is the single source of truth for a run; manifests are always rebuilt from
it (never appended to), so a resumed run cannot contain duplicated rows
(SPEC_LOADERFILTER_VI.md section 13).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import SourceRecord
from .io_utils import utc_now_iso

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    mode TEXT NOT NULL,
    scope TEXT NOT NULL,
    policy TEXT NOT NULL,
    semantic_config_hash TEXT NOT NULL,
    analysis_fingerprint TEXT NOT NULL,
    config_path TEXT,
    effective_config_json TEXT,
    counters_json TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    run_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    absolute_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    processing_status TEXT NOT NULL,
    report_id TEXT,
    report_content_sha256 TEXT,
    sample_sha256_filename TEXT,
    sample_sha256_target TEXT,
    sample_sha256 TEXT,
    sample_identity_status TEXT,
    family_identity_status TEXT,
    execution_status TEXT,
    strict_attribution_status TEXT,
    delivery_flags_json TEXT,
    label_pair_state TEXT,
    candidate_reasons_json TEXT,
    is_seed_candidate INTEGER NOT NULL DEFAULT 0,
    is_candidate INTEGER NOT NULL DEFAULT 0,
    machine_decision TEXT,
    machine_decision_reasons_json TEXT,
    effective_decision TEXT,
    human_disposition TEXT,
    error_code TEXT,
    error_message TEXT,
    quality_flags_json TEXT,
    secondary_locators_json TEXT,
    updated_at TEXT,
    PRIMARY KEY (run_id, source_id)
);
CREATE TABLE IF NOT EXISTS reports (
    run_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    content_sha256 TEXT,
    size_bytes INTEGER,
    adapter_version TEXT,
    analysis_fingerprint TEXT,
    facts_path TEXT,
    processes_path TEXT,
    strict_count INTEGER NOT NULL DEFAULT 0,
    bucket_counts_json TEXT,
    status TEXT,
    updated_at TEXT,
    PRIMARY KEY (run_id, report_id, source_id)
);
CREATE TABLE IF NOT EXISTS label_observations (
    run_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_kind TEXT NOT NULL,
    sample_sha256 TEXT,
    raw_label TEXT,
    normalized_label TEXT,
    canonical_family TEXT,
    state TEXT,
    provenance TEXT,
    json_pointer TEXT,
    source_file TEXT,
    source_sha256 TEXT,
    duplicate_count INTEGER DEFAULT 1,
    secondary_raw_label TEXT,
    limitations_json TEXT,
    PRIMARY KEY (run_id, source_id, source_kind, raw_label)
);
CREATE TABLE IF NOT EXISTS jobs (
    run_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error_code TEXT,
    last_error_message TEXT,
    started_at TEXT,
    finished_at TEXT,
    PRIMARY KEY (run_id, source_id)
);
CREATE TABLE IF NOT EXISTS artifacts (
    run_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    size_bytes INTEGER,
    created_at TEXT,
    PRIMARY KEY (run_id, artifact_id)
);
CREATE TABLE IF NOT EXISTS machine_decisions (
    run_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reasons_json TEXT,
    analysis_fingerprint TEXT,
    created_at TEXT,
    PRIMARY KEY (run_id, source_id)
);
CREATE TABLE IF NOT EXISTS review_revisions (
    run_id TEXT NOT NULL,
    review_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    disposition TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    analysis_fingerprint TEXT,
    created_at TEXT,
    PRIMARY KEY (run_id, review_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_sources_report ON sources (run_id, report_id);
CREATE INDEX IF NOT EXISTS idx_sources_sample ON sources (run_id, sample_sha256);
CREATE TABLE IF NOT EXISTS report_meta (
    run_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    updated_at TEXT,
    PRIMARY KEY (run_id, report_id)
);
"""


@dataclass
class RunRow:
    run_id: str
    created_at: str
    status: str
    mode: str
    scope: str
    policy: str
    semantic_config_hash: str
    analysis_fingerprint: str
    config_path: str | None
    effective_config: dict[str, Any]
    counters: dict[str, Any]


class StateStore:
    """Thin, explicit wrapper around the run database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=30.0, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(_SCHEMA)

    # -- lifecycle ---------------------------------------------------------------------
    def close(self) -> None:
        try:
            self.connection.close()
        except sqlite3.Error:  # pragma: no cover - defensive
            pass

    def __enter__(self) -> "StateStore":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- runs --------------------------------------------------------------------------
    def create_run(
        self,
        *,
        run_id: str,
        mode: str,
        scope: str,
        policy: str,
        semantic_config_hash: str,
        analysis_fingerprint: str,
        config_path: str | None,
        effective_config: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO runs (run_id, created_at, status, mode, scope, policy, "
            "semantic_config_hash, analysis_fingerprint, config_path, effective_config_json, counters_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                utc_now_iso(),
                "running",
                mode,
                scope,
                policy,
                semantic_config_hash,
                analysis_fingerprint,
                config_path,
                json.dumps(effective_config, ensure_ascii=False, default=str),
                json.dumps({}, ensure_ascii=False),
            ),
        )

    def get_run(self, run_id: str) -> RunRow | None:
        row = self.connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return RunRow(
            run_id=row["run_id"],
            created_at=row["created_at"],
            status=row["status"],
            mode=row["mode"],
            scope=row["scope"],
            policy=row["policy"],
            semantic_config_hash=row["semantic_config_hash"],
            analysis_fingerprint=row["analysis_fingerprint"],
            config_path=row["config_path"],
            effective_config=json.loads(row["effective_config_json"] or "{}"),
            counters=json.loads(row["counters_json"] or "{}"),
        )

    def update_run_status(self, run_id: str, status: str, counters: dict[str, Any] | None = None) -> None:
        if counters is None:
            self.connection.execute("UPDATE runs SET status = ? WHERE run_id = ?", (status, run_id))
        else:
            self.connection.execute(
                "UPDATE runs SET status = ?, counters_json = ? WHERE run_id = ?",
                (status, json.dumps(counters, ensure_ascii=False, default=str), run_id),
            )

    def list_runs(self) -> list[RunRow]:
        rows = self.connection.execute("SELECT * FROM runs ORDER BY created_at DESC").fetchall()
        return [
            RunRow(
                run_id=row["run_id"],
                created_at=row["created_at"],
                status=row["status"],
                mode=row["mode"],
                scope=row["scope"],
                policy=row["policy"],
                semantic_config_hash=row["semantic_config_hash"],
                analysis_fingerprint=row["analysis_fingerprint"],
                config_path=row["config_path"],
                effective_config=json.loads(row["effective_config_json"] or "{}"),
                counters=json.loads(row["counters_json"] or "{}"),
            )
            for row in rows
        ]

    # -- sources -----------------------------------------------------------------------
    def upsert_source(self, run_id: str, record: SourceRecord) -> None:
        payload = record.to_dict()
        self.connection.execute(
            """
            INSERT INTO sources (
                run_id, source_id, root_id, relative_path, absolute_path, size_bytes, mtime_ns,
                processing_status, report_id, report_content_sha256, sample_sha256_filename,
                sample_sha256_target, sample_sha256, sample_identity_status, family_identity_status,
                execution_status, strict_attribution_status, delivery_flags_json, label_pair_state,
                candidate_reasons_json, is_seed_candidate, is_candidate, machine_decision,
                machine_decision_reasons_json, effective_decision, human_disposition, error_code,
                error_message, quality_flags_json, secondary_locators_json, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id, source_id) DO UPDATE SET
                processing_status=excluded.processing_status,
                report_id=excluded.report_id,
                report_content_sha256=excluded.report_content_sha256,
                sample_sha256_filename=excluded.sample_sha256_filename,
                sample_sha256_target=excluded.sample_sha256_target,
                sample_sha256=excluded.sample_sha256,
                sample_identity_status=excluded.sample_identity_status,
                family_identity_status=excluded.family_identity_status,
                execution_status=excluded.execution_status,
                strict_attribution_status=excluded.strict_attribution_status,
                delivery_flags_json=excluded.delivery_flags_json,
                label_pair_state=excluded.label_pair_state,
                candidate_reasons_json=excluded.candidate_reasons_json,
                is_seed_candidate=excluded.is_seed_candidate,
                is_candidate=excluded.is_candidate,
                machine_decision=excluded.machine_decision,
                machine_decision_reasons_json=excluded.machine_decision_reasons_json,
                effective_decision=excluded.effective_decision,
                human_disposition=excluded.human_disposition,
                error_code=excluded.error_code,
                error_message=excluded.error_message,
                quality_flags_json=excluded.quality_flags_json,
                secondary_locators_json=excluded.secondary_locators_json,
                size_bytes=excluded.size_bytes,
                mtime_ns=excluded.mtime_ns,
                updated_at=excluded.updated_at
            """,
            (
                run_id,
                payload["source_id"],
                payload["root_id"],
                payload["relative_path"],
                payload["absolute_path"],
                payload["size_bytes"],
                payload["mtime_ns"],
                payload["processing_status"],
                payload["report_id"],
                payload["report_content_sha256"],
                payload["sample_sha256_filename"],
                payload["sample_sha256_target"],
                payload["sample_sha256"],
                payload["sample_identity_status"],
                payload["family_identity_status"],
                payload["execution_status"],
                payload["strict_attribution_status"],
                json.dumps(payload["delivery_flags"], ensure_ascii=False),
                payload["label_pair_state"],
                json.dumps(payload["candidate_reasons"], ensure_ascii=False),
                int(payload["is_seed_candidate"]),
                int(payload["is_candidate"]),
                payload["machine_decision"],
                json.dumps(payload["machine_decision_reasons"], ensure_ascii=False),
                payload["effective_decision"],
                payload["human_disposition"],
                payload["error_code"],
                payload["error_message"],
                json.dumps(payload["quality_flags"], ensure_ascii=False),
                json.dumps(payload["secondary_locators"], ensure_ascii=False),
                utc_now_iso(),
            ),
        )

    def upsert_sources(self, run_id: str, records: Iterable[SourceRecord]) -> int:
        count = 0
        for record in records:
            self.upsert_source(run_id, record)
            count += 1
        return count

    def get_source(self, run_id: str, source_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM sources WHERE run_id = ? AND source_id = ?", (run_id, source_id)
        ).fetchone()
        return _source_row_to_dict(row) if row else None

    def get_sources_by_report(self, run_id: str, report_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM sources WHERE run_id = ? AND report_id = ? ORDER BY source_id", (run_id, report_id)
        ).fetchall()
        return [_source_row_to_dict(row) for row in rows]

    def list_sources(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM sources WHERE run_id = ? ORDER BY root_id, relative_path", (run_id,)
        ).fetchall()
        return [_source_row_to_dict(row) for row in rows]

    def count_sources_by_status(self, run_id: str) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT processing_status, COUNT(*) AS n FROM sources WHERE run_id = ? GROUP BY processing_status",
            (run_id,),
        ).fetchall()
        return {row["processing_status"]: row["n"] for row in rows}

    # -- reports -----------------------------------------------------------------------
    def upsert_report(
        self,
        run_id: str,
        *,
        report_id: str,
        source_id: str,
        content_sha256: str,
        size_bytes: int,
        adapter_version: str,
        analysis_fingerprint: str,
        facts_path: str | None,
        processes_path: str | None,
        strict_count: int,
        bucket_counts: dict[str, int],
        status: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO reports (run_id, report_id, source_id, content_sha256, size_bytes, adapter_version,
                                 analysis_fingerprint, facts_path, processes_path, strict_count,
                                 bucket_counts_json, status, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id, report_id, source_id) DO UPDATE SET
                content_sha256=excluded.content_sha256,
                size_bytes=excluded.size_bytes,
                adapter_version=excluded.adapter_version,
                analysis_fingerprint=excluded.analysis_fingerprint,
                facts_path=excluded.facts_path,
                processes_path=excluded.processes_path,
                strict_count=excluded.strict_count,
                bucket_counts_json=excluded.bucket_counts_json,
                status=excluded.status,
                updated_at=excluded.updated_at
            """,
            (
                run_id,
                report_id,
                source_id,
                content_sha256,
                size_bytes,
                adapter_version,
                analysis_fingerprint,
                facts_path,
                processes_path,
                strict_count,
                json.dumps(bucket_counts, ensure_ascii=False),
                status,
                utc_now_iso(),
            ),
        )

    def list_reports(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM reports WHERE run_id = ? ORDER BY report_id, source_id", (run_id,)
        ).fetchall()
        return [
            {
                "report_id": row["report_id"],
                "source_id": row["source_id"],
                "content_sha256": row["content_sha256"],
                "size_bytes": row["size_bytes"],
                "adapter_version": row["adapter_version"],
                "analysis_fingerprint": row["analysis_fingerprint"],
                "facts_path": row["facts_path"],
                "processes_path": row["processes_path"],
                "strict_count": row["strict_count"],
                "bucket_counts": json.loads(row["bucket_counts_json"] or "{}"),
                "status": row["status"],
            }
            for row in rows
        ]

    # -- report metadata ---------------------------------------------------------------
    def upsert_report_meta(self, run_id: str, report_id: str, metadata: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO report_meta (run_id, report_id, metadata_json, updated_at) "
            "VALUES (?,?,?,?)",
            (run_id, report_id, json.dumps(metadata, ensure_ascii=False, default=str), utc_now_iso()),
        )

    def list_report_meta(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT report_id, metadata_json FROM report_meta WHERE run_id = ? ORDER BY report_id",
            (run_id,),
        ).fetchall()
        result = []
        for row in rows:
            metadata = json.loads(row["metadata_json"] or "{}")
            metadata["report_id"] = row["report_id"]
            result.append(metadata)
        return result

    def get_report_meta(self, run_id: str, report_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT metadata_json FROM report_meta WHERE run_id = ? AND report_id = ?",
            (run_id, report_id),
        ).fetchone()
        if row is None:
            return None
        metadata = json.loads(row["metadata_json"] or "{}")
        metadata["report_id"] = report_id
        return metadata

    # -- label observations ------------------------------------------------------------
    def upsert_label_observations(self, run_id: str, source_id: str, observations: Iterable[dict[str, Any]]) -> int:
        count = 0
        for observation in observations:
            self.connection.execute(
                """
                INSERT INTO label_observations (run_id, source_id, source_kind, sample_sha256, raw_label,
                    normalized_label, canonical_family, state, provenance, json_pointer, source_file,
                    source_sha256, duplicate_count, secondary_raw_label, limitations_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id, source_id, source_kind, raw_label) DO UPDATE SET
                    normalized_label=excluded.normalized_label,
                    canonical_family=excluded.canonical_family,
                    state=excluded.state,
                    provenance=excluded.provenance,
                    json_pointer=excluded.json_pointer,
                    source_file=excluded.source_file,
                    source_sha256=excluded.source_sha256,
                    duplicate_count=excluded.duplicate_count,
                    secondary_raw_label=excluded.secondary_raw_label,
                    limitations_json=excluded.limitations_json
                """,
                (
                    run_id,
                    source_id,
                    observation["source_kind"],
                    observation["sample_sha256"],
                    observation["raw_label"],
                    observation["normalized_label"],
                    observation["canonical_family"],
                    observation["state"],
                    observation["provenance"],
                    observation["json_pointer"],
                    observation["source_file"],
                    observation["source_sha256"],
                    observation["duplicate_count"],
                    observation["secondary_raw_label"],
                    json.dumps(observation["limitations"], ensure_ascii=False),
                ),
            )
            count += 1
        return count

    def list_label_observations(self, run_id: str, source_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM label_observations WHERE run_id = ? AND source_id = ? ORDER BY source_kind, raw_label",
            (run_id, source_id),
        ).fetchall()
        return [
            {
                "source_kind": row["source_kind"],
                "sample_sha256": row["sample_sha256"],
                "raw_label": row["raw_label"],
                "normalized_label": row["normalized_label"],
                "canonical_family": row["canonical_family"],
                "state": row["state"],
                "provenance": row["provenance"],
                "json_pointer": row["json_pointer"],
                "source_file": row["source_file"],
                "source_sha256": row["source_sha256"],
                "duplicate_count": row["duplicate_count"],
                "secondary_raw_label": row["secondary_raw_label"],
                "limitations": json.loads(row["limitations_json"] or "[]"),
            }
            for row in rows
        ]

    # -- jobs --------------------------------------------------------------------------
    def set_job(
        self,
        run_id: str,
        source_id: str,
        status: str,
        *,
        error_code: str | None = None,
        error_message: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        increment_attempts: bool = False,
    ) -> None:
        now = utc_now_iso()
        self.connection.execute(
            """
            INSERT INTO jobs (run_id, source_id, status, attempts, last_error_code, last_error_message,
                              started_at, finished_at)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id, source_id) DO UPDATE SET
                status=excluded.status,
                attempts=jobs.attempts + ?,
                last_error_code=excluded.last_error_code,
                last_error_message=excluded.last_error_message,
                started_at=COALESCE(excluded.started_at, jobs.started_at),
                finished_at=excluded.finished_at
            """,
            (
                run_id,
                source_id,
                status,
                1 if increment_attempts else 0,
                error_code,
                error_message,
                started_at or now,
                finished_at,
                1 if increment_attempts else 0,
            ),
        )

    def list_jobs(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM jobs WHERE run_id = ? ORDER BY source_id", (run_id,)).fetchall()
        return [
            {
                "source_id": row["source_id"],
                "status": row["status"],
                "attempts": row["attempts"],
                "last_error_code": row["last_error_code"],
                "last_error_message": row["last_error_message"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
            }
            for row in rows
        ]

    # -- artifacts ---------------------------------------------------------------------
    def add_artifact(
        self,
        run_id: str,
        *,
        artifact_id: str,
        kind: str,
        path: str,
        sha256: str | None,
        size_bytes: int | None,
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO artifacts (run_id, artifact_id, kind, path, sha256, size_bytes, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (run_id, artifact_id, kind, path, sha256, size_bytes, utc_now_iso()),
        )

    def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY artifact_id", (run_id,)).fetchall()
        return [
            {
                "artifact_id": row["artifact_id"],
                "kind": row["kind"],
                "path": row["path"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    # -- decisions ---------------------------------------------------------------------
    def record_machine_decision(
        self,
        run_id: str,
        source_id: str,
        decision: str,
        reasons: list[str],
        analysis_fingerprint: str,
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO machine_decisions (run_id, source_id, decision, reasons_json, "
            "analysis_fingerprint, created_at) VALUES (?,?,?,?,?,?)",
            (run_id, source_id, decision, json.dumps(reasons, ensure_ascii=False), analysis_fingerprint, utc_now_iso()),
        )

    def list_machine_decisions(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM machine_decisions WHERE run_id = ? ORDER BY source_id", (run_id,)
        ).fetchall()
        return [
            {
                "source_id": row["source_id"],
                "decision": row["decision"],
                "reasons": json.loads(row["reasons_json"] or "[]"),
                "analysis_fingerprint": row["analysis_fingerprint"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    # -- reviews -----------------------------------------------------------------------
    def add_review_revision(
        self,
        run_id: str,
        *,
        review_id: str,
        source_id: str,
        revision: int,
        disposition: str,
        payload: dict[str, Any],
        analysis_fingerprint: str,
    ) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO review_revisions (run_id, review_id, source_id, revision, disposition, "
            "payload_json, analysis_fingerprint, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                run_id,
                review_id,
                source_id,
                revision,
                disposition,
                json.dumps(payload, ensure_ascii=False, default=str),
                analysis_fingerprint,
                utc_now_iso(),
            ),
        )

    def list_review_revisions(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM review_revisions WHERE run_id = ? ORDER BY source_id, revision", (run_id,)
        ).fetchall()
        return [
            {
                "review_id": row["review_id"],
                "source_id": row["source_id"],
                "revision": row["revision"],
                "disposition": row["disposition"],
                "payload": json.loads(row["payload_json"] or "{}"),
                "analysis_fingerprint": row["analysis_fingerprint"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    # -- transactions ------------------------------------------------------------------
    def begin(self) -> None:
        self.connection.execute("BEGIN")

    def commit(self) -> None:
        if self.connection.in_transaction:
            self.connection.execute("COMMIT")

    def rollback(self) -> None:
        try:
            self.connection.execute("ROLLBACK")
        except sqlite3.Error:  # pragma: no cover - defensive
            pass


def _source_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source_id": row["source_id"],
        "root_id": row["root_id"],
        "relative_path": row["relative_path"],
        "absolute_path": row["absolute_path"],
        "size_bytes": row["size_bytes"],
        "mtime_ns": row["mtime_ns"],
        "processing_status": row["processing_status"],
        "report_id": row["report_id"],
        "report_content_sha256": row["report_content_sha256"],
        "sample_sha256_filename": row["sample_sha256_filename"],
        "sample_sha256_target": row["sample_sha256_target"],
        "sample_sha256": row["sample_sha256"],
        "sample_identity_status": row["sample_identity_status"],
        "family_identity_status": row["family_identity_status"],
        "execution_status": row["execution_status"],
        "strict_attribution_status": row["strict_attribution_status"],
        "delivery_flags": json.loads(row["delivery_flags_json"] or "{}"),
        "label_pair_state": row["label_pair_state"],
        "candidate_reasons": json.loads(row["candidate_reasons_json"] or "[]"),
        "is_seed_candidate": bool(row["is_seed_candidate"]),
        "is_candidate": bool(row["is_candidate"]),
        "machine_decision": row["machine_decision"],
        "machine_decision_reasons": json.loads(row["machine_decision_reasons_json"] or "[]"),
        "effective_decision": row["effective_decision"],
        "human_disposition": row["human_disposition"],
        "error_code": row["error_code"],
        "error_message": row["error_message"],
        "quality_flags": json.loads(row["quality_flags_json"] or "[]"),
        "secondary_locators": json.loads(row["secondary_locators_json"] or "[]"),
    }
