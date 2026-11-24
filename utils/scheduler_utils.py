"""Process-pool scheduler for report parsing.

A Windows ``spawn`` pool is used because the adapter keeps no global state. A task that
exceeds ``report_timeout_seconds`` cannot be cancelled reliably, so the whole pool is
terminated and recreated; the remaining in-flight tasks are resubmitted once and then
reported as ``resource_limit`` if they time out again.
"""

from __future__ import annotations

import dataclasses
import multiprocessing
import multiprocessing.pool
import time
from collections import deque
from pathlib import Path
from typing import Any, Iterator

from .cape_adapter import CapeAdapter, ParseLimits
from .models import Fact, ProcessSummary, ReportFacts

MAX_TIMEOUT_RETRIES = 1


def report_facts_from_dict(data: dict[str, Any]) -> ReportFacts:
    """Rebuild a :class:`ReportFacts` from ``ReportFacts.to_dict()`` output."""
    facts = [Fact(**item) for item in data.get("facts") or []]
    processes = [ProcessSummary(**item) for item in data.get("processes") or []]
    kwargs: dict[str, Any] = {}
    for field in dataclasses.fields(ReportFacts):
        if field.name in ("facts", "processes"):
            continue
        kwargs[field.name] = data.get(field.name)
    return ReportFacts(facts=facts, processes=processes, **kwargs)


def parse_task(payload: dict[str, Any]) -> dict[str, Any]:
    """Entry point executed inside a worker process."""
    adapter = CapeAdapter()
    limits = ParseLimits(**payload["limits"])
    outcome = adapter.parse(Path(payload["path"]), limits)
    return {
        "source_id": payload["source_id"],
        "error_code": outcome.error_code,
        "error_message": outcome.error_message,
        "diagnostics": outcome.diagnostics,
        "content_sha256": outcome.content_sha256,
        "size_bytes": outcome.size_bytes,
        "facts": outcome.facts.to_dict() if outcome.facts is not None else None,
    }


class ParseScheduler:
    def __init__(self, *, workers: int, timeout_seconds: int, limits: ParseLimits):
        self.workers = max(1, int(workers))
        self.timeout_seconds = int(timeout_seconds)
        self.limits = limits
        self._context = multiprocessing.get_context("spawn")
        self._pool: multiprocessing.pool.Pool | None = None
        self.resets = 0

    def __enter__(self) -> "ParseScheduler":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _ensure_pool(self) -> multiprocessing.pool.Pool:
        if self._pool is None:
            self._pool = self._context.Pool(processes=self.workers)
        return self._pool

    def close(self) -> None:
        if self._pool is not None:
            self._pool.terminate()
            self._pool.join()
            self._pool = None

    def _reset(self) -> None:
        self.close()
        self.resets += 1

    def _payload(self, source_id: str, path: Path) -> dict[str, Any]:
        return {"source_id": source_id, "path": str(path), "limits": dataclasses.asdict(self.limits)}

    def map(self, items: list[tuple[str, Path]]) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield ``(source_id, result)`` as tasks finish, honouring the timeout."""
        queue = deque(items)
        attempts: dict[str, int] = {}
        inflight: dict[Any, dict[str, Any]] = {}
        pool = self._ensure_pool()

        def submit() -> None:
            nonlocal pool
            while queue and len(inflight) < self.workers:
                source_id, path = queue.popleft()
                async_result = pool.apply_async(parse_task, (self._payload(source_id, path),))
                inflight[async_result] = {"source_id": source_id, "path": path, "started": time.monotonic()}

        def timeout_result(source_id: str) -> dict[str, Any]:
            return {
                "source_id": source_id,
                "error_code": "resource_limit",
                "error_message": f"report parsing exceeded {self.timeout_seconds}s timeout",
                "diagnostics": {"limit": "report_timeout_seconds", "observed": self.timeout_seconds},
                "content_sha256": None,
                "size_bytes": 0,
                "facts": None,
            }

        submit()
        while inflight:
            finished = False
            for async_result, meta in list(inflight.items()):
                if not async_result.ready():
                    continue
                finished = True
                del inflight[async_result]
                try:
                    result = async_result.get(timeout=0)
                except Exception as exc:  # noqa: BLE001 - worker crash becomes a task error
                    result = {
                        "source_id": meta["source_id"],
                        "error_code": "worker_crash",
                        "error_message": f"{type(exc).__name__}: {exc}",
                        "diagnostics": {},
                        "content_sha256": None,
                        "size_bytes": 0,
                        "facts": None,
                    }
                yield meta["source_id"], result
                submit()
            if not inflight:
                break
            if finished:
                continue

            now = time.monotonic()
            expired = [key for key, meta in inflight.items() if now - meta["started"] > self.timeout_seconds]
            if not expired:
                time.sleep(0.02)
                continue

            for key in expired:
                meta = inflight.pop(key)
                attempts[meta["source_id"]] = attempts.get(meta["source_id"], 0) + 1
                if attempts[meta["source_id"]] > MAX_TIMEOUT_RETRIES:
                    yield meta["source_id"], timeout_result(meta["source_id"])
                else:
                    queue.appendleft((meta["source_id"], meta["path"]))
            remaining = [(meta["source_id"], meta["path"]) for meta in inflight.values()]
            self._reset()
            pool = self._ensure_pool()
            inflight.clear()
            queue.extendleft(reversed(remaining))
            submit()
