"""Canonical RunLogger for TemporalKG step-oriented modules.

Ghi 1 record JSON mỗi lần chạy module, lưu vào file log dạng mảng JSON
tại State/Logs/<module>_logs.json.
Tuân thủ tuyệt đối Section 15 của Project Structure & Naming Rules.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class RunLogger:
    """Ghi 1 record JSON mỗi lần chạy module, lưu vào file log dạng mảng JSON."""

    def __init__(self, module: str, log_path: Optional[Path] = None, max_events: int = 5000):
        self.module: str = module
        if log_path is None:
            # Default to State/Logs/<module>_logs.json relative to project root
            base_dir = Path(__file__).resolve().parent.parent
            self.log_path: Path = base_dir / "State" / "Logs" / f"{module}_logs.json"
        else:
            self.log_path = Path(log_path)
        self.max_events: int = max_events
        self.run_id: str = uuid.uuid4().hex[:12]
        self.started_epoch: float = time.time()
        self.events: List[dict] = []
        self.summary: Dict[str, Any] = {}
        self.params: Dict[str, Any] = {}
        self.status: str = "running"
        self.error: Optional[str] = None
        self._finished: bool = False

    def note(self, phase: str, message: str = "", **extra: Any) -> None:
        """Ghi một sự kiện tiến trình (có timestamp + elapsed)."""
        if self._finished or len(self.events) >= self.max_events:
            return
        now = time.time()
        self.events.append({
            "ts": _iso(now),
            "elapsed_s": round(now - self.started_epoch, 3),
            "phase": phase,
            "message": message,
            "extra": {k: v for k, v in extra.items()},
        })

    def set_params(self, params: Optional[Dict[str, Any]] = None, **extra: Any) -> None:
        """Lưu params của run."""
        if params:
            self.params.update(params)
        if extra:
            self.params.update(extra)

    def set_summary(self, **kv: Any) -> None:
        """Bổ sung counter/kết quả cuối step vào summary."""
        if self._finished:
            return
        self.summary.update(kv)

    def finish(self, status: str = "success", error: Optional[str] = None) -> None:
        """Kết thúc run và ghi vào file log."""
        if self._finished:
            return
        self.status = status
        self.error = error
        self._finished = True
        self.flush()

    def _load_existing(self) -> List[dict]:
        """Đọc các record đã có, tương thích cả mảng JSON lẫn JSONL cũ."""
        try:
            text = self.log_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            return []
        if not text:
            return []
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass
        records: List[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                continue
        return records

    def _upsert_record(self, record: dict) -> None:
        """Ghi record theo run_id: đã có thì thay thế, chưa có thì append."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        records = self._load_existing()
        found = False
        for idx, item in enumerate(records):
            if isinstance(item, dict) and item.get("run_id") == self.run_id:
                records[idx] = record
                found = True
                break
        if not found:
            records.append(record)
        tmp = self.log_path.with_name(f"{self.log_path.name}.tmp")
        tmp.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.log_path)

    def flush(self) -> None:
        """Ghi snapshot hiện tại xuống đĩa."""
        finished_epoch = time.time()
        record = {
            "run_id": self.run_id,
            "module": self.module,
            "status": self.status,
            "started_at": _iso(self.started_epoch),
            "finished_at": _iso(finished_epoch) if self._finished else None,
            "duration_seconds": round(finished_epoch - self.started_epoch, 3),
            "params": self.params,
            "events": self.events,
            "summary": self.summary,
            "error": self.error,
        }
        self._upsert_record(record)
