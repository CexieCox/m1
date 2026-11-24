"""Streaming CAPE JSON adapter.

The parser is an event-level state machine built on ``ijson.parse``. It never calls
``ijson.items(..., 'behavior.processes.item')`` and never builds a whole process object
containing millions of calls: each call map is assembled on its own, converted to a
compact fact if it is relevant, and released immediately
(SPEC_LOADERFILTER_VI.md section 9).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import ijson

from .errors import ReportProcessingError, ResourceLimitError, SourceChangedError, UnsupportedReportError
from .models import Fact, ProcessSummary, ReportFacts
from .io_utils import is_sha256, sha256_bytes

from dataclasses import dataclass, field
from typing import Protocol

@dataclass
class ParseLimits:
    max_file_bytes: int = 2147483648
    max_call_record_bytes: int = 16777216
    max_json_depth: int = 128
    timeout_seconds: int = 600

@dataclass
class ParseOutcome:
    facts: ReportFacts | None = None
    error_code: str | None = None
    error_message: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    content_sha256: str | None = None
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return self.facts is not None and self.error_code is None

class Adapter(Protocol):
    name: str
    version: str

    def parse(self, path: Path, limits: ParseLimits) -> ParseOutcome: ...

ADAPTER_NAME = "cape"
ADAPTER_VERSION = "cape-json-v1"
RULES_VERSION = "1"
POLICY_VERSION = "conservative-v1"

#: arrays whose items are dispatched one by one and never collected
UNCOLLECTED_ARRAYS = {
    ("detections",),
    ("signatures",),
    ("procdump",),
    ("dropped",),
    ("CAPE", "payloads"),
    ("behavior", "processes"),
    ("behavior", "processes", "*", "calls"),
    ("behavior", "enhanced"),
    ("behavior", "processtree"),
}

#: subtrees that are skipped entirely (large and not used by conservative-v1)
SKIP_PREFIXES = {
    ("target", "file", "pe"),
    ("target", "file", "strings"),
    ("target", "file", "data"),
    ("target", "file", "virustotal"),
    ("target", "file", "yara"),
    ("target", "file", "cape_yara"),
    ("procdump", "*", "pe"),
    ("procdump", "*", "dotnet"),
    ("procdump", "*", "strings"),
    ("procdump", "*", "data"),
    ("dropped", "*", "data"),
    ("dropped", "*", "strings"),
    ("CAPE", "payloads", "*", "data"),
    ("CAPE", "payloads", "*", "strings"),
    ("info",),
    ("debug",),
    ("network",),
    ("procmemory",),
    ("behavior", "summary"),
    ("behavior", "anomaly"),
    ("behavior", "encryptedbuffers"),
    ("CAPE", "configs"),
}

PROCESS_CREATE_APIS = {
    "CreateProcessInternalW",
    "CreateProcessW",
    "CreateProcessA",
    "NtCreateUserProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "ShellExecuteExW",
    "ShellExecuteExA",
    "WinExec",
    "RtlCreateUserProcess",
}
REMOTE_THREAD_APIS = {
    "NtCreateThreadEx",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "RtlCreateUserThread",
    "NtQueueApcThread",
    "QueueUserAPC",
}
REMOTE_WRITE_APIS = {
    "NtWriteVirtualMemory",
    "WriteProcessMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "VirtualAllocEx",
    "VirtualProtectEx",
}
MEMORY_APIS = {
    "NtAllocateVirtualMemory",
    "VirtualAlloc",
    "NtProtectVirtualMemory",
    "VirtualProtect",
    "NtFreeVirtualMemory",
}
FILE_APIS = {"NtCreateFile", "NtOpenFile", "CreateFileW", "CreateFileA", "NtWriteFile", "WriteFile"}
NETWORK_APIS = {
    "InternetConnectW",
    "InternetConnectA",
    "InternetOpenW",
    "InternetOpenUrlW",
    "InternetOpenUrlA",
    "HttpOpenRequestW",
    "URLDownloadToFileW",
    "URLDownloadToFileA",
    "WinHttpConnect",
    "WinHttpOpen",
    "WinHttpOpenRequest",
    "send",
    "recv",
    "WSASend",
    "WSARecv",
}
DOWNLOAD_APIS = {"URLDownloadToFileW", "URLDownloadToFileA", "InternetOpenUrlW", "InternetOpenUrlA"}
#: APIs where the PID argument is a genuine created-process out-parameter
PID_OUT_APIS = {"NtCreateUserProcess", "NtCreateProcess", "NtCreateProcessEx", "RtlCreateUserProcess"}
HANDLE_APIS = {"NtOpenProcess", "OpenProcess", "NtClose", "CloseHandle", "NtDuplicateObject"}
INTERESTING_APIS = (
    PROCESS_CREATE_APIS
    | REMOTE_THREAD_APIS
    | REMOTE_WRITE_APIS
    | MEMORY_APIS
    | FILE_APIS
    | NETWORK_APIS
    | HANDLE_APIS
)

NTSTATUS_APIS = {
    "NtCreateUserProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtWriteVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtFreeVirtualMemory",
    "NtCreateFile",
    "NtOpenFile",
    "NtWriteFile",
    "NtOpenProcess",
    "NtClose",
    "NtDuplicateObject",
}
BOOL_APIS = {
    "CreateProcessInternalW",
    "CreateProcessW",
    "CreateProcessA",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "VirtualProtectEx",
    "CloseHandle",
    "WriteFile",
    "WinExec",
}
HANDLE_RESULT_APIS = {
    "OpenProcess",
    "CreateFileW",
    "CreateFileA",
    "WinHttpOpen",
    "WinHttpConnect",
    "InternetConnectW",
    "InternetConnectA",
    "InternetOpenW",
}

MAX_ARRAY_ITEMS = 5_000_000


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


class _HashingReader:
    """Binary reader that hashes every byte exactly once."""

    def __init__(self, stream: Any):
        self.stream = stream
        self.digest = hashlib.sha256()
        self.size = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self.stream.read(size)
        if chunk:
            self.digest.update(chunk)
            self.size += len(chunk)
        return chunk

    def drain(self) -> int:
        extra = 0
        while True:
            chunk = self.stream.read(1024 * 1024)
            if not chunk:
                return extra
            self.digest.update(chunk)
            self.size += len(chunk)
            extra += len(chunk)


def _normalize_path(path: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple("*" if isinstance(part, int) else part for part in path)


def _is_skipped(path: tuple[Any, ...]) -> bool:
    normalized = _normalize_path(path)
    if normalized[:2] == ("behavior", "processtree") and normalized.count("children") >= 2:
        # CAPE sometimes emits pathological children-of-children chains that carry no
        # extra information: child pids are already known from behavior.processes.
        return True
    for prefix in SKIP_PREFIXES:
        if len(normalized) >= len(prefix) and normalized[: len(prefix)] == prefix:
            return True
    return False


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def _hex_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return _as_int(value)
    text = value.strip().lower()
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text)
    except ValueError:
        return None


def _guest_paths(value: Any) -> list[str]:
    items: list[str] = []
    for entry in _as_list(value):
        if not isinstance(entry, str):
            continue
        parts = entry.split(";?") if ";?" in entry else [entry]
        for index, part in enumerate(parts):
            part = part.strip().lstrip("?").strip()
            if index == 0 and parts[0].strip().isdigit():
                continue  # leading occurrence count in the "1;?C:\..." form
            if part and part not in items:
                items.append(part)
    return items


def _decode_result(api: str, status: Any, raw_return: Any) -> tuple[str, list[str]]:
    """Decode an API result. Never treat a missing value as success."""
    limitations: list[str] = []
    value = _hex_int(raw_return)
    if value is None:
        return "unknown", ["api_result_unavailable"]
    if api in NTSTATUS_APIS:
        success = value == 0
        kind = "ntstatus"
    elif api in BOOL_APIS:
        success = value != 0
        kind = "bool"
    elif api in HANDLE_RESULT_APIS:
        success = value not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
        kind = "handle"
    else:
        return "unknown", ["api_result_not_decoded"]
    if isinstance(status, bool) and status != success:
        limitations.append("api_status_return_conflict")
        return "unknown", limitations
    if isinstance(status, bool) and status is False:
        limitations.append("api_status_false")
    return ("success" if success else "failure"), limitations


def _arg_values(arguments: Any) -> tuple[dict[str, list[str]], bool]:
    """Return a case-insensitive multi-value argument map and an ambiguity flag."""
    values: dict[str, list[str]] = {}
    ambiguous = False
    for item in _as_list(arguments):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        key = name.strip().casefold()
        raw = item.get("pretty_value")
        if raw is None:
            raw = item.get("value")
        text = "" if raw is None else str(raw)
        bucket = values.setdefault(key, [])
        if bucket and text not in bucket:
            ambiguous = True
        bucket.append(text)
    return values, ambiguous


def _arg(args: dict[str, list[str]], *names: str) -> tuple[str | None, bool]:
    for name in names:
        bucket = args.get(name.casefold())
        if bucket:
            if len(bucket) > 1 and len(set(bucket)) > 1:
                return None, True
            return bucket[0], False
    return None, False


def _evidence_id(kind: str, process_index: int | None, call_index: int | None, extra: str = "") -> str:
    return sha256_bytes(f"{kind}|{process_index}|{call_index}|{extra}".encode("utf-8"))[:20]


@dataclass
class _ProcessState:
    index: int
    meta: dict[str, Any] = field(default_factory=dict)
    call_count: int = 0
    enhanced_count: int = 0
    api_counts: Counter = field(default_factory=Counter)
    category_counts: Counter = field(default_factory=Counter)
    handle_targets: dict[str, int | None] = field(default_factory=dict)
    unresolved_handles: set[str] = field(default_factory=set)
    remote_write_pids: set[int] = field(default_factory=set)
    remote_thread_pids: set[int] = field(default_factory=set)
    created_child_pids: set[int] = field(default_factory=set)
    has_network_activity: bool = False
    has_download_api: bool = False
    has_file_create: bool = False
    has_file_write: bool = False
    has_remote_write: bool = False
    has_remote_thread: bool = False
    has_process_create: bool = False
    first_call_index: int | None = None
    last_call_index: int | None = None
    role_hints: list[str] = field(default_factory=list)
    invalid_handle_uses: int = 0


class CapeAdapter:
    name = ADAPTER_NAME
    version = ADAPTER_VERSION

    def parse(self, path: Path, limits: ParseLimits) -> ParseOutcome:
        path = Path(path)
        outcome = ParseOutcome()
        try:
            info_before = os.stat(path)
        except OSError as exc:
            outcome.error_code = "source_missing"
            outcome.error_message = f"cannot stat report: {exc}"
            return outcome
        if info_before.st_size > limits.max_file_bytes:
            outcome.error_code = "resource_limit"
            outcome.error_message = (
                f"report size {info_before.st_size} exceeds max_file_bytes {limits.max_file_bytes}"
            )
            outcome.diagnostics = {"limit": "max_file_bytes", "observed": info_before.st_size}
            return outcome

        collector = _Collector(limits)
        reader: _HashingReader | None = None
        started = time.monotonic()
        try:
            with open(path, "rb") as stream:
                reader = _HashingReader(stream)
                collector.feed(reader)
                collector.finish()
                reader.drain()
        except ResourceLimitError as exc:
            outcome.error_code = "resource_limit"
            outcome.error_message = exc.message
            outcome.diagnostics = exc.details or {}
            outcome.content_sha256 = reader.digest.hexdigest() if reader else None
            outcome.size_bytes = reader.size if reader else 0
            return outcome
        except SourceChangedError as exc:
            outcome.error_code = "source_changed"
            outcome.error_message = exc.message
            return outcome
        except UnsupportedReportError as exc:
            outcome.error_code = "unsupported_schema"
            outcome.error_message = exc.message
            return outcome
        except (ijson.JSONError, json.JSONDecodeError) as exc:
            outcome.error_code = "invalid_json"
            outcome.error_message = f"invalid or truncated JSON: {exc}"
            outcome.content_sha256 = reader.digest.hexdigest() if reader else None
            outcome.size_bytes = reader.size if reader else 0
            return outcome
        except _DuplicateKey as exc:
            outcome.error_code = "duplicate_json_key"
            outcome.error_message = str(exc)
            return outcome
        except ReportProcessingError as exc:
            outcome.error_code = exc.error_code
            outcome.error_message = exc.message
            outcome.diagnostics = exc.details if isinstance(exc.details, dict) else {}
            return outcome

        elapsed = time.monotonic() - started
        outcome.content_sha256 = reader.digest.hexdigest()
        outcome.size_bytes = reader.size
        try:
            info_after = os.stat(path)
        except OSError:
            outcome.error_code = "source_changed"
            outcome.error_message = "report disappeared while being parsed"
            return outcome
        if info_after.st_size != info_before.st_size or info_after.st_mtime_ns != info_before.st_mtime_ns:
            outcome.error_code = "source_changed"
            outcome.error_message = "report changed while being parsed"
            return outcome

        facts = collector.build(report_id=outcome.content_sha256, size_bytes=outcome.size_bytes)
        if elapsed > limits.timeout_seconds:
            outcome.error_code = "resource_limit"
            outcome.error_message = f"parse took {elapsed:.1f}s, above report_timeout_seconds"
            outcome.content_sha256 = outcome.content_sha256
            outcome.size_bytes = outcome.size_bytes
            return outcome
        outcome.facts = facts
        outcome.diagnostics = {
            "elapsed_seconds": round(elapsed, 3),
            "processes": len(facts.processes),
            "calls": facts.total_calls,
            "enhanced": facts.enhanced_count,
            "bytes_read": outcome.size_bytes,
        }
        return outcome


class _DuplicateKey(ReportProcessingError):
    def __init__(self, message: str):
        super().__init__("duplicate_json_key", message)


@dataclass
class _Frame:
    kind: str
    key: str | None
    path: tuple[Any, ...]
    data: Any
    seen: set[str] = field(default_factory=set)


class _Collector:
    def __init__(self, limits: ParseLimits):
        self.limits = limits
        self.frames: list[_Frame] = []
        self.counters: dict[tuple[Any, ...], int] = {}
        self.processes: dict[int, _ProcessState] = {}
        self.facts: list[Fact] = []
        self.detections: list[dict[str, Any]] = []
        self.payloads: list[dict[str, Any]] = []
        self.dropped: list[dict[str, Any]] = []
        self.procdump: list[dict[str, Any]] = []
        self.signatures: list[dict[str, Any]] = []
        self.tree_nodes: list[dict[str, Any]] = []
        self.enhanced_counts: Counter = Counter()
        self.target: dict[str, Any] = {}
        self.avclass_detection: str | None = None
        self.quality_flags: list[str] = []
        self.field_presence: set[str] = set()
        self.total_calls = 0
        self.total_enhanced = 0
        self.root_seen = False
        self.root_is_map: bool | None = None
        self.skip_depth = 0
        self.started = time.monotonic()
        self._last_time_check = 0

    # -- parsing -----------------------------------------------------------------------
    def feed(self, reader: Any) -> None:
        for _prefix, event, value in ijson.parse(reader):
            if self.skip_depth:
                if event in ("start_map", "start_array"):
                    self.skip_depth += 1
                elif event in ("end_map", "end_array"):
                    self.skip_depth -= 1
                continue
            if event == "start_map":
                path = self._child_path()
                if path and _is_skipped(path):
                    if _normalize_path(path)[:2] == ("behavior", "processtree"):
                        self.quality_flags.append("processtree_children_truncated")
                    self.skip_depth = 1
                    continue
                self._check_depth(path)
                self.root_seen = True
                if not self.frames:
                    self.root_is_map = True
                self.frames.append(_Frame("map", self._pending_key(), path, {}))
            elif event == "start_array":
                path = self._child_path()
                if path and _is_skipped(path):
                    if _normalize_path(path)[:2] == ("behavior", "processtree"):
                        self.quality_flags.append("processtree_children_truncated")
                    self.skip_depth = 1
                    continue
                self._check_depth(path)
                collect = _normalize_path(path) not in UNCOLLECTED_ARRAYS
                self.frames.append(_Frame("array", self._pending_key(), path, [] if collect else {"items": 0}))
            elif event == "end_map":
                frame = self.frames.pop()
                self._on_map_end(frame)
            elif event == "end_array":
                frame = self.frames.pop()
                self._on_array_end(frame)
            elif event == "map_key":
                frame = self.frames[-1]
                if frame.kind != "map":
                    raise UnsupportedReportError("map_key outside a map")
                if value in frame.seen:
                    raise _DuplicateKey(f"duplicate JSON key {value!r} at {'/'.join(map(str, frame.path))}")
                frame.seen.add(value)
                frame.key = value
            else:
                frame = self.frames[-1]
                if frame.kind == "map":
                    if frame.key is None:
                        raise UnsupportedReportError("scalar without key")
                    frame.data[frame.key] = value
                    frame.key = None
                else:
                    if isinstance(frame.data, list):
                        frame.data.append(value)
                    else:
                        frame.data["items"] += 1

    def finish(self) -> None:
        if not self.root_seen or self.root_is_map is not True:
            raise UnsupportedReportError("report must be a JSON object with a CAPE/CAPE-like shape")
        if not self.processes and not self.target and not self.payloads and not self.procdump:
            raise UnsupportedReportError("report does not contain CAPE target/behavior fields")

    def _pending_key(self) -> str | None:
        if not self.frames:
            return None
        parent = self.frames[-1]
        if parent.kind == "map":
            key = parent.key
            parent.key = None
            return key
        return None

    def _child_path(self) -> tuple[Any, ...]:
        if not self.frames:
            return ()
        parent = self.frames[-1]
        if parent.kind == "map":
            key = parent.key
            return parent.path + ((key,) if key is not None else ("?",))
        index = self.counters.get(parent.path, 0)
        self.counters[parent.path] = index + 1
        return parent.path + (index,)

    def _check_depth(self, path: tuple[Any, ...]) -> None:
        if len(path) > self.limits.max_json_depth:
            raise ResourceLimitError(
                f"JSON depth {len(path)} exceeds max_json_depth {self.limits.max_json_depth}",
                limit="max_json_depth",
                observed=len(path),
            )

    # -- frame completion --------------------------------------------------------------
    def _on_map_end(self, frame: _Frame) -> None:
        if frame.path:
            self.field_presence.add("/".join(str(part) for part in _normalize_path(frame.path)))
        self._dispatch(frame)
        self._attach(frame)

    def _on_array_end(self, frame: _Frame) -> None:
        if isinstance(frame.data, dict) and frame.data.get("items", 0) > MAX_ARRAY_ITEMS:
            raise ResourceLimitError(
                f"array at {'/'.join(map(str, frame.path))} exceeds {MAX_ARRAY_ITEMS} items",
                limit="array_items",
                observed=frame.data["items"],
            )
        self._attach(frame)

    def _attach(self, frame: _Frame) -> None:
        if not self.frames:
            return
        parent = self.frames[-1]
        if parent.kind == "map":
            if frame.key is not None:
                parent.data[frame.key] = frame.data
                frame.key = None
            return
        if isinstance(parent.data, list):
            parent.data.append(frame.data)
        else:
            parent.data["items"] = parent.data.get("items", 0) + 1

    # -- dispatch ----------------------------------------------------------------------
    def _dispatch(self, frame: _Frame) -> None:
        path = _normalize_path(frame.path)
        if path == ():
            value = frame.data.get("avclass_detection")
            if isinstance(value, str) and value.strip():
                self.avclass_detection = value.strip()
            return
        if path == ("target", "file"):
            self.target = {
                "name": _text(frame.data.get("name")),
                "path": _text(frame.data.get("path")),
                "sha256": _text(frame.data.get("sha256")),
                "type": _text(frame.data.get("type")),
                "guest_paths": _guest_paths(frame.data.get("guest_paths")),
                "size": _as_int(frame.data.get("size")),
            }
            if not self.target["sha256"]:
                self.quality_flags.append("target_sha256_missing")
            elif not is_sha256(self.target["sha256"]):
                self.quality_flags.append("target_sha256_invalid")
                self.target["sha256"] = None
        elif path == ("detections", "*"):
            family = _text(frame.data.get("family"))
            if family:
                self.detections.append({"family": family, "details": _list_of_dicts(frame.data.get("details"))})
        elif path == ("CAPE", "payloads", "*"):
            self.payloads.append(self._artifact(frame.data, kind="cape_payload"))
        elif path == ("procdump", "*"):
            self.procdump.append(self._artifact(frame.data, kind="procdump"))
        elif len(path) == 2 and path[0] == "dropped" and isinstance(frame.data, dict):
            # "dropped" is keyed by sha256 in some CAPE versions and a list in others;
            # either way every artifact map is dispatched on its own.
            self.dropped.append(self._artifact(frame.data, kind="dropped"))
        elif path == ("signatures", "*"):
            self.signatures.append(
                {
                    "name": _text(frame.data.get("name")),
                    "severity": _as_int(frame.data.get("severity")),
                    "description": _text(frame.data.get("description")),
                    "data": frame.data.get("data"),
                }
            )
        elif path == ("behavior", "processtree", "*"):
            self.tree_nodes.append(
                {
                    "pid": _as_int(frame.data.get("pid")),
                    "parent_id": _as_int(frame.data.get("parent_id")),
                    "name": _text(frame.data.get("name")),
                    "module_path": _text(frame.data.get("module_path")),
                    "children": self._child_pids(frame.data.get("children")),
                }
            )
        elif path == ("behavior", "enhanced", "*"):
            self._on_enhanced(frame.data)
        elif path == ("behavior", "processes", "*", "calls", "*"):
            record_size = len(json.dumps(frame.data, default=str))
            if record_size > self.limits.max_call_record_bytes:
                raise ResourceLimitError(
                    f"call record at {'/'.join(map(str, frame.path))} is {record_size} bytes, "
                    f"above max_call_record_bytes {self.limits.max_call_record_bytes}",
                    limit="max_call_record_bytes",
                    observed=record_size,
                )
            self._on_call(frame.path, frame.data)
        elif path == ("behavior", "processes", "*"):
            self._on_process(frame.path, frame.data)

    def _artifact(self, data: dict[str, Any], *, kind: str) -> dict[str, Any]:
        sha = _text(data.get("sha256"))
        if sha and not is_sha256(sha):
            self.quality_flags.append(f"{kind}_sha256_invalid")
        return {
            "kind": kind,
            "sha256": sha if is_sha256(sha) else None,
            "name": _text(data.get("name")),
            "type": _text(data.get("type")),
            "size": _as_int(data.get("size")),
            "guest_paths": _guest_paths(data.get("guest_paths")),
            "pid": _as_int(data.get("pid")),
            "process_name": _text(data.get("process_name")),
            "cape_type": _text(data.get("cape_type")),
            "yara": _string_list(data.get("yara")),
            "cape_yara": _string_list(data.get("cape_yara")),
        }

    @staticmethod
    def _child_pids(value: Any) -> list[int]:
        pids: list[int] = []
        for item in _as_list(value):
            if isinstance(item, dict):
                pid = _as_int(item.get("pid"))
                if pid is not None:
                    pids.append(pid)
        return pids

    def _on_enhanced(self, data: dict[str, Any]) -> None:
        event = _text(data.get("event"))
        obj = _text(data.get("object"))
        if not event or not obj:
            self.quality_flags.append("enhanced_record_unparsed")
            return
        self.total_enhanced += 1
        self.enhanced_counts[(event, obj)] += 1

    def _process_state(self, index: int) -> _ProcessState:
        state = self.processes.get(index)
        if state is None:
            state = _ProcessState(index=index)
            self.processes[index] = state
        return state

    def _on_call(self, raw_path: tuple[Any, ...], data: dict[str, Any]) -> None:
        process_index = int(raw_path[2])
        call_index = int(raw_path[4])
        state = self._process_state(process_index)
        api = _text(data.get("api")) or ""
        category = _text(data.get("category")) or ""
        status = data.get("status")
        raw_return = data.get("return")
        repeated = _as_int(data.get("repeated"))
        call_id = _as_int(data.get("id"))
        timestamp = _text(data.get("timestamp"))
        caller = _text(data.get("caller"))
        parentcaller = _text(data.get("parentcaller"))
        thread_id = _text(data.get("thread_id"))
        arguments = data.get("arguments")

        state.call_count += 1
        if state.first_call_index is None:
            state.first_call_index = call_index
        state.last_call_index = call_index
        if api:
            state.api_counts[api] += 1
        if category:
            state.category_counts[category] += 1
        self.total_calls += 1

        if "status" not in data:
            self.quality_flags.append("call_status_missing")
        if "return" not in data:
            self.quality_flags.append("call_return_missing")
        if arguments is not None and not isinstance(arguments, list):
            self.quality_flags.append("call_arguments_not_list")

        if api not in INTERESTING_APIS:
            return
        self._check_time()
        args, ambiguous = _arg_values(arguments)
        if ambiguous:
            self.quality_flags.append("call_argument_duplicate_name")
        result, result_limits = _decode_result(api, status, raw_return)
        limitations = list(result_limits)
        if ambiguous:
            limitations.append("ambiguous_duplicate_argument")

        pointer = "/behavior/processes/" + str(process_index) + "/calls/" + str(call_index)
        kind = self._classify(api)
        attributes: dict[str, Any] = {
            "api": api,
            "category": category,
            "result": result,
            "raw_return": raw_return,
            "raw_status": status,
            "repeated": repeated,
            "call_id": call_id,
            "caller": caller,
            "parentcaller": parentcaller,
            "thread_id": thread_id,
            "timestamp": timestamp,
        }

        if kind == "process_create":
            state.has_process_create = True
            target_pid, target_ambiguous = _arg(args, "ProcessId", "ProcessIdentifier", "pid")
            if target_ambiguous:
                limitations.append("target_pid_ambiguous")
            attributes["target_pid"] = _as_int(target_pid)
            pid_value = _as_int(target_pid)
            plausible_pid = pid_value is not None and 4 <= pid_value < 2**31
            if pid_value is not None and not plausible_pid:
                limitations.append("target_pid_implausible")
            if result == "success" and api in PID_OUT_APIS and plausible_pid:
                state.created_child_pids.add(pid_value)
            command, _ = _arg(args, "CommandLine", "lpCommandLine", "ApplicationName", "lpApplicationName")
            attributes["command_line"] = command
        elif kind == "remote_thread":
            pid_text, pid_ambiguous = _arg(args, "ProcessId", "ProcessIdentifier")
            if pid_ambiguous:
                limitations.append("target_pid_ambiguous")
            target_pid = _as_int(pid_text)
            if target_pid is None:
                target_pid = self._handle_to_pid(state, args, limitations)
            if target_pid is None:
                state.invalid_handle_uses += 1
                limitations.append("handle_unresolved")
            else:
                attributes["target_pid"] = target_pid
                state.remote_thread_pids.add(target_pid)
        elif kind == "remote_write":
            target_pid = self._handle_to_pid(state, args, limitations)
            if target_pid is None:
                limitations.append("handle_unresolved")
                handle_text, _ = _arg(args, "ProcessHandle", "hProcess")
                if handle_text:
                    state.unresolved_handles.add(handle_text.strip().lower())
            else:
                attributes["target_pid"] = target_pid
                state.remote_write_pids.add(target_pid)
            base, _ = _arg(args, "BaseAddress", "lpBaseAddress")
            attributes["base_address"] = base
            buffer_length, _ = _arg(args, "BufferLength", "nSize", "Size")
            attributes["size"] = buffer_length
        elif kind == "memory":
            base, _ = _arg(args, "BaseAddress", "lpAddress")
            protection, _ = _arg(args, "Protection", "NewAccessProtection", "flNewProtect")
            attributes["base_address"] = base
            attributes["protection"] = protection
        elif kind == "file":
            file_name, file_ambiguous = _arg(args, "FileName", "lpFileName")
            if file_ambiguous:
                limitations.append("file_name_ambiguous")
            disposition, _ = _arg(args, "CreateDisposition")
            attributes["file_path"] = file_name
            attributes["disposition"] = disposition
            if api in ("NtWriteFile", "WriteFile"):
                state.has_file_write = True
            elif result == "success" and str(disposition or "").upper() in (
                "FILE_OVERWRITE",
                "FILE_OVERWRITE_IF",
                "FILE_SUPERSEDE",
                "FILE_CREATE",
                "2",
                "3",
                "5",
                "6",
            ):
                state.has_file_create = True
        elif kind == "network":
            state.has_network_activity = True
            if api in DOWNLOAD_APIS:
                state.has_download_api = True
            host, _ = _arg(args, "HostName", "lpszHostName", "ServerName", "lpszServerName", "szUrl", "lpszUrl")
            attributes["host"] = host
        elif kind == "handle":
            target_pid = self._on_handle(api, state, args, result, raw_return, limitations)
            if target_pid is not None:
                attributes["target_pid"] = target_pid

        self.facts.append(
            Fact(
                evidence_id=_evidence_id(kind, process_index, call_index),
                report_id="",
                rule_id=f"cape.{kind}.v1",
                rule_version=RULES_VERSION,
                kind=kind,
                subject_sha256=None,
                subject_kind=None,
                process_key=None,
                process_index=process_index,
                event_keys=[f"{process_index}:{call_index}"],
                source_json_pointers=[pointer],
                limitations=limitations,
                attributes=attributes,
            )
        )

    @staticmethod
    def _classify(api: str) -> str:
        if api in PROCESS_CREATE_APIS:
            return "process_create"
        if api in REMOTE_THREAD_APIS:
            return "remote_thread"
        if api in REMOTE_WRITE_APIS:
            return "remote_write"
        if api in MEMORY_APIS:
            return "memory"
        if api in FILE_APIS:
            return "file"
        if api in NETWORK_APIS:
            return "network"
        return "handle"

    def _own_pid(self, state: _ProcessState) -> int | None:
        return _as_int(state.meta.get("process_id"))

    def _handle_to_pid(self, state: _ProcessState, args: dict[str, list[str]], limitations: list[str]) -> int | None:
        handle, ambiguous = _arg(args, "ProcessHandle", "hProcess")
        if ambiguous or handle is None:
            return None
        normalized = handle.strip().lower()
        if normalized in ("0xffffffffffffffff", "0xffffffff", "-1"):
            return -1  # pseudo-handle meaning "current process"; resolved at build time
        if normalized in state.handle_targets:
            return state.handle_targets[normalized]
        limitations.append("handle_not_open_at_call_time")
        return None

    def _on_handle(
        self,
        api: str,
        state: _ProcessState,
        args: dict[str, list[str]],
        result: str,
        raw_return: Any,
        limitations: list[str],
    ) -> int | None:
        """Track handle -> target PID in call order (never resolve a later handle)."""
        if api in ("NtOpenProcess", "OpenProcess"):
            if result != "success":
                return None
            pid_text, pid_ambiguous = _arg(args, "ProcessIdentifier", "ProcessId")
            if pid_ambiguous:
                limitations.append("handle_target_pid_ambiguous")
                return None
            target_pid = _as_int(pid_text)
            handle, _ = _arg(args, "ProcessHandle", "hProcess")
            if api == "OpenProcess" and handle is None:
                handle = str(raw_return) if raw_return is not None else None
            if handle:
                state.handle_targets[handle.strip().lower()] = target_pid
            return target_pid
        if api in ("NtClose", "CloseHandle"):
            handle, _ = _arg(args, "Handle", "hObject")
            if handle:
                state.handle_targets.pop(handle.strip().lower(), None)
            return None
        if api == "NtDuplicateObject":
            source, _ = _arg(args, "SourceHandle")
            target, _ = _arg(args, "TargetHandle")
            if source and target:
                state.handle_targets[target.strip().lower()] = state.handle_targets.get(source.strip().lower())
                limitations.append("handle_duplicate_tracking_approximate")
                return state.handle_targets[target.strip().lower()]
            limitations.append("handle_duplicate_target_unknown")
            return None
        limitations.append("handle_api_not_tracked")
        return None

    def _on_process(self, raw_path: tuple[Any, ...], data: dict[str, Any]) -> None:
        index = int(raw_path[2])
        state = self._process_state(index)
        calls = data.pop("calls", None)
        if isinstance(calls, dict):
            state.call_count = max(state.call_count, int(calls.get("items", 0)))
        state.meta = data
        if "environ" not in data:
            self.quality_flags.append("process_environ_missing")

    # -- time guard --------------------------------------------------------------------
    def _check_time(self) -> None:
        if self.total_calls - self._last_time_check < 500:
            return
        self._last_time_check = self.total_calls
        elapsed = time.monotonic() - self.started
        if elapsed > self.limits.timeout_seconds:
            raise ResourceLimitError(
                f"parse exceeded report_timeout_seconds ({self.limits.timeout_seconds}s)",
                limit="report_timeout_seconds",
                observed=round(elapsed, 1),
            )

    # -- build -------------------------------------------------------------------------
    def build(self, *, report_id: str, size_bytes: int) -> ReportFacts:
        processes: list[ProcessSummary] = []
        parent_of_pid = {
            _as_int(state.meta.get("process_id")): _as_int(state.meta.get("parent_id"))
            for state in self.processes.values()
        }
        for index in sorted(self.processes):
            state = self.processes[index]
            own_pid = _as_int(state.meta.get("process_id"))
            tree_children = self._tree_children_for(state)
            if own_pid is not None:
                tree_children |= {
                    pid for pid, parent in parent_of_pid.items() if pid is not None and parent == own_pid
                }
            remote_write = sorted(pid for pid in state.remote_write_pids if pid not in (-1, own_pid))
            remote_thread = sorted(pid for pid in state.remote_thread_pids if pid not in (-1, own_pid))
            if own_pid is None and (state.remote_write_pids or state.remote_thread_pids):
                self.quality_flags.append("process_id_unknown_for_self_filter")
            summary = ProcessSummary(
                process_index=index,
                process_id=own_pid,
                parent_id=_as_int(state.meta.get("parent_id")),
                process_name=_text(state.meta.get("process_name")),
                module_path=_text(state.meta.get("module_path")),
                command_line=_text(state.meta.get("command_line")),
                first_seen=_text(state.meta.get("first_seen")),
                call_count=state.call_count,
                enhanced_count=state.enhanced_count,
                api_counts=dict(state.api_counts),
                category_counts=dict(state.category_counts),
                created_child_pids=sorted(state.created_child_pids | tree_children),
                remote_write_pids=remote_write,
                remote_thread_pids=remote_thread,
                unresolved_handle_pids=[],
                has_network_activity=state.has_network_activity,
                has_download_api=state.has_download_api,
                has_file_create=state.has_file_create,
                has_file_write=state.has_file_write,
                has_remote_write=bool(remote_write),
                has_remote_thread=bool(remote_thread),
                has_process_create=state.has_process_create,
                role_hints=[],
            )
            processes.append(summary)

        for fact in self.facts:
            fact.report_id = report_id
            if fact.process_index is not None:
                fact.process_key = f"{report_id}:{fact.process_index}"

        quality = list(dict.fromkeys(self.quality_flags))
        if any(state.invalid_handle_uses for state in self.processes.values()):
            quality.append("unresolved_handle_targets")
        coverage = self._coverage_flags()
        facts = ReportFacts(
            report_id=report_id,
            report_content_sha256=report_id,
            size_bytes=size_bytes,
            target_sha256=self.target.get("sha256"),
            target_name=self.target.get("name"),
            target_type=self.target.get("type"),
            target_guest_paths=list(self.target.get("guest_paths") or []),
            avclass_detection=self.avclass_detection,
            detections=self.detections,
            cape_payloads=self.payloads,
            dropped=self.dropped,
            procdump=self.procdump,
            signature_names=[item["name"] for item in self.signatures if item.get("name")],
            processes=processes,
            facts=self.facts,
            total_calls=self.total_calls,
            enhanced_count=self.total_enhanced,
            quality_flags=quality,
            coverage_flags=coverage,
            errors=[],
        )
        return facts

    def _coverage_flags(self) -> list[str]:
        """Curated record of the report regions that actually contained data."""
        seen_maps = self.field_presence
        checks: dict[str, tuple[bool, tuple[str, ...]]] = {
            "target.file": ("target/file" in seen_maps, ("target", "file")),
            "behavior.processes": (bool(self.processes), ("behavior", "processes")),
            "behavior.enhanced": (self.total_enhanced > 0, ("behavior", "enhanced")),
            "behavior.processtree": (bool(self.tree_nodes), ("behavior", "processtree")),
            "detections": (bool(self.detections), ("detections",)),
            "signatures": (bool(self.signatures), ("signatures",)),
            "CAPE.payloads": (bool(self.payloads), ("CAPE", "payloads")),
            "procdump": (bool(self.procdump), ("procdump",)),
            "dropped": (bool(self.dropped), ("dropped",)),
            "avclass_detection": (self.avclass_detection is not None, ("avclass_detection",)),
        }
        flags: list[str] = []
        for name, (present, _path) in checks.items():
            flags.append(f"present:{name}" if present else f"empty_or_absent:{name}")
        if self.total_calls == 0:
            flags.append("empty_or_absent:behavior.calls")
        return sorted(flags)

    def _tree_children_for(self, state: _ProcessState) -> set[int]:
        own_pid = self._own_pid(state)
        children: set[int] = set()
        if own_pid is None:
            return children
        for node in self.tree_nodes:
            if node.get("parent_id") == own_pid and node.get("pid") is not None:
                children.add(int(node["pid"]))
            for pid in node.get("children") or []:
                if self._parent_of(pid) == own_pid:
                    children.add(int(pid))
        return children

    def _parent_of(self, pid: int) -> int | None:
        for node in self.tree_nodes:
            if node.get("pid") == pid:
                return node.get("parent_id")
        return None


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)


def _string_list(value: Any) -> list[str]:
    return [item for item in _as_list(value) if isinstance(item, str)]


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in _as_list(value) if isinstance(item, dict)]
