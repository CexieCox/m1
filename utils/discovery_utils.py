"""File discovery utilities: deterministic, link-safe enumeration of report locators.

Tuân thủ Rule 8.2 (<domain>_utils.py).
"""

from __future__ import annotations

import os
import re
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .configs import Config, InputSpec
from .io_utils import path_is_within, sha256_text

OUTPUT_MARKER = ".loaderfilter-output.json"


def translate_pattern(pattern: str) -> re.Pattern[str]:
    """Translate a glob into a regular expression."""
    out: list[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern[index : index + 3] == "**/":
                out.append("(?:.*/)?")
                index += 3
                continue
            if pattern[index : index + 2] == "**":
                out.append(".*")
                index += 2
                continue
            out.append("[^/]*")
            index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        elif char == "[":
            close = pattern.find("]", index + 1)
            if close == -1:
                out.append(re.escape(char))
                index += 1
                continue
            body = pattern[index + 1 : close]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body + "]")
            index = close + 1
        else:
            out.append(re.escape(char))
            index += 1
    return re.compile("^" + "".join(out) + "$")


@dataclass
class PatternSet:
    patterns: list[str] = field(default_factory=list)
    regexes: list[re.Pattern[str]] = field(default_factory=list)

    @classmethod
    def build(cls, patterns: Iterable[str]) -> "PatternSet":
        items = list(patterns)
        return cls(patterns=items, regexes=[translate_pattern(item) for item in items])

    def matches(self, relative_path: str, basename: str) -> bool:
        if not self.regexes:
            return False
        for pattern, regex in zip(self.patterns, self.regexes):
            target = basename if "/" not in pattern else relative_path
            if regex.match(target):
                return True
        return False


@dataclass
class DiscoveredFile:
    source_id: str
    root_id: str
    relative_path: str
    absolute_path: str
    size_bytes: int
    mtime_ns: int
    secondary_locators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "root_id": self.root_id,
            "relative_path": self.relative_path,
            "absolute_path": self.absolute_path,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
            "secondary_locators": list(self.secondary_locators),
        }


@dataclass
class DiscoveryResult:
    files: list[DiscoveredFile] = field(default_factory=list)
    coverage_limited: bool = False
    limit: Optional[int] = None
    stats: dict[str, Any] = field(default_factory=dict)


def is_link_like(path: Path) -> bool:
    """True for symlinks, junctions and other reparse points."""
    try:
        if os.path.islink(path):
            return True
    except OSError:
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None:
        try:
            if is_junction(path):
                return True
        except OSError:
            return True
    try:
        attributes = os.lstat(path).st_file_attributes
    except (OSError, AttributeError):
        return False
    reparse_flag = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def physical_key(path: Path) -> Optional[tuple[int, int]]:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino)


def compute_source_id(root_id: str, relative_path: str) -> str:
    return sha256_text(f"{root_id}\x00{relative_path}")


def _excluded_containers(config: Config) -> list[Path]:
    containers: list[Path] = []
    for path in config.excluded_absolute_paths():
        containers.append(path)
    return containers


def discover(config: Config, limit: Optional[int] = None) -> DiscoveryResult:
    """Enumerate report files for every configured input root."""
    include = PatternSet.build(config.discovery.include)
    exclude = PatternSet.build(config.discovery.exclude)
    output_root = config.output.root
    excluded_files = {Path(os.path.normcase(str(path))) for path in _excluded_containers(config)}

    result = DiscoveryResult(limit=limit)
    counters = {
        "roots": 0,
        "files_seen": 0,
        "files_matched": 0,
        "excluded_by_pattern": 0,
        "excluded_by_path": 0,
        "skipped_links": 0,
        "pruned_output_dirs": 0,
        "duplicate_physical_paths": 0,
    }

    primary_by_physical: dict[tuple[int, int], DiscoveredFile] = {}
    pending_secondary: list[tuple[tuple[int, int], str, str, str]] = []

    for spec in config.inputs:
        root = _resolve_root(spec.path)
        counters["roots"] += 1
        for absolute, relative in _walk(root, spec.id, config, include, exclude, excluded_files, counters):
            counters["files_seen"] += 1
            try:
                info = os.stat(absolute)
            except OSError:
                counters["excluded_by_path"] += 1
                continue
            if not stat_module.S_ISREG(info.st_mode):
                counters["excluded_by_path"] += 1
                continue
            key = (info.st_dev, info.st_ino)
            source_id = compute_source_id(spec.id, relative)
            if key in primary_by_physical:
                counters["duplicate_physical_paths"] += 1
                pending_secondary.append((key, source_id, spec.id, relative))
                continue
            counters["files_matched"] += 1
            record = DiscoveredFile(
                source_id=source_id,
                root_id=spec.id,
                relative_path=relative,
                absolute_path=str(absolute),
                size_bytes=info.st_size,
                mtime_ns=info.st_mtime_ns,
            )
            primary_by_physical[key] = record
            result.files.append(record)

    for key, source_id, root_id, relative in pending_secondary:
        primary = primary_by_physical.get(key)
        if primary is not None:
            primary.secondary_locators.append(f"{root_id}:{relative}")

    result.files.sort(key=lambda item: (item.root_id, item.relative_path))

    if limit is not None and len(result.files) > limit:
        result.files = result.files[:limit]
        result.coverage_limited = True
        counters["coverage_limited"] = True

    counters["discovered"] = len(result.files)
    result.stats = counters
    return result


def _resolve_root(path: Path) -> Path:
    return Path(os.path.normpath(str(path.expanduser().absolute())))


def _walk(
    root: Path,
    root_id: str,
    config: Config,
    include: PatternSet,
    exclude: PatternSet,
    excluded_files: set[Path],
    counters: dict[str, Any],
) -> Iterable[tuple[Path, str]]:
    output_root = config.output.root
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if not config.discovery.recursive:
            dirnames[:] = []
        else:
            keep: list[str] = []
            for name in sorted(dirnames):
                child = current / name
                relative = _relative(child, root)
                if is_link_like(child):
                    counters["skipped_links"] += 1
                    continue
                if exclude.matches(relative, name):
                    counters["excluded_by_pattern"] += 1
                    continue
                if path_is_within(child, output_root):
                    counters["pruned_output_dirs"] += 1
                    continue
                if (child / OUTPUT_MARKER).is_file():
                    counters["pruned_output_dirs"] += 1
                    continue
                keep.append(name)
            dirnames[:] = keep

        for name in sorted(filenames):
            child = current / name
            relative = _relative(child, root)
            if not include.matches(relative, name):
                continue
            if exclude.matches(relative, name):
                counters["excluded_by_pattern"] += 1
                continue
            if is_link_like(child):
                counters["skipped_links"] += 1
                continue
            if Path(os.path.normcase(str(child))) in excluded_files:
                counters["excluded_by_path"] += 1
                continue
            if path_is_within(child, output_root):
                counters["excluded_by_path"] += 1
                continue
            yield child, relative


def _relative(path: Path, root: Path) -> str:
    try:
        rel = os.path.relpath(str(path), str(root))
    except ValueError:
        return path.name
    return rel.replace(os.sep, "/")


def input_specs(config: Config) -> list[InputSpec]:
    return list(config.inputs)
