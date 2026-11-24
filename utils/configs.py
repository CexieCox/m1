"""Configuration loading, validation and effective-config computation.

Tuân thủ Rule 11.1 (utils/configs.py), Rule 11.2 (BASE_DIR = Path(__file__).resolve().parent.parent).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Optional

from .errors import ConfigError, UsageError
from .models import (
    ANALYSIS_MODES,
    ANALYSIS_SCOPES,
    IDENTITY_MODES,
    ROW_ERROR_POLICIES,
)
from .io_utils import canonical_json, read_json_strict, sha256_json

# Canonical root pattern (Rule 11.2)
BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_SCHEMA_VERSION = 1
SUPPORTED_POLICIES = ("conservative-v1",)
LABEL_FILE_NAMES = {
    "avclass": "avclass_report_to_label_mapping.json",
    "cape": "cape_report_to_label_mapping.json",
    "consensus": "reports_consensus_label.json",
}
INPUT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")

_ALLOWED_TOP_LEVEL = {
    "config_schema_version",
    "inputs",
    "discovery",
    "labels",
    "taxonomy",
    "analysis",
    "resources",
    "output",
    "logging",
}
_ALLOWED_DISCOVERY = {"recursive", "include", "exclude", "follow_links", "identity"}
_ALLOWED_LABELS = {"avclass", "cape", "consensus", "row_errors", "require_full_coverage"}
_ALLOWED_ANALYSIS = {"mode", "scope", "policy", "trusted_rule_registry"}
_ALLOWED_RESOURCES = {
    "workers",
    "max_pending",
    "max_file_bytes",
    "max_call_record_bytes",
    "max_json_depth",
    "report_timeout_seconds",
}
_ALLOWED_OUTPUT = {"root", "keep_fact_cache"}
_ALLOWED_LOGGING = {"level", "progress_interval_seconds"}


@dataclass(frozen=True)
class InputSpec:
    id: str
    path: Path

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "path": str(self.path)}


@dataclass
class DiscoveryConfig:
    recursive: bool = True
    include: list[str] = field(default_factory=lambda: ["*.json"])
    exclude: list[str] = field(default_factory=list)
    follow_links: bool = False
    identity: str = "auto"

    def to_dict(self) -> dict[str, Any]:
        return {
            "recursive": self.recursive,
            "include": list(self.include),
            "exclude": list(self.exclude),
            "follow_links": self.follow_links,
            "identity": self.identity,
        }


@dataclass
class LabelsConfig:
    avclass: Optional[Path] = None
    cape: Optional[Path] = None
    consensus: Optional[Path] = None
    row_errors: str = "quarantine"
    require_full_coverage: bool = False

    @property
    def configured(self) -> bool:
        return any(value is not None for value in (self.avclass, self.cape, self.consensus))

    def to_dict(self) -> dict[str, Any]:
        return {
            "avclass": str(self.avclass) if self.avclass else None,
            "cape": str(self.cape) if self.cape else None,
            "consensus": str(self.consensus) if self.consensus else None,
            "row_errors": self.row_errors,
            "require_full_coverage": self.require_full_coverage,
        }


@dataclass
class AnalysisConfig:
    mode: str = "labels"
    scope: str = "candidates"
    policy: str = "conservative-v1"
    trusted_rule_registry: Optional[Path] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "scope": self.scope,
            "policy": self.policy,
            "trusted_rule_registry": str(self.trusted_rule_registry) if self.trusted_rule_registry else None,
        }


@dataclass
class ResourcesConfig:
    workers: int = 1
    max_pending: Optional[int] = None
    max_file_bytes: int = 2147483648
    max_call_record_bytes: int = 16777216
    max_json_depth: int = 128
    report_timeout_seconds: int = 600

    def effective_max_pending(self) -> int:
        if self.max_pending is not None:
            return self.max_pending
        return max(2, 2 * self.workers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workers": self.workers,
            "max_pending": self.max_pending,
            "max_file_bytes": self.max_file_bytes,
            "max_call_record_bytes": self.max_call_record_bytes,
            "max_json_depth": self.max_json_depth,
            "report_timeout_seconds": self.report_timeout_seconds,
        }


@dataclass
class OutputConfig:
    root: Path = BASE_DIR / "Results"
    keep_fact_cache: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"root": str(self.root), "keep_fact_cache": self.keep_fact_cache}


@dataclass
class LoggingConfig:
    level: str = "INFO"
    progress_interval_seconds: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {"level": self.level, "progress_interval_seconds": self.progress_interval_seconds}


@dataclass
class Config:
    config_schema_version: int = CONFIG_SCHEMA_VERSION
    inputs: list[InputSpec] = field(default_factory=list)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    labels: LabelsConfig = field(default_factory=LabelsConfig)
    taxonomy: Optional[Path] = None
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    resources: ResourcesConfig = field(default_factory=ResourcesConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    config_path: Optional[Path] = None
    sources: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_schema_version": self.config_schema_version,
            "inputs": [spec.to_dict() for spec in self.inputs],
            "discovery": self.discovery.to_dict(),
            "labels": self.labels.to_dict(),
            "taxonomy": str(self.taxonomy) if self.taxonomy else None,
            "analysis": self.analysis.to_dict(),
            "resources": self.resources.to_dict(),
            "output": self.output.to_dict(),
            "logging": self.logging.to_dict(),
            "config_path": str(self.config_path) if self.config_path else None,
            "value_sources": dict(self.sources),
        }

    def semantic_settings(self) -> dict[str, Any]:
        return {
            "config_schema_version": self.config_schema_version,
            "discovery": {
                "recursive": self.discovery.recursive,
                "include": list(self.discovery.include),
                "exclude": list(self.discovery.exclude),
                "follow_links": self.discovery.follow_links,
                "identity": self.discovery.identity,
            },
            "labels": {
                "row_errors": self.labels.row_errors,
                "require_full_coverage": self.labels.require_full_coverage,
                "avclass_configured": self.labels.avclass is not None,
                "cape_configured": self.labels.cape is not None,
                "consensus_configured": self.labels.consensus is not None,
            },
            "analysis": {
                "mode": self.analysis.mode,
                "scope": self.analysis.scope,
                "policy": self.analysis.policy,
                "trusted_rule_registry_configured": self.analysis.trusted_rule_registry is not None,
            },
            "resources": {
                "max_file_bytes": self.resources.max_file_bytes,
                "max_call_record_bytes": self.resources.max_call_record_bytes,
                "max_json_depth": self.resources.max_json_depth,
                "report_timeout_seconds": self.resources.report_timeout_seconds,
            },
        }

    def semantic_config_hash(self) -> str:
        return sha256_json(self.semantic_settings())

    def label_source_paths(self) -> list[Path]:
        return [p for p in (self.labels.avclass, self.labels.cape, self.labels.consensus) if p is not None]

    def excluded_absolute_paths(self) -> list[Path]:
        paths: list[Path] = []
        if self.config_path is not None:
            paths.append(self.config_path)
        if self.taxonomy is not None:
            paths.append(self.taxonomy)
        paths.extend(self.label_source_paths())
        if self.analysis.trusted_rule_registry is not None:
            paths.append(self.analysis.trusted_rule_registry)
        paths.append(self.output.root)
        return paths


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a JSON object")
    return value


def _check_keys(mapping: dict[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ConfigError(
            f"unknown key(s) in {where}: {', '.join(unknown)}",
            details={"unknown_keys": unknown, "allowed_keys": sorted(allowed)},
        )


def _as_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be a boolean")
    return value


def _as_int(value: Any, where: str, *, minimum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where} must be an integer")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{where} must be >= {minimum}")
    return value


def _as_str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{where} must be a list of strings")
    return list(value)


def _resolve(base: Path, value: Optional[str]) -> Optional[Path]:
    if value is None:
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return Path(os.path.normpath(str(candidate)))


def load_config_file(config_path: Path) -> Config:
    """Load and validate a configuration file. Paths resolve against its directory."""
    config_path = Path(config_path).expanduser()
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")
    try:
        raw = read_json_strict(config_path)
    except ValueError as exc:
        raise ConfigError(f"invalid config JSON in {config_path}: {exc}") from exc
    base = config_path.parent.resolve()
    return build_config(raw, base=base, config_path=config_path.resolve(), source="config")


def build_config(
    raw: Any,
    *,
    base: Path,
    config_path: Optional[Path] = None,
    source: str = "config",
) -> Config:
    data = _require_mapping(raw, "config")
    _check_keys(data, _ALLOWED_TOP_LEVEL, "config")

    version = data.get("config_schema_version", CONFIG_SCHEMA_VERSION)
    if version != CONFIG_SCHEMA_VERSION:
        raise ConfigError(
            f"unsupported config_schema_version {version!r}; this build implements {CONFIG_SCHEMA_VERSION}"
        )

    inputs = _parse_inputs(data.get("inputs", []), base)
    discovery = _parse_discovery(data.get("discovery", {}))
    labels = _parse_labels(data.get("labels", {}), base)
    analysis = _parse_analysis(data.get("analysis", {}), base)
    resources = _parse_resources(data.get("resources", {}))
    output = _parse_output(data.get("output", {}), base)
    logging_cfg = _parse_logging(data.get("logging", {}))
    taxonomy = _resolve(base, data.get("taxonomy"))

    config = Config(
        config_schema_version=version,
        inputs=inputs,
        discovery=discovery,
        labels=labels,
        taxonomy=taxonomy,
        analysis=analysis,
        resources=resources,
        output=output,
        logging=logging_cfg,
        config_path=config_path,
    )
    validate_config(config)
    config.sources["_base"] = f"{source}:{base}"
    return config


def _parse_inputs(value: Any, base: Path) -> list[InputSpec]:
    if not isinstance(value, list):
        raise ConfigError("inputs must be a list")
    specs: list[InputSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        entry = _require_mapping(item, f"inputs[{index}]")
        _check_keys(entry, {"id", "path"}, f"inputs[{index}]")
        if "id" not in entry or "path" not in entry:
            raise ConfigError(f"inputs[{index}] requires 'id' and 'path'")
        input_id = entry["id"]
        if not isinstance(input_id, str) or not INPUT_ID_RE.match(input_id):
            raise ConfigError(
                f"inputs[{index}].id must match {INPUT_ID_RE.pattern!r} (letters, digits, '_' and '-')"
            )
        if input_id in seen:
            raise ConfigError(f"duplicate input id: {input_id}")
        seen.add(input_id)
        path = entry["path"]
        if not isinstance(path, str) or not path:
            raise ConfigError(f"inputs[{index}].path must be a non-empty string")
        resolved = _resolve(base, path)
        assert resolved is not None
        specs.append(InputSpec(id=input_id, path=resolved))
    return specs


def _parse_discovery(value: Any) -> DiscoveryConfig:
    data = _require_mapping(value, "discovery")
    _check_keys(data, _ALLOWED_DISCOVERY, "discovery")
    identity = data.get("identity", "auto")
    if identity not in IDENTITY_MODES:
        raise ConfigError(f"discovery.identity must be one of {IDENTITY_MODES}")
    follow_links = _as_bool(data.get("follow_links", False), "discovery.follow_links")
    if follow_links:
        raise ConfigError(
            "discovery.follow_links=true is not implemented in LoaderFilter v1 "
            "(symlink/junction traversal is never followed); remove the flag or set it to false",
            error_code="capability_not_implemented",
        )
    include = _as_str_list(data.get("include", ["*.json"]), "discovery.include")
    if not include:
        raise ConfigError("discovery.include must not be empty")
    exclude = _as_str_list(data.get("exclude", []), "discovery.exclude")
    return DiscoveryConfig(
        recursive=_as_bool(data.get("recursive", True), "discovery.recursive"),
        include=include,
        exclude=exclude,
        follow_links=follow_links,
        identity=identity,
    )


def _parse_labels(value: Any, base: Path) -> LabelsConfig:
    data = _require_mapping(value, "labels")
    _check_keys(data, _ALLOWED_LABELS, "labels")
    row_errors = data.get("row_errors", "quarantine")
    if row_errors not in ROW_ERROR_POLICIES:
        raise ConfigError(f"labels.row_errors must be one of {ROW_ERROR_POLICIES}")
    require_full_coverage = _as_bool(data.get("require_full_coverage", False), "labels.require_full_coverage")
    labels = LabelsConfig(
        avclass=_resolve(base, data.get("avclass")),
        cape=_resolve(base, data.get("cape")),
        consensus=_resolve(base, data.get("consensus")),
        row_errors=row_errors,
        require_full_coverage=require_full_coverage,
    )
    if labels.require_full_coverage and not labels.configured:
        raise ConfigError(
            "labels.require_full_coverage=true requires at least one configured label source"
        )
    return labels


def _parse_analysis(value: Any, base: Path) -> AnalysisConfig:
    data = _require_mapping(value, "analysis")
    _check_keys(data, _ALLOWED_ANALYSIS, "analysis")
    mode = data.get("mode", "labels")
    scope = data.get("scope", "candidates")
    policy = data.get("policy", "conservative-v1")
    if mode not in ANALYSIS_MODES:
        raise ConfigError(f"analysis.mode must be one of {ANALYSIS_MODES}")
    if scope not in ANALYSIS_SCOPES:
        raise ConfigError(f"analysis.scope must be one of {ANALYSIS_SCOPES}")
    if policy not in SUPPORTED_POLICIES:
        raise ConfigError(
            f"analysis.policy {policy!r} is not implemented; supported policies: {', '.join(SUPPORTED_POLICIES)}"
        )
    return AnalysisConfig(
        mode=mode,
        scope=scope,
        policy=policy,
        trusted_rule_registry=_resolve(base, data.get("trusted_rule_registry")),
    )


def _parse_resources(value: Any) -> ResourcesConfig:
    data = _require_mapping(value, "resources")
    _check_keys(data, _ALLOWED_RESOURCES, "resources")
    workers = _as_int(data.get("workers", 1), "resources.workers", minimum=1)
    max_pending = data.get("max_pending")
    if max_pending is not None:
        max_pending = _as_int(max_pending, "resources.max_pending", minimum=1)
        if max_pending < workers:
            raise ConfigError(
                f"resources.max_pending ({max_pending}) must be >= resources.workers ({workers}); "
                f"increase --max-pending (suggested: {max(2, 2 * workers)})"
            )
    return ResourcesConfig(
        workers=workers,
        max_pending=max_pending,
        max_file_bytes=_as_int(data.get("max_file_bytes", 2147483648), "resources.max_file_bytes", minimum=1),
        max_call_record_bytes=_as_int(
            data.get("max_call_record_bytes", 16777216), "resources.max_call_record_bytes", minimum=1
        ),
        max_json_depth=_as_int(data.get("max_json_depth", 128), "resources.max_json_depth", minimum=2),
        report_timeout_seconds=_as_int(
            data.get("report_timeout_seconds", 600), "resources.report_timeout_seconds", minimum=1
        ),
    )


def _parse_output(value: Any, base: Path) -> OutputConfig:
    data = _require_mapping(value, "output")
    _check_keys(data, _ALLOWED_OUTPUT, "output")
    root = _resolve(base, data.get("root", "./Results"))
    assert root is not None
    return OutputConfig(root=root, keep_fact_cache=_as_bool(data.get("keep_fact_cache", True), "output.keep_fact_cache"))


def _parse_logging(value: Any) -> LoggingConfig:
    data = _require_mapping(value, "logging")
    _check_keys(data, _ALLOWED_LOGGING, "logging")
    level = data.get("level", "INFO")
    if not isinstance(level, str) or level.upper() not in LOG_LEVELS:
        raise ConfigError(f"logging.level must be one of {LOG_LEVELS}")
    return LoggingConfig(
        level=level.upper(),
        progress_interval_seconds=_as_int(data.get("progress_interval_seconds", 5), "logging.progress_interval_seconds", minimum=0),
    )


def validate_config(config: Config) -> None:
    """Validate a fully assembled configuration (structure, limits and containment)."""
    if not config.inputs:
        raise ConfigError("no input roots configured; add 'inputs' to the config or use --input ID=PATH")

    seen_ids: set[str] = set()
    for spec in config.inputs:
        if not INPUT_ID_RE.match(spec.id):
            raise ConfigError(f"invalid input id: {spec.id!r}")
        if spec.id in seen_ids:
            raise ConfigError(f"duplicate input id: {spec.id}")
        seen_ids.add(spec.id)
        path = spec.path if spec.path.is_absolute() else Path(os.getcwd()) / spec.path
        if not path.exists():
            raise ConfigError(f"input root does not exist: {spec.path}")
        if not path.is_dir():
            raise ConfigError(f"input root is not a directory: {spec.path}")

    output_root = config.output.root
    for spec in config.inputs:
        root = spec.path if spec.path.is_absolute() else Path(os.getcwd()) / spec.path
        root_resolved = Path(os.path.normcase(str(root.resolve())))
        out_resolved = Path(os.path.normcase(str(output_root.resolve())))
        if root_resolved == out_resolved:
            raise ConfigError(
                f"output root must not be the same directory as input root {spec.id!r}"
            )
        try:
            out_resolved.relative_to(root_resolved)
        except ValueError:
            pass
        else:
            raise ConfigError(
                f"output root {output_root} is inside input root {spec.id!r}; "
                "refusing to write results into an input tree"
            )

    if config.analysis.mode == "labels" and config.discovery.identity == "report":
        raise ConfigError("discovery.identity=report requires analysis.mode=evidence")
    if config.taxonomy is not None and not config.taxonomy.is_file():
        raise ConfigError(f"taxonomy file not found: {config.taxonomy}")
    for label_path in config.label_source_paths():
        if not label_path.is_file():
            raise ConfigError(f"label source file not found: {label_path}")
    if config.analysis.trusted_rule_registry is not None and not config.analysis.trusted_rule_registry.is_file():
        raise ConfigError(f"trusted rule registry not found: {config.analysis.trusted_rule_registry}")

    effective_pending = config.resources.effective_max_pending()
    if effective_pending < config.resources.workers:
        raise ConfigError(
            f"effective max_pending ({effective_pending}) must be >= workers ({config.resources.workers})"
        )


def parse_input_argument(value: str) -> InputSpec:
    """Parse a ``ID=PATH`` command line input specification."""
    if "=" not in value:
        raise UsageError(f"--input expects ID=PATH, got {value!r}")
    input_id, _, raw_path = value.partition("=")
    input_id = input_id.strip()
    raw_path = raw_path.strip()
    if not input_id or not raw_path:
        raise UsageError(f"--input expects ID=PATH, got {value!r}")
    if not INPUT_ID_RE.match(input_id):
        raise UsageError(f"--input id {input_id!r} must match {INPUT_ID_RE.pattern!r}")
    return InputSpec(id=input_id, path=Path(raw_path))


def apply_cli_overrides(config: Config, overrides: dict[str, Any], *, cwd: Optional[Path] = None) -> Config:
    """Return a copy of *config* with command line overrides applied."""
    cwd = Path(cwd or Path.cwd())
    new = replace(
        config,
        inputs=list(config.inputs),
        discovery=replace(config.discovery, include=list(config.discovery.include), exclude=list(config.discovery.exclude)),
        labels=replace(config.labels),
        analysis=replace(config.analysis),
        resources=replace(config.resources),
        output=replace(config.output),
        logging=replace(config.logging),
        sources=dict(config.sources),
    )

    if overrides.get("inputs") is not None:
        new.inputs = [
            InputSpec(id=spec.id, path=(spec.path if spec.path.is_absolute() else cwd / spec.path))
            for spec in overrides["inputs"]
        ]
        new.sources["inputs"] = "cli"

    if overrides.get("output") is not None:
        out = Path(overrides["output"]).expanduser()
        new.output = replace(new.output, root=(out if out.is_absolute() else cwd / out))
        new.sources["output.root"] = "cli"

    labels = new.labels
    if overrides.get("no_labels"):
        if overrides.get("labels_dir") or overrides.get("avclass_map") or overrides.get("cape_map") or overrides.get("consensus_map"):
            raise UsageError("--no-labels cannot be combined with --labels-dir or --*-map")
        labels = replace(labels, avclass=None, cape=None, consensus=None)
        new.sources["labels"] = "cli:--no-labels"
    else:
        if overrides.get("labels_dir"):
            labels_dir = Path(overrides["labels_dir"]).expanduser()
            labels_dir = labels_dir if labels_dir.is_absolute() else cwd / labels_dir
            labels = replace(
                labels,
                avclass=labels_dir / LABEL_FILE_NAMES["avclass"],
                cape=labels_dir / LABEL_FILE_NAMES["cape"],
                consensus=labels_dir / LABEL_FILE_NAMES["consensus"],
            )
            new.sources["labels"] = "cli:--labels-dir"
        for key, attr in (("avclass_map", "avclass"), ("cape_map", "cape"), ("consensus_map", "consensus")):
            value = overrides.get(key)
            if value:
                path = Path(value).expanduser()
                path = path if path.is_absolute() else cwd / path
                labels = replace(labels, **{attr: path})
                new.sources[f"labels.{attr}"] = f"cli:{key}"
    new.labels = labels

    if overrides.get("taxonomy"):
        path = Path(overrides["taxonomy"]).expanduser()
        new.taxonomy = path if path.is_absolute() else cwd / path
        new.sources["taxonomy"] = "cli"

    if overrides.get("registry"):
        path = Path(overrides["registry"]).expanduser()
        new.analysis = replace(
            new.analysis, trusted_rule_registry=(path if path.is_absolute() else cwd / path)
        )
        new.sources["analysis.trusted_rule_registry"] = "cli"

    if overrides.get("mode"):
        if overrides["mode"] not in ANALYSIS_MODES:
            raise UsageError(f"--mode must be one of {ANALYSIS_MODES}")
        new.analysis = replace(new.analysis, mode=overrides["mode"])
        new.sources["analysis.mode"] = "cli"
    if overrides.get("scope"):
        if overrides["scope"] not in ANALYSIS_SCOPES:
            raise UsageError(f"--scope must be one of {ANALYSIS_SCOPES}")
        new.analysis = replace(new.analysis, scope=overrides["scope"])
        new.sources["analysis.scope"] = "cli"

    if overrides.get("recursive") is not None:
        new.discovery = replace(new.discovery, recursive=bool(overrides["recursive"]))
        new.sources["discovery.recursive"] = "cli"
    if overrides.get("identity"):
        if overrides["identity"] not in IDENTITY_MODES:
            raise UsageError(f"--identity must be one of {IDENTITY_MODES}")
        new.discovery = replace(new.discovery, identity=overrides["identity"])
        new.sources["discovery.identity"] = "cli"

    if overrides.get("workers") is not None:
        workers = int(overrides["workers"])
        if workers < 1:
            raise UsageError("--workers must be >= 1")
        new.resources = replace(new.resources, workers=workers)
        new.sources["resources.workers"] = "cli"
    if overrides.get("max_pending") is not None:
        max_pending = int(overrides["max_pending"])
        if max_pending < 1:
            raise UsageError("--max-pending must be >= 1")
        new.resources = replace(new.resources, max_pending=max_pending)
        new.sources["resources.max_pending"] = "cli"

    validate_config(new)
    return new


def config_digest(config: Config) -> str:
    return sha256_json(canonical_json(config.to_dict()))
