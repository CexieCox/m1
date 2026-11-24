"""Trusted rule registry (``analysis.trusted_rule_registry``).

The registry is the only machine source of ``trusted_identity`` support. Anything not
listed here stays ``provisional``; nothing is inferred from a family name substring in a
YARA rule name unless the rule is listed explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .errors import ConfigError
from .io_utils import is_sha256, read_json_strict

REGISTRY_SCHEMA_VERSION = 1
TRUST_LEVELS = ("trusted_identity", "review")
RULE_TYPES = ("yara_name", "cape_yara_name", "avclass_detection", "sha256")


@dataclass(frozen=True)
class RegistryRule:
    rule_id: str
    rule_type: str
    value: str
    family: str
    trust_level: str
    version: str = "1"
    source: str | None = None
    match: str = "exact"

    def matches(self, candidate: str) -> bool:
        if self.match == "exact":
            return candidate == self.value
        if self.match == "substring":
            return self.value.casefold() in candidate.casefold()
        if self.match == "prefix":
            return candidate.casefold().startswith(self.value.casefold())
        return False


@dataclass
class RegistryMatch:
    rule: RegistryRule
    matched_value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.version,
            "rule_type": self.rule.rule_type,
            "family": self.rule.family,
            "trust_level": self.rule.trust_level,
            "matched_value": self.matched_value,
            "source": self.rule.source,
        }


@dataclass
class TrustedRuleRegistry:
    rules: list[RegistryRule] = field(default_factory=list)
    path: Path | None = None
    content_sha256: str | None = None

    def match_yara(self, names: Iterable[str]) -> list[RegistryMatch]:
        return self._match("yara_name", names)

    def match_cape_yara(self, names: Iterable[str]) -> list[RegistryMatch]:
        return self._match("cape_yara_name", names)

    def match_detection(self, value: str | None) -> list[RegistryMatch]:
        if not value:
            return []
        return self._match("avclass_detection", [value])

    def match_sha256(self, value: str | None) -> list[RegistryMatch]:
        if not value:
            return []
        return self._match("sha256", [value])

    def _match(self, rule_type: str, values: Iterable[str]) -> list[RegistryMatch]:
        found: list[RegistryMatch] = []
        for value in values:
            if not isinstance(value, str):
                continue
            for rule in self.rules:
                if rule.rule_type == rule_type and rule.matches(value):
                    found.append(RegistryMatch(rule=rule, matched_value=value))
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "content_sha256": self.content_sha256,
            "rules": len(self.rules),
        }


def load_registry(path: Path | str | None) -> TrustedRuleRegistry:
    if path is None:
        return TrustedRuleRegistry()
    path = Path(path)
    try:
        document = read_json_strict(path)
    except FileNotFoundError as exc:
        raise ConfigError(f"trusted rule registry not found: {path}") from exc
    except ValueError as exc:
        raise ConfigError(f"trusted rule registry is not valid JSON: {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigError("trusted rule registry must be a JSON object")
    version = document.get("registry_schema_version")
    if version != REGISTRY_SCHEMA_VERSION:
        raise ConfigError(
            f"unsupported trusted rule registry schema version {version!r} "
            f"(expected {REGISTRY_SCHEMA_VERSION})"
        )
    unknown = set(document) - {"registry_schema_version", "rules"}
    if unknown:
        raise ConfigError(f"unknown trusted rule registry keys: {sorted(unknown)}")
    rules_raw = document.get("rules")
    if not isinstance(rules_raw, list):
        raise ConfigError("trusted rule registry 'rules' must be a list")
    rules: list[RegistryRule] = []
    seen: set[str] = set()
    for index, item in enumerate(rules_raw):
        where = f"rules[{index}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be an object")
        allowed = {"rule_id", "rule_type", "value", "family", "trust_level", "version", "source", "match"}
        extra = set(item) - allowed
        if extra:
            raise ConfigError(f"{where} has unknown keys: {sorted(extra)}")
        for key in ("rule_id", "rule_type", "value", "family", "trust_level"):
            if not isinstance(item.get(key), str) or not item.get(key):
                raise ConfigError(f"{where}.{key} is required and must be a non-empty string")
        if item["rule_type"] not in RULE_TYPES:
            raise ConfigError(f"{where}.rule_type must be one of {list(RULE_TYPES)}")
        if item["trust_level"] not in TRUST_LEVELS:
            raise ConfigError(f"{where}.trust_level must be one of {list(TRUST_LEVELS)}")
        match = item.get("match", "exact")
        if match not in ("exact", "substring", "prefix"):
            raise ConfigError(f"{where}.match must be one of ['exact', 'substring', 'prefix']")
        if item["rule_type"] == "sha256" and not is_sha256(item["value"]):
            raise ConfigError(f"{where}.value must be a sha256 digest for rule_type=sha256")
        rule = RegistryRule(
            rule_id=item["rule_id"],
            rule_type=item["rule_type"],
            value=item["value"],
            family=item["family"],
            trust_level=item["trust_level"],
            version=item.get("version", "1"),
            source=item.get("source"),
            match=match,
        )
        if rule.rule_id in seen:
            raise ConfigError(f"duplicate registry rule_id {rule.rule_id!r}")
        seen.add(rule.rule_id)
        rules.append(rule)
    from .io_utils import sha256_file

    digest, _ = sha256_file(path)
    return TrustedRuleRegistry(rules=rules, path=path, content_sha256=digest)
