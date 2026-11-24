"""Taxonomy loading, normalisation and alias resolution.

Tuân thủ Rule 8.2 (<domain>_utils.py) và Rule 11.2 (BASE_DIR).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .errors import TaxonomyError
from .io_utils import normalize_label, read_json_strict, sha256_bytes

_BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TAXONOMY_RESOURCE = _BASE_DIR / "configs" / "taxonomy.seed.json"
GENERIC_LABELS = {"loader", "downloader", "dropper", "installer", "crypter"}


@dataclass
class TaxonomyFamily:
    canonical: str
    canonical_normalized: str
    aliases: list[str]
    source_url: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical": self.canonical,
            "aliases": list(self.aliases),
            "source_url": self.source_url,
        }


class Taxonomy:
    """Immutable view over a taxonomy document."""

    def __init__(self, document: dict[str, Any], *, content_sha256: str, path: Optional[Path] = None):
        self.document = document
        self.content_sha256 = content_sha256
        self.path = path
        self.version = str(document.get("version", "unknown"))
        self.families: list[TaxonomyFamily] = []
        self.alias_map: dict[str, str] = {}
        self.canonical_by_normalized: dict[str, str] = {}
        self.missing_values: set[str] = set()
        self.review_examples: set[str] = set()
        self._load()

    def _load(self) -> None:
        families = self.document.get("families")
        if not isinstance(families, list) or not families:
            raise TaxonomyError("taxonomy must define a non-empty 'families' list")
        for index, family in enumerate(families):
            if not isinstance(family, dict):
                raise TaxonomyError(f"taxonomy families[{index}] must be an object")
            canonical = family.get("canonical")
            if not isinstance(canonical, str) or not canonical.strip():
                raise TaxonomyError(f"taxonomy families[{index}].canonical must be a non-empty string")
            canonical_norm = normalize_label(canonical)
            if canonical_norm in self.canonical_by_normalized:
                raise TaxonomyError(
                    f"duplicate canonical family after normalisation: {canonical!r}",
                    details={"canonical": canonical},
                )
            aliases_raw = family.get("aliases", [])
            if not isinstance(aliases_raw, list) or not all(isinstance(a, str) for a in aliases_raw):
                raise TaxonomyError(f"taxonomy families[{index}].aliases must be a list of strings")
            aliases: list[str] = []
            for alias in aliases_raw:
                alias_norm = normalize_label(alias)
                if not alias_norm:
                    continue
                existing = self.alias_map.get(alias_norm)
                if existing is not None and existing != canonical_norm:
                    raise TaxonomyError(
                        f"alias collision after normalisation: {alias!r} maps to both "
                        f"{existing!r} and {canonical_norm!r}",
                        details={"alias": alias, "families": sorted({existing, canonical_norm})},
                    )
                self.alias_map[alias_norm] = canonical_norm
                aliases.append(alias)
            existing = self.alias_map.get(canonical_norm)
            if existing is not None and existing != canonical_norm:
                raise TaxonomyError(
                    f"canonical family {canonical!r} collides with an alias of another family",
                    details={"canonical": canonical},
                )
            self.alias_map[canonical_norm] = canonical_norm
            self.canonical_by_normalized[canonical_norm] = canonical_norm
            self.families.append(
                TaxonomyFamily(
                    canonical=canonical,
                    canonical_normalized=canonical_norm,
                    aliases=aliases,
                    source_url=family.get("source_url"),
                )
            )

        missing_values = self.document.get("missing_values", ["", "(n/a)"])
        if not isinstance(missing_values, list) or not all(isinstance(v, str) for v in missing_values):
            raise TaxonomyError("taxonomy 'missing_values' must be a list of strings")
        self.missing_values = {normalize_label(value) for value in missing_values}

        review_examples = self.document.get("review_examples_not_automatically_included", [])
        if not isinstance(review_examples, list) or not all(isinstance(v, str) for v in review_examples):
            raise TaxonomyError("taxonomy 'review_examples_not_automatically_included' must be a list of strings")
        self.review_examples = {normalize_label(value) for value in review_examples}

    @property
    def seed_families(self) -> list[str]:
        return [family.canonical for family in self.families]

    @property
    def seed_family_normalized(self) -> set[str]:
        return set(self.canonical_by_normalized)

    def canonical_for(self, raw_label: object) -> Optional[str]:
        """Resolve a raw label to a canonical family name, or None."""
        if not isinstance(raw_label, str):
            return None
        normalized = normalize_label(raw_label)
        if not normalized or normalized in self.missing_values:
            return None
        canonical = self.alias_map.get(normalized)
        if canonical is None:
            return None
        return self.canonical_by_normalized[canonical]

    def is_missing(self, raw_label: object) -> bool:
        if raw_label is None:
            return True
        if not isinstance(raw_label, str):
            return False
        return normalize_label(raw_label) in self.missing_values

    def is_seed_family(self, canonical: object) -> bool:
        if not isinstance(canonical, str):
            return False
        return normalize_label(canonical) in self.seed_family_normalized

    def is_generic_label(self, raw_label: object) -> bool:
        if not isinstance(raw_label, str):
            return False
        return normalize_label(raw_label) in GENERIC_LABELS

    def is_review_example(self, raw_label: object) -> bool:
        if not isinstance(raw_label, str):
            return False
        return normalize_label(raw_label) in self.review_examples

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "content_sha256": self.content_sha256,
            "seed_families": self.seed_families,
            "families": [family.to_dict() for family in self.families],
            "missing_values": sorted(self.missing_values),
            "review_examples_not_automatically_included": sorted(self.review_examples),
        }


def load_taxonomy(path: Path | str | None = None) -> Taxonomy:
    """Load a taxonomy document from disk (or the packaged default)."""
    if path is not None:
        taxonomy_path = Path(path)
    else:
        # Check configs/ first, then fallback to resources/
        if DEFAULT_TAXONOMY_RESOURCE.is_file():
            taxonomy_path = DEFAULT_TAXONOMY_RESOURCE
        else:
            fallback = _BASE_DIR / "src" / "loaderfilter" / "resources" / "taxonomy.seed.json"
            taxonomy_path = fallback
    if not taxonomy_path.is_file():
        raise TaxonomyError(f"taxonomy file not found: {taxonomy_path}")
    try:
        raw_bytes = taxonomy_path.read_bytes()
    except OSError as exc:
        raise TaxonomyError(f"cannot read taxonomy file {taxonomy_path}: {exc}") from exc
    try:
        document = read_json_strict(taxonomy_path)
    except ValueError as exc:
        raise TaxonomyError(f"invalid taxonomy JSON in {taxonomy_path}: {exc}") from exc
    if not isinstance(document, dict):
        raise TaxonomyError("taxonomy document must be a JSON object")
    return Taxonomy(document, content_sha256=sha256_bytes(raw_bytes), path=taxonomy_path.resolve())
