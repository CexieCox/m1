"""STEP 2 — BUILD INVENTORY
=========================
Đọc ba bảng mapping (AVClass, CAPE, consensus) và taxonomy họ loader.
Phân loại các mẫu: seed_candidate, generic_label_review, raw_loader_detection,...

Tuân thủ Rule 8.1 (stepN_<verb>_<noun>.py) và Rule 15 (RunLogger tại State/Logs/).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from utils.configs import Config, load_config_file
from utils.discovery_utils import discover, DiscoveredFile
from utils.inventory_utils import build_inventory, InventoryResult
from utils.label_utils import LabelStore
from utils.logging_utils import RunLogger
from utils.taxonomy_utils import load_taxonomy, Taxonomy


def run_step2(
    config: Config,
    files: list[DiscoveredFile] | None = None,
    target_shas: dict[str, str] | None = None,
    logger: RunLogger | None = None,
) -> tuple[InventoryResult, LabelStore, Taxonomy]:
    if logger is None:
        logger = RunLogger("step2_build_inventory")
    logger.note("inventory_start", "Loading taxonomy and label mappings")

    if config.taxonomy is None:
        raise ValueError("A taxonomy is required for inventory classification")
    taxonomy = load_taxonomy(config.taxonomy)
    label_store = LabelStore(taxonomy)

    if config.label_source_paths():
        label_store.load(
            config.labels.avclass,
            config.labels.cape,
            config.labels.consensus,
            config.labels.row_errors,
        )
    logger.note("labels_loaded", "Labels loaded into memory", **label_store.to_dict())

    if files is None:
        discovery = discover(config)
        files = discovery.files

    logger.note("build_inventory", f"Classifying {len(files)} files into candidate categories")
    inventory = build_inventory(
        files,
        label_store,
        taxonomy,
        target_sha256_by_source=target_shas or {},
        identity_mode=config.discovery.identity,
    )

    logger.set_summary(
        total_sources=len(inventory.entries),
        seed_candidates=len(inventory.seed_candidates),
        candidates=len(inventory.candidates),
        counters=inventory.counters,
    )
    logger.note(
        "inventory_complete",
        f"Inventory complete: {len(inventory.candidates)} candidates, {len(inventory.seed_candidates)} seed loaders",
    )
    logger.finish("success")
    return inventory, label_store, taxonomy


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 2: Build candidate inventory")
    parser.add_argument("--config", "-c", required=True, help="Path to config file")
    args = parser.parse_args()

    config = load_config_file(Path(args.config))
    inventory, _, _ = run_step2(config)
    print(f"[SUCCESS] Inventory built: {len(inventory.candidates)} candidates, {len(inventory.seed_candidates)} seed candidates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
