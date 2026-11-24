"""STEP 1 — DISCOVER SOURCES
==========================
Quét và phát hiện các source report JSON từ các thư mục đầu vào được cấu hình.
Tránh quét lặp, kiểm tra liên kết/symlink/reparse points, prefetch SHA256 danh tính.

Tuân thủ Rule 8.1 (stepN_<verb>_<noun>.py) và Rule 15 (RunLogger tại State/Logs/).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add project root to sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from utils.configs import Config, load_config_file, apply_cli_overrides
from utils.discovery_utils import discover, DiscoveryResult
from utils.identity_utils import sha256_from_filename
from utils.io_utils import is_sha256, write_json
from utils.logging_utils import RunLogger


def _peek_target_sha256(path: Path, max_bytes: int) -> str | None:
    """Read target sha256 from a CAPE report; never used as evidence."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        import ijson

        with path.open("rb") as stream:
            for prefix, event, value in ijson.parse(stream):
                if prefix in ("target.file.sha256", "target.sha256") and event == "string" and isinstance(value, str):
                    if is_sha256(value):
                        return value.lower()
                if prefix == "target" and event == "end_map":
                    return None
    except Exception:
        return None
    return None


def _needs_target_prefetch(config: Config, absolute_path: str) -> bool:
    mode = config.discovery.identity
    if mode == "report":
        return True
    if mode == "auto":
        return sha256_from_filename(Path(absolute_path)) is None
    return False


def run_step1(config: Config, limit: int | None = None, logger: RunLogger | None = None) -> DiscoveryResult:
    if logger is None:
        logger = RunLogger("step1_discover_sources")
    logger.set_params(
        config_path=str(config.config_path) if config.config_path else None,
        inputs=[spec.to_dict() for spec in config.inputs],
        limit=limit,
    )
    logger.note("discovery_start", "Starting file discovery across inputs")

    discovery = discover(config, limit=limit)
    logger.note(
        "discovery_complete",
        f"Found {len(discovery.files)} candidate files",
        files=len(discovery.files),
        coverage_limited=discovery.coverage_limited,
        stats=discovery.stats,
    )

    prefetch = [item for item in discovery.files if _needs_target_prefetch(config, item.absolute_path)]
    resolved_count = 0
    target_shas: dict[str, str] = {}
    for item in prefetch:
        sha = _peek_target_sha256(Path(item.absolute_path), config.resources.max_file_bytes)
        if sha:
            target_shas[item.source_id] = sha
            resolved_count += 1

    logger.note(
        "identity_prefetch",
        f"Prefetched identities: {resolved_count}/{len(prefetch)}",
        considered=len(prefetch),
        resolved=resolved_count,
    )
    logger.set_summary(
        files_matched=len(discovery.files),
        coverage_limited=discovery.coverage_limited,
        prefetched_identities=resolved_count,
    )
    logger.finish("success")
    return discovery


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 1: Discover report sources")
    parser.add_argument("--config", "-c", required=True, help="Path to config file")
    parser.add_argument("--limit", type=int, help="Limit number of discovered files")
    args = parser.parse_args()

    config = load_config_file(Path(args.config))
    discovery = run_step1(config, limit=args.limit)
    print(f"[SUCCESS] Discovered {len(discovery.files)} sources.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
