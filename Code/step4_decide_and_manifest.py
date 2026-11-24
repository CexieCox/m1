"""STEP 4 — DECIDE AND MANIFEST
==============================
Thực thi policy (conservative-v1) đánh giá bằng chứng kỹ thuật.
Kết luận trạng thái: observed chỉ khi supported + binding trusted/reviewed + execution thực tế.
Xuất các file manifest CSV (UTF-8 BOM, an toàn trước formula injection) và all_reports.jsonl.

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
from utils.logging_utils import RunLogger
from utils.manifest_utils import write_manifests
from utils.state_utils import StateStore


def run_step4(
    store: StateStore,
    run_id: str,
    manifest_dir: Path,
    all_reports_jsonl: Path,
    logger: RunLogger | None = None,
) -> dict[str, int]:
    if logger is None:
        logger = RunLogger("step4_decide_and_manifest")
    logger.note("manifest_start", f"Writing manifests to {manifest_dir}")

    counts = write_manifests(store, run_id, manifest_dir, all_reports_jsonl)

    logger.set_summary(**counts)
    logger.note("manifest_complete", "Manifest generation completed", **counts)
    logger.finish("success")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 4: Render decision manifests")
    parser.add_argument("--run-id", required=True, help="Run ID")
    parser.add_argument("--state-db", required=True, help="Path to state.sqlite")
    parser.add_argument("--out-dir", required=True, help="Path to output manifest directory")
    args = parser.parse_args()

    store = StateStore(Path(args.state_db))
    out_dir = Path(args.out_dir)
    jsonl_path = out_dir / "all_reports.jsonl"
    counts = run_step4(store, args.run_id, out_dir, jsonl_path)
    print(f"[SUCCESS] Manifests written: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
