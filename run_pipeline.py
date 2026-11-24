"""run_pipeline.py — Main pipeline orchestrator for LoaderFilter.

Điều phối toàn bộ quy trình từ:
  1. Discovery: Phát hiện source files
  2. Inventory: Phân loại nhãn và candidate
  3. Evidence: Stream-parse CAPE JSON & bóc tách fact/process
  4. Decision: Đánh giá chính sách bảo thủ & sinh manifest CSV
  5. QA: Chạy 15 tiêu chuẩn kiểm định chất lượng

Tuân thủ Rule 6.3 & Rule 29 của TemporalKG Repository Contract.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from utils.configs import Config, load_config_file, apply_cli_overrides
from utils.logging_utils import RunLogger
from utils.runner_utils import RunOptions, RunOutcome, generate_run_id, run


def main() -> int:
    parser = argparse.ArgumentParser(description="LoaderFilter Pipeline Orchestrator")
    parser.add_argument("--config", "-c", help="Path to config JSON file")
    parser.add_argument("--run-id", help="Explicit run ID (default: auto-generated)")
    parser.add_argument("--resume", help="Resume an existing run directory", type=Path)
    parser.add_argument("--retry-errors", action="store_true", help="Retry failed reports on resume")
    parser.add_argument("--limit", type=int, help="Limit number of sources to process")
    parser.add_argument("--workers", type=int, help="Number of worker processes")
    parser.add_argument("--mode", choices=["labels", "evidence"], help="Execution mode")
    parser.add_argument("--scope", choices=["candidates", "all"], help="Target scope")

    args = parser.parse_args()

    if args.config:
        config = load_config_file(Path(args.config))
    else:
        # Check configs/config.example.json or local config
        default_config = BASE_DIR / "configs" / "config.example.json"
        if default_config.is_file():
            config = load_config_file(default_config)
        else:
            print("[ERROR] Please provide --config <path>")
            return 2

    overrides = {
        "workers": args.workers,
        "mode": args.mode,
        "scope": args.scope,
    }
    config = apply_cli_overrides(config, overrides, cwd=Path.cwd())

    run_id = args.run_id or (args.resume.name if args.resume else generate_run_id(config))
    options = RunOptions(
        run_id=run_id,
        resume=bool(args.resume),
        limit=args.limit,
        retry_errors=args.retry_errors,
    )

    print(f"[INFO] Starting LoaderFilter pipeline run: {run_id}")
    outcome: RunOutcome = run(config, options)
    print(f"[INFO] Pipeline finished with exit code {outcome.exit_code}. QA Status: {outcome.qa_status}")
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
