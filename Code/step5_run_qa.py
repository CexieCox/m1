"""STEP 5 — RUN QA CHECKS
=======================
Thực hiện bộ kiểm tra toàn vẹn chất lượng (QC-01 đến QC-15) cho toàn bộ run.
Kiểm tra cấu trúc CSV, tính nhất quán của nhãn, đối soát QA và phát hiện lỗi ngầm.

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
from utils.qa_utils import run_checks
from utils.runner_utils import RunLayout
from utils.state_utils import StateStore


def run_step5(
    config: Config,
    layout: RunLayout,
    store: StateStore,
    logger: RunLogger | None = None,
) -> dict[str, Any]:
    if logger is None:
        logger = RunLogger("step5_run_qa")
    logger.note("qa_start", f"Running QA checks for run {layout.run_id}")

    qa_result = run_checks(config, layout, store)
    passed = qa_result.get("passed", False)
    status = "success" if passed else "failed"

    logger.set_summary(
        passed=passed,
        checks_count=len(qa_result.get("checks", [])),
        failures_count=len(qa_result.get("failures", [])),
    )
    logger.note("qa_complete", f"QA checks finished with status: {status}")
    logger.finish(status)
    return qa_result


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 5: Run QA checks")
    parser.add_argument("--config", "-c", required=True, help="Path to config file")
    parser.add_argument("--run-id", required=True, help="Run ID")
    args = parser.parse_args()

    config = load_config_file(Path(args.config))
    layout = RunLayout.build(config, args.run_id)
    store = StateStore(layout.state_path)
    result = run_step5(config, layout, store)
    print(f"[RESULT] QA passed: {result.get('passed')}")
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
