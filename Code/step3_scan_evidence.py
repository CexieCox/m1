"""STEP 3 — SCAN EVIDENCE
=======================
Stream-parse báo cáo sandbox CAPE JSON bằng multi-worker pool.
Bóc tách các facts, processes, artifacts, và enhanced context records.

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
from utils.evidence_utils import ReportEvidence, collect_report, write_evidence
from utils.inventory_utils import InventoryEntry
from utils.logging_utils import RunLogger
from utils.models import SourceRecord
from utils.scheduler_utils import ParseScheduler, report_facts_from_dict


def run_step3(
    config: Config,
    entries: list[InventoryEntry],
    evidence_root: Path,
    logger: RunLogger | None = None,
) -> dict[str, ReportEvidence]:
    if logger is None:
        logger = RunLogger("step3_scan_evidence")
    logger.note("scan_start", f"Scheduling evidence parsing for {len(entries)} items")

    evidence_by_report: dict[str, ReportEvidence] = {}
    scheduler = ParseScheduler(config.resources, config.resources.workers)

    tasks = []
    for entry in entries:
        if config.analysis.scope == "candidates" and not entry.is_candidate:
            continue
        tasks.append({
            "source_id": entry.source.source_id,
            "path": entry.source.absolute_path,
            "limits": {
                "max_file_bytes": config.resources.max_file_bytes,
                "max_call_record_bytes": config.resources.max_call_record_bytes,
                "max_json_depth": config.resources.max_json_depth,
                "timeout_seconds": config.resources.report_timeout_seconds,
            },
        })

    logger.note("workers_dispatched", f"Dispatched {len(tasks)} parsing tasks to workers")

    completed = 0
    errors = 0
    for outcome in scheduler.run(tasks):
        source_id = outcome["source_id"]
        if outcome.get("error_code"):
            errors += 1
            continue
        raw_facts = outcome.get("facts")
        if raw_facts:
            facts_obj = report_facts_from_dict(raw_facts)
            evidence = collect_report(facts_obj, report_id=facts_obj.report_id)
            write_evidence(evidence_root, evidence)
            evidence_by_report[evidence.report_id] = evidence
            completed += 1

    logger.set_summary(
        tasks_submitted=len(tasks),
        reports_completed=completed,
        reports_errored=errors,
    )
    logger.note("scan_complete", f"Evidence scanning completed: {completed} parsed, {errors} errors")
    logger.finish("success")
    return evidence_by_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Step 3: Scan report evidence")
    parser.add_argument("--config", "-c", required=True, help="Path to config file")
    args = parser.parse_args()

    config = load_config_file(Path(args.config))
    print("[INFO] Run step3 via full pipeline or programmatic invocation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
