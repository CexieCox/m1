"""CLI tool to organize JSON reports into year-based subdirectories.

Tuân thủ Rule 17 (tools vs pipeline code).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.export_run import organize_directory_by_year


def main() -> int:
    parser = argparse.ArgumentParser(description="Organize report files into year-based folders.")
    parser.add_argument("--dir", required=True, help="Directory containing report files")
    parser.add_argument("--out", help="Destination directory (required for mode=copy)")
    parser.add_argument("--mode", choices=["move", "copy"], default="move", help="Operation mode")
    parser.add_argument("--limit", type=int, help="Optional limit on files processed")
    args = parser.parse_args()

    in_dir = Path(args.dir)
    out_dir = Path(args.out) if args.out else None
    counts = organize_directory_by_year(in_dir, out_dir, mode=args.mode, limit=args.limit)
    print("Organization completed:", counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
