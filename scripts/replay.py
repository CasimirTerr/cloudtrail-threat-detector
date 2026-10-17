#!/usr/bin/env python3
"""Replay CloudTrail events through the detector locally: no AWS account needed.

  python scripts/replay.py                         # all sample events
  python scripts/replay.py path/to/event.json ...  # your own records
  python scripts/replay.py --cloudtrail-file 123456789012_CloudTrail_us-east-1_....json.gz
"""
import argparse, gzip, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from detector.rules import evaluate  # noqa: E402

COLORS = {"CRITICAL": "\033[41;97m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def records_from(path: Path):
    raw = gzip.open(path, "rt").read() if path.suffix == ".gz" else path.read_text()
    data = json.loads(raw)
    if "Records" in data:            # a CloudTrail log file from S3
        return data["Records"]
    return [data.get("detail", data)]  # one record, or an EventBridge event


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--cloudtrail-file", type=Path, help="a CloudTrail log file (.json or .json.gz) from S3")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    files = list(args.files)
    if args.cloudtrail_file:
        files.append(args.cloudtrail_file)
    if not files:
        files = sorted((ROOT / "tests" / "events").glob("*/*.json"))

    total, hits = 0, 0
    for f in files:
        for rec in records_from(f):
            total += 1
            for a in evaluate(rec):
                hits += 1
                c, r = ("", "") if args.no_color else (COLORS[a.severity], RESET)
                print(f"{c}{a.severity:<8}{r} {a.rule_id:<20} {a.actor:<22} {a.description}")
    print(f"\n{total} events scanned, {hits} alerts")


if __name__ == "__main__":
    main()
