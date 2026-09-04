#!/usr/bin/env python3
"""Measure SpoofZero local pipeline overhead with every external service mocked."""
import argparse
import json
import math
from pathlib import Path
import statistics
import sys
import time
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.analyze import analyze_email


def percentile(values, percentile_value):
    ordered = sorted(values)
    index = max(0, math.ceil((percentile_value / 100) * len(ordered)) - 1)
    return ordered[index]


def run(sample, runs, warmups):
    patches = (
        patch("backend.analyze.analyze_domains", return_value=[]),
        patch("backend.analyze.analyze_reputation", return_value={"domains": [], "ips": []}),
        patch("backend.analyze.analyze_attachment_reputation", return_value=[]),
        patch("backend.analyze.geolocate_ip", return_value={
            "status": "not_available", "service_status": "SKIPPED",
        }),
    )
    for active_patch in patches:
        active_patch.start()
    try:
        for _ in range(warmups):
            analyze_email(sample)
        durations = []
        result = None
        for _ in range(runs):
            started = time.perf_counter()
            result = analyze_email(sample)
            durations.append((time.perf_counter() - started) * 1000)
    finally:
        for active_patch in reversed(patches):
            active_patch.stop()
    return {
        "sample": str(sample),
        "external_services": "mocked",
        "warmups": warmups,
        "runs": runs,
        "median_ms": round(statistics.median(durations), 3),
        "p95_ms": round(percentile(durations, 95), 3),
        "min_ms": round(min(durations), 3),
        "max_ms": round(max(durations), 3),
        "risk_score": result["final_assessment"]["risk_score"],
        "fusion_policy": result["final_assessment"]["fusion_policy_version"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=Path, default=PROJECT_ROOT / "data/samples/test.eml")
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0:
        parser.error("runs must be positive and warmups cannot be negative")
    print(json.dumps(run(args.sample.resolve(), args.runs, args.warmups), indent=2))


if __name__ == "__main__":
    main()
