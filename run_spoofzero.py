#!/usr/bin/env python3
"""Cross-platform, shell-free SpoofZero startup helper."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

from backend.readiness import build_readiness

ROOT = Path(__file__).resolve().parent


def _host(value):
    if value == "localhost":
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise argparse.ArgumentTypeError("host must be localhost or an IP address") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description="Start SpoofZero locally")
    parser.add_argument("--check", action="store_true", help="run readiness checks and exit")
    parser.add_argument("--no-storage", action="store_true", help="skip storage in --check mode")
    parser.add_argument("--demo", action="store_true", help="disable all live external intelligence")
    parser.add_argument("--host", type=_host, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8501)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.demo:
        os.environ["SPOOFZERO_MODE"] = "demo"
    readiness = build_readiness(check_storage=not args.no_storage)
    if args.check:
        print(json.dumps(readiness, indent=2))
        return 0 if readiness["app_operational"] else 1
    if not readiness["app_operational"]:
        print("SpoofZero readiness checks failed. Run with --check for details.", file=sys.stderr)
        return 1
    environment = os.environ.copy()
    command = [
        sys.executable, "-m", "streamlit", "run", str(ROOT / "frontend" / "app.py"),
        "--server.address", args.host,
        "--server.port", str(args.port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
    ]
    return subprocess.run(command, cwd=ROOT, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
