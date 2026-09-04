"""Secret-free local readiness report and CLI."""
import argparse
import json
import os
import sys

from dotenv import load_dotenv

from .case_store import CaseStore
from .runtime_config import get_runtime_config
from .version import VERSION_LABEL
from ml.model_policy import LEGACY_VERSION, load_legacy_compatibility_model


def build_readiness(*, check_storage=True):
    load_dotenv()
    config = get_runtime_config()
    python_supported = sys.version_info >= (3, 11)
    try:
        load_legacy_compatibility_model()
        model = {
            "status": "LOADABLE", "version": LEGACY_VERSION,
            "validation_status": "NOT VALIDATED", "production_eligible": False,
        }
    except Exception:
        model = {
            "status": "ERROR", "version": LEGACY_VERSION,
            "validation_status": "NOT VALIDATED", "production_eligible": False,
        }
    if check_storage:
        try:
            store = CaseStore()
            with store.connection() as connection:
                connection.execute("SELECT 1").fetchone()
            storage = {"status": "AVAILABLE", "encrypted_at_rest": False}
        except Exception:
            storage = {"status": "ERROR", "encrypted_at_rest": False}
    else:
        storage = {"status": "NOT_CHECKED", "encrypted_at_rest": False}
    vt_configured = bool(os.getenv("VT_API_KEY"))
    external = {
        "live_connectivity_checked": False,
        "virus_total": (
            "DISABLED" if not config.virus_total_enabled else
            "CONFIGURED" if vt_configured else "UNCONFIGURED"
        ),
        "dns": "ENABLED" if config.dns_enabled else "DISABLED",
        "rdap": "ENABLED" if config.rdap_enabled else "DISABLED",
        "geolocation": "ENABLED" if config.geolocation_enabled else "DISABLED",
    }
    required_ready = (
        python_supported and model["status"] == "LOADABLE"
        and storage["status"] in {"AVAILABLE", "NOT_CHECKED"}
    )
    return {
        "product": VERSION_LABEL,
        "status": "READY" if required_ready else "NOT_READY",
        "app_operational": required_ready,
        "python": {
            "status": "SUPPORTED" if python_supported else "UNSUPPORTED",
            "minimum": "3.11", "recommended": "3.12",
            "running": ".".join(map(str, sys.version_info[:3])),
        },
        "case_storage": storage,
        "model": model,
        "external_services": external,
        "mode": config.mode.upper(),
        "configuration_warnings": list(config.warnings),
        "notes": [
            "External intelligence is optional and was not contacted by this readiness check.",
            "No secrets, storage paths, or private evidence are included in this report.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="SpoofZero local readiness check")
    parser.add_argument("--no-storage", action="store_true")
    args = parser.parse_args(argv)
    report = build_readiness(check_storage=not args.no_storage)
    print(json.dumps(report, indent=2))
    return 0 if report["app_operational"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
