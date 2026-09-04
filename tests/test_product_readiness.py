import json
import os
from hashlib import sha256
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from backend.analyze import analysis_health
from backend.analyzers.campaign_correlator import correlate_emails
from backend.analyzers.geo_analyzer import geolocate_ip
from backend.analyzers.reputation_analyzer import vt_request
from backend.analyzers.threat_intel import dns_lookup, rdap_lookup
from backend.case_reporting import (
    AI_LIMITATION, GEOLOCATION_LIMITATION, build_forensic_report,
    report_html, report_json, verify_report_integrity,
)
from backend.case_store import CaseStore
from backend.demo import (
    DEMO_EMAILS, DEMO_ROOT, demo_choices, demo_filename, run_demo_analysis,
)
from backend.external_services import UNAVAILABLE
from backend.readiness import build_readiness
from backend.runtime_config import get_runtime_config
from backend.version import VERSION_LABEL, __version__
from ml.model_policy import LEGACY_HASHES, activation_eligibility


ROOT = Path(__file__).resolve().parents[1]


class RuntimeConfigurationTests(unittest.TestCase):
    def test_release_candidate_version_is_centralized(self):
        self.assertEqual(__version__, "1.0.0-rc1")
        self.assertEqual(VERSION_LABEL, "SpoofZero v1.0.0-rc1")

    def test_runtime_defaults_preserve_existing_service_behavior(self):
        config = get_runtime_config({})
        self.assertEqual(config.mode, "local")
        self.assertTrue(config.external_services_enabled)
        self.assertTrue(config.virus_total_enabled)
        self.assertTrue(config.dns_enabled)
        self.assertTrue(config.rdap_enabled)
        self.assertTrue(config.geolocation_enabled)
        self.assertFalse(config.privacy_safe_default)
        self.assertEqual(
            (
                config.vt_timeout_seconds, config.dns_timeout_seconds,
                config.rdap_timeout_seconds, config.geolocation_timeout_seconds,
            ),
            (15.0, 3.0, 8.0, 10.0),
        )

    def test_demo_mode_overrides_every_external_service_switch(self):
        config = get_runtime_config({
            "SPOOFZERO_MODE": "demo",
            "SPOOFZERO_EXTERNAL_SERVICES_ENABLED": "true",
            "SPOOFZERO_VIRUSTOTAL_ENABLED": "true",
            "SPOOFZERO_DNS_ENABLED": "true",
            "SPOOFZERO_RDAP_ENABLED": "true",
            "SPOOFZERO_GEOLOCATION_ENABLED": "true",
        })
        self.assertFalse(config.external_services_enabled)
        self.assertFalse(config.virus_total_enabled)
        self.assertFalse(config.dns_enabled)
        self.assertFalse(config.rdap_enabled)
        self.assertFalse(config.geolocation_enabled)

    def test_invalid_configuration_falls_back_and_is_reported(self):
        config = get_runtime_config({
            "SPOOFZERO_MODE": "public",
            "SPOOFZERO_EXTERNAL_SERVICES_ENABLED": "maybe",
            "SPOOFZERO_DNS_TIMEOUT_SECONDS": "999",
            "SPOOFZERO_FAILURE_CACHE_TTL_SECONDS": "zero",
        })
        self.assertEqual(config.mode, "local")
        self.assertTrue(config.external_services_enabled)
        self.assertEqual(config.dns_timeout_seconds, 3.0)
        self.assertEqual(config.failure_cache_ttl_seconds, 20)
        self.assertEqual(len(config.warnings), 4)

    def test_individual_analyzers_do_not_contact_disabled_services(self):
        environment = {"SPOOFZERO_EXTERNAL_SERVICES_ENABLED": "false"}
        with patch.dict(os.environ, environment), patch(
            "backend.analyzers.reputation_analyzer.request_json",
            side_effect=AssertionError("VirusTotal contacted"),
        ), patch(
            "backend.analyzers.threat_intel.dns.resolver.resolve",
            side_effect=AssertionError("DNS contacted"),
        ), patch(
            "backend.analyzers.threat_intel.request_json",
            side_effect=AssertionError("RDAP contacted"),
        ), patch(
            "backend.analyzers.geo_analyzer.request_json",
            side_effect=AssertionError("geolocation contacted"),
        ):
            self.assertEqual(vt_request("/domains/example.com")["service_status"], UNAVAILABLE)
            self.assertEqual(dns_lookup("example.com")["service_status"], UNAVAILABLE)
            self.assertEqual(rdap_lookup("example.com")["service_status"], UNAVAILABLE)
            self.assertEqual(geolocate_ip("8.8.8.8")["service_status"], UNAVAILABLE)


class DemoAndReadinessTests(unittest.TestCase):
    def test_demo_catalog_is_allowlisted_and_files_exist(self):
        self.assertEqual(len(demo_choices()), 5)
        root = DEMO_ROOT.resolve()
        for key in demo_choices():
            path = DEMO_EMAILS[key]["path"].resolve()
            self.assertTrue(path.is_relative_to(root))
            self.assertTrue(path.is_file())
            self.assertEqual(demo_filename(key), path.name)
        with self.assertRaisesRegex(ValueError, "Unknown"):
            run_demo_analysis("../../private.eml")

    def test_offline_demo_never_invokes_external_analyzers(self):
        with patch("backend.analyze.analyze_domains",
                   side_effect=AssertionError("domain intelligence contacted")), patch(
            "backend.analyze.analyze_reputation",
            side_effect=AssertionError("reputation contacted"),
        ), patch(
            "backend.analyze.analyze_attachment_reputation",
            side_effect=AssertionError("attachment reputation contacted"),
        ), patch(
            "backend.analyze.geolocate_ip",
            side_effect=AssertionError("geolocation contacted"),
        ):
            result = run_demo_analysis("single_email", analysis_id="a" * 32)
        self.assertEqual(result["email"]["processing"]["evidence_source"], "BUILT_IN_DEMO")
        self.assertEqual(result["email"]["processing"]["external_intelligence"], "DISABLED")
        self.assertEqual(result["final_assessment"]["risk_score"], 75)
        self.assertEqual(
            result["final_assessment"]["fusion_policy_version"],
            "validated_evidence_fusion_v2",
        )
        self.assertEqual(result["final_assessment"]["ai_numeric_contribution"], 0.0)
        self.assertFalse(result["final_assessment"]["ai_included_in_numeric_score"])
        statuses = {
            item["service_status"]
            for items in result["reputation"].values() for item in items
        }
        self.assertEqual(statuses, {UNAVAILABLE})
        self.assertEqual(analysis_health(result)["status"], "PARTIAL")

    def test_demo_is_deterministic_for_the_same_evidence(self):
        first = run_demo_analysis("single_email", analysis_id="b" * 32)
        second = run_demo_analysis("single_email", analysis_id="c" * 32)
        self.assertEqual(first, second)

    def test_readiness_is_secret_free_and_does_not_probe_live_services(self):
        with TemporaryDirectory() as directory, patch.dict(os.environ, {
            "SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3"),
            "VT_API_KEY": "DO_NOT_PRINT_THIS_KEY",
            "SPOOFZERO_MODE": "demo",
        }), patch("urllib.request.urlopen", side_effect=AssertionError("network contacted")):
            report = build_readiness()
        encoded = json.dumps(report)
        self.assertEqual(report["status"], "READY")
        self.assertEqual(report["external_services"]["virus_total"], "DISABLED")
        self.assertFalse(report["external_services"]["live_connectivity_checked"])
        self.assertNotIn("DO_NOT_PRINT_THIS_KEY", encoded)
        self.assertNotIn(directory, encoded)

    def test_readiness_handles_model_failure_without_details_or_crash(self):
        with patch("backend.readiness.load_legacy_compatibility_model",
                   side_effect=ValueError("sensitive path details")):
            report = build_readiness(check_storage=False)
        self.assertEqual(report["status"], "NOT_READY")
        self.assertEqual(report["model"]["status"], "ERROR")
        self.assertNotIn("sensitive path details", json.dumps(report))

    def test_cross_directory_startup_readiness_command(self):
        with TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.update({
                "SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3"),
                "SPOOFZERO_MODE": "demo",
                "VT_API_KEY": "STARTUP_SECRET",
            })
            completed = subprocess.run(
                [sys.executable, str(ROOT / "run_spoofzero.py"), "--check", "--demo"],
                cwd=directory, env=environment, capture_output=True, text=True,
                timeout=30, check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "READY")
        self.assertEqual(report["mode"], "DEMO")
        self.assertNotIn("STARTUP_SECRET", completed.stdout)

    def test_real_streamlit_process_reaches_local_health_endpoint(self):
        with TemporaryDirectory() as directory:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            environment = os.environ.copy()
            environment.update({
                "SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3"),
                "SPOOFZERO_MODE": "demo",
            })
            process = subprocess.Popen(
                [
                    sys.executable, str(ROOT / "run_spoofzero.py"), "--demo",
                    "--host", "127.0.0.1", "--port", str(port),
                ],
                cwd=directory, env=environment,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            healthy = False
            try:
                for _ in range(80):
                    if process.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/_stcore/health", timeout=1
                        ) as response:
                            healthy = response.status == 200
                        if healthy:
                            break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.assertTrue(healthy, "Streamlit did not reach its local health endpoint")

    def test_streamlit_demo_control_renders_complete_result(self):
        with TemporaryDirectory() as directory, patch.dict(os.environ, {
            "SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3"),
            "SPOOFZERO_MODE": "demo",
        }), patch("urllib.request.urlopen", side_effect=AssertionError("network contacted")):
            app = AppTest.from_file(str(ROOT / "frontend" / "app.py")).run()
            self.assertEqual(len(app.exception), 0)
            app.selectbox(key="sz_demo_scenario").set_value("single_email")
            app.button(key="sz_run_demo").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.session_state["spoofzero_result"]["final_assessment"]["risk_score"], 75)
        visible = "\n".join(x.value for x in list(app.markdown) + list(app.info) + list(app.caption))
        self.assertIn("Offline demo evidence is loaded", visible)
        self.assertIn("does not identify", visible)


class EndToEndReleaseTests(unittest.TestCase):
    def test_demo_case_history_correlation_and_report_flow(self):
        first = run_demo_analysis("campaign_related_1", analysis_id="1" * 32)
        second = run_demo_analysis("campaign_related_2", analysis_id="2" * 32)
        with TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "case.sqlite3")
            case_id = store.create_case("Release smoke", "Offline end-to-end verification")
            self.assertTrue(store.add_analysis(
                case_id, "related_1.eml", first, analysis_id="1" * 32,
                analyzed_at="2026-01-01T00:00:00+00:00",
            ))
            self.assertTrue(store.add_analysis(
                case_id, "related_2.eml", second, analysis_id="2" * 32,
                analyzed_at="2026-01-01T00:01:00+00:00",
            ))
            original_evidence = json.dumps(
                store.list_analysis_history(case_id)[0]["analysis"], sort_keys=True)
            self.assertTrue(store.add_analysis(
                case_id, "related_1.eml", first, allow_reanalysis=True,
                analysis_id="3" * 32, analyzed_at="2026-01-01T00:02:00+00:00",
            ))
            history = store.list_analysis_history(case_id)
            self.assertEqual(
                json.dumps(history[0]["analysis"], sort_keys=True), original_evidence)
            latest = store.list_analyses(case_id)
            correlation = correlate_emails(latest)
            self.assertTrue(correlation["campaigns"])
            report = build_forensic_report(
                store.get_case(case_id), history, correlation,
                generated_at="2026-01-01T01:00:00+00:00",
            )
        self.assertEqual(report["analysis_count"], 3)
        self.assertTrue(verify_report_integrity(report))
        self.assertTrue(report_json(report).endswith("\n"))
        self.assertIn("SpoofZero Forensic Investigation Report", report_html(report))
        self.assertIn(AI_LIMITATION, report["limitations_and_confidence"])
        self.assertIn(GEOLOCATION_LIMITATION, report["limitations_and_confidence"])
        for item in report["analyses"]:
            ledger = item["risk_assessment"]["contribution_ledger"]
            self.assertEqual(ledger["total"], item["risk_assessment"]["score"])
            self.assertEqual(ledger["ai"], 0.0)

    def test_protected_model_hashes_and_nine_candidate_gates(self):
        for name, expected in LEGACY_HASHES.items():
            self.assertEqual(sha256((ROOT / "ml" / name).read_bytes()).hexdigest(), expected)
        candidates = sorted((ROOT / "ml" / "models").glob("candidate*/**/metadata.json"))
        self.assertEqual(len(candidates), 9)
        for path in candidates:
            metadata = json.loads(path.read_text())
            self.assertFalse(metadata.get("validated"))
            self.assertIsNot(metadata.get("active"), True)
            self.assertIsNot(metadata.get("activation_eligible"), True)
            self.assertFalse(activation_eligibility(metadata)["eligible"])

    def test_release_files_encode_private_deployment_boundaries(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        dockerignore = (ROOT / ".dockerignore").read_text()
        example = (ROOT / ".env.example").read_text()
        deployment = (ROOT / "docs" / "deployment.md").read_text()
        self.assertIn("USER spoofzero", dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn("127.0.0.1:8501:8501", deployment)
        self.assertIn("Unrestricted public deployment", deployment)
        self.assertIn("Readiness is **NO**", deployment)
        self.assertIn("*.eml", dockerignore)
        self.assertIn("!data/samples/**/*.eml", dockerignore)
        self.assertIn("VT_API_KEY=", example)
        self.assertNotRegex(example, r"VT_API_KEY=\S+")

    def test_ui_and_docs_use_safe_model_and_geo_language(self):
        source = (ROOT / "frontend" / "app.py").read_text()
        docs = "\n".join(
            path.read_text() for path in (
                ROOT / "README.md",
                ROOT / "docs" / "demo-walkthrough.md",
                ROOT / "docs" / "deployment.md",
            )
        )
        combined = (source + docs).lower()
        self.assertIn("local analysis ready", combined)
        self.assertIn("upload email", combined)
        self.assertIn("compare / correlate", combined)
        self.assertIn("does not identify", combined)
        self.assertNotIn("ai confirmed phishing", combined)
        self.assertNotIn("chance this email is phishing", combined)


if __name__ == "__main__":
    unittest.main()
