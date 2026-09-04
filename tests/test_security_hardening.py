import io
import json
import logging
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from backend.analyze import analysis_health, analyze_email, EXTERNAL_CONCURRENCY
from backend.analyzers.attachment_analyzer import analyze_attachments
from backend.analyzers.email_parser import parse_email
from backend.analyzers.reputation_analyzer import (
    analyze_attachment_reputation, check_domain_reputation,
)
from backend.analyzers.threat_intel import clear_threat_intel_cache, analyze_domain
from backend.case_reporting import build_forensic_report, report_html
from backend.case_store import CaseStorageError, CaseStore
from backend.external_services import (
    ERROR, NOT_FOUND, RATE_LIMITED, SUCCESS, TIMEOUT, UNAVAILABLE,
    MAX_HTTP_ATTEMPTS, TTLCache, request_json, service_result,
)
from backend.input_safety import (
    EmailLimits, EmailStructureError, EmailTooLargeError,
    safe_display_text, safe_evidence_filename,
)
from backend.observability import log_event
from backend.fusion_policy import CURRENT_FUSION_POLICY
from ml.model_policy import activation_eligibility


class Response:
    def __init__(self, payload=b'{}'):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, _size=-1):
        return self.payload


def write_message(directory, message, name="message.eml"):
    path = Path(directory) / name
    path.write_bytes(message.as_bytes())
    return path


def basic_message(body="Hello"):
    message = EmailMessage()
    message["Subject"] = "Status"
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.net"
    message.set_content(body)
    return message


class InputLimitTests(unittest.TestCase):
    def test_oversized_eml_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.eml"
            path.write_bytes(b"x" * 65)
            with self.assertRaisesRegex(EmailTooLargeError, "upload limit"):
                parse_email(path, limits=EmailLimits(max_eml_bytes=64))

    def test_excessive_mime_parts_are_rejected(self):
        message = basic_message()
        message.make_mixed()
        for number in range(4):
            child = EmailMessage()
            child.set_content(str(number))
            message.attach(child)
        with tempfile.TemporaryDirectory() as directory:
            path = write_message(directory, message)
            with self.assertRaisesRegex(EmailStructureError, "MIME parts"):
                parse_email(path, limits=EmailLimits(max_mime_parts=3))

    def test_pathological_mime_depth_is_rejected(self):
        outer = basic_message()
        for _ in range(5):
            wrapper = EmailMessage()
            wrapper.make_mixed()
            wrapper.attach(outer)
            outer = wrapper
        with tempfile.TemporaryDirectory() as directory:
            path = write_message(directory, outer)
            with self.assertRaisesRegex(EmailStructureError, "nesting"):
                parse_email(path, limits=EmailLimits(max_mime_depth=3))

    def test_body_text_is_bounded_and_explicitly_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_message(directory, basic_message("A" * 500))
            result = parse_email(path, limits=EmailLimits(max_body_text_bytes=80))
        self.assertLessEqual(len(result["body"].encode()), 80)
        self.assertEqual(result["processing"]["status"], "PARTIAL")
        self.assertTrue(result["processing"]["warnings"])

    def test_oversized_attachment_is_not_decoded_or_partially_hashed(self):
        message = basic_message()
        message.add_attachment(b"A" * 100, maintype="application", subtype="octet-stream",
                               filename="../../payload.bin")
        with tempfile.TemporaryDirectory() as directory:
            path = write_message(directory, message)
            result = analyze_attachments(path, limits=EmailLimits(max_attachment_bytes=32))
        item = result["attachments"][0]
        self.assertEqual(item["status"], "skipped_limit")
        self.assertIsNone(item["sha256"])
        self.assertEqual(item["filename"], "payload.bin")
        self.assertEqual(result["processing"]["status"], "PARTIAL")

    def test_attachment_count_and_total_bytes_are_bounded(self):
        message = basic_message()
        for index in range(4):
            message.add_attachment(b"x" * 10, maintype="application",
                                   subtype="octet-stream", filename=f"{index}.bin")
        limits = EmailLimits(max_attachments=2, max_total_attachment_bytes=15)
        with tempfile.TemporaryDirectory() as directory:
            result = analyze_attachments(write_message(directory, message), limits=limits)
        self.assertEqual(result["attachment_count"], 4)
        self.assertLessEqual(len(result["attachments"]), 2)
        self.assertLessEqual(result["processing"]["total_decoded_bytes"], 15)
        self.assertGreaterEqual(result["processing"]["skipped_count"], 3)

    def test_filenames_and_control_characters_are_inert(self):
        filename = safe_evidence_filename("../..\\evil\x00<script>.eml")
        self.assertNotIn("/", filename)
        self.assertNotIn(chr(92), filename)
        self.assertNotIn("<", filename)
        self.assertNotIn("\x00", filename)
        self.assertTrue(filename.endswith(".eml"))
        self.assertNotIn("\x1b", safe_display_text("subject\x1b[31m red"))


class ExternalServiceTests(unittest.TestCase):
    def setUp(self):
        self.sleeps = []

    def call(self, opener, **kwargs):
        return request_json("test_service", "https://service.invalid/item",
                            opener=opener, sleep=self.sleeps.append,
                            max_attempts=kwargs.pop("max_attempts", 2), **kwargs)

    def http_error(self, code):
        error = urllib.error.HTTPError("https://secret.invalid", code, "failure", {}, None)
        error.close()
        return error

    def test_malformed_json_and_partial_shape_are_errors(self):
        malformed = self.call(lambda *_a, **_k: Response(b"{broken"), max_attempts=1)
        array = self.call(lambda *_a, **_k: Response(b"[]"), max_attempts=1)
        self.assertEqual(malformed["service_status"], ERROR)
        self.assertEqual(array["service_status"], ERROR)
        self.assertEqual(malformed["verdict"], "UNKNOWN")

    def test_timeout_retries_once_with_backoff(self):
        count = 0
        def opener(*_a, **_k):
            nonlocal count
            count += 1
            raise socket.timeout()
        result = self.call(opener)
        self.assertEqual((result["service_status"], result["attempts"]), (TIMEOUT, 2))
        self.assertEqual(count, MAX_HTTP_ATTEMPTS)
        self.assertEqual(len(self.sleeps), 1)

    def test_401_403_404_and_429_are_not_retried(self):
        expected = {401: ERROR, 403: ERROR, 404: NOT_FOUND, 429: RATE_LIMITED}
        for code, status in expected.items():
            with self.subTest(code=code):
                calls = []
                def opener(*_a, **_k):
                    calls.append(code)
                    raise self.http_error(code)
                result = self.call(opener)
                self.assertEqual(result["service_status"], status)
                self.assertEqual(result["attempts"], 1)
                self.assertEqual(len(calls), 1)

    def test_5xx_is_bounded_to_one_retry(self):
        calls = []
        def opener(*_a, **_k):
            calls.append(1)
            raise self.http_error(503)
        result = self.call(opener)
        self.assertEqual(result["service_status"], ERROR)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(len(calls), 2)

    def test_connection_failure_is_unavailable_and_unknown(self):
        result = self.call(lambda *_a, **_k: (_ for _ in ()).throw(
            urllib.error.URLError("offline")))
        self.assertEqual(result["service_status"], UNAVAILABLE)
        self.assertEqual(result["verdict"], "UNKNOWN")

    def test_ttl_cache_hits_and_expires_without_plaintext_keys(self):
        now = [10.0]
        cache = TTLCache(2, clock=lambda: now[0])
        calls = []
        def opener(*_a, **_k):
            calls.append(1)
            return Response(b'{"ok": true}')
        first = self.call(opener, cache=cache, cache_key="token=do-not-store", ttl_seconds=5)
        second = self.call(opener, cache=cache, cache_key="token=do-not-store", ttl_seconds=5)
        now[0] = 16
        third = self.call(opener, cache=cache, cache_key="token=do-not-store", ttl_seconds=5)
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        self.assertFalse(third["cache_hit"])
        self.assertEqual(len(calls), 2)
        self.assertNotIn("do-not-store", repr(cache._items))

    def test_authorization_headers_and_urls_never_enter_logs(self):
        stream = io.StringIO()
        logger = logging.getLogger("spoofzero")
        handler = logging.StreamHandler(stream)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            request_json("vt", "https://host.invalid/api-key-in-url",
                         headers={"Authorization": "Bearer extremely-secret-value"},
                         opener=lambda *_a, **_k: Response(), max_attempts=1)
        finally:
            logger.removeHandler(handler)
        text = stream.getvalue()
        self.assertNotIn("extremely-secret-value", text)
        self.assertNotIn("api-key-in-url", text)

    def test_operational_logging_rejects_untrusted_identifiers(self):
        record = log_event("complete", analyzer="parser",
                           analysis_id="secret\nraw body", duration_ms=1)
        self.assertEqual(record["analysis_id"], "unavailable")


class EnrichmentAndPipelineTests(unittest.TestCase):
    def test_api_failure_is_unknown_not_safe(self):
        with patch("backend.analyzers.reputation_analyzer.vt_request",
                   return_value=service_result(UNAVAILABLE, "offline")):
            result = check_domain_reputation("real-domain.example.dev")
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["service_status"], UNAVAILABLE)

    def test_duplicate_attachment_hash_requests_are_suppressed(self):
        digest = "a" * 64
        attachments = {"attachments": [
            {"filename": "one.bin", "sha256": digest},
            {"filename": "two.bin", "sha256": digest},
        ]}
        with patch("backend.analyzers.reputation_analyzer.check_file_hash_reputation",
                   return_value={"status": "not_found", "service_status": NOT_FOUND,
                                 "verdict": "UNKNOWN"}) as lookup:
            results = analyze_attachment_reputation(attachments)
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual([x["filename"] for x in results], ["one.bin", "two.bin"])
        self.assertTrue(all(x["lookup_method"] == "sha256_only" for x in results))

    def test_dns_timeout_does_not_become_no_records_safe_signal(self):
        clear_threat_intel_cache()
        with patch("backend.analyzers.threat_intel.dns.resolver.resolve",
                   side_effect=socket.timeout), patch(
                       "backend.analyzers.threat_intel.rdap_lookup",
                       return_value=service_result(UNAVAILABLE, "offline")):
            result = analyze_domain("unavailable.example.dev")
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["evidence_status"], "PARTIAL")
        self.assertIn("no safety conclusion", " ".join(result["indicators"]).lower())

    def test_partial_external_failure_does_not_abort_analysis(self):
        failure = service_result(UNAVAILABLE, "offline")
        with patch("backend.analyze.analyze_domains", return_value=[
                {"domain": "x.dev", "risk_score": None, **failure}
             ]), patch("backend.analyze.analyze_reputation", return_value={
                "domains": [{"type": "domain", "value": "x.dev", **failure}], "ips": []
             }), patch("backend.analyze.analyze_attachment_reputation", return_value=[]):
            result = analyze_email("data/samples/test.eml")
        health = analysis_health(result)
        self.assertEqual(health["status"], "PARTIAL")
        self.assertIn("not treated as safe", health["message"])
        self.assertIn("final_assessment", result)

    def test_independent_enrichments_use_bounded_concurrency(self):
        active = maximum = 0
        lock = threading.Lock()
        def delayed(value):
            def call(*_args):
                nonlocal active, maximum
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                time.sleep(0.03)
                with lock:
                    active -= 1
                return value
            return call
        with patch("backend.analyze.analyze_domains", delayed([])), patch(
                "backend.analyze.analyze_reputation", delayed({"domains": [], "ips": []})), patch(
                "backend.analyze.analyze_attachment_reputation", delayed([])):
            analyze_email("data/samples/test.eml")
        self.assertGreaterEqual(maximum, 2)
        self.assertLessEqual(maximum, EXTERNAL_CONCURRENCY)


class StorageAndReportTests(unittest.TestCase):
    def test_database_permissions_are_restrictive_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permission check")
        with tempfile.TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "cases.sqlite3")
            mode = stat.S_IMODE(store.path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_database_symlink_and_corruption_fail_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corrupt = root / "corrupt.sqlite3"
            original = b"not a database"
            corrupt.write_bytes(original)
            with self.assertRaisesRegex(CaseStorageError, "unreadable or corrupted"):
                CaseStore(corrupt)
            self.assertEqual(corrupt.read_bytes(), original)
            link = root / "link.sqlite3"
            try:
                link.symlink_to(corrupt)
            except OSError:
                return
            with self.assertRaisesRegex(CaseStorageError, "symlinks"):
                CaseStore(link)

    def test_storage_never_persists_raw_payloads_or_secrets(self):
        snapshot = {
            "email": {"sha256": "a" * 64, "subject": "API_KEY=real-secret-value",
                      "from": "person@example.dev", "to": "other@example.dev"},
            "body": "private raw body", "payload": "binary",
            "api_key": "real-secret-value", "iocs": {"emails": ["person@example.dev"]},
            "attachments": {"attachments": [{"filename": "name.pdf", "sha256": "b" * 64}]},
            "final_assessment": {"risk_score": 1, "verdict": "LIKELY SAFE"},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "cases.sqlite3")
            case_id = store.create_case("case")
            store.add_analysis(case_id, "../../mail.eml", snapshot)
            stored = store.list_analyses(case_id)[0]
            serialized = json.dumps(stored["analysis"])
        self.assertNotIn("private raw body", serialized)
        self.assertNotIn("real-secret-value", serialized)
        self.assertEqual(stored["filename"], "mail.eml")

    def test_privacy_safe_mode_minimizes_personal_metadata(self):
        snapshot = {
            "email": {"sha256": "c" * 64, "subject": "private",
                      "from": "person@example.dev", "to": "other@example.dev"},
            "iocs": {"emails": ["person@example.dev"], "domains": ["example.dev"]},
            "attachments": {"attachments": [{"filename": "salary.pdf", "sha256": "d" * 64}]},
            "final_assessment": {"risk_score": 10, "verdict": "LIKELY SAFE"},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "cases.sqlite3")
            case_id = store.create_case("case")
            store.add_analysis(case_id, "mail.eml", snapshot, privacy_safe=True)
            result = store.list_analyses(case_id)[0]["analysis"]
        self.assertNotIn("subject", result["email"])
        self.assertNotIn("from", result["email"])
        self.assertEqual(result["iocs"]["emails"], [])
        self.assertEqual(result["iocs"]["domains"], ["example.dev"])
        self.assertEqual(result["storage_privacy"]["mode"], "MINIMIZED")

    def test_report_escapes_script_injection(self):
        report = build_forensic_report(
            {"case_id": "abc", "name": "<script>alert(1)</script>",
             "description": "<img src=x onerror=alert(1)>"},
            [], generated_at="2026-01-01T00:00:00+00:00")
        html = report_html(report)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;", html)


class ProtectedStateTests(unittest.TestCase):
    def test_fusion_and_candidate_policy_are_unchanged(self):
        self.assertEqual(CURRENT_FUSION_POLICY, "validated_evidence_fusion_v2")
        paths = sorted(Path("ml/models").glob("candidate*/**/metadata.json"))
        self.assertEqual(len(paths), 9)
        self.assertTrue(all(
            not activation_eligibility(json.loads(path.read_text()))["eligible"]
            for path in paths))


if __name__ == "__main__":
    unittest.main()
