import copy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyzers.campaign_correlator import (
    EMPTY_SHA256, correlate_emails, extract_indicators, normalize_domain,
    normalize_ip, normalize_url,
)
from backend.case_analysis import MAX_EMAIL_BYTES, analyze_batch
from backend.case_store import CaseStore


def analysis(sender="one@alpha.test", urls=(), ips=(), domains=(), hashes=()):
    return {
        "email": {"from": sender, "subject": "Example email", "sha256": sha256(sender.encode()).hexdigest()},
        "iocs": {"urls": list(urls), "ips": list(ips), "domains": list(domains)},
        "attachments": {"attachments": [{"sha256": value, "size_bytes": 3} for value in hashes]},
        "final_assessment": {"risk_score": 42, "verdict": "SUSPICIOUS"},
    }


def record(name, result):
    return {"email_id": sha256(name.encode()).hexdigest(), "filename": name,
            "analyzed_at": "2026-09-04T00:00:00+00:00", "analysis": result}


class CorrelationTests(unittest.TestCase):
    def test_normalization_preserves_meaningful_url_components(self):
        self.assertEqual(normalize_domain("BÜCHER.test."), "xn--bcher-kva.test")
        self.assertEqual(normalize_url("HTTPS://BÜCHER.test:443/Login?a=1#x"),
                         "https://xn--bcher-kva.test/Login?a=1#x")
        self.assertEqual(normalize_url("http://Example.test:80"), "http://example.test/")
        self.assertEqual(normalize_ip("2001:4860:4860:0:0:0:0:8888"), "2001:4860:4860::8888")
        self.assertNotEqual(normalize_url("https://a.test/Login"), normalize_url("https://a.test/login"))
        self.assertNotEqual(normalize_url("https://a.test/?a=1&b=2"), normalize_url("https://a.test/?b=2&a=1"))
        self.assertNotEqual(normalize_url("https://a.test/#x"), normalize_url("https://a.test/#y"))
        for url in ("https://example.test:bad/", "file:///etc/passwd", "https://a.test/\nfoo", "https://[bad/"):
            self.assertIsNone(normalize_url(url))
        for domain in ("", "999.999.999.999", "-bad.test", "localhost", "example.test.evil/"):
            self.assertIsNone(normalize_domain(domain))
        self.assertIsNone(normalize_ip("999.999.999.999"))

    def test_actual_sender_roles_and_provenance(self):
        a = analysis('Display Name <One@ALPHA.test>')
        a["email"].update(reply_to="reply@beta.test", return_path="<bounce@gamma.test>")
        a["iocs"]["emails"] = ["recipient@unrelated.test"]
        items = {(i["kind"], i["value"]): i for i in extract_indicators(a)}
        self.assertEqual(items[("sender", "one@alpha.test")]["sources"], ["email.from"])
        self.assertIn(("sender", "reply@beta.test"), items)
        self.assertIn(("sender", "bounce@gamma.test"), items)
        self.assertNotIn(("sender", "recipient@unrelated.test"), items)

    def test_exact_hash_links_and_duplicates_do_not_inflate(self):
        a = record("a", analysis(hashes=["a" * 64]))
        b = record("b", analysis(sender="two@beta.test", hashes=["A" * 64]))
        report = correlate_emails([a, a, b])
        self.assertEqual(report["email_count"], 2)
        self.assertEqual(len(report["campaigns"]), 1)
        self.assertEqual(report["pairs"][0]["score"], 60)
        self.assertEqual(correlate_emails([a, a])["pairs"], [])

    def test_transitive_groups_keep_direct_links_explicit(self):
        a = record("a", analysis(sender="a@a.test", hashes=["a" * 64]))
        b = record("b", analysis(sender="b@b.test", hashes=["a" * 64], urls=["https://payload.test/login"]))
        c = record("c", analysis(sender="c@c.test", urls=["https://payload.test/login"]))
        d = record("d", analysis(sender="d@d.test"))
        report = correlate_emails([d, c, b, a])
        self.assertEqual(len(report["campaigns"]), 1)
        self.assertEqual(len(report["campaigns"][0]["email_ids"]), 3)
        self.assertEqual(report["campaigns"][0]["link_count"], 2)
        self.assertEqual(report["unlinked_email_ids"], [d["email_id"]])
        self.assertEqual(report, correlate_emails([a, b, c, d]))

    def test_common_receiving_infrastructure_stays_weak(self):
        items = []
        for name in ("alice", "bob"):
            a = analysis(sender=f"{name}@gmail.com", domains=["gmail.com", "mx.receiver.test"], ips=["10.0.0.1", "8.8.8.8"])
            a["relay_trace"] = {"candidate_origin_ip": "8.8.8.8", "hops": [{"by_host": "mx.receiver.test"}]}
            a["threat_intelligence"] = [{"dns": {"MX": ["10 mx.provider.test."], "NS": ["ns.provider.test."]},
                                        "rdap": {"nameservers": ["ns.provider.test"]}}]
            a["geo_analysis"] = {"status": "success", "asn": 15169}
            items.append(record(name, a))
        report = correlate_emails(items)
        self.assertFalse(report["campaigns"])
        self.assertEqual(report["pairs"][0]["score"], 20)
        self.assertFalse(correlate_emails(items, 1)["campaigns"])
        kinds = {item["kind"] for item in report["shared_indicators"]}
        self.assertTrue({"ip", "domain", "relay_host", "mail_server", "nameserver", "asn"} <= kinds)

    def test_repeated_evidence_in_one_family_is_capped(self):
        domains = [f"d{i}.test" for i in range(20)]
        a = record("a", analysis(domains=domains))
        b = record("b", analysis(sender="two@elsewhere.test", domains=domains))
        report = correlate_emails([a, b])
        self.assertEqual(report["pairs"][0]["score"], 10)
        self.assertFalse(report["campaigns"])

    def test_empty_hash_and_non_public_ips_are_context(self):
        a = record("a", analysis(sender="a@a.test", hashes=[EMPTY_SHA256], ips=["10.0.0.2", "192.0.2.1"]))
        b = record("b", analysis(sender="b@b.test", hashes=[EMPTY_SHA256], ips=["10.0.0.2", "192.0.2.1"]))
        report = correlate_emails([a, b])
        self.assertEqual(report["pairs"][0]["score"], 0)
        self.assertFalse(report["campaigns"])

    def test_dns_ip_matches_email_ip_and_exposes_both_sources(self):
        a = analysis(sender="a@a.test", ips=["8.8.4.4"])
        b = analysis(sender="b@b.test")
        b["threat_intelligence"] = [{"domain": "infra.test", "dns": {"A": ["8.8.4.4"]}}]
        report = correlate_emails([record("a", a), record("b", b)])
        evidence = report["pairs"][0]["evidence"][0]
        self.assertEqual((evidence["kind"], evidence["value"], evidence["weight"]), ("ip", "8.8.4.4", 10))
        self.assertIn("dns.A:infra.test", evidence["left_sources"] + evidence["right_sources"])
        self.assertIn("iocs.ips", evidence["left_sources"] + evidence["right_sources"])

    def test_sender_plus_candidate_ip_forms_link_without_altering_threat_score(self):
        a = analysis()
        a["relay_trace"] = {"candidate_origin_ip": "8.8.8.8"}
        before = copy.deepcopy(a)
        report = correlate_emails([record("a", a), record("b", a)])
        self.assertEqual(report["pairs"][0]["score"], 50)
        self.assertTrue(report["campaigns"])
        self.assertEqual(a, before)
        self.assertFalse(correlate_emails([record("a", a), record("b", a)], 55)["campaigns"])

    def test_missing_evidence_and_invalid_indicators_do_not_crash(self):
        empty = {"email": None, "iocs": {"urls": None, "ips": ["999.999.999.999"], "domains": None},
                 "attachments": None, "threat_intelligence": None}
        self.assertEqual(extract_indicators(empty), [])
        self.assertEqual(correlate_emails([])["email_count"], 0)
        with self.assertRaises(ValueError):
            correlate_emails([], 0)


class CaseStorageAndBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite3"
        self.store = CaseStore(self.path)
        self.case_id = self.store.create_case("Investigation")

    def test_persistence_case_isolation_and_duplicate_identity(self):
        a = analysis()
        self.assertTrue(self.store.add_analysis(self.case_id, "a.eml", a))
        self.assertFalse(self.store.add_analysis(self.case_id, "renamed.eml", a))
        other = self.store.create_case("'; DROP TABLE cases; --")
        self.assertTrue(self.store.add_analysis(other, "a.eml", a))
        reopened = CaseStore(self.path)
        self.assertEqual(len(reopened.list_cases()), 2)
        self.assertEqual(len(reopened.list_analyses(self.case_id)), 1)
        saved = reopened.get_analysis(self.case_id, a["email"]["sha256"])
        self.assertEqual(saved["analysis"], a)
        self.assertEqual(saved["filename"], "a.eml")
        with self.assertRaises(ValueError):
            reopened.add_analysis("missing-case", "a.eml", a)

    def test_capacity_and_invalid_results_fail_without_corrupting_case(self):
        with patch("backend.case_store.MAX_CASE_EMAILS", 1):
            self.store.add_analysis(self.case_id, "a.eml", analysis())
            with self.assertRaises(ValueError):
                self.store.add_analysis(self.case_id, "b.eml", analysis(sender="b@b.test"))
            self.assertFalse(self.store.add_analysis(self.case_id, "a.eml", analysis()))
        with self.assertRaises(ValueError):
            self.store.add_analysis(self.case_id, "bad.eml", {"email": {}})
        with self.assertRaises(ValueError):
            self.store.create_case("   ")
        self.assertEqual(len(self.store.list_analyses(self.case_id)), 1)

    def test_batch_isolates_failures_deduplicates_and_removes_temporary_payloads(self):
        paths = []
        def analyzer(path):
            paths.append(Path(path))
            content = Path(path).read_bytes()
            if content == b"broken":
                raise ValueError("Malformed message")
            return analysis()
        files = [("../../one.eml", b"one"), ("renamed.eml", b"one"),
                 ("broken.eml", b"broken"), ("two.eml", b"two"), ("empty.eml", b"")]
        outcomes = list(analyze_batch(files, self.case_id, self.store, analyzer))
        self.assertEqual([item["status"] for item in outcomes], ["saved", "duplicate", "error", "saved", "error"])
        self.assertEqual(len(paths), 3)
        self.assertTrue(all(not path.exists() and not path.parent.exists() for path in paths))
        self.assertEqual(len(self.store.list_analyses(self.case_id)), 2)
        self.assertNotEqual(outcomes[0]["email_id"], outcomes[3]["email_id"])
        self.assertEqual(outcomes[0]["analysis"]["email"]["sha256"], sha256(b"one").hexdigest())

    def test_batch_limits_and_lazy_readers(self):
        with self.assertRaises(ValueError):
            list(analyze_batch([("a", b"x")] * 26, self.case_id, self.store, lambda _: analysis()))
        outcomes = list(analyze_batch([("big", b"x" * (MAX_EMAIL_BYTES + 1)),
                                      ("small", lambda: b"hello")], self.case_id, self.store, lambda _: analysis()))
        self.assertEqual([item["status"] for item in outcomes], ["error", "saved"])

    def test_demo_batch_uses_real_pipeline_and_separates_unrelated_email(self):
        files = [(path.name, path.read_bytes()) for path in sorted(Path("data/samples/campaign").glob("*.eml"))]
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No network in demo tests")), \
             patch("dns.resolver.resolve", side_effect=AssertionError("No DNS in demo tests")) as dns_lookup:
            outcomes = list(analyze_batch(files, self.case_id, self.store))
        self.assertEqual([item["status"] for item in outcomes], ["saved", "saved", "saved"])
        dns_lookup.assert_not_called()
        records = self.store.list_analyses(self.case_id)
        report = correlate_emails(records)
        self.assertEqual(len(report["campaigns"]), 1)
        self.assertEqual(len(report["campaigns"][0]["email_ids"]), 2)
        unrelated_id = next(item["email_id"] for item in records if item["filename"] == "unrelated.eml")
        self.assertEqual(report["unlinked_email_ids"], [unrelated_id])

    def test_existing_sample_baseline_and_additive_metadata(self):
        from backend.analyze import analyze_email
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No network in regression tests")):
            result = analyze_email("data/samples/test.eml")
            attachment_result = analyze_email("data/samples/attachment_test.eml")
        self.assertEqual(result["final_assessment"]["risk_score"], 69)
        self.assertEqual(result["ai_analysis"]["phishing_probability"], 58.05)
        self.assertEqual(result["relay_trace"]["hop_count"], 3)
        self.assertEqual(result["email"]["sha256"], sha256(Path("data/samples/test.eml").read_bytes()).hexdigest())
        self.assertEqual(result["email"]["message_id"], "<123456@example.com>")
        self.assertEqual(attachment_result["attachments"]["attachment_count"], 1)
        self.assertEqual(attachment_result["attachment_reputation"][0]["status"], "error")


if __name__ == "__main__":
    unittest.main()
