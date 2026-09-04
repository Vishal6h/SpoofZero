"""Offline tests for versioned cases, comparison, and forensic reports."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from backend.case_analysis import analyze_batch
from backend.case_reporting import (
    AI_LIMITATION, GEOLOCATION_LIMITATION, REPORT_SCHEMA, REPORT_VERSION,
    build_forensic_report, compare_analyses, report_html, report_json,
    sanitize_export_filename, verify_report_integrity,
)
from backend.case_store import CaseStore, DB_SCHEMA_VERSION
from backend.analyzers.campaign_correlator import correlate_emails
from backend.fusion_policy import CURRENT_FUSION_POLICY, LEGACY_FUSION_V1
from ml.model_policy import legacy_output_metadata


def snapshot(email_id, *, score=42, verdict="SUSPICIOUS",
             policy=CURRENT_FUSION_POLICY, sender="one@alpha.test",
             urls=(), domains=(), ips=(), attachment_hashes=(), subject="Example"):
    ai = {
        "phishing_probability": 58.05,
        "verdict": "SUSPICIOUS",
        **legacy_output_metadata(),
    }
    ai_points = 0 if policy == CURRENT_FUSION_POLICY else 20.3175
    return {
        "email": {
            "from": sender, "to": "analyst@example.test", "subject": subject,
            "date": "Thu, 4 Sep 2026 00:00:00 +0000", "sha256": email_id,
        },
        "final_assessment": {
            "risk_score": score, "verdict": verdict,
            "fusion_policy_version": policy,
            "ai_numeric_contribution": ai_points,
            "contributions": {
                "sender_identity": score - ai_points, "authentication": 0,
                "reputation": 0, "attachment": 0, "relay": 0,
                "ai": ai_points, "total_before_rounding_and_cap": score,
                "rounding_and_cap_adjustment": 0, "total": score,
                "cap_applied": False,
            },
            "reasons": ["Controlled fixture reason"],
        },
        "sender_identity": {
            "from_domain": sender.rsplit("@", 1)[-1],
            "findings": [{"type": "TEST", "message": "Fixture finding"}],
        },
        "authentication": {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "findings": [], "verification": {"independently_verified": False},
        },
        "iocs": {
            "urls": list(urls), "domains": list(domains),
            "ips": list(ips), "emails": [],
        },
        "relay_trace": {
            "candidate_origin_ip": next(iter(ips), None), "hop_count": 1,
            "hops": [{"chain_status": "MATCH"}],
        },
        "geo_analysis": {"status": "success", "country": "Documentation"},
        "threat_intelligence": [],
        "reputation": {"domains": [], "ips": []},
        "attachments": {
            "attachment_count": len(attachment_hashes),
            "attachments": [{"filename": "evidence.bin", "sha256": value,
                             "size_bytes": 10} for value in attachment_hashes],
        },
        "attachment_reputation": [],
        "ai_analysis": ai,
    }


class VersionedCaseStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite3"
        self.store = CaseStore(self.path)
        self.case_id = self.store.create_case("Investigation", "Short description")
        self.digest = sha256(b"same eml").hexdigest()

    def test_fresh_schema_is_versioned_and_additive(self):
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0],
                             DB_SCHEMA_VERSION)
            tables = {r[0] for r in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            columns = {r[1] for r in connection.execute("PRAGMA table_info(cases)")}
        self.assertIn("analysis_versions", tables)
        self.assertTrue({"description", "updated_at", "archived"}.issubset(columns))

    def test_case_create_rename_archive_restore_and_timestamps(self):
        original = self.store.get_case(self.case_id)
        self.assertEqual(original["description"], "Short description")
        self.assertTrue(original["created_at"])
        self.assertTrue(original["updated_at"])
        self.store.rename_case(self.case_id, "Renamed", "Revised")
        changed = self.store.get_case(self.case_id)
        self.assertEqual((changed["name"], changed["description"]), ("Renamed", "Revised"))
        self.assertGreaterEqual(changed["updated_at"], original["updated_at"])
        self.store.archive_case(self.case_id)
        self.assertEqual(self.store.list_cases(), [])
        self.assertTrue(self.store.list_cases(include_archived=True)[0]["archived"])
        with self.assertRaisesRegex(ValueError, "Restore"):
            self.store.add_analysis(self.case_id, "a.eml", snapshot(self.digest))
        self.store.archive_case(self.case_id, False)
        self.assertFalse(self.store.get_case(self.case_id)["archived"])

    def test_same_raw_email_retains_multiple_immutable_versions(self):
        first = snapshot(self.digest, score=69, verdict="HIGH RISK",
                         policy=LEGACY_FUSION_V1)
        second = snapshot(self.digest, score=75, verdict="HIGH RISK")
        before = json.dumps(first, ensure_ascii=False)
        self.assertTrue(self.store.add_analysis(
            self.case_id, "old.eml", first, analysis_id="1" * 32,
            analyzed_at="2026-09-01T00:00:00+00:00"))
        self.assertFalse(self.store.add_analysis(
            self.case_id, "same.eml", second, analysis_id="2" * 32))
        self.assertTrue(self.store.add_analysis(
            self.case_id, "same.eml", second, allow_reanalysis=True,
            analysis_id="2" * 32, analyzed_at="2026-09-02T00:00:00+00:00"))
        history = self.store.list_analysis_history(self.case_id, self.digest)
        self.assertEqual([x["version"] for x in history], [1, 2])
        self.assertEqual([x["is_latest"] for x in history], [False, True])
        self.assertEqual(history[0]["analysis"], first)
        self.assertEqual(json.dumps(history[0]["analysis"], ensure_ascii=False), before)
        self.assertEqual(self.store.get_analysis(self.case_id, self.digest)["analysis"], second)
        self.assertEqual(len(self.store.list_analyses(self.case_id)), 1)
        with sqlite3.connect(self.path) as connection:
            original = connection.execute(
                "SELECT analysis_json FROM case_emails").fetchone()[0]
        self.assertEqual(json.loads(original), first)

    def test_analysis_id_is_idempotent_and_cannot_be_rebound(self):
        item = snapshot(self.digest)
        self.assertTrue(self.store.add_analysis(
            self.case_id, "a.eml", item, analysis_id="a" * 32))
        self.assertFalse(self.store.add_analysis(
            self.case_id, "a.eml", item, allow_reanalysis=True,
            analysis_id="a" * 32))
        with self.assertRaisesRegex(ValueError, "different evidence"):
            self.store.add_analysis(
                self.case_id, "a.eml", snapshot(self.digest, score=60),
                allow_reanalysis=True, analysis_id="a" * 32)

    def test_evidence_tables_reject_update_and_delete(self):
        self.store.add_analysis(self.case_id, "a.eml", snapshot(self.digest))
        with sqlite3.connect(self.path) as connection:
            for statement in (
                "UPDATE analysis_versions SET filename='x'",
                "DELETE FROM analysis_versions",
                "UPDATE case_emails SET filename='x'",
                "DELETE FROM case_emails",
            ):
                with self.subTest(statement=statement):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                        connection.execute(statement)

    def test_legacy_database_migrates_with_verified_backup_and_exact_snapshot(self):
        legacy = Path(self.temp.name) / "legacy.sqlite3"
        old = snapshot(self.digest, score=69, policy=LEGACY_FUSION_V1)
        raw = json.dumps(old, ensure_ascii=False)
        with sqlite3.connect(legacy) as connection:
            connection.executescript("""
                CREATE TABLE cases(case_id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at TEXT NOT NULL);
                CREATE TABLE case_emails(
                  case_id TEXT NOT NULL REFERENCES cases(case_id),email_id TEXT NOT NULL,
                  filename TEXT NOT NULL,analyzed_at TEXT NOT NULL,analysis_json TEXT NOT NULL,
                  PRIMARY KEY(case_id,email_id));
            """)
            connection.execute("INSERT INTO cases VALUES('legacy','Old','2026-08-01T00:00:00+00:00')")
            connection.execute("INSERT INTO case_emails VALUES(?,?,?,?,?)", (
                "legacy", self.digest, "old.eml", "2026-08-02T00:00:00+00:00", raw))
        migrated = CaseStore(legacy)
        self.assertIsNotNone(migrated.migration_backup)
        self.assertTrue(migrated.migration_backup.exists())
        history = migrated.list_analysis_history("legacy")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["analysis"], old)
        self.assertEqual(history[0]["version"], 1)
        with sqlite3.connect(migrated.migration_backup) as backup:
            self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(backup.execute(
                "SELECT analysis_json FROM case_emails").fetchone()[0], raw)

    def test_unknown_database_schema_is_refused_without_modification(self):
        future = Path(self.temp.name) / "future.sqlite3"
        with sqlite3.connect(future) as connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute("INSERT INTO evidence VALUES('preserve')")
            connection.execute("PRAGMA user_version=99")
        before = future.read_bytes()
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            CaseStore(future)
        self.assertEqual(future.read_bytes(), before)

    def test_latest_correlation_view_does_not_duplicate_or_use_stale_versions(self):
        other_id = sha256(b"other").hexdigest()
        first = snapshot(self.digest, urls=["https://shared.test/a"])
        other = snapshot(other_id, sender="different@other.test",
                         urls=["https://shared.test/a"])
        self.store.add_analysis(self.case_id, "a.eml", first)
        self.store.add_analysis(self.case_id, "b.eml", other)
        self.assertEqual(len(correlate_emails(
            self.store.list_analyses(self.case_id))["campaigns"]), 1)
        new = snapshot(self.digest, sender="new@new.test", urls=["https://new.test/a"])
        self.store.add_analysis(self.case_id, "a.eml", new, allow_reanalysis=True)
        latest = self.store.list_analyses(self.case_id)
        self.assertEqual(len(latest), 2)
        self.assertEqual(len(self.store.list_analysis_history(self.case_id)), 3)
        self.assertEqual(correlate_emails(latest)["campaigns"], [])
        self.assertEqual(len(self.store.list_cases(sender="alpha.test")), 1)

    def test_search_filter_sort_and_campaign_relationship(self):
        related = self.store.create_case("Related campaign", "invoice investigation")
        other = self.store.create_case("Routine", "business mail")
        a = sha256(b"a").hexdigest()
        b = sha256(b"b").hexdigest()
        c = sha256(b"c").hexdigest()
        self.store.add_analysis(
            related, "a.eml", snapshot(a, score=80, verdict="CRITICAL",
                                      sender="a@fraud.test",
                                      urls=["https://shared.test/login"],
                                      domains=["fraud.test"]),
            analyzed_at="2026-08-10T00:00:00+00:00")
        self.store.add_analysis(
            related, "b.eml", snapshot(b, score=60, verdict="HIGH RISK",
                                      sender="b@fraud.test",
                                      urls=["https://shared.test/login"],
                                      domains=["fraud.test"]),
            analyzed_at="2026-08-11T00:00:00+00:00")
        self.store.add_analysis(
            other, "c.eml", snapshot(c, score=0, verdict="LIKELY SAFE",
                                    sender="service@legit.test"),
            analyzed_at="2026-09-01T00:00:00+00:00")
        self.assertEqual(
            [x["case_id"] for x in self.store.list_cases(query="invoice")], [related])
        self.assertEqual(
            [x["case_id"] for x in self.store.list_cases(sender="fraud.test")], [related])
        self.assertEqual(
            [x["case_id"] for x in self.store.list_cases(verdict="CRITICAL")], [related])
        self.assertEqual(
            [x["case_id"] for x in self.store.list_cases(
                date_from="2026-08-10", date_to="2026-08-11")], [related])
        self.assertEqual(
            [x["case_id"] for x in self.store.list_cases(campaign=True)], [related])
        high = self.store.list_cases(sort="highest_risk")
        self.assertEqual(high[0]["case_id"], related)
        oldest = self.store.list_cases(sort="oldest")
        newest = self.store.list_cases(sort="newest")
        self.assertNotEqual(oldest[0]["case_id"], newest[0]["case_id"])

    def test_batch_duplicate_default_and_explicit_reanalysis(self):
        def analyzer(path):
            return snapshot(sha256(Path(path).read_bytes()).hexdigest())
        first = list(analyze_batch(
            [("one.eml", b"one")], self.case_id, self.store, analyzer))
        duplicate = list(analyze_batch(
            [("rename.eml", b"one")], self.case_id, self.store, analyzer))
        repeated = list(analyze_batch(
            [("again.eml", b"one"), ("same-batch.eml", b"one")],
            self.case_id, self.store, analyzer, allow_reanalysis=True))
        self.assertEqual(first[0]["status"], "saved")
        self.assertEqual(duplicate[0]["status"], "duplicate")
        self.assertEqual([x["status"] for x in repeated], ["reanalyzed", "duplicate"])
        self.assertEqual(len(self.store.list_analysis_history(self.case_id)), 2)


class ComparisonAndReportTests(unittest.TestCase):
    def setUp(self):
        self.digest = sha256(b"email").hexdigest()
        self.case = {
            "case_id": "c" * 32, "name": "../../Investigation",
            "description": "Review API_KEY=very-secret-value",
            "created_at": "2026-09-01T00:00:00+00:00",
            "updated_at": "2026-09-03T00:00:00+00:00", "archived": False,
        }
        self.first = snapshot(
            self.digest, score=69, verdict="HIGH RISK",
            policy=LEGACY_FUSION_V1, urls=["https://shared.test/a"],
            domains=["old.test"], attachment_hashes=["a" * 64])
        self.second = snapshot(
            self.digest, score=75, verdict="HIGH RISK",
            urls=["https://shared.test/a", "https://new.test/b"],
            domains=["new.test"], attachment_hashes=["a" * 64])
        self.second["reputation"]["api_key"] = "never-export"
        self.second["reputation"]["credentials"] = {"value": "credential-secret"}
        self.second["reputation"][".env"] = "environment-secret"
        self.second["email"]["body"] = "private stored body"
        self.records = [
            {"case_id": self.case["case_id"], "email_id": self.digest,
             "analysis_id": "1" * 32, "version": 1, "filename": "../../old.eml",
             "analyzed_at": "2026-09-01T00:00:00+00:00",
             "first_analyzed_at": "2026-09-01T00:00:00+00:00",
             "is_latest": False, "analysis": self.first},
            {"case_id": self.case["case_id"], "email_id": self.digest,
             "analysis_id": "2" * 32, "version": 2, "filename": r"C:\private\new.eml",
             "analyzed_at": "2026-09-03T00:00:00+00:00",
             "first_analyzed_at": "2026-09-01T00:00:00+00:00",
             "is_latest": True, "analysis": self.second},
        ]

    def build(self, **kwargs):
        return build_forensic_report(
            self.case, self.records,
            generated_at="2026-09-04T12:00:00+00:00", **kwargs)

    def test_mixed_policy_comparison_and_shared_indicators(self):
        comparison = compare_analyses(self.records[0], self.records[1])
        fields = {item["field"] for item in comparison["changes"]}
        self.assertTrue({"Forensic risk score", "Fusion policy", "URLs", "Domains"}.issubset(fields))
        self.assertTrue(comparison["same_raw_email"])
        self.assertEqual(
            comparison["shared_indicators"]["urls"], ["https://shared.test/a"])
        self.assertEqual(
            comparison["shared_indicators"]["attachment_sha256"], ["a" * 64])
        self.assertEqual(
            comparison["shared_indicators"]["sender_mailboxes"], ["one@alpha.test"])
        self.assertEqual(
            comparison["shared_indicators"]["sender_domains"], ["alpha.test"])
        self.assertIn("do not prove", comparison["note"])

    def test_json_report_schema_sections_and_contribution_ledger(self):
        report = self.build()
        self.assertEqual((report["report_schema"], report["report_version"]),
                         (REPORT_SCHEMA, REPORT_VERSION))
        self.assertEqual(report["analysis_count"], 2)
        self.assertEqual(report["analyses"][0]["raw_email_sha256"], self.digest)
        self.assertEqual(report["analyses"][1]["risk_assessment"]
                         ["contribution_ledger"]["total"], 75)
        for key in (
            "sender_identity", "authentication", "iocs", "relay_reconstruction",
            "origin_infrastructure_and_geolocation",
            "dns_rdap_threat_intelligence", "domain_ip_reputation",
            "attachments", "attachment_reputation", "ai_signal",
        ):
            self.assertIn(key, report["analyses"][0])
        self.assertEqual(json.loads(report_json(report)), report)

    def test_integrity_is_deterministic_and_tamper_evident(self):
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        self.assertTrue(verify_report_integrity(first))
        second["analyses"][0]["risk_assessment"]["score"] = 100
        self.assertFalse(verify_report_integrity(second))
        self.assertFalse(first["integrity"]["legal_digital_signature"])

    def test_filename_sanitization_never_produces_a_path(self):
        for name in ("../../etc/passwd", r"C:\Users\secret", "CON", "   ", "résumé"):
            with self.subTest(name=name):
                filename = sanitize_export_filename(name, self.case["case_id"], "json")
                self.assertNotIn("/", filename)
                self.assertNotIn("\\", filename)
                self.assertTrue(filename.startswith("spoofzero-"))
                self.assertTrue(filename.endswith(".json"))
        with self.assertRaises(ValueError):
            sanitize_export_filename("case", "x", "exe")

    def test_summary_default_excludes_secrets_paths_and_body(self):
        text = report_json(self.build())
        self.assertNotIn("never-export", text)
        self.assertNotIn("credential-secret", text)
        self.assertNotIn("environment-secret", text)
        self.assertNotIn("very-secret-value", text)
        self.assertNotIn("private stored body", text)
        self.assertNotIn(r"C:\private", text)
        self.assertTrue(all(
            item["sensitive_content"] == {
                "included": False, "handling": "summary_only"}
            for item in self.build()["analyses"]
        ))

    def test_sensitive_body_requires_explicit_opt_in_and_redacts_credentials(self):
        bodies = {"2" * 32: "Investigator excerpt\nTOKEN=private-token\nRelevant text"}
        omitted = self.build(sensitive_bodies=bodies)
        included = self.build(include_sensitive=True, sensitive_bodies=bodies)
        self.assertNotIn("readable_body", omitted["analyses"][1]["sensitive_content"])
        content = included["analyses"][1]["sensitive_content"]
        self.assertTrue(content["included"])
        self.assertIn("Relevant text", content["readable_body"])
        self.assertNotIn("private-token", content["readable_body"])
        self.assertNotIn("raw EML", report_json(omitted))

    def test_required_ai_and_geolocation_limitations_are_exact(self):
        report = self.build()
        self.assertIn(GEOLOCATION_LIMITATION, report["limitations_and_confidence"])
        self.assertIn(AI_LIMITATION, report["limitations_and_confidence"])
        ai = report["analyses"][1]["ai_signal"]
        self.assertEqual(ai["model_status"], "EXPERIMENTAL")
        self.assertEqual(ai["validation_status"], "NOT VALIDATED")
        self.assertEqual(ai["numeric_contribution"], 0)

    def test_html_is_printable_escaped_human_readable_and_integrity_checked(self):
        report = self.build()
        report["case"]["name"] = "<script>alert(1)</script>"
        report["integrity"] = {
            **report["integrity"],
            "sha256": "",
        }
        report["integrity"] = __import__("backend.case_reporting",
            fromlist=["_integrity"])._integrity(
                {k: v for k, v in report.items() if k != "integrity"})
        html = report_html(report)
        self.assertIn("SpoofZero Forensic Investigation Report", html)
        self.assertIn("@media print", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Controlled fixture reason", html)
        self.assertIn("Evidence file old.eml", html)
        self.assertNotIn("<script>", html)
        bad = deepcopy(report)
        bad["case"]["name"] = "tampered"
        with self.assertRaisesRegex(ValueError, "integrity"):
            report_html(bad)

    def test_campaign_correlation_is_preserved_in_report(self):
        other_hash = sha256(b"other").hexdigest()
        other = snapshot(other_hash, urls=["https://shared.test/a"])
        latest = [self.records[1], {
            "case_id": self.case["case_id"], "email_id": other_hash,
            "analysis_id": "3" * 32, "version": 1, "filename": "other.eml",
            "analyzed_at": "2026-09-04T00:00:00+00:00",
            "first_analyzed_at": "2026-09-04T00:00:00+00:00",
            "is_latest": True, "analysis": other,
        }]
        correlation = correlate_emails(latest)
        report = build_forensic_report(
            self.case, latest, correlation,
            generated_at="2026-09-04T12:00:00+00:00")
        self.assertEqual(len(report["campaign_correlation"]["campaigns"]), 1)
        self.assertIn("not a maliciousness verdict",
                      report["campaign_correlation"]["note"])

    def test_old_snapshot_without_new_metadata_still_reports_without_recalculation(self):
        old = {"email": {"sha256": self.digest},
               "final_assessment": {"risk_score": 69, "verdict": "HIGH RISK"}}
        record = {
            "email_id": self.digest, "filename": "old.eml",
            "analyzed_at": "2025-01-01T00:00:00+00:00", "analysis": old,
        }
        before = deepcopy(record)
        report = build_forensic_report(
            self.case, [record], generated_at="2026-09-04T00:00:00+00:00")
        self.assertEqual(report["analyses"][0]["risk_assessment"]["score"], 69)
        self.assertEqual(report["analyses"][0]["risk_assessment"]
                         ["fusion_policy_version"], "LEGACY SNAPSHOT")
        self.assertEqual(record, before)
        self.assertIsNone(report["analyses"][0]["ai_signal"]["numeric_contribution"])
        self.assertFalse(compare_analyses({}, {})["same_raw_email"])


if __name__ == "__main__":
    unittest.main()
