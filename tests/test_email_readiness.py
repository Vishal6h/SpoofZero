from email.message import EmailMessage
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyzers.campaign_correlator import correlate_emails
from backend.analyzers.email_parser import parse_email
from backend.analyzers.nlp_detector import analyze_text
from backend.case_store import CaseStore


ROOT = Path(__file__).resolve().parents[1]


class ModelPathTests(unittest.TestCase):
    def child_environment(self):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT)
        return environment

    def test_fresh_import_uses_existing_models_from_unrelated_directory(self):
        artifacts = [ROOT / "ml" / name for name in ("vectorizer.joblib", "phishing_model.joblib")]
        before = {path: sha256(path.read_bytes()).hexdigest() for path in artifacts}
        with TemporaryDirectory() as directory:
            shadow = Path(directory) / "ml"
            shadow.mkdir()
            for artifact in artifacts:
                (shadow / artifact.name).write_bytes(b"Not a model: must never be loaded")
            code = """
import json, sys
from backend.analyzers.email_parser import parse_email
from backend.analyzers.nlp_detector import analyze_text, MODEL_PATH, VECTOR_PATH
assert MODEL_PATH.is_absolute() and VECTOR_PATH.is_absolute()
print(json.dumps(analyze_text(parse_email(sys.argv[1]))))
"""
            process = subprocess.run(
                [sys.executable, "-c", code, str(ROOT / "data/samples/test.eml")],
                cwd=directory, env=self.child_environment(), capture_output=True,
                text=True, timeout=30,
            )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["phishing_probability"], 58.05)
        self.assertEqual(before, {path: sha256(path.read_bytes()).hexdigest() for path in artifacts})

    def test_existing_nlp_cli_works_from_another_directory(self):
        with TemporaryDirectory() as directory:
            process = subprocess.run(
                [sys.executable, "-m", "backend.analyzers.nlp_detector", str(ROOT / "data/samples/test.eml")],
                cwd=directory, env=self.child_environment(), capture_output=True,
                text=True, timeout=30,
            )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout), {
            "phishing_probability": 58.05, "verdict": "SUSPICIOUS",
        })


class EmailReadinessIntegrationTests(unittest.TestCase):
    def test_equivalent_plain_and_html_text_produce_identical_model_predictions(self):
        with TemporaryDirectory() as directory:
            results = []
            for subtype, body in (
                ("plain", "Urgent verify your account immediately."),
                ("html", "<p>Urgent <b>verify your account</b> immediately.</p>"),
            ):
                message = EmailMessage()
                message["Subject"] = "Account verification"
                message.set_content(body, subtype=subtype)
                path = Path(directory) / f"{subtype}.eml"
                path.write_bytes(message.as_bytes())
                results.append(analyze_text(parse_email(path)))
        self.assertEqual(results[0], results[1])

    def test_html_and_ipv6_evidence_fit_existing_enrichment_and_case_contracts(self):
        from backend.analyze import analyze_email
        with TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "cases.sqlite3")
            case_id = store.create_case("HTML readiness")
            with patch("backend.analyze.analyze_domains", return_value=[]) as domains, \
                 patch("backend.analyze.analyze_reputation", return_value={"domains": [], "ips": []}) as reputation, \
                 patch("backend.analyze.analyze_attachment_reputation", return_value=[]), \
                 patch("urllib.request.urlopen") as fetch:
                for index in (1, 2):
                    message = EmailMessage()
                    message["From"] = f"sender{index}@notice{index}.test"
                    message["Subject"] = "Account review"
                    message["Authentication-Results"] = "receiver.test; spf=fail; dkim=none; dmarc=fail"
                    message.set_content('''<p>Verify your account immediately.</p>
                        <a href="HTTPS://CAMPAIGN.test:443/verify">Review</a>
                        <img src="https://[2001:db8::5]/pixel">''', subtype="html")
                    message.add_attachment("Attachment evidence only", filename="evidence.txt")
                    path = Path(directory) / f"message-{index}.eml"
                    path.write_bytes(message.as_bytes())
                    result = analyze_email(path)
                    self.assertEqual(set(result), {
                        "email", "final_assessment", "ai_analysis", "sender_identity", "authentication",
                        "iocs", "attachments", "attachment_reputation", "reputation", "threat_intelligence",
                        "relay_trace", "geo_analysis",
                    })
                    self.assertEqual(result["authentication"]["risk_score"], 80)
                    self.assertIn("https://campaign.test/verify", result["iocs"]["urls"])
                    self.assertEqual(result["iocs"]["ips"], ["2001:db8::5"])
                    self.assertIn("campaign.test", domains.call_args.args[0])
                    self.assertEqual(reputation.call_args.args[0], result["iocs"])
                    self.assertEqual(result["attachments"]["attachment_count"], 1)
                    self.assertEqual(result["attachments"]["attachments"][0]["sha256"], sha256(b"Attachment evidence only\n").hexdigest())
                    self.assertNotIn("html_parts", result["email"])
                    self.assertTrue(store.add_analysis(case_id, path.name, result))
                fetch.assert_not_called()
            records = store.list_analyses(case_id)
            report = correlate_emails(records)
            self.assertEqual(len(report["campaigns"]), 1)
            self.assertEqual(len(report["campaigns"][0]["email_ids"]), 2)
            self.assertEqual(json.loads(json.dumps(records)), records)


if __name__ == "__main__":
    unittest.main()
