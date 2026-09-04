import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from backend.case_store import CaseStore
from test_campaign_correlation import analysis


class Upload:
    def __init__(self, name, content):
        self.name, self.content = name, content

    def getvalue(self):
        return self.content


class CaseUITests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "cases.sqlite3")
        env = patch.dict(os.environ, {"SPOOFZERO_CASE_DB": self.db})
        env.start()
        self.addCleanup(env.stop)

    def assert_clean(self, app):
        self.assertEqual(len(app.exception), 0, [item.message for item in app.exception])

    def create_case(self, app, name="Demo case"):
        app.text_input[0].set_value(name)
        next(button for button in app.button if button.label == "Create case").click()
        app.run()
        self.assert_clean(app)

    def test_original_single_email_dashboard_and_case_save(self):
        from backend.analyze import analyze_email
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No network")):
            original = analyze_email("data/samples/test.eml")
        upload = Upload("test.eml", Path("data/samples/test.eml").read_bytes())
        def uploader(*args, **kwargs):
            return [] if kwargs.get("key") == "sz_batch_files" else upload
        with patch("streamlit.file_uploader", side_effect=uploader), \
             patch("backend.analyze.analyze_email", return_value=original):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
            self.assert_clean(app)
            self.create_case(app)
            next(button for button in app.button if button.label == "Analyze").click().run()
            self.assert_clean(app)
            visible = "\n".join(item.value for item in list(app.markdown) + list(app.caption))
            self.assertIn("Forensic Risk Score", visible)
            self.assertIn("Fusion policy: Validated Evidence v2", visible)
            self.assertIn("AI numeric contribution: 0 points", visible)
            self.assertIn("not a statistically calibrated probability", visible)
            self.assertIn("Forensic Score Breakdown", visible)
            self.assertIn("Evidence contributions plus the explicit rounding / score-cap", visible)
            labels = [tab.label for tab in app.tabs]
            for label in ("Overview", "Email Forensics", "Threat Intelligence", "Attachments", "Raw Evidence", "Campaign / Cases"):
                self.assertIn(label, labels)
            # The save control appears immediately after the first analysis.
            app.button(key="sz_save_current").click().run()
            self.assert_clean(app)
            store = CaseStore(self.db)
            case = store.list_cases()[0]
            saved = store.list_analyses(case["case_id"])
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0]["analysis"], original)
            app.button(key="sz_save_current").click().run()
            self.assert_clean(app)
            self.assertEqual(len(store.list_analyses(case["case_id"])), 1)
            # A new browser session can reopen the saved result.
            fresh = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
            fresh.button(key="sz_open_email").click().run()
            self.assert_clean(fresh)
            self.assertEqual(fresh.session_state["spoofzero_result"], original)

    def test_reanalysis_display_does_not_replace_historical_case_snapshot(self):
        from copy import deepcopy
        from backend.analyze import analyze_email
        from backend.analyzers.fusion_engine import calculate_final_risk
        from backend.fusion_policy import LEGACY_FUSION_V1, CURRENT_FUSION_POLICY
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No network")):
            fresh = analyze_email("data/samples/test.eml")
        historical = deepcopy(fresh)
        historical["final_assessment"] = calculate_final_risk(
            historical["sender_identity"], historical["authentication"],
            historical["relay_trace"], historical["ai_analysis"],
            historical["reputation"], historical["attachment_reputation"],
            policy_version=LEGACY_FUSION_V1,
        )
        store = CaseStore(self.db)
        case_id = store.create_case("Preserved historical case")
        store.add_analysis(case_id, "test.eml", historical)
        with store.connection() as connection:
            before = connection.execute("SELECT analysis_json FROM case_emails").fetchone()[0]
        upload = Upload("test.eml", Path("data/samples/test.eml").read_bytes())
        def uploader(*args, **kwargs):
            return [] if kwargs.get("key") == "sz_batch_files" else upload
        with patch("streamlit.file_uploader", side_effect=uploader), \
             patch("backend.analyze.analyze_email", return_value=fresh) as analyzer:
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
            app.button(key="sz_open_email").click().run()
            self.assert_clean(app)
            self.assertEqual(app.session_state["spoofzero_result"]["final_assessment"]["risk_score"], 69)
            next(button for button in app.button if button.label == "Analyze").click().run()
            self.assert_clean(app)
            self.assertEqual(analyzer.call_count, 1)
            self.assertEqual(app.session_state["spoofzero_result"], fresh)
            self.assertEqual(fresh["final_assessment"]["fusion_policy_version"], CURRENT_FUSION_POLICY)
            app.button(key="sz_save_current").click().run()
            self.assert_clean(app)
            self.assertTrue(any("saved historical snapshot" in item.value for item in app.info))
            self.assertEqual(app.session_state["spoofzero_result"]["final_assessment"]["risk_score"], 75)
            app.button(key="sz_open_email").click().run()
            self.assert_clean(app)
            self.assertEqual(app.session_state["spoofzero_result"], historical)
        with store.connection() as connection:
            after = connection.execute("SELECT analysis_json FROM case_emails").fetchone()[0]
        self.assertEqual(before, after)

    def test_explicit_reanalysis_appends_history_in_same_case(self):
        from backend.analyze import analyze_email
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No network")):
            original = analyze_email("data/samples/test.eml")
        upload = Upload("test.eml", Path("data/samples/test.eml").read_bytes())

        def uploader(*args, **kwargs):
            return [] if kwargs.get("key") == "sz_batch_files" else upload

        with patch("streamlit.file_uploader", side_effect=uploader), \
             patch("backend.analyze.analyze_email", return_value=original):
            app = AppTest.from_file(str(
                Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
            self.create_case(app, "Version history")
            next(button for button in app.button if button.label == "Analyze").click().run()
            app.button(key="sz_save_current").click().run()
            store = CaseStore(self.db)
            case_id = store.list_cases()[0]["case_id"]
            first = store.list_analysis_history(case_id)[0]
            next(button for button in app.button if button.label == "Analyze").click().run()
            app.checkbox(key=f"sz_save_version_{case_id}").check().run()
            app.button(key="sz_save_current").click().run()
            self.assert_clean(app)
            history = store.list_analysis_history(case_id)
            self.assertEqual([item["version"] for item in history], [1, 2])
            self.assertEqual([item["is_latest"] for item in history], [False, True])
            self.assertEqual(history[0]["analysis_id"], first["analysis_id"])
            self.assertEqual(history[0]["analysis"], first["analysis"])

    def test_batch_upload_failure_duplicate_and_report_controls(self):
        uploads = [Upload("one.eml", b"one"), Upload("two.eml", b"two"),
                   Upload("renamed.eml", b"one"), Upload("bad.eml", b"bad")]
        def uploader(*args, **kwargs):
            return uploads if kwargs.get("key") == "sz_batch_files" else None
        def analyzer(path):
            content = Path(path).read_bytes()
            if content == b"bad":
                raise ValueError("Unable to parse this demo file")
            return analysis(sender=content.decode() + "@alpha.test", hashes=["a" * 64])
        with patch("streamlit.file_uploader", side_effect=uploader), \
             patch("backend.analyze.analyze_email", side_effect=analyzer) as mock_analyze:
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
            self.create_case(app)
            app.button(key="sz_analyze_batch").click().run(timeout=15)
            self.assert_clean(app)
            self.assertEqual(mock_analyze.call_count, 3)
            self.assertEqual(next(x.value for x in app.metric if x.label == "Case emails"), "2")
            self.assertEqual(next(x.value for x in app.metric if x.label == "Candidate groups"), "1")
            self.assertEqual(len(app.get("download_button")), 2)
            self.assertEqual(CaseStore(self.db).list_cases()[0]["email_count"], 2)
            # Threshold and relationship filtering must not leave stale pair widgets.
            app.slider(key="sz_minimum_link_score").set_value(90).run()
            self.assert_clean(app)
            app.checkbox(key="sz_show_weak").uncheck().run()
            self.assert_clean(app)
            self.assertEqual(next(x.value for x in app.metric if x.label == "Candidate groups"), "0")
            app.slider(key="sz_minimum_link_score").set_value(50).run()
            self.assert_clean(app)
            self.assertEqual(next(x.value for x in app.metric if x.label == "Candidate groups"), "1")
            app.button(key="sz_open_email").click().run()
            self.assert_clean(app)
            self.create_case(app, "Isolated second case")
            self.assertTrue(any("Add analyzed emails" in item.value for item in app.info))

    def test_unavailable_case_storage_does_not_block_existing_dashboard(self):
        with patch("frontend.case_ui.CaseStore", side_effect=OSError("Read-only case directory")):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "frontend" / "app.py")).run()
        self.assert_clean(app)
        self.assertTrue(any("Case storage is unavailable" in item.value for item in app.warning))
        self.assertEqual(len(app.get("file_uploader")), 1)


if __name__ == "__main__":
    unittest.main()
