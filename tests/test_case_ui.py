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
            self.assertEqual(app.metric[0].value, "2")
            self.assertEqual(app.metric[1].value, "1")
            self.assertEqual(len(app.get("download_button")), 1)
            self.assertEqual(CaseStore(self.db).list_cases()[0]["email_count"], 2)
            # Threshold and relationship filtering must not leave stale pair widgets.
            app.slider(key="sz_minimum_link_score").set_value(90).run()
            self.assert_clean(app)
            app.checkbox(key="sz_show_weak").uncheck().run()
            self.assert_clean(app)
            self.assertEqual(app.metric[1].value, "0")
            app.slider(key="sz_minimum_link_score").set_value(50).run()
            self.assert_clean(app)
            self.assertEqual(app.metric[1].value, "1")
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
