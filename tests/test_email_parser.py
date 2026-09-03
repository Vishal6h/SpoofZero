from email.message import EmailMessage
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyzers.auth_analyzer import analyze_authentication
from backend.analyzers.email_parser import extract_html_content, parse_email


class EmailParserTests(unittest.TestCase):
    def parse(self, content):
        if isinstance(content, EmailMessage):
            content = content.as_bytes()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sample.eml"
            path.write_bytes(content)
            return parse_email(path)

    def test_single_plain_body_and_authentication_headers_are_preserved(self):
        message = EmailMessage()
        message["From"] = "Support <help@example.test>"
        message["Subject"] = "Account notice"
        message["Authentication-Results"] = "receiver.test; spf=fail; dkim=none; dmarc=fail"
        message["Received"] = "from sender.test by receiver.test"
        message.set_content("First line\nSecond line\n")
        parsed = self.parse(message)
        self.assertEqual(parsed["body"], "First line\nSecond line\n")
        self.assertEqual(parsed["html_parts"], [])
        self.assertEqual(parsed["subject"], "Account notice")
        self.assertEqual(parsed["received"], ["from sender.test by receiver.test"])
        self.assertEqual(analyze_authentication(parsed)["risk_score"], 80)

    def test_html_only_body_is_readable_and_never_fetches_resources(self):
        message = EmailMessage()
        message.set_content('''<html><head><title>Hidden title</title><style>.bad {color:red}</style></head>
            <body><h1>Account &amp; Billing</h1><p>Hello <b>Vishal</b>!</p>
            <p>Review&nbsp;your account<br>Today</p><table><tr><td>Item</td><td>Value</td></tr></table>
            <img src="https://tracker.test/pixel" alt="Account verification">
            <script>window.location="https://hidden.test"</script><!-- hidden comment -->
            <a href="https://verify.test/login?a=1&amp;b=2">Verify now</a></body></html>''', subtype="html")
        with patch("urllib.request.urlopen") as fetch:
            parsed = self.parse(message)
        fetch.assert_not_called()
        self.assertEqual(parsed["body"], "Account & Billing\nHello Vishal!\nReview your account\nToday\nItem Value\nAccount verification Verify now")
        for unwanted in ("<", "window.location", "Hidden title", ".bad", "hidden comment"):
            self.assertNotIn(unwanted, parsed["body"])
        self.assertEqual(len(parsed["html_parts"]), 1)
        html = extract_html_content(parsed["html_parts"][0])
        self.assertIn("https://verify.test/login?a=1&b=2", html["references"])

    def test_multipart_alternative_deduplicates_wrapping_but_keeps_link_evidence(self):
        message = EmailMessage()
        message.set_content("Hello\nPlease verify your account.\n")
        message.add_alternative('<p>Hello Please verify your account.</p><a href="https://hidden-target.test"></a>', subtype="html")
        parsed = self.parse(message)
        self.assertEqual(parsed["body"], "Hello\nPlease verify your account.\n")
        self.assertIn("hidden-target.test", parsed["html_parts"][0])

    def test_distinct_html_text_is_retained_without_repeating_shared_lines(self):
        message = EmailMessage()
        message.set_content("Hello\nYour weekly report.\n")
        message.add_alternative("<p>Hello</p><p>Verify your password immediately!</p>", subtype="html")
        parsed = self.parse(message)
        self.assertEqual(parsed["body"].count("Hello"), 1)
        self.assertIn("Your weekly report.", parsed["body"])
        self.assertIn("Verify your password immediately!", parsed["body"])

    def test_mixed_parts_have_separators_and_duplicate_parts_are_removed(self):
        message = EmailMessage()
        message.make_mixed()
        for text in ("First", "Second", "First"):
            part = EmailMessage()
            part.set_content(text)
            message.attach(part)
        self.assertEqual(self.parse(message)["body"], "First\n\nSecond")

    def test_legitimate_repetition_inside_a_single_body_is_preserved(self):
        message = EmailMessage()
        message.set_content("Important\nImportant\n")
        self.assertEqual(self.parse(message)["body"], "Important\nImportant\n")

    def test_text_html_and_attached_messages_are_excluded_from_body(self):
        message = EmailMessage()
        message.set_content("Main message only.")
        message.add_attachment("Text attachment secret", filename="notes.txt")
        message.add_attachment("<p>HTML attachment secret</p>", subtype="html", filename="page.html")
        forwarded = EmailMessage()
        forwarded.set_content("Nested forwarded message secret")
        message.add_attachment(forwarded)
        inline_file = EmailMessage()
        inline_file.set_content("Named inline file secret")
        inline_file.add_header("Content-Disposition", "inline", filename="inline.txt")
        message.attach(inline_file)
        parsed = self.parse(message)
        self.assertEqual(parsed["body"], "Main message only.\n")
        self.assertEqual(parsed["html_parts"], [])

    def test_related_start_selects_body_and_ignores_other_text_resources(self):
        message = EmailMessage()
        message.make_related()
        resource = EmailMessage()
        resource.set_content("Unrelated resource text")
        resource["Content-ID"] = "<resource>"
        body = EmailMessage()
        body.set_content("<p>Actual related body</p>", subtype="html")
        body["Content-ID"] = "<body>"
        message.attach(resource)
        message.attach(body)
        message.set_param("start", "<body>")
        self.assertEqual(self.parse(message)["body"], "Actual related body")

    def test_empty_plain_alternative_falls_back_to_html(self):
        message = EmailMessage()
        message.set_content("   \n")
        message.add_alternative("<p>Useful HTML</p>", subtype="html")
        self.assertEqual(self.parse(message)["body"], "Useful HTML")

    def test_preformatted_lines_and_declared_legacy_charsets_remain_readable(self):
        self.assertEqual(extract_html_content("<pre>First\nSecond</pre>")["text"], "First\nSecond")
        parsed = self.parse(b'Content-Type: text/plain; charset="iso-8859-1"\n\nCaf\xe9')
        self.assertEqual(parsed["body"], "Café")

    def test_related_body_supports_encoded_start_parameter(self):
        raw = (b"Content-Type: multipart/related; boundary=x; start*=utf-8''%3Cbody%3E\n\n"
               b"--x\nContent-Type: text/plain\nContent-ID: <resource>\n\nResource only\n"
               b"--x\nContent-Type: text/html\nContent-ID: <body>\n\n<p>Root body</p>\n--x--\n")
        self.assertEqual(self.parse(raw)["body"], "Root body")

    def test_unknown_charset_and_broken_transfer_encoding_recover_text(self):
        cases = [
            (b'Content-Type: text/plain; charset="not-a-charset"\n\nHello caf\xc3\xa9', "Hello café"),
            (b'Content-Type: text/plain; charset="utf-8"\n\nBad byte \xff', "Bad byte �"),
            (b'Content-Type: text/plain\nContent-Transfer-Encoding: base64\n\nSGVsbG8', "Hello"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(self.parse(raw)["body"], expected)

    def test_malformed_mime_and_html_remain_safe(self):
        missing_end = b'Content-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/html\n\n<p>Recovered <b>text'
        self.assertEqual(self.parse(missing_end)["body"], "Recovered text")
        missing_boundary = b'Content-Type: multipart/mixed\n\nUnstructured payload'
        self.assertEqual(self.parse(missing_boundary)["body"], "")
        self.assertEqual(self.parse(b"")["body"], "")
        self.assertEqual(extract_html_content("<head><title>Hidden</title><body><p>Readable")['text'], "Readable")


if __name__ == "__main__":
    unittest.main()
