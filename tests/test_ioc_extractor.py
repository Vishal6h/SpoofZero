from email.message import EmailMessage
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.analyzers.email_parser import parse_email
from backend.analyzers.ioc_extractor import extract_iocs


class IOCExtractorTests(unittest.TestCase):
    def extract_message(self, message):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "email.eml"
            path.write_bytes(message.as_bytes())
            return extract_iocs(parse_email(path))

    def test_ipv4_ipv6_validation_and_canonical_deduplication(self):
        result = extract_iocs({
            "body": "192.0.2.1 192.0.2.1:25 999.1.2.3 192.0.2.999 "
                    "2001:0DB8:0:0:0:0:0:1 [2001:db8::1] ::1 ::ffff:192.0.2.4 ::ffff:c000:204 "
                    "2001:db8:::1 2001:db8::xyz aa:bb:cc:dd:ee:ff 10:30:45",
            "received": ["from host.test ([IPv6:2001:db8::2]) by mail.test"],
        })
        mapped = [value for value in result["ips"] if value.startswith("::ffff:")]
        self.assertEqual(len(mapped), 1)
        self.assertIn(mapped[0], {"::ffff:c000:204", "::ffff:192.0.2.4"})
        self.assertEqual([value for value in result["ips"] if value not in mapped], ["192.0.2.1", "2001:db8::1", "2001:db8::2", "::1"])
        self.assertNotIn("192.0.2.4", result["ips"])
        self.assertEqual(set(result), {"urls", "ips", "emails", "domains"})

    def test_sentence_punctuation_does_not_hide_ips_or_accept_invalid_extensions(self):
        result = extract_iocs({"body": "192.0.2.5. [2001:db8::3]. 2001:db8::4. 192.0.2.5.6"})
        self.assertEqual(result["ips"], ["192.0.2.5", "2001:db8::3", "2001:db8::4"])

    def test_valid_local_urls_and_case_sensitive_components_are_preserved(self):
        result = extract_iocs({"body": "http://LOCALHOST:8080/path https://a.test/Login?x=1#A https://a.test/login?x=1#A https://a.test/Login?x=2#A"})
        self.assertEqual(len(result["urls"]), 4)
        self.assertIn("http://localhost:8080/path", result["urls"])
        self.assertEqual(result["domains"], ["a.test"])

    def test_ipv6_url_hosts_default_ports_and_case_are_normalized(self):
        result = extract_iocs({"body": "HTTPS://[2001:0DB8::1]:443/Verify?a=1#Step https://[2001:db8::1]/Verify?a=1#Step"})
        self.assertEqual(result["urls"], ["https://[2001:db8::1]/Verify?a=1#Step"])
        self.assertEqual(result["ips"], ["2001:db8::1"])
        self.assertEqual(result["domains"], [])

    def test_prose_url_punctuation_is_removed_without_losing_balanced_parentheses(self):
        result = extract_iocs({"body": "See (https://Example.test/login). Also https://example.test/a_(b), please."})
        self.assertEqual(result["urls"], ["https://example.test/a_(b)", "https://example.test/login"])
        self.assertEqual(result["domains"], ["example.test"])

    def test_html_alternative_link_resource_form_and_mailto_targets_survive_deduplication(self):
        message = EmailMessage()
        message.set_content("Please review your account.")
        message.add_alternative('''<p>Please review your account.</p>
            <a href="HTTPS://LOGIN.test:443/Verify?a=1&amp;b=2">Review</a>
            <img src="https://assets.test/logo.png">
            <form action="https://submit.test/collect"><button formaction="https://second.test/send">Send</button></form>
            <a href="mailto:Support%40Reply.test">Contact</a>''', subtype="html")
        result = self.extract_message(message)
        self.assertEqual(result["urls"], ["https://assets.test/logo.png", "https://login.test/Verify?a=1&b=2", "https://second.test/send", "https://submit.test/collect"])
        self.assertEqual(result["domains"], ["assets.test", "login.test", "reply.test", "second.test", "submit.test"])
        self.assertEqual(result["emails"], ["support@reply.test"])
        self.assertNotIn("logo.png", result["domains"])

    def test_html_base_resolves_relative_links_but_does_not_guess_schemes(self):
        result = extract_iocs({"html_parts": ['''<base href="https://host.test/root/">
            <a href="login">Sign in</a><img src="//cdn.test/image.png">''']})
        self.assertEqual(result["urls"], ["https://cdn.test/image.png", "https://host.test/root/", "https://host.test/root/login"])
        without_base = extract_iocs({"html_parts": ['<img src="//cdn.test/x"><a href="/local/path">Local</a>']})
        self.assertEqual(without_base["domains"], ["cdn.test"])
        self.assertEqual(without_base["urls"], [])

    def test_static_urls_in_style_srcset_scripts_and_refresh_are_extracted(self):
        result = extract_iocs({"html_parts": ['''<head>
            <style>.header.title {background: url("https://css.test/a.png")}</style>
            <meta http-equiv="refresh" content="0; url=https://redirect.test/login">
            </head><body><img srcset="https://small.test/a.png 1x, https://large.test/a.png 2x">
            <div style="background:url(https://inline.test/b.png)">Visible</div>
            <script>const destination = "https://script.test/path";</script></body>''']})
        self.assertEqual(result["domains"], ["css.test", "inline.test", "large.test", "redirect.test", "script.test", "small.test"])
        self.assertEqual(len(result["urls"]), 6)
        self.assertNotIn("header.title", result["domains"])

    def test_long_malformed_ipv6_token_is_rejected_as_a_whole(self):
        result = extract_iocs({"body": ":" * 10000 + "not-an-ip"})
        self.assertEqual(result["ips"], [])

    def test_html_attribute_url_punctuation_and_entities_keep_exact_meaning(self):
        result = extract_iocs({"html_parts": ['<a href="https://a.test/download?token=end.&amp;amp;next=1">Click</a>']})
        self.assertEqual(result["urls"], ["https://a.test/download?token=end.&amp;next=1"])

    def test_domain_email_normalization_and_filename_noise_filter(self):
        result = extract_iocs({"body": "BÜCHER.test. xn--bcher-kva.test ALICE@EXAMPLE.test alice@example.test "
                                     "invoice.pdf report.docx image.png app.js styles.css file.eml "
                                     "archive.zip video.mov 123.456 bad..test -bad.test bad_.test"})
        self.assertEqual(result["domains"], ["archive.zip", "example.test", "video.mov", "xn--bcher-kva.test"])
        self.assertEqual(result["emails"], ["alice@example.test"])

    def test_explicit_hosts_are_preserved_but_url_path_noise_is_not_promoted(self):
        result = extract_iocs({"body": "https://download.test/report.pdf?name=invoice.docx user@internal.txt https://internal.txt/path"})
        self.assertEqual(result["domains"], ["download.test", "internal.txt"])
        self.assertEqual(result["emails"], ["user@internal.txt"])

    def test_malformed_and_unsupported_references_produce_no_garbage(self):
        result = extract_iocs({"html_parts": ['''<a href="https://999.999.999.999/path">Bad</a>
            <a href="https://bad.test:nope/">Bad</a><img src="https://[bad/">
            <a href="javascript:alert(1)">JS</a><img src="data:image/png;base64,AAAA">
            <img src="cid:resource"><img src="//bad.test:nope/">''']})
        self.assertEqual(result, {"urls": [], "ips": [], "emails": [], "domains": []})
        self.assertEqual(extract_iocs({"body": None, "received": None}), {"urls": [], "ips": [], "emails": [], "domains": []})

    def test_legacy_raw_html_body_remains_supported(self):
        result = extract_iocs({"body": '<a href="https://one.test/?a=1&amp;b=2">Visit two.test</a>'})
        self.assertEqual(result["urls"], ["https://one.test/?a=1&b=2"])
        self.assertEqual(result["domains"], ["one.test", "two.test"])

    def test_text_attachment_iocs_do_not_leak_into_message_body(self):
        message = EmailMessage()
        message.set_content("Visit https://body.test/check")
        message.add_attachment("https://attachment.test/only", filename="notes.txt")
        result = self.extract_message(message)
        self.assertEqual(result["domains"], ["body.test"])

    def test_scoped_or_malformed_ip_tokens_are_not_partially_extracted(self):
        result = extract_iocs({"body": "fe80::1%eth0 bad:2001:db8::1xyz 300.300.300.300"})
        self.assertEqual(result["ips"], [])
        self.assertEqual(result["domains"], [])


if __name__ == "__main__":
    unittest.main()
