import unittest

from phishverdict import engine
from phishverdict.engine import analyze


def ids(result):
    return sorted(h.signal_id for h in result.hits)


class TestVerdictThresholds(unittest.TestCase):
    def test_clean_is_zero(self):
        self.assertEqual(analyze("https://python.org/").verdict, "CLEAN")
        self.assertEqual(analyze("https://python.org/").score, 0)

    def test_critical_at_fifty(self):
        r = analyze("http://paypal.com.verify-login.xyz/webscr")
        self.assertEqual(r.verdict, "CRITICAL")
        self.assertGreaterEqual(r.score, 50)

    def test_suspicious_at_twenty(self):
        r = analyze("http://secure-login-app.top/session")
        self.assertEqual(r.verdict, "SUSPICIOUS")
        self.assertGreaterEqual(r.score, 20)

    def test_exit_codes_follow_verdict(self):
        self.assertEqual(analyze("https://python.org/").exit_code, 0)
        self.assertEqual(analyze("https://bit.ly/x").exit_code, 0)  # LOW
        self.assertEqual(analyze("http://192.0.2.1/x").exit_code, 1)


class TestIndividualSignals(unittest.TestCase):
    def test_dangerous_scheme(self):
        for url in ("javascript:alert(document.cookie)",
                    "data:text/html;base64,WFdY",
                    "vbscript:msgbox(1)"):
            r = analyze(url)
            self.assertIn("dangerous_scheme", ids(r), url)
            self.assertEqual(r.verdict, "CRITICAL")

    def test_ip_literal_registrable_is_host(self):
        r = analyze("http://192.0.2.1/admin")
        self.assertEqual(r.registrable, "192.0.2.1")

    def test_ip_literal_dotted(self):
        r = analyze("http://93.184.216.34/bank/update")
        self.assertIn("ip_literal_host", ids(r))

    def test_ip_literal_decimal(self):
        self.assertIn("ip_literal_host", ids(analyze("http://2130706433/login")))

    def test_ip_literal_hex(self):
        self.assertIn("ip_literal_host", ids(analyze("http://0x7f000001/admin")))

    def test_idn_homoglyph(self):
        r = analyze("http://xn--80ak6aa92e.com/")
        self.assertIn("idn_homoglyph", ids(r))
        detail = [h.detail for h in r.hits if h.signal_id == "idn_homoglyph"][0]
        # xn--80ak6aa92e decodes to a Cyrillic lookalike of "apple"
        self.assertTrue(any(ord(c) > 127 for c in detail), detail)

    def test_brand_impersonation_in_subdomain(self):
        r = analyze("https://paypal.com.verify-login.xyz/webscr")
        self.assertIn("brand_impersonation", ids(r))
        self.assertIn("risky_tld", ids(r))
        self.assertIn("login_keyword", ids(r))

    def test_brand_impersonation_respects_official_sites(self):
        for url in ("https://accounts.google.com/signin",
                    "https://mail.google.com/",
                    "https://outlook.office.com/mail/"):
            self.assertEqual(analyze(url).verdict, "CLEAN", url)

    def test_brand_lookalike_leetsquat(self):
        self.assertIn("brand_lookalike", ids(analyze("https://g00gle.com/")))

    def test_brand_lookalike_hyphen_chunk(self):
        self.assertIn("brand_lookalike", ids(analyze("http://paypa1-secure.com/webscr")))

    def test_brand_lookalike_typosquat(self):
        self.assertIn("brand_lookalike", ids(analyze("https://paypa1.com/")))

    def test_risky_tld(self):
        self.assertIn("risky_tld", ids(analyze("http://free-gift-survey.zip/")))

    def test_url_shortener(self):
        self.assertIn("url_shortener", ids(analyze("https://bit.ly/4aBc")))

    def test_userinfo_trick(self):
        r = analyze("http://paypal@gitlab.com/login")
        self.assertIn("userinfo_trick", ids(r))

    def test_userinfo_not_fooled_by_email_in_query(self):
        r = analyze("https://example.com/reset?email=user@evil.com")
        self.assertNotIn("userinfo_trick", ids(r))

    def test_nested_url(self):
        self.assertIn("nested_url",
                      ids(analyze("https://mail.example.com/r?u=http://evil.tld/a")))

    def test_excessive_depth(self):
        self.assertIn("excessive_depth", ids(
            analyze("https://a.b.verify.mail.login.example.com/x")))

    def test_hyphen_stuffing(self):
        self.assertIn("hyphen_stuffing", ids(
            analyze("http://secure-my-account-now-verify.example.net/")))


class TestBenignCorpus(unittest.TestCase):
    """Real-world respectable URLs must stay CLEAN (heuristic FP control)."""

    CORPUS = [
        "https://github.com/mehulpatel23b-pixel/phishverdict",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.bbc.co.uk/news",
        "https://stackoverflow.com/questions/tagged/python",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://mail.google.com/",
        "https://outlook.office.com/mail/",
        "https://www.icicibank.com/",
        "https://pypi.org/project/pip/",
        "https://mail.example.com/list?id=123456789",
    ]

    def test_no_corpus_url_above_low(self):
        for url in self.CORPUS:
            r = analyze(url)
            self.assertIn(r.verdict, ("CLEAN", "LOW"), f"{url} -> {ids(r)}")


class TestTriageHelper(unittest.TestCase):
    def test_triage_summary(self):
        results, summary = engine.triage([
            "https://python.org/",
            "https://bit.ly/x",
            "http://192.0.2.1/a",
            "javascript:alert(1)",
        ])
        self.assertEqual(len(results), 4)
        self.assertEqual(summary["CLEAN"], 1)
        self.assertEqual(summary["LOW"], 1)
        self.assertEqual(summary["SUSPICIOUS"], 1)
        self.assertEqual(summary["CRITICAL"], 1)


if __name__ == "__main__":
    unittest.main()
