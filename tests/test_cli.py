import contextlib
import io
import json
import os
import tempfile
import unittest

from phishverdict.cli import main

BENIGN = [
    "https://github.com/mehulpatel23b-pixel/phishverdict",
    "https://docs.python.org/3/library/urllib.parse.html",
]

PHISHY = [
    "https://github.com/mehulpatel23b-pixel/phishverdict",
    "http://paypal.com.verify-login.xyz/webscr",
    "javascript:alert(document.cookie)",
]


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class TestCli(unittest.TestCase):
    def _write(self, lines):
        f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        f.write("\n".join(lines) + "\n")
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_benign_file_exits_zero(self):
        code, out = run_main([self._write(BENIGN)])
        self.assertEqual(code, 0)
        self.assertIn("CLEAN", out)

    def test_phishy_file_exits_one(self):
        code, out = run_main([self._write(PHISHY)])
        self.assertEqual(code, 1)
        self.assertIn("CRITICAL", out)
        self.assertIn("summary", out)

    def test_comments_and_blanks_ignored(self):
        path = self._write(["# comment line", "", "  https://python.org/  "])
        code, out = run_main([path])
        self.assertEqual(code, 0)
        self.assertIn("python.org", out)

    def test_json_output(self):
        code, out = run_main(["--json"] + [self._write(PHISHY)])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["CRITICAL"], 2)  # paypal.ext + javascript:
        self.assertEqual(doc["summary"]["CLEAN"], 1)
        self.assertEqual(len(doc["results"]), 3)
        self.assertIn("signals", doc["results"][1])

    def test_direct_url_args(self):
        code, out = run_main(["https://python.org/"])
        self.assertEqual(code, 0)
        self.assertIn("no triage signals", out)

    def test_stdin_dash(self):
        import sys
        real_stdin, sys.stdin = sys.stdin, io.StringIO(
            "http://0x7f000001/admin\nhttps://python.org/\n")
        try:
            code, out = run_main(["-"])
        finally:
            sys.stdin = real_stdin
        self.assertEqual(code, 1)
        self.assertIn("ip_literal_host", out)

    def test_missing_file_errors(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code, out = run_main(["/nonexistent/file.txt"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", stderr.getvalue())

    def test_no_inputs_prints_usage(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main([])
        self.assertEqual(code, 64)
        self.assertIn("usage", stderr.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
