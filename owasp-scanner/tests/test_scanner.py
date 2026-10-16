# owasp-ignore-file: 테스트용 취약 코드 문자열 포함
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from owasp_scanner.cli import main
from owasp_scanner.deps_scan import parse_package_json, parse_requirements, scan_dependencies
from owasp_scanner.models import MAP_2021_TO_2025, OWASP_TOP10_2025, Finding, Severity
from owasp_scanner.static_scan import scan_path, scan_text
from owasp_scanner.web_scan import scan_url

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_app"


def rule_ids(text, suffix=".py"):
    return {f.rule_id for f in scan_text(text, "t", suffix)}


class StaticRuleTests(unittest.TestCase):
    def test_detects_vulnerable_python(self):
        cases = {
            'cur.execute(f"SELECT * FROM t WHERE id={uid}")': "A03-SQLI",
            'cur.execute("SELECT * FROM t WHERE id=%s" % uid)': "A03-SQLI",
            'os.system("rm " + name)': "A03-CMDI",
            "subprocess.run(cmd, shell=True)": "A03-CMDI",
            "data = pickle.loads(blob)": "A08-UNSAFE-DESERIALIZE",
            "cfg = yaml.load(stream)": "A08-UNSAFE-DESERIALIZE",
            "h = hashlib.md5(pw)": "A02-WEAK-HASH",
            "requests.get(url, verify=False)": "A02-TLS-VERIFY-OFF",
            'password = "SuperSecret123"': "A02-HARDCODED-SECRET",
            "r = requests.get(request.args['u'])": "A10-SSRF",
            "return send_file(request.args.get('f'))": "A01-PATH-TRAVERSAL",
            "app.run(debug=True)": "A05-DEBUG-ON",
            'jwt.decode(t, options={"verify_signature": False})': "A07-JWT-NOVERIFY",
            "except Exception: pass": "A09-SWALLOWED-EXCEPTION",
            "exec(user_code)": "A03-CODE-EXEC",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertIn(expected, rule_ids(line))

    def test_detects_vulnerable_js(self):
        cases = {
            "db.query(\"SELECT * FROM a WHERE n = '\" + req.query.q + \"'\")": "A03-SQLI",
            "el.innerHTML = userInput;": "A03-XSS-DOM",
            "eval(code)": "A03-CODE-EVAL",
            "const token = Math.random().toString(36)": "A02-INSECURE-RANDOM",
            "User.findOne(req.body)": "A03-NOSQLI",
            "https.request({ rejectUnauthorized: false })": "A02-TLS-VERIFY-OFF",
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertIn(expected, rule_ids(line, ".js"))

    def test_safe_code_not_flagged(self):
        safe = [
            'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))',
            'cur.execute(f"SELECT 1")',
            "subprocess.run(['ls', '-l'])",
            "cfg = yaml.load(stream, Loader=yaml.SafeLoader)",
            "data = yaml.safe_load(stream)",
            "h = hashlib.sha256(data)",
            "password = os.environ['DB_PASSWORD']",
            'password = "changeme"',
            "pattern = re.compile(r'abc')",
            "value = ast.literal_eval(text)",
            "# os.system('example in comment')",
            "token = secrets.token_urlsafe(32)",
        ]
        for line in safe:
            with self.subTest(line=line):
                self.assertEqual(set(), rule_ids(line))

    def test_owasp_2025_rules(self):
        self.assertIn("A04-FAIL-OPEN", rule_ids("    except Exception: return True"))
        self.assertIn("A04-BARE-EXCEPT", rule_ids("    except:"))
        self.assertIn("A08-CURL-PIPE-SH", rule_ids("curl -fsSL https://x.example/i.sh | sudo bash", ".sh"))
        self.assertIn("A08-INSECURE-INDEX", rule_ids("pip install --trusted-host foo -r r.txt", ".sh"))

    def test_multiline_except_block(self):
        findings = scan_text("try:\n    x()\nexcept Exception:\n    pass\n", "t", ".py")
        f = next(f for f in findings if f.rule_id == "A09-SWALLOWED-EXCEPTION")
        self.assertEqual((f.line, f.category("2025"), f.category("2021")), (3, "A10", "A09"))
        findings = scan_text("try { a() } catch (e) {\n  return true;\n}", "t", ".js")
        self.assertIn("A04-FAIL-OPEN", {f.rule_id for f in findings})

    def test_suppression_comment(self):
        self.assertEqual(set(), rule_ids("os.system(cmd)  # nosec"))
        self.assertEqual(set(), rule_ids("eval(x) // owasp-ignore", ".js"))

    def test_secret_masked_in_evidence(self):
        [f] = scan_text('api_key = "abcdef123456"', "t", ".py")
        self.assertNotIn("abcdef123456", f.evidence)

    def test_scan_examples_covers_categories(self):
        findings, count = scan_path(EXAMPLES)
        self.assertGreaterEqual(count, 3)
        cats = {f.owasp for f in findings}
        for c in ("A01", "A02", "A03", "A05", "A07", "A08", "A09", "A10"):
            self.assertIn(c, cats)


class StandardMappingTests(unittest.TestCase):
    def test_every_2021_code_maps_to_2025(self):
        self.assertEqual(set(MAP_2021_TO_2025.values()) - set(OWASP_TOP10_2025), set())
        self.assertEqual(len(MAP_2021_TO_2025), 10)

    def test_default_and_override_mapping(self):
        self.assertEqual(Finding("x", "t", "A03", Severity.LOW, "l").category("2025"), "A05")
        self.assertEqual(Finding("x", "t", "A10", Severity.LOW, "l").category("2025"), "A01")
        self.assertEqual(Finding("x", "t", "A08", Severity.LOW, "l", owasp2025="A03").category("2025"), "A03")

    def test_examples_cover_all_2025_categories_except_design(self):
        findings, _ = scan_path(EXAMPLES)
        findings += scan_dependencies(EXAMPLES)[0]
        cats = {f.category("2025") for f in findings}
        self.assertEqual(set(OWASP_TOP10_2025) - cats, {"A06"})


class DependencyTests(unittest.TestCase):
    def test_parse_requirements(self):
        deps = parse_requirements("flask\nrequests==2.19.0  # c\npyyaml>=3.0; python_version>'3'\n-r other.txt\n", "r")
        self.assertEqual([(d.name, d.version) for d in deps],
                         [("flask", None), ("requests", "2.19.0"), ("pyyaml", None)])

    def test_parse_package_json(self):
        deps = parse_package_json(json.dumps({"dependencies": {"a": "1.2.3", "b": "^1.0.0"}}), "p")
        self.assertEqual([(d.name, d.version) for d in deps], [("a", "1.2.3"), ("b", None)])

    def test_scan_dependencies_offline(self):
        findings, deps, err = scan_dependencies(EXAMPLES)
        self.assertIsNone(err)
        ids = {f.rule_id for f in findings}
        self.assertIn("A06-UNPINNED", ids)
        self.assertIn("A08-UNVERIFIED-SOURCE", ids)
        self.assertIn("A08-NO-LOCKFILE", ids)
        self.assertIn("A08-INSTALL-SCRIPT", ids)

    def test_exclude_dirs(self):
        findings, deps, _ = scan_dependencies(EXAMPLES.parent, exclude_dirs={"vulnerable_app"})
        self.assertEqual((findings, deps), ([], []))

    def test_lockfile_present(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "package.json").write_text('{"dependencies": {"a": "1.0.0"}}')
            Path(d, "package-lock.json").write_text("{}")
            ids = {f.rule_id for f in scan_dependencies(d)[0]}
            self.assertNotIn("A08-NO-LOCKFILE", ids)


class _VulnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _common(self):
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Server", "Apache/2.2.15")
        self.send_header("X-Powered-By", "PHP/5.4.1")

    def do_GET(self):
        if self.path == "/.git/HEAD":
            body, status, ctype = "ref: refs/heads/main\n", 200, "text/plain"
        elif self.path == "/":
            body = ('<html><head><script src="https://cdn.other.example/x.js"></script></head><body>'
                    '<form action="/login" method="get"><input type="password" name="pw"></form></body></html>')
            status, ctype = 200, "text/html"
        else:
            body, status, ctype = "Traceback (most recent call last):\n  File app.py", 404, "text/html"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        if self.path == "/":
            self.send_header("Set-Cookie", "sessionid=abc; Path=/")
        self._common()
        self.end_headers()
        self.wfile.write(body.encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self._common()
        self.end_headers()


class WebScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_web_findings(self):
        findings, notes = scan_url(self.url, timeout=5)
        ids = {f.rule_id for f in findings}
        expected = {
            "A02-NO-HTTPS", "A05-NO-CSP", "A05-NO-CLICKJACK", "A05-NO-NOSNIFF",
            "A06-VERSION-DISCLOSURE", "A07-COOKIE-ATTR", "A01-CORS-REFLECT", "A05-TRACE-ENABLED",
            "A05-STACK-TRACE", "A08-NO-SRI", "A07-FORM-GET", "A05-EXPOSED-GIT-HEAD",
        }
        self.assertTrue(expected <= ids, f"누락: {expected - ids}")
        cors = next(f for f in findings if f.rule_id == "A01-CORS-REFLECT")
        self.assertEqual(cors.severity, Severity.HIGH)
        trace = next(f for f in findings if f.rule_id == "A05-STACK-TRACE")
        self.assertEqual(trace.category("2025"), "A10")


class CliTests(unittest.TestCase):
    def test_fail_on_and_json_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            code = main(["code", str(EXAMPLES), "-f", "json", "-o", str(out), "--fail-on", "critical"])
            self.assertEqual(code, 1)
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["total"], len(data["findings"]))
            self.assertEqual(data["summary"]["standard"], "OWASP Top 10:2025")
            self.assertIn("owasp2025", data["findings"][0])

    def test_standard_2021_filter(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.json"
            main(["code", str(EXAMPLES), "-f", "json", "-o", str(out), "--standard", "2021", "--owasp", "A10"])
            data = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["standard"], "OWASP Top 10:2021")
            self.assertTrue(data["findings"])
            self.assertTrue(all(f["owasp"] == "A10" for f in data["findings"]))

    def test_html_report_and_filters(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.html"
            code = main(["code", str(EXAMPLES), "-f", "html", "-o", str(out), "--owasp", "A03",
                         "--min-severity", "high"])
            self.assertEqual(code, 0)
            self.assertIn("<!DOCTYPE html>", out.read_text(encoding="utf-8"))

    def test_web_requires_confirmation(self):
        self.assertEqual(main(["web", "http://127.0.0.1:1"]), 2)


if __name__ == "__main__":
    unittest.main()
