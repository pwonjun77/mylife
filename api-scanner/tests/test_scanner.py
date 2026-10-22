import base64
import hashlib
import hmac
import json
import unittest
from pathlib import Path

from api_scanner.cli import main
from api_scanner.jwt_check import analyze as jwt_analyze
from api_scanner.jwt_check import forge_none
from api_scanner.models import Severity, dedupe, sort_findings
from api_scanner.report import render_html, render_json, render_text
from api_scanner.spec import base_url, iter_properties, parse_spec
from api_scanner.spec_scan import scan_spec

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_api" / "openapi.json"


def load_example():
    return parse_spec(EXAMPLE.read_text(encoding="utf-8"), str(EXAMPLE))


def rule_ids(findings):
    return {f.rule_id for f in findings}


def make_jwt(header: dict, payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    signing_input = f"{enc(header)}.{enc(payload)}".encode()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, digest).digest()).rstrip(b"=").decode()
    return f"{signing_input.decode()}.{sig}"


class SpecScanTests(unittest.TestCase):
    def setUp(self):
        self.findings = scan_spec(load_example())
        self.ids = rule_ids(self.findings)

    def test_detects_core_categories(self):
        expected = {
            "API3-SENSITIVE-RESPONSE",   # 응답에 password_hash
            "API3-MASS-ASSIGNMENT",      # role / is_admin 변경 가능
            "API5-ADMIN-NO-AUTH",        # /admin/users security:[]
            "API8-HTTP-SERVER",          # http:// 서버
            "API4-NO-PAGE-LIMIT",        # limit/page_size maximum 없음
            "API7-URL-PARAM",            # image_url
            "API6-SENSITIVE-FLOW",       # /checkout
            "API9-DEPRECATED-OP",        # /legacy/export deprecated
            "API8-DEBUG-ENDPOINT",       # /debug/config
            "API9-MULTIPLE-VERSIONS",    # v1 + v2
            "API9-NONPROD-SERVER",       # staging 서버
            "API2-BASIC-AUTH",
            "API2-APIKEY-IN-QUERY",
        }
        missing = expected - self.ids
        self.assertFalse(missing, f"탐지하지 못한 규칙: {missing}")

    def test_mass_assignment_is_admin(self):
        hits = [f for f in self.findings if f.rule_id == "API3-MASS-ASSIGNMENT"]
        props = {f.evidence for f in hits}
        self.assertTrue(any("role" in p for p in props))
        self.assertTrue(any("is_admin" in p for p in props))

    def test_login_token_response_not_flagged(self):
        # /login 의 access_token 반환은 민감정보 노출로 보지 않아야 한다
        sensitive = [f for f in self.findings
                     if f.rule_id == "API3-SENSITIVE-RESPONSE" and f.location == "POST /login"]
        self.assertEqual(sensitive, [])

    def test_no_findings_on_clean_spec(self):
        clean = {
            "openapi": "3.0.0",
            "info": {"title": "Clean", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com/v1"}],
            "security": [{"bearerAuth": []}],
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "paths": {
                "/items/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True,
                                        "schema": {"type": "string", "format": "uuid"}}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
        findings = scan_spec(parse_spec(json.dumps(clean)))
        high = [f for f in findings if f.severity >= Severity.MEDIUM]
        self.assertEqual(high, [], f"깨끗한 명세에서 중간 이상 오탐: {[f.rule_id for f in high]}")


class SwaggerV2Tests(unittest.TestCase):
    def test_parses_swagger_2(self):
        doc = {
            "swagger": "2.0",
            "info": {"title": "V2", "version": "1.0"},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["http"],
            "securityDefinitions": {"key": {"type": "apiKey", "in": "query", "name": "k"}},
            "security": [{"key": []}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "required": True, "type": "integer"}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
        spec = parse_spec(json.dumps(doc))
        self.assertEqual(spec.version, "2.0")
        self.assertEqual(base_url(spec), "http://api.example.com/v1")
        ids = rule_ids(scan_spec(spec))
        self.assertIn("API8-HTTP-SERVER", ids)
        self.assertIn("API2-APIKEY-IN-QUERY", ids)


class RefResolutionTests(unittest.TestCase):
    def test_resolves_ref_in_response(self):
        spec = load_example()
        op = next(o for o in spec.operations if o.key == "GET /users/{id}")
        props = {p for p, _ in iter_properties(op.responses["200"])}
        self.assertIn("password_hash", props)


class JwtTests(unittest.TestCase):
    def test_alg_none(self):
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        token = f"{enc({'alg': 'none'})}.{enc({'sub': '1'})}."
        self.assertIn("API2-JWT-ALG-NONE", rule_ids(jwt_analyze(token)))

    def test_weak_secret(self):
        token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, secret="secret")
        self.assertIn("API2-JWT-WEAK-SECRET", rule_ids(jwt_analyze(token)))

    def test_strong_secret_not_flagged(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999},
                         secret="f9c2a1e7b4d8036a5c1e9f2b7d4a6c8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c")
        self.assertNotIn("API2-JWT-WEAK-SECRET", rule_ids(jwt_analyze(token)))

    def test_no_exp(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1"},
                         secret="f9c2a1e7b4d8036a5c1e9f2b7d4a6c8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c")
        self.assertIn("API2-JWT-NO-EXP", rule_ids(jwt_analyze(token)))

    def test_sensitive_claim(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1", "exp": 9999999999, "password": "x"},
                         secret="f9c2a1e7b4d8036a5c1e9f2b7d4a6c8e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c")
        self.assertIn("API2-JWT-SENSITIVE-CLAIM", rule_ids(jwt_analyze(token)))

    def test_opaque_token_ignored(self):
        self.assertEqual(jwt_analyze("not-a-jwt-token"), [])

    def test_forge_none_roundtrip(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1"})
        forged = forge_none(token)
        self.assertTrue(forged.endswith("."))
        self.assertIn("API2-JWT-ALG-NONE", rule_ids(jwt_analyze(forged)))


class ModelTests(unittest.TestCase):
    def test_dedupe_and_sort(self):
        findings = scan_spec(load_example())
        self.assertEqual(len(findings), len(dedupe(findings)))
        ordered = sort_findings(findings)
        sevs = [f.severity for f in ordered]
        self.assertEqual(sevs, sorted(sevs, reverse=True))


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.findings = scan_spec(load_example())
        self.meta = {"mode": "spec", "target": "demo", "started": "now"}

    def test_text(self):
        text = render_text(self.findings, self.meta)
        self.assertIn("OWASP API Security Top 10:2023", text)

    def test_json_roundtrip(self):
        data = json.loads(render_json(self.findings, self.meta))
        self.assertEqual(data["summary"]["total"], len(self.findings))
        self.assertIn("category_name", data["findings"][0])

    def test_html(self):
        out = render_html(self.findings, self.meta)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("API3", out)


class CliTests(unittest.TestCase):
    def test_spec_command(self):
        self.assertEqual(main(["spec", str(EXAMPLE), "--min-severity", "info"]), 0)

    def test_fail_on(self):
        self.assertEqual(main(["spec", str(EXAMPLE), "--fail-on", "high"]), 1)
        self.assertEqual(main(["spec", str(EXAMPLE), "--fail-on", "critical"]), 0)

    def test_category_filter(self):
        self.assertEqual(main(["spec", str(EXAMPLE), "--category", "API7"]), 0)

    def test_rules(self):
        self.assertEqual(main(["rules"]), 0)

    def test_jwt_command(self):
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        token = f"{enc({'alg': 'none'})}.{enc({'sub': '1'})}."
        self.assertEqual(main(["jwt", token, "--fail-on", "critical"]), 1)


if __name__ == "__main__":
    unittest.main()
