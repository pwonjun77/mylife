# owasp-ignore-file: 테스트용 취약 코드 문자열 포함
"""AI 오탐 검토 테스트. 실제 API 대신 가짜 Claude 클라이언트를 사용한다."""
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from owasp_scanner import ai_review
from owasp_scanner.cli import main
from owasp_scanner.models import Finding, Severity
from owasp_scanner.static_scan import scan_path

SAMPLES = Path(__file__).resolve().parent.parent / "examples" / "fp_samples"
LABELS = SAMPLES / "labels.json"


def _response(payload, stop_reason="end_turn"):
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5-5",
                           content=[SimpleNamespace(type="thinking", thinking=""),
                                    SimpleNamespace(type="text", text=text)])


class FakeClient:
    """프롬프트의 '위치:' 줄을 보고 정답 라벨대로(또는 지정한 값으로) 답하는 가짜 클라이언트."""

    def __init__(self, answers=None, response=None):
        self.calls = []
        self.answers = answers or {}
        self.response = response
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.response is not None:
            return self.response
        loc = re.search(r"위치: (\S+)", kwargs["messages"][0]["content"]).group(1)
        verdict = self.answers.get(loc, "needs_review")
        return _response({"verdict": verdict, "confidence": "high", "reason": "테스트", "fix": ""})


class ContextAndPromptTests(unittest.TestCase):
    def test_context_marks_line_and_masks_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a.py").write_text("x = 1\napi_key = 'abcdef123456'\ny = 2\n")
            f = Finding("A02-HARDCODED-SECRET", "t", "A02", Severity.HIGH, "a.py", line=2)
            ctx = ai_review.build_context(f, Path(d), context_lines=1)
        self.assertIn(">>    2 |", ctx)
        self.assertIn("    1 | x = 1", ctx)
        self.assertNotIn("abcdef123456", ctx)

    def test_prompt_without_source(self):
        f = Finding("A06-UNPINNED", "flask: 버전 미고정", "A06", Severity.LOW, "requirements.txt")
        prompt = ai_review.build_prompt(f, ai_review.build_context(f, None))
        self.assertIn("A03", prompt)  # 2025 분류로 안내
        self.assertNotIn("<code>", prompt)


class ReviewOneTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding("A03-CMDI", "명령 실행", "A03", Severity.HIGH, "views.py", line=19)

    def test_request_shape_and_parse(self):
        client = FakeClient(response=_response(
            {"verdict": "true_positive", "confidence": "high", "reason": "입력이 셸로 감", "fix": "목록 인자 사용"}))
        result = ai_review.review_one(client, self.finding, SAMPLES)
        call = client.calls[0]
        self.assertEqual(call["model"], "claude-opus-5-5")
        self.assertEqual(call["fallbacks"], "default")
        self.assertEqual(call["betas"], ["server-side-fallback-2026-07-01"])
        self.assertEqual(call["output_config"]["format"]["schema"], ai_review.RESULT_SCHEMA)
        self.assertNotIn("thinking", call)
        self.assertIn('"convert " + tool', call["messages"][0]["content"])
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(result["model"], "claude-opus-5-5")

    def test_refusal_and_bad_output_become_needs_review(self):
        for resp in (_response("", stop_reason="refusal"), _response("not json"),
                     _response({"verdict": "maybe", "confidence": "high", "reason": "", "fix": ""}),
                     _response("{", stop_reason="max_tokens")):
            with self.subTest(resp=resp):
                result = ai_review.review_one(FakeClient(response=resp), self.finding, SAMPLES)
                self.assertEqual(result["verdict"], "needs_review")
                self.assertTrue(result["error"])

    def test_auth_error_stops_review(self):
        try:
            import anthropic
        except ImportError:
            self.skipTest("anthropic 패키지 없음")
        import httpx2
        request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
        err = anthropic.AuthenticationError("bad key", response=httpx2.Response(401, request=request), body=None)

        def raise_auth(**kwargs):
            raise err
        client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=raise_auth)))
        with self.assertRaises(ai_review.AIReviewError):
            ai_review.review_one(client, self.finding, SAMPLES)


class RealSdkTests(unittest.TestCase):
    """실제 anthropic SDK로 요청을 만들고, 네트워크 대신 가짜 HTTP 응답을 돌려준다."""

    def test_request_serialization_and_response_parsing(self):
        try:
            import anthropic
            import httpx2
        except ImportError:
            self.skipTest("anthropic 패키지 없음")
        seen = {}

        def handler(request):
            seen["beta"] = request.headers.get("anthropic-beta")
            seen["body"] = json.loads(request.content)
            verdict = {"verdict": "false_positive", "confidence": "high", "reason": "고정 명령", "fix": ""}
            return httpx2.Response(200, json={
                "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "content": [{"type": "thinking", "thinking": "", "signature": "sig"},
                            {"type": "text", "text": json.dumps(verdict, ensure_ascii=False)}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1},
            })

        client = anthropic.Anthropic(api_key="test-key",
                                     http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))
        f = Finding("A03-CMDI", "명령 실행", "A03", Severity.HIGH, "views.py", line=14)
        result = ai_review.review_one(client, f, SAMPLES)
        self.assertEqual(result["verdict"], "false_positive")
        self.assertEqual(seen["beta"], "server-side-fallback-2026-07-01")
        body = seen["body"]
        self.assertEqual((body["model"], body["fallbacks"], body["output_config"]["effort"]),
                         ("claude-opus-5-5", "default", "medium"))
        self.assertEqual(body["output_config"]["format"]["type"], "json_schema")


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.findings, _ = scan_path(SAMPLES)
        self.labels = ai_review.load_labels(LABELS)

    def test_scanner_precision_without_ai(self):
        result = ai_review.evaluate(self.findings, self.labels)
        self.assertEqual((result["scanner_true_positives"], result["scanner_false_positives"]), (3, 5))
        self.assertEqual(result["missed_by_scanner"], [])
        self.assertEqual(result["ai_reviewed"], 0)

    def test_ai_accuracy(self):
        answers = {f"{l['location']}:{l['line']}": l["expected"] for l in self.labels}
        answers["views.py:24"] = "true_positive"  # 하나는 일부러 틀리게
        ai_review.review_findings(self.findings, SAMPLES, client=FakeClient(answers), workers=2)
        result = ai_review.evaluate(self.findings, self.labels)
        self.assertEqual((result["ai_reviewed"], result["ai_correct"]), (8, 7))
        self.assertEqual(result["ai_false_positive_caught"], 4)
        self.assertEqual([(m["line"], m["ai_verdict"]) for m in result["ai_mismatches"]], [(24, "true_positive")])
        notes = "\n".join(ai_review.evaluation_notes(result))
        self.assertIn("AI 판정 정확도: 7/8 (88%)", notes)

    def test_max_items_reviews_most_severe_first(self):
        n = ai_review.review_findings(self.findings, SAMPLES, client=FakeClient(), max_items=2)
        self.assertEqual(n, 2)
        reviewed = [f for f in self.findings if "ai" in f.extra]
        self.assertTrue(all(f.severity == Severity.CRITICAL for f in reviewed))

    def test_bad_label_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "l.json")
            p.write_text('[{"location": "a", "line": 1, "rule_id": "X", "expected": "maybe"}]')
            with self.assertRaises(ValueError):
                ai_review.load_labels(p)


class CliAiTests(unittest.TestCase):
    def setUp(self):
        answers = {f"{l['location']}:{l['line']}": l["expected"] for l in ai_review.load_labels(LABELS)}
        self.client = FakeClient(answers)
        patcher = mock.patch.object(ai_review, "make_client", return_value=self.client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_json(self, *argv):
        out = Path(self.tmp.name) / "r.json"
        with redirect_stderr(io.StringIO()):
            code = main([*argv, "-f", "json", "-o", str(out)])
        return code, json.loads(out.read_text(encoding="utf-8"))

    def test_code_ai_review_with_expected(self):
        code, data = self.run_json("code", str(SAMPLES), "--ai-review", "--ai-yes", "--expected", str(LABELS))
        self.assertEqual(code, 0)
        self.assertEqual(data["meta"]["ai_review"]["false_positive"], 5)
        self.assertEqual(data["meta"]["evaluation"]["ai_correct"], 8)
        self.assertTrue(all("ai" in f["extra"] for f in data["findings"]))

    def test_hide_fp_and_fail_on(self):
        code, data = self.run_json("code", str(SAMPLES), "--ai-review", "--ai-yes", "--hide-fp",
                                   "--fail-on", "critical")
        self.assertEqual(len(data["findings"]), 3)
        self.assertEqual(code, 1)  # 남은 실제 SQL 인젝션(긴급) 때문에 실패

    def test_review_command_from_saved_report(self):
        report = Path(self.tmp.name) / "scan.json"
        with redirect_stderr(io.StringIO()):
            main(["code", str(SAMPLES), "-f", "json", "-o", str(report)])
        code, data = self.run_json("review", str(report), "--ai-yes")
        self.assertEqual(code, 0)
        self.assertEqual(data["meta"]["ai_review"]["reviewed"], 8)
        self.assertIn('"convert " + tool', "".join(c["messages"][0]["content"] for c in self.client.calls))

    def test_consent_required_without_tty(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["code", str(SAMPLES), "--ai-review"]), 2)
        self.assertEqual(self.client.calls, [])

    def test_text_report_shows_verdict(self):
        out = Path(self.tmp.name) / "r.txt"
        with redirect_stderr(io.StringIO()):
            main(["code", str(SAMPLES), "--ai-review", "--ai-yes", "-o", str(out)])
        text = out.read_text(encoding="utf-8")
        self.assertIn("AI   : 오탐 (확신도 높음)", text)
        self.assertIn("AI 검토(claude-opus-5-5): 8건 검토", text)


if __name__ == "__main__":
    unittest.main()
