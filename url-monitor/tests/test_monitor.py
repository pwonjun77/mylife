import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from url_monitor.cli import main
from url_monitor.config import ConfigError, in_maintenance, load_config, parse_status_ranges, target_from_url
from url_monitor.evaluator import check_target
from url_monitor.models import Status
from url_monitor.notifier import decide
from url_monitor.probe import _bypass, proxy_for
from url_monitor.store import Store

WEBHOOK_CALLS = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        p = self.path
        if p == "/ok":
            self._send(200, "<h1>서비스 정상 OK</h1>".encode(), {"Content-Type": "text/html; charset=utf-8"})
        elif p == "/euckr":
            self._send(200, "점검 중입니다".encode("euc-kr"), {"Content-Type": "text/html; charset=euc-kr"})
        elif p == "/500":
            self._send(500, b"error")
        elif p == "/404":
            self._send(404, b"nope")
        elif p == "/slow":
            time.sleep(0.3)
            self._send(200, b"slow ok")
        elif p == "/hang":
            time.sleep(2)
            self._send(200, b"late")
        elif p == "/redirect":
            self._send(302, b"", {"Location": "/ok"})
        elif p == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        elif p == "/auth":
            ok = self.headers.get("Authorization") == "Bearer s3cret"
            self._send(200 if ok else 401, b"auth")
        else:
            self._send(404, b"")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        WEBHOOK_CALLS.append((self.path, json.loads(self.rfile.read(n))))
        self._send(200, b"ok")


def serve(ctx=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if ctx:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tgt(url, **kw):
    kw.setdefault("retries", 0)
    return target_from_url(url, **kw)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = serve()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        WEBHOOK_CALLS.clear()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class ProbeTests(Base):
    def test_ok(self):
        r = check_target(tgt(self.base + "/ok", body_contains="정상"))
        self.assertEqual(r.status, Status.UP)
        self.assertEqual(r.probe.http_status, 200)
        self.assertIsNotNone(r.probe.dns_ms)
        self.assertIsNotNone(r.probe.ttfb_ms)

    def test_http_errors(self):
        self.assertEqual(check_target(tgt(self.base + "/500")).reason, "HTTP_5XX")
        self.assertEqual(check_target(tgt(self.base + "/404")).reason, "HTTP_4XX")
        self.assertEqual(check_target(tgt(self.base + "/404", expect_status="200,404")).status, Status.UP)

    def test_keywords_and_charset(self):
        self.assertEqual(check_target(tgt(self.base + "/ok", body_contains="없는문구")).reason, "KEYWORD_MISSING")
        r = check_target(tgt(self.base + "/euckr", body_not_contains="점검 중"))
        self.assertEqual(r.reason, "KEYWORD_FOUND")

    def test_slow_is_warn(self):
        r = check_target(tgt(self.base + "/slow", warn_response_ms=100))
        self.assertEqual((r.status, r.reason), (Status.WARN, "SLOW"))

    def test_timeout(self):
        r = check_target(tgt(self.base + "/hang", timeout_sec=0.5))
        self.assertEqual(r.reason, "HTTP_TIMEOUT")

    def test_redirects(self):
        r = check_target(tgt(self.base + "/redirect"))
        self.assertEqual((r.status, r.probe.redirects), (Status.UP, 1))
        self.assertTrue(r.probe.final_url.endswith("/ok"))
        self.assertEqual(check_target(tgt(self.base + "/redirect", follow_redirects=False)).probe.http_status, 302)
        self.assertEqual(check_target(tgt(self.base + "/loop")).reason, "TOO_MANY_REDIRECTS")

    def test_head_and_headers(self):
        self.assertEqual(check_target(tgt(self.base + "/ok", method="HEAD")).status, Status.UP)
        self.assertEqual(check_target(tgt(self.base + "/auth")).reason, "HTTP_4XX")
        r = check_target(tgt(self.base + "/auth", headers={"Authorization": "Bearer s3cret"}))
        self.assertEqual(r.status, Status.UP)

    def test_connection_refused_and_dns(self):
        self.assertEqual(check_target(tgt(f"http://127.0.0.1:{free_port()}/")).reason, "CONN_REFUSED")
        r = check_target(tgt("http://no-such-host.invalid/", proxy="none"))
        self.assertEqual(r.reason, "DNS_FAIL")

    def test_retry_counts_attempts(self):
        t = tgt(self.base + "/500", retries=2, retry_delay_sec=0)
        r = check_target(t, sleep=lambda s: None)
        self.assertEqual((r.status, r.attempts), (Status.DOWN, 3))

    def test_tcp(self):
        port = self.srv.server_address[1]
        self.assertEqual(check_target(tgt("http://x", type="tcp", host="127.0.0.1", port=port)).status, Status.UP)
        r = check_target(tgt("http://x", type="tcp", host="127.0.0.1", port=free_port()))
        self.assertEqual(r.reason, "CONN_REFUSED")


@unittest.skipUnless(shutil.which("openssl"), "openssl 필요")
class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cls.cert, key = cls.dir / "cert.pem", cls.dir / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "10",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cls.cert)], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, key)
        cls.srv = serve(ctx)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_untrusted_cert_is_down(self):
        r = check_target(tgt(f"https://127.0.0.1:{self.port}/ok"))
        self.assertEqual(r.reason, "CERT_INVALID")

    def test_trusted_with_ca_file_warns_expiring(self):
        r = check_target(tgt(f"https://localhost:{self.port}/ok", ca_file=str(self.cert)))
        self.assertEqual((r.status, r.reason), (Status.WARN, "CERT_EXPIRING"))
        self.assertIn(r.probe.cert_days_left, (9, 10))
        self.assertIsNotNone(r.probe.tls_ms)

    def test_verify_off(self):
        r = check_target(tgt(f"https://127.0.0.1:{self.port}/ok", verify_tls=False))
        self.assertEqual(r.status, Status.UP)


class ConfigTests(Base):
    def test_status_ranges(self):
        self.assertEqual(parse_status_ranges("200-399"), [(200, 399)])
        self.assertEqual(parse_status_ranges("2xx,304"), [(200, 299), (304, 304)])
        with self.assertRaises(ValueError):
            parse_status_ranges("abc")

    def test_json_with_defaults_env_and_csv(self):
        (self.tmp / "more.csv").write_text("﻿group,name,url\n외부,추가,https://a.example\n", encoding="utf-8")
        cfg_path = self.tmp / "t.json"
        cfg_path.write_text(json.dumps({
            "defaults": {"timeout_sec": 3},
            "groups": {"내부": [{"name": "API", "url": "https://api.example/health",
                                 "headers": {"Authorization": "env:UM_TEST_TOKEN"}}]},
            "include_csv": ["more.csv"],
        }), encoding="utf-8")
        with mock.patch.dict(os.environ, {"UM_TEST_TOKEN": "abc"}):
            cfg = load_config(cfg_path)
        self.assertEqual([t.key for t in cfg.targets], ["내부/API", "외부/추가"])
        self.assertEqual(cfg.targets[0].headers["Authorization"], "abc")
        self.assertEqual(cfg.targets[1].timeout_sec, 3)

    def test_errors_are_collected(self):
        p = self.tmp / "bad.json"
        p.write_text(json.dumps({"groups": {"g": [
            {"name": "a", "url": "ftp://x"}, {"name": "b", "url": "https://x", "method": "POST"},
            {"name": "c", "url": "https://x", "headers": {"X": "env:UM_MISSING_VAR"}},
            {"name": "c", "url": "https://y"}, {"name": "d", "url": "https://z", "typo": 1}]}}), encoding="utf-8")
        with self.assertRaises(ConfigError) as cm:
            load_config(p)
        msg = "\n".join(cm.exception.errors)
        for needle in ("http:// 또는 https://", "GET 또는 HEAD", "UM_MISSING_VAR", "중복", "typo"):
            self.assertIn(needle, msg)

    def test_maintenance_window(self):
        w = [{"days": "Sun", "start": "23:00", "end": "02:00"}]
        self.assertTrue(in_maintenance(w, datetime(2026, 10, 25, 23, 30)))   # 일요일 23:30
        self.assertTrue(in_maintenance(w, datetime(2026, 10, 26, 1, 0)))     # 월요일 01:00 (자정 넘김)
        self.assertFalse(in_maintenance(w, datetime(2026, 10, 26, 3, 0)))
        self.assertTrue(in_maintenance([{"days": "월-금", "start": "09:00", "end": "10:00"}], datetime(2026, 10, 27, 9, 5)))

    def test_proxy_bypass(self):
        rules = "localhost,10.0.0.0/8,.corp.local,example.org"
        self.assertTrue(_bypass("10.1.2.3", rules))
        self.assertTrue(_bypass("app.corp.local", rules))
        self.assertTrue(_bypass("www.example.org", rules))
        self.assertTrue(_bypass("127.0.0.1", ""))
        self.assertFalse(_bypass("example.com", rules))
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://p:3128", "NO_PROXY": "10.0.0.0/8"}, clear=True):
            self.assertEqual(proxy_for("https", "example.com"), "http://p:3128")
            self.assertIsNone(proxy_for("https", "10.0.0.5"))
            self.assertIsNone(proxy_for("https", "example.com", "none"))


class AlertTests(Base):
    def test_state_transitions(self):
        store = Store(str(self.tmp / "m.db"))
        ok, bad = tgt(self.base + "/ok", name="svc"), tgt(self.base + "/500", name="svc")
        cfg = {"repeat_every_min": 30}

        prev = store.record(check_target(ok))
        self.assertIsNone(prev)
        down = check_target(bad)
        ev = decide(store.record(down), down, cfg)
        self.assertEqual(ev.kind, "down")
        store.mark_notified(ok.key, down.checked_at)

        again = check_target(bad)
        self.assertIsNone(decide(store.record(again), again, cfg))           # 30분 안: 재알림 없음
        later = datetime.fromisoformat(again.checked_at).replace(year=2099)
        self.assertEqual(decide(store.get_state(ok.key), again, cfg, now=later).kind, "still_down")

        up = check_target(ok)
        ev = decide(store.record(up), up, cfg)
        self.assertEqual(ev.kind, "recovered")
        self.assertTrue(ev.down_since)
        incidents = store.incidents(__import__("datetime").timedelta(days=1))
        self.assertEqual(len(incidents), 1)
        self.assertIsNotNone(incidents[0]["ended_at"])
        avail = store.availability(__import__("datetime").timedelta(days=1))[0]
        self.assertEqual((avail["total"], avail["down"]), (4, 2))
        self.assertEqual(avail["availability"], 50.0)
        store.close()

    def test_maintenance_suppresses(self):
        t = tgt(self.base + "/500", maintenance=[{"days": "*", "start": "00:00", "end": "24:00"}])
        self.assertIsNone(decide(None, check_target(t), {}))


class CliTests(Base):
    def write_cfg(self, extra=None):
        p = self.tmp / "t.json"
        p.write_text(json.dumps({
            "defaults": {"retries": 0, "interval_sec": 5},
            "groups": {"웹": [{"name": "정상", "url": self.base + "/ok"},
                              {"name": "오류", "url": self.base + "/500"}]},
            "notify": {"webhooks": [{"type": "slack", "url": self.base + "/hook"}], "repeat_every_min": 30},
            **(extra or {}),
        }), encoding="utf-8")
        return str(p)

    def test_check_exit_codes_and_formats(self):
        self.assertEqual(main(["check", "--url", self.base + "/ok"]), 0)
        self.assertEqual(main(["check", "--url", self.base + "/slow", "--no-retry"]), 0)
        out = self.tmp / "r.json"
        self.assertEqual(main(["check", self.write_cfg(), "-f", "json", "-o", str(out)]), 2)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["down"], 1)
        html_out = self.tmp / "r.html"
        main(["check", self.write_cfg(), "-f", "html", "-o", str(html_out)])
        self.assertIn("접속 장애가 있는 시스템", html_out.read_text(encoding="utf-8"))
        self.assertEqual(main(["check", self.write_cfg(), "--group", "웹", "--group", "없음"]), 2)

    def test_notify_only_on_change_with_db(self):
        db = str(self.tmp / "m.db")
        cfg = self.write_cfg()
        main(["check", cfg, "--db", db, "--notify", "-o", str(self.tmp / "x.txt")])
        self.assertEqual(len(WEBHOOK_CALLS), 1)
        self.assertIn("장애", WEBHOOK_CALLS[0][1]["text"])
        main(["check", cfg, "--db", db, "--notify", "-o", str(self.tmp / "x.txt")])
        self.assertEqual(len(WEBHOOK_CALLS), 1)  # 상태 변화 없음 -> 알림 없음

        out = self.tmp / "rep.txt"
        self.assertEqual(main(["report", "--db", db, "--since", "1d", "-o", str(out)]), 0)
        self.assertIn("웹/오류", out.read_text(encoding="utf-8"))

    def test_watch_rounds_and_status_page(self):
        page = self.tmp / "status.html"
        rc = main(["watch", self.write_cfg(), "--db", str(self.tmp / "w.db"), "--status-page", str(page),
                   "--rounds", "1", "-q"])
        self.assertEqual(rc, 0)
        text = page.read_text(encoding="utf-8")
        self.assertIn("가용률(24h)", text)
        self.assertIn('http-equiv="refresh"', text)
        self.assertEqual(len(WEBHOOK_CALLS), 1)

    def test_validate_and_config_error(self):
        self.assertEqual(main(["validate", self.write_cfg()]), 0)
        bad = self.tmp / "bad.json"
        bad.write_text('{"groups": {"g": [{"url": "nope"}]}}', encoding="utf-8")
        self.assertEqual(main(["validate", str(bad)]), 3)
        self.assertEqual(main(["check"]), 3)
        self.assertEqual(main(["report", "--db", str(self.tmp / "none.db")]), 3)

    def test_examples_are_valid(self):
        ex = Path(__file__).resolve().parent.parent / "examples"
        self.assertEqual(main(["validate", str(ex / "targets.json")]), 0)
        self.assertEqual(main(["validate", str(ex / "targets.csv")]), 0)


if __name__ == "__main__":
    unittest.main()
