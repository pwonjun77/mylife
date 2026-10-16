"""웹 애플리케이션 비파괴(passive) 점검 엔진.

GET/HEAD/OPTIONS 요청만 사용하며 공격 페이로드를 전송하지 않는다.
반드시 점검 권한이 있는 대상에만 사용할 것.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .models import Finding, Severity

USER_AGENT = "owasp-scanner/1.0 (+authorized security assessment)"
MAX_BODY = 1024 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: Message
    body: str
    history: list[tuple[int, str]] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def header_all(self, name: str) -> list[str]:
        return self.headers.get_all(name) or []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # 리다이렉트는 직접 추적
        return None


class HttpClient:
    def __init__(self, timeout: float = 10.0, insecure: bool = False):
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False  # nosec
            ctx.verify_mode = ssl.CERT_NONE  # nosec - 사용자가 --insecure 를 명시한 경우만
        self.opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(self, url: str, method: str = "GET", headers: dict | None = None,
                follow: bool = True, max_redirects: int = 5) -> Response:
        history: list[tuple[int, str]] = []
        for _ in range(max_redirects + 1):
            req = urllib.request.Request(url, method=method,
                                         headers={"User-Agent": USER_AGENT, **(headers or {})})
            try:
                resp = self.opener.open(req, timeout=self.timeout)
                status, hdrs, raw = resp.status, resp.headers, resp.read(MAX_BODY)
            except urllib.error.HTTPError as err:
                status, hdrs = err.code, err.headers
                raw = err.read(MAX_BODY) if err.fp else b""
            body = raw.decode(_charset(hdrs), errors="replace")
            location = hdrs.get("Location")
            if follow and status in (301, 302, 303, 307, 308) and location:
                history.append((status, url))
                url = urljoin(url, location)
                continue
            return Response(url, status, hdrs, body, history)
        raise RuntimeError(f"리다이렉트가 너무 많습니다: {url}")


def _charset(headers: Message) -> str:
    m = re.search(r"charset=([\w\-]+)", headers.get("Content-Type", ""), re.I)
    return m.group(1) if m else "utf-8"


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[dict] = []
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.resources: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "form":
            self.forms.append(a)
        elif tag == "input":
            self.inputs.append(a)
        if tag in ("script", "img", "iframe", "link") and (a.get("src") or a.get("href")):
            self.resources.append(a.get("src") or a.get("href"))


# (경로, 응답 본문에 있어야 하는 서명 정규식, 제목, OWASP, 심각도)
SENSITIVE_PATHS = [
    ("/.git/HEAD", r"^ref:\s*refs/", "Git 저장소 메타데이터 노출", "A05", Severity.HIGH),
    ("/.git/config", r"\[core\]", "Git 설정 파일 노출", "A05", Severity.HIGH),
    ("/.env", r"^[A-Z_][A-Z0-9_]*\s*=", ".env 환경 설정 파일 노출", "A05", Severity.CRITICAL),
    ("/.svn/entries", r"^\d+\s*$|svn", "SVN 메타데이터 노출", "A05", Severity.HIGH),
    ("/.DS_Store", r"Bud1", ".DS_Store 파일 노출", "A05", Severity.LOW),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo 페이지 노출", "A05", Severity.MEDIUM),
    ("/server-status", r"Apache Server Status", "Apache server-status 노출", "A05", Severity.MEDIUM),
    ("/actuator/env", r"\"(activeProfiles|propertySources)\"", "Spring Boot Actuator env 노출", "A05", Severity.HIGH),
    ("/actuator/heapdump", None, "Spring Boot Actuator heapdump 노출", "A05", Severity.CRITICAL),
    ("/config.json", r"\"(password|secret|apiKey|api_key)\"", "설정 파일(config.json) 노출", "A05", Severity.HIGH),
    ("/backup.zip", None, "백업 파일 노출", "A05", Severity.HIGH),
    ("/db.sql", r"(CREATE TABLE|INSERT INTO)", "DB 덤프 파일 노출", "A05", Severity.CRITICAL),
    ("/admin/", r"<form|login|password", "관리자 페이지 외부 노출", "A01", Severity.LOW),
    ("/swagger-ui.html", r"swagger", "API 문서(Swagger) 공개 노출", "A05", Severity.INFO),
]

STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|"
    r"Fatal error: .* on line \d+|Warning: .* in /.+ on line|Microsoft OLE DB|ORA-\d{5}|"
    r"SQLSTATE\[|You have an error in your SQL syntax|Werkzeug Debugger|"
    r"Whitelabel Error Page|Django Version:|Exception Details:|node_modules/express",
    re.I,
)
VERSION_RE = re.compile(r"\d+\.\d+")


class WebScanner:
    def __init__(self, url: str, timeout: float = 10.0, insecure: bool = False,
                 check_paths: bool = True):
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        self.url = url
        self.client = HttpClient(timeout, insecure)
        self.timeout = timeout
        self.check_paths = check_paths
        self.findings: list[Finding] = []
        self.notes: list[str] = []

    def add(self, rule_id, title, owasp, severity, description, recommendation, evidence="", cwe="",
            location=None, owasp2025=""):
        self.findings.append(Finding(rule_id, title, owasp, severity, location or self.url,
                                     description, recommendation, evidence, cwe, owasp2025=owasp2025))

    # ------------------------------------------------------------
    def run(self) -> list[Finding]:
        try:
            main = self.client.request(self.url)
        except (urllib.error.URLError, socket.timeout, ConnectionError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                self.add("A02-TLS-CERT-INVALID", "유효하지 않은 TLS 인증서", "A02", Severity.HIGH,
                         "인증서 검증에 실패했습니다(만료, 자체 서명, 호스트명 불일치 등).",
                         "공인 CA에서 발급한 유효한 인증서를 사용하세요.", str(reason), "CWE-295")
                return self.findings
            raise ConnectionError(f"대상에 접속할 수 없습니다: {reason}") from exc

        self.final_url = main.url
        self.notes.append(f"최종 URL: {main.url} (HTTP {main.status})")
        checks = [
            lambda: self.check_transport(main),
            lambda: self.check_tls(main.url),
            lambda: self.check_security_headers(main),
            lambda: self.check_info_disclosure(main),
            lambda: self.check_cookies(main),
            lambda: self.check_page_content(main),
            lambda: self.check_cors(main.url),
            lambda: self.check_methods(main.url),
            lambda: self.check_error_page(main.url),
        ]
        if self.check_paths:
            checks.append(lambda: self.check_sensitive_paths(main.url))
        for check in checks:
            try:
                check()
            except Exception as exc:  # 개별 점검 실패가 전체를 중단시키지 않도록
                self.notes.append(f"점검 일부 실패: {exc}")
        return self.findings

    # ---------------- A02: 전송 구간 암호화 ----------------
    def check_transport(self, main: Response):
        parsed = urlparse(main.url)
        if parsed.scheme == "http":
            self.add("A02-NO-HTTPS", "HTTPS 미사용", "A02", Severity.HIGH,
                     "평문 HTTP로 서비스되어 자격 증명과 세션이 도청될 수 있습니다.",
                     "HTTPS를 적용하고 HTTP 요청은 HTTPS로 영구 리다이렉트(301)하세요.", main.url, "CWE-319")
            return
        if parsed.port and parsed.port != 443:
            return  # 비표준 포트는 HTTP 리다이렉트 점검 생략
        netloc = parsed.netloc[:-4] if parsed.netloc.endswith(":443") else parsed.netloc
        http_url = parsed._replace(scheme="http", netloc=netloc).geturl()
        try:
            r = self.client.request(http_url, follow=False)
        except Exception:
            return  # 80 포트 미개방은 정상
        loc = r.header("Location") or ""
        if r.status < 300 or r.status >= 400 or not loc.lower().startswith("https://"):
            self.add("A02-HTTP-NO-REDIRECT", "HTTP 요청이 HTTPS로 리다이렉트되지 않음", "A02", Severity.MEDIUM,
                     "HTTP로 접속한 사용자가 평문 통신을 계속하게 됩니다.",
                     "모든 HTTP 요청을 HTTPS로 301 리다이렉트하세요.", f"{http_url} -> HTTP {r.status} {loc}", "CWE-319")

    def check_tls(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return
        host, port = parsed.hostname, parsed.port or 443
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # nosec
        ctx.verify_mode = ssl.CERT_NONE  # nosec - 프로토콜/만료 정보 수집용 (검증은 아래에서 별도 수행)
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version()
                cipher = tls.cipher()
        self.notes.append(f"TLS: {version}, 암호군: {cipher[0] if cipher else '?'}")
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            self.add("A02-TLS-OLD", f"취약한 TLS 버전 사용 ({version})", "A02", Severity.HIGH,
                     "TLS 1.1 이하 버전은 알려진 취약점이 있어 사용이 중단되었습니다.",
                     "TLS 1.2 이상만 허용하세요(권장: TLS 1.3).", version, "CWE-326")
        if cipher and re.search(r"RC4|DES|NULL|EXPORT|MD5", cipher[0]):  # nosec
            self.add("A02-TLS-WEAK-CIPHER", "취약한 TLS 암호군 사용", "A02", Severity.HIGH,
                     "협상된 암호군이 안전하지 않습니다.", "AEAD 기반 암호군(AES-GCM, CHACHA20)만 허용하세요.",
                     cipher[0], "CWE-327")
        # 인증서 만료일 확인 (검증 컨텍스트로 별도 조회)
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with vctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
            not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            self.notes.append(f"인증서 만료: {not_after:%Y-%m-%d} ({days}일 남음)")
            if days < 30:
                self.add("A02-CERT-EXPIRING", f"TLS 인증서 만료 임박 ({days}일 남음)", "A02", Severity.MEDIUM,
                         "인증서가 만료되면 서비스 접속 불가 및 사용자 경고가 발생합니다.",
                         "인증서 자동 갱신(예: ACME/Let's Encrypt)을 설정하세요.", f"notAfter={cert['notAfter']}", "CWE-298")
        except ssl.SSLCertVerificationError as exc:
            self.add("A02-TLS-CERT-INVALID", "유효하지 않은 TLS 인증서", "A02", Severity.HIGH,
                     "인증서 검증에 실패했습니다(만료, 자체 서명, 호스트명 불일치 등).",
                     "공인 CA에서 발급한 유효한 인증서를 사용하세요.", str(exc), "CWE-295")

    # ---------------- A05: 보안 헤더 ----------------
    def check_security_headers(self, main: Response):
        h = main.header
        is_https = main.url.lower().startswith("https://")
        is_html = "html" in (h("Content-Type") or "").lower()

        if is_https:
            hsts = h("Strict-Transport-Security")
            if not hsts:
                self.add("A05-NO-HSTS", "HSTS 헤더 누락", "A05", Severity.MEDIUM,
                         "HSTS가 없으면 SSL 스트리핑 공격으로 HTTP 다운그레이드가 가능합니다.",
                         "Strict-Transport-Security: max-age=31536000; includeSubDomains 를 설정하세요.", cwe="CWE-523")
            else:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                if not m or int(m.group(1)) < 15552000:
                    self.add("A05-WEAK-HSTS", "HSTS max-age가 너무 짧음", "A05", Severity.LOW,
                             "HSTS 유지 기간이 6개월 미만입니다.", "max-age를 31536000(1년) 이상으로 설정하세요.",
                             hsts, "CWE-523")

        csp = h("Content-Security-Policy")
        if not csp:
            if is_html:
                self.add("A05-NO-CSP", "Content-Security-Policy 헤더 누락", "A05", Severity.MEDIUM,
                         "CSP가 없으면 XSS 발생 시 피해를 완화할 수단이 없습니다.",
                         "default-src 'self' 등 최소 권한 CSP를 설정하세요.", cwe="CWE-1021")
        else:
            weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'", " * ", "data:") if t in f" {csp} "]
            if re.search(r"(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\s\*(\s|;|$))", csp):
                self.add("A05-WEAK-CSP", "취약한 CSP 정책", "A05", Severity.LOW,
                         "script-src에 unsafe-inline/unsafe-eval/* 가 허용되어 XSS 방어 효과가 약합니다.",
                         "nonce 또는 hash 기반 CSP를 사용하세요.", ", ".join(weak) or csp[:150], "CWE-1021")

        if is_html and not h("X-Frame-Options") and "frame-ancestors" not in (csp or ""):
            self.add("A05-NO-CLICKJACK", "클릭재킹 방어 헤더 누락", "A05", Severity.MEDIUM,
                     "X-Frame-Options 또는 CSP frame-ancestors가 없어 iframe으로 삽입될 수 있습니다.",
                     "X-Frame-Options: DENY 또는 CSP frame-ancestors 'self' 를 설정하세요.", cwe="CWE-1021")
        if (h("X-Content-Type-Options") or "").lower() != "nosniff":
            self.add("A05-NO-NOSNIFF", "X-Content-Type-Options 헤더 누락", "A05", Severity.LOW,
                     "브라우저 MIME 스니핑으로 업로드 파일이 스크립트로 해석될 수 있습니다.",
                     "X-Content-Type-Options: nosniff 를 설정하세요.", cwe="CWE-693")
        if not h("Referrer-Policy"):
            self.add("A05-NO-REFERRER-POLICY", "Referrer-Policy 헤더 누락", "A05", Severity.INFO,
                     "외부 사이트로 이동 시 URL(토큰 포함 가능)이 Referer로 유출될 수 있습니다.",
                     "Referrer-Policy: strict-origin-when-cross-origin 을 설정하세요.", cwe="CWE-200")
        if not h("Permissions-Policy"):
            self.add("A05-NO-PERMISSIONS-POLICY", "Permissions-Policy 헤더 누락", "A05", Severity.INFO,
                     "카메라/위치 등 브라우저 기능 사용 범위가 제한되지 않습니다.",
                     "사용하지 않는 기능을 Permissions-Policy로 비활성화하세요.", cwe="CWE-693")

    # ---------------- A05/A06: 정보 노출 ----------------
    def check_info_disclosure(self, main: Response):
        for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
            value = main.header(name)
            if value and VERSION_RE.search(value):
                self.add("A06-VERSION-DISCLOSURE", f"{name} 헤더로 버전 정보 노출", "A06", Severity.LOW,
                         "소프트웨어 버전이 노출되면 공격자가 알려진 취약점을 쉽게 찾을 수 있습니다.",
                         "버전 정보 헤더를 제거하고, 해당 소프트웨어가 최신 보안 패치 버전인지 확인하세요.",
                         f"{name}: {value}", "CWE-200")
        m = re.search(r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)", main.body, re.I)
        if m and VERSION_RE.search(m.group(1)):
            self.add("A06-GENERATOR-META", "generator 메타 태그로 버전 노출", "A06", Severity.LOW,
                     "CMS/프레임워크 버전이 페이지에 노출됩니다.", "generator 메타 태그를 제거하세요.",
                     m.group(1), "CWE-200")
        if re.search(r"<title>\s*Index of /", main.body, re.I):
            self.add("A05-DIR-LISTING", "디렉터리 목록 노출", "A05", Severity.MEDIUM,
                     "디렉터리 인덱싱이 활성화되어 파일 목록이 노출됩니다.",
                     "웹 서버 설정에서 디렉터리 목록(autoindex/Indexes)을 비활성화하세요.", main.url, "CWE-548")

    # ---------------- A07: 쿠키/세션 ----------------
    def check_cookies(self, main: Response):
        is_https = main.url.lower().startswith("https://")
        for raw in main.header_all("Set-Cookie"):
            name = raw.split("=", 1)[0].strip()
            attrs = raw.lower()
            missing = []
            if is_https and "secure" not in re.split(r";\s*", attrs):
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            elif "samesite=none" in attrs and "secure" not in attrs:
                missing.append("Secure(SameSite=None에 필수)")
            if missing:
                sev = Severity.MEDIUM if re.search(r"sess|auth|token|jwt|sid", name, re.I) else Severity.LOW
                self.add("A07-COOKIE-ATTR", f"쿠키 '{name}' 보안 속성 누락: {', '.join(missing)}", "A07", sev,
                         "쿠키 보안 속성이 없으면 세션 탈취(XSS, 도청)나 CSRF에 악용될 수 있습니다.",
                         "세션 쿠키에 Secure; HttpOnly; SameSite=Lax 를 설정하세요.", raw[:150], "CWE-614")

    def check_page_content(self, main: Response):
        if "html" not in (main.header("Content-Type") or "").lower():
            return
        parser = _PageParser()
        try:
            parser.feed(main.body)
        except Exception:
            return
        host = urlparse(main.url).hostname
        is_https = main.url.lower().startswith("https://")

        # A08: 외부 스크립트 SRI
        for s in parser.scripts:
            src = urljoin(main.url, s["src"])
            if urlparse(src).hostname not in (host, None) and not s.get("integrity"):
                self.add("A08-NO-SRI", "외부 스크립트에 SRI 무결성 검증 없음", "A08", Severity.LOW,
                         "외부 CDN 스크립트가 변조되면 악성 코드가 실행됩니다.",
                         "integrity/crossorigin 속성을 추가하세요.", src, "CWE-353")
        # A02: 혼합 콘텐츠
        if is_https:
            mixed = [r for r in parser.resources if r.lower().startswith("http://")]
            if mixed:
                self.add("A02-MIXED-CONTENT", "HTTPS 페이지에 HTTP 리소스 포함(혼합 콘텐츠)", "A02", Severity.MEDIUM,
                         "HTTP로 로드되는 리소스는 중간에서 변조될 수 있습니다.", "모든 리소스를 HTTPS로 로드하세요.",
                         ", ".join(mixed[:3]), "CWE-319")
        # A07/A02: 로그인 폼
        has_password = any(i.get("type", "").lower() == "password" for i in parser.inputs)
        if has_password:
            for form in parser.forms:
                action = urljoin(main.url, form.get("action") or main.url)
                if action.lower().startswith("http://"):
                    self.add("A02-FORM-HTTP", "비밀번호 폼이 HTTP로 전송됨", "A02", Severity.HIGH,
                             "자격 증명이 평문으로 전송됩니다.", "폼 action을 HTTPS로 지정하세요.", action, "CWE-319")
                if (form.get("method") or "get").lower() == "get":
                    self.add("A07-FORM-GET", "비밀번호 폼이 GET 방식 사용", "A07", Severity.MEDIUM,
                             "비밀번호가 URL에 포함되어 로그·브라우저 기록·Referer로 유출됩니다.",
                             "로그인 폼은 POST 방식을 사용하세요.", action, "CWE-598")

    # ---------------- A01/A05: CORS ----------------
    def check_cors(self, url: str):
        evil = f"https://{uuid.uuid4().hex[:8]}.evil-origin.example"
        r = self.client.request(url, headers={"Origin": evil}, follow=False)
        acao = r.header("Access-Control-Allow-Origin")
        acac = (r.header("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao == evil:
            self.add("A01-CORS-REFLECT", "임의 Origin을 그대로 허용하는 CORS 설정", "A01",
                     Severity.HIGH if acac else Severity.MEDIUM,
                     "공격자 사이트에서 사용자 권한으로 API 응답을 읽을 수 있습니다." +
                     (" 자격 증명(쿠키) 포함 요청도 허용됩니다." if acac else ""),
                     "Origin 허용 목록을 사용하고 요청 Origin을 그대로 반사하지 마세요.",
                     f"Origin: {evil} -> ACAO: {acao}, ACAC: {acac}", "CWE-942")
        elif acao == "null":
            self.add("A01-CORS-NULL", "null Origin을 허용하는 CORS 설정", "A01", Severity.MEDIUM,
                     "sandbox iframe 등에서 null Origin으로 접근할 수 있습니다.", "null Origin을 허용하지 마세요.",
                     "Access-Control-Allow-Origin: null", "CWE-942")
        elif acao == "*" and acac:
            self.add("A01-CORS-WILDCARD-CRED", "와일드카드 CORS와 자격 증명 동시 허용", "A01", Severity.MEDIUM,
                     "잘못된 CORS 구성입니다.", "신뢰하는 Origin만 명시적으로 허용하세요.",
                     "ACAO: *, ACAC: true", "CWE-942")

    # ---------------- A05: HTTP 메서드 ----------------
    def check_methods(self, url: str):
        r = self.client.request(url, method="OPTIONS", follow=False)
        allow = (r.header("Allow") or "") + "," + (r.header("Access-Control-Allow-Methods") or "")
        risky = sorted({m for m in re.split(r"[,\s]+", allow.upper()) if m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT")})
        if "TRACE" in risky or "TRACK" in risky:
            self.add("A05-TRACE-ENABLED", "TRACE 메서드 허용", "A05", Severity.LOW,
                     "TRACE는 크로스 사이트 트레이싱(XST)에 악용될 수 있습니다.", "TRACE/TRACK 메서드를 비활성화하세요.",
                     f"Allow: {allow.strip(',')}", "CWE-16")
        other = [m for m in risky if m not in ("TRACE", "TRACK")]
        if other:
            self.add("A05-RISKY-METHODS", f"위험한 HTTP 메서드 허용 광고: {', '.join(other)}", "A05", Severity.INFO,
                     "불필요한 메서드가 허용되면 리소스 변경/삭제 위험이 있습니다(인증 여부 수동 확인 필요).",
                     "필요한 메서드만 허용하고 인증·인가를 적용하세요.", f"Allow: {allow.strip(',')}", "CWE-650")

    # ---------------- A05/A09: 오류 페이지 정보 노출 ----------------
    def check_error_page(self, url: str):
        probe = urljoin(url, f"/owasp-scanner-{uuid.uuid4().hex[:10]}")
        r = self.client.request(probe, follow=False)
        m = STACK_TRACE_RE.search(r.body)
        if m:
            self.add("A05-STACK-TRACE", "오류 페이지에 스택 트레이스/내부 정보 노출", "A05", Severity.MEDIUM,
                     "상세 오류 메시지는 내부 경로, 프레임워크, 쿼리 구조를 노출합니다.",
                     "운영 환경에서는 사용자 정의 오류 페이지를 사용하고 상세 오류는 서버 로그에만 기록하세요.",
                     m.group(0)[:150], "CWE-209", location=probe, owasp2025="A10")
        if r.status == 200 and len(r.body) > 0:
            self.notes.append("존재하지 않는 경로에 200 응답 (soft-404) – 경로 노출 점검 결과는 본문 서명으로만 판단")

    # ---------------- A05/A01: 민감 파일 노출 ----------------
    def check_sensitive_paths(self, url: str):
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path, signature, title, owasp, severity in SENSITIVE_PATHS:
            target = base + path
            try:
                r = self.client.request(target, follow=False)
            except Exception:
                continue
            if r.status != 200:
                continue
            ctype = (r.header("Content-Type") or "").lower()
            if signature:
                if not re.search(signature, r.body, re.I | re.M):
                    continue
            else:
                # 서명이 없는 바이너리 파일: HTML이 아닌 응답만 인정 (soft-404 오탐 방지)
                if "html" in ctype or not r.body:
                    continue
            self.add(f"{owasp}-EXPOSED-{path.strip('/').replace('/', '-').replace('.', '').upper() or 'ROOT'}",
                     title, owasp, severity,
                     "외부에서 접근하면 안 되는 파일/페이지가 공개되어 있습니다.",
                     "웹 서버 설정으로 접근을 차단하거나 배포 대상에서 제거하세요.",
                     f"GET {path} -> 200 ({ctype or 'unknown'})", "CWE-538", location=target)


def scan_url(url: str, timeout: float = 10.0, insecure: bool = False,
             check_paths: bool = True) -> tuple[list[Finding], list[str]]:
    scanner = WebScanner(url, timeout, insecure, check_paths)
    findings = scanner.run()
    return findings, scanner.notes
