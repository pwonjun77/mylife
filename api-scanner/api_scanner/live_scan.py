"""실제 API 서버에 대한 비파괴 점검 (authorized, passive).

안전한 메서드(GET/HEAD/OPTIONS)와 사용자가 명시적으로 넘긴 토큰만 사용하며,
데이터를 바꾸는 요청은 보내지 않는다. 반드시 점검 권한이 있는 대상에만 사용할 것.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message

from .models import Finding, Severity
from .spec import SAFE_METHODS, ApiSpec, Operation, base_url

USER_AGENT = "api-scanner/1.0 (+authorized security assessment)"
MAX_BODY = 512 * 1024

SECURITY_HEADERS = {
    "Strict-Transport-Security": (Severity.MEDIUM, "HTTPS 강제(HSTS) 헤더가 없습니다."),
    "X-Content-Type-Options": (Severity.LOW, "MIME 스니핑 방지(nosniff) 헤더가 없습니다."),
    "Content-Type": (Severity.LOW, "응답 Content-Type 이 명시되지 않았습니다."),
}


class Client:
    def __init__(self, timeout: float = 10.0, insecure: bool = False):
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False  # nosec
            ctx.verify_mode = ssl.CERT_NONE  # nosec - 사용자가 --insecure 명시 시에만
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def request(self, url: str, method: str = "GET", headers: dict | None = None):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            resp = self.opener.open(req, timeout=self.timeout)
            return resp.status, resp.headers, resp.read(MAX_BODY)
        except urllib.error.HTTPError as err:
            return err.code, err.headers, (err.read(MAX_BODY) if err.fp else b"")
        except (urllib.error.URLError, ssl.SSLError, OSError) as err:
            return None, Message(), str(err).encode()


def _fill_path(path: str, params, sample_id: str | None) -> str | None:
    """경로 파라미터를 샘플 값으로 채운다. 채울 수 없으면 None."""
    result = path
    for name in re.findall(r"\{([^}]+)\}", path):
        p = next((p for p in params if p.name == name and p.location == "path"), None)
        value = sample_id
        if p and p.schema.get("example") is not None:
            value = str(p.schema["example"])
        elif p and p.schema.get("enum"):
            value = str(p.schema["enum"][0])
        elif p and p.schema.get("type") == "integer":
            value = sample_id or "1"
        elif value is None:
            value = sample_id
        if value is None:
            return None
        result = result.replace("{" + name + "}", urllib.parse.quote(str(value), safe=""))
    return result


class LiveScanner:
    def __init__(self, spec: ApiSpec, base: str, token: str | None = None, token_b: str | None = None,
                 sample_id: str | None = None, timeout: float = 10.0, insecure: bool = False):
        self.spec = spec
        self.base = base.rstrip("/")
        self.token = token
        self.token_b = token_b
        self.sample_id = sample_id
        self.client = Client(timeout, insecure)
        self.findings: list[Finding] = []
        self._header_checked = False

    def _auth(self, token: str | None) -> dict:
        return {"Authorization": f"Bearer {token}"} if token else {}

    def run(self) -> list[Finding]:
        for op in self.spec.operations:
            if op.method not in SAFE_METHODS:
                continue  # 비파괴 원칙: 읽기 전용 메서드만 호출
            self._scan_op(op)
        return self.findings

    def _scan_op(self, op: Operation):
        url_path = _fill_path(op.path, op.params, self.sample_id)
        if url_path is None:
            return
        url = self.base + url_path
        needs_auth = self.spec.requires_auth(op)

        status, headers, _ = self.client.request(url, op.method)  # 인증 헤더 없이
        if status is None:
            return
        if not self._header_checked:
            self._check_headers(url, headers)
            self._header_checked = True

        # API2: 인증이 필요한데 토큰 없이 2xx
        if needs_auth and 200 <= status < 300:
            self.findings.append(Finding(
                "API2-AUTH-NOT-ENFORCED", "인증이 필요한 API가 토큰 없이 응답함", "API2", Severity.HIGH, op.key,
                f"명세상 인증이 필요하지만 Authorization 헤더 없이 요청해도 {status} 로 응답했습니다.",
                "서버에서 모든 보호 대상 API에 인증을 강제하고, 미인증 요청은 401/403 으로 거부하세요.",
                f"GET {url} -> {status} (토큰 없음)", "CWE-306"))

        # API1: 두 사용자 토큰으로 같은 객체 접근 비교 (BOLA)
        if self.token and self.token_b and "{" in op.path:
            sa, _, _ = self.client.request(url, op.method, self._auth(self.token))
            sb, _, _ = self.client.request(url, op.method, self._auth(self.token_b))
            if sa and 200 <= sa < 300 and sb is not None and 200 <= sb < 300:
                self.findings.append(Finding(
                    "API1-BOLA-CROSS-USER", "다른 사용자의 토큰으로 동일 객체에 접근됨", "API1", Severity.CRITICAL, op.key,
                    f"서로 다른 두 사용자 토큰 모두 같은 객체({url_path})를 {sa}/{sb} 로 조회했습니다. "
                    "객체 소유권 검사가 누락되었을 수 있습니다(BOLA).",
                    "요청자가 해당 객체에 접근할 권한이 있는지 서버에서 객체 단위로 검사하세요.",
                    f"user A -> {sa}, user B -> {sb}", "CWE-639"))

    def _check_headers(self, url: str, headers: Message):
        present = {k.lower() for k in headers.keys()}
        if url.lower().startswith("https://") and "strict-transport-security" not in present:
            sev, msg = SECURITY_HEADERS["Strict-Transport-Security"]
            self.findings.append(Finding("API8-NO-HSTS", "HSTS 헤더 없음", "API8", sev, url, msg,
                                         "Strict-Transport-Security 헤더를 설정하세요.", cwe="CWE-319"))
        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            self.findings.append(Finding("API8-NO-NOSNIFF", "X-Content-Type-Options 헤더 없음", "API8", Severity.LOW,
                                         url, SECURITY_HEADERS["X-Content-Type-Options"][1],
                                         "X-Content-Type-Options: nosniff 를 설정하세요.", cwe="CWE-16"))
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acac == "true":
            self.findings.append(Finding(
                "API8-CORS-WILDCARD-CREDS", "CORS가 모든 출처에 인증정보 공유를 허용함", "API8", Severity.HIGH, url,
                "Access-Control-Allow-Origin: * 와 Allow-Credentials: true 를 함께 쓰면 "
                "어떤 사이트에서든 인증된 요청을 보낼 수 있습니다.",
                "신뢰하는 출처만 허용 목록으로 지정하고, 자격 증명 공유 시 와일드카드를 쓰지 마세요.",
                f"ACAO={acao}, ACAC={acac}", "CWE-942"))
        for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if headers.get(h):
                self.findings.append(Finding(
                    "API8-VERSION-DISCLOSURE", f"서버 버전 정보 노출 ({h})", "API8", Severity.INFO, url,
                    f"{h}: {headers.get(h)} 헤더가 구성요소와 버전을 노출해 알려진 취약점 탐색을 쉽게 합니다.",
                    "불필요한 식별 헤더를 제거하세요.", f"{h}: {headers.get(h)}", "CWE-200"))
