"""명세 없이 기본 URL만으로 점검하기 위한 보조 기능.

1) discover_spec : 흔한 표준 경로에서 OpenAPI/Swagger 명세를 찾는다.
2) scan_base_url : 명세가 전혀 없을 때 단일 기준 URL에 대한 비파괴 설정·노출 점검.

모두 안전한 메서드(GET/HEAD)만 사용한다. 반드시 점검 권한이 있는 대상에만 사용할 것.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from .live_scan import Client
from .models import Finding, Severity
from .spec import ApiSpec, SpecError, parse_spec

# 널리 쓰이는 명세 공개 경로 (프레임워크별)
SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/v3/api-docs", "/v3/api-docs.yaml", "/v2/api-docs", "/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/api/v1/openapi.json",
    "/docs/openapi.json", "/redoc/openapi.json", "/api-docs/swagger.json",
    "/.well-known/openapi.json",
]

# (경로, 본문 서명 정규식 또는 None, 제목, 분류, 심각도)
SENSITIVE_PATHS = [
    ("/.env", r"^[A-Z_][A-Z0-9_]*\s*=", ".env 환경 설정 파일 노출", "API8", Severity.CRITICAL),
    ("/.git/config", r"\[core\]", "Git 설정 파일 노출", "API8", Severity.HIGH),
    ("/.git/HEAD", r"^ref:\s*refs/", "Git 저장소 메타데이터 노출", "API8", Severity.HIGH),
    ("/actuator/env", r"\"(activeProfiles|propertySources)\"", "Spring Boot Actuator env 노출", "API8", Severity.HIGH),
    ("/actuator/heapdump", None, "Spring Boot Actuator heapdump 노출", "API8", Severity.CRITICAL),
    ("/actuator", r"\"_links\"|\"health\"", "Spring Boot Actuator 엔드포인트 노출", "API8", Severity.MEDIUM),
    ("/config.json", r"\"(password|secret|apiKey|api_key)\"", "설정 파일(config.json) 노출", "API8", Severity.HIGH),
    ("/server-status", r"Apache Server Status", "Apache server-status 노출", "API8", Severity.MEDIUM),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "phpinfo 페이지 노출", "API8", Severity.MEDIUM),
]

# 공개 문서/탐색 지점 (노출 자체는 정보성)
DOC_PATHS = [
    ("/swagger-ui.html", r"swagger", "API 문서(Swagger UI) 공개 노출", "API9", Severity.INFO),
    ("/swagger-ui/index.html", r"swagger", "API 문서(Swagger UI) 공개 노출", "API9", Severity.INFO),
    ("/graphql", r"__schema|GraphQL|\"data\"|\"errors\"", "GraphQL 엔드포인트 노출", "API9", Severity.INFO),
    ("/metrics", r"# (HELP|TYPE)", "Prometheus metrics 노출", "API8", Severity.LOW),
]


def _normalize_base(target: str) -> str:
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target.rstrip("/")


def discover_spec(base: str, client: Client | None = None, verbose: bool = False) -> tuple[ApiSpec | None, str | None]:
    """기준 URL에서 명세를 탐색한다. (spec, 찾은 URL) 또는 (None, None)."""
    base = _normalize_base(base)
    client = client or Client()
    tried: list[str] = []
    for path in SPEC_PATHS:
        url = base + path
        tried.append(url)
        status, headers, body = client.request(url)
        if status != 200 or not body:
            continue
        text = body.decode("utf-8", errors="replace")
        try:
            spec = parse_spec(text, url)
        except (SpecError, ValueError):
            continue
        spec.source = url
        return spec, url
    return None, None


def scan_base_url(base: str, client: Client | None = None, check_paths: bool = True) -> list[Finding]:
    """명세 없이 기준 URL 하나에 대한 설정·노출 점검 (API8/API9 중심)."""
    base = _normalize_base(base)
    client = client or Client()
    findings: list[Finding] = []

    status, headers, body = client.request(base)
    if status is None:
        findings.append(Finding("API8-UNREACHABLE", "대상에 연결할 수 없음", "API8", Severity.INFO, base,
                                f"요청이 실패했습니다: {body.decode('utf-8', 'replace')[:120]}",
                                "주소와 네트워크 접근 권한을 확인하세요."))
        return findings

    findings += _header_findings(base, headers)

    if base.lower().startswith("https://"):
        # http 로도 접속되는지(평문 허용) 확인
        http_url = "http://" + base[len("https://"):]
        s2, h2, _ = client.request(http_url)
        if s2 and s2 < 400 and (h2.get("Location", "").startswith("http://") or s2 == 200):
            findings.append(Finding("API8-HTTP-ALLOWED", "평문 HTTP 접속이 허용됨", "API8", Severity.MEDIUM, http_url,
                                    "HTTPS 사이트가 http:// 요청도 받아들여 중간자 공격에 노출될 수 있습니다.",
                                    "HTTP 요청은 HTTPS로 강제 리다이렉트하고 HSTS를 적용하세요.", cwe="CWE-319"))

    if check_paths:
        for path, sig, title, cat, sev in SENSITIVE_PATHS + DOC_PATHS:
            url = base + path
            st, hd, bd = client.request(url)
            if st != 200 or not bd:
                continue
            text = bd.decode("utf-8", errors="replace")
            if sig and not re.search(sig, text, re.I | re.M):
                continue
            findings.append(Finding("API8-EXPOSED-PATH" if cat == "API8" else "API9-EXPOSED-PATH",
                                    title, cat, sev, url,
                                    "민감하거나 내부 정보를 담을 수 있는 경로가 외부에 노출되어 있습니다.",
                                    "해당 경로를 차단하거나 인증 뒤로 옮기고, 운영 환경에서 비활성화하세요.",
                                    f"GET {url} -> 200", "CWE-200"))
    return findings


def _header_findings(url: str, headers) -> list[Finding]:
    out: list[Finding] = []
    present = {k.lower() for k in headers.keys()}
    if url.lower().startswith("https://") and "strict-transport-security" not in present:
        out.append(Finding("API8-NO-HSTS", "HSTS 헤더 없음", "API8", Severity.MEDIUM, url,
                           "Strict-Transport-Security 헤더가 없어 HTTPS 강제가 되지 않습니다.",
                           "Strict-Transport-Security 헤더를 설정하세요.", cwe="CWE-319"))
    if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        out.append(Finding("API8-NO-NOSNIFF", "X-Content-Type-Options 헤더 없음", "API8", Severity.LOW, url,
                           "MIME 스니핑 방지(nosniff) 헤더가 없습니다.",
                           "X-Content-Type-Options: nosniff 를 설정하세요.", cwe="CWE-16"))
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(Finding("API8-CORS-WILDCARD-CREDS", "CORS가 모든 출처에 인증정보 공유를 허용함", "API8",
                           Severity.HIGH, url,
                           "Access-Control-Allow-Origin: * 와 Allow-Credentials: true 를 함께 쓰면 "
                           "어떤 사이트에서든 인증된 요청을 보낼 수 있습니다.",
                           "신뢰하는 출처만 허용 목록으로 지정하세요.", f"ACAO={acao}, ACAC={acac}", "CWE-942"))
    elif acao == "*":
        out.append(Finding("API8-CORS-WILDCARD", "CORS가 모든 출처를 허용함", "API8", Severity.LOW, url,
                           "Access-Control-Allow-Origin: * 로 모든 출처의 읽기 접근을 허용합니다.",
                           "필요한 출처만 허용 목록으로 지정하세요.", f"ACAO={acao}", "CWE-942"))
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        if headers.get(h):
            out.append(Finding("API8-VERSION-DISCLOSURE", f"서버 버전 정보 노출 ({h})", "API8", Severity.INFO, url,
                               f"{h}: {headers.get(h)} 헤더가 구성요소와 버전을 노출합니다.",
                               "불필요한 식별 헤더를 제거하세요.", f"{h}: {headers.get(h)}", "CWE-200"))
    return out
