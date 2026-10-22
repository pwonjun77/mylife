"""OpenAPI/Swagger 명세 정적 점검 (서버에 요청을 보내지 않음)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Finding, Severity, dedupe
from .spec import SAFE_METHODS, ApiSpec, Operation, iter_properties

SENSITIVE_FIELD_RE = re.compile(
    r"(^|[._\[\]])(password|passwd|pwd|password_?hash|secret|client_?secret|api_?key|access_?token|"
    r"refresh_?token|private_?key|ssn|social_?security|resident_?(no|number)|jumin|credit_?card|card_?number|"
    r"cvv|cvc|pin|otp|mfa_?secret|salt)$",
    re.I,
)
PRIVILEGED_FIELD_RE = re.compile(
    r"(^|[._])(role|roles|is_?admin|admin|is_?staff|is_?superuser|permissions?|scopes?|privileges?|"
    r"group_?id|tenant_?id|owner_?id|account_?type|is_?verified|verified|email_?verified|balance|credit|"
    r"price|discount|status)$",
    re.I,
)
OBJECT_ID_RE = re.compile(r"(^id$|_?id$|Id$|^uuid$|_?uuid$|^key$|^no$|number$)")
SSRF_PARAM_RE = re.compile(
    r"^(url|uri|link|href|src|source|target|dest|destination|redirect(_?ur[il])?|return_?url|next|callback(_?url)?|"
    r"webhook(_?url)?|endpoint|feed|host|domain|image_?url|avatar_?url|file_?url|proxy|fetch|import_?url)$",
    re.I,
)
ADMIN_PATH_RE = re.compile(r"/(admin|administrator|internal|manage|management|ops|superuser|sudo|root|"
                           r"system|staff|backoffice|console)(/|$)", re.I)
DEBUG_PATH_RE = re.compile(r"/(debug|test|tests|dev|staging|sandbox|beta|actuator|metrics|health/details|"
                           r"env|config|phpinfo|trace|dump|heapdump)(/|$)", re.I)
BUSINESS_FLOW_RE = re.compile(
    r"/(checkout|purchase|buy|order|orders|payment|payments|pay|transfer|withdraw|coupon|coupons|redeem|"
    r"voucher|reservation|reservations|booking|bookings|ticket|tickets|vote|votes|comment|comments|review|"
    r"reviews|signup|sign-up|register|registration|invite|referral|otp|sms|verify|verification|"
    r"password[-_]?reset|reset[-_]?password|forgot[-_]?password)(/|$)",
    re.I,
)
AUTH_FLOW_RE = re.compile(r"/(login|signin|sign-in|auth|token|oauth/token|otp|verify|password[-_]?reset|"
                          r"reset[-_]?password|forgot[-_]?password|mfa|2fa)(/|$)", re.I)
VERSION_RE = re.compile(r"/v(\d+)(/|$)", re.I)
NONPROD_HOST_RE = re.compile(r"(^|[.-])(dev|develop|test|testing|qa|stage|staging|sandbox|beta|local|localhost|"
                             r"internal|uat)([.-]|$)|^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.", re.I)
PAGING_PARAM_RE = re.compile(r"^(limit|size|page_?size|per_?page|count|max|max_?results|top|first|last|take|"
                             r"batch_?size|page\[size\])$", re.I)


def _f(rule, title, cat, sev, loc, desc, rec, evidence="", cwe=""):
    return Finding(rule, title, cat, sev, loc, desc, rec, evidence, cwe)


def scan_spec(spec: ApiSpec) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_global(spec)
    for op in spec.operations:
        findings += _check_operation(spec, op)
    findings += _check_inventory(spec)
    return dedupe(findings)


# ---------------------------------------------------------------- 전역 설정

def _check_global(spec: ApiSpec) -> list[Finding]:
    out: list[Finding] = []
    loc = spec.source or "(spec)"
    if not spec.security_schemes:
        out.append(_f("API2-NO-SECURITY-SCHEME", "명세에 인증 방식(securitySchemes)이 정의되어 있지 않음", "API2",
                      Severity.MEDIUM, loc,
                      "명세에 인증 방식이 전혀 없습니다. 실제로 인증이 없거나, 문서가 실제 구현과 다를 수 있습니다.",
                      "OAuth2/OIDC 또는 Bearer(JWT) 등의 인증 방식을 정의하고 각 API에 적용하세요.", cwe="CWE-306"))
    for name, sch in spec.security_schemes.items():
        if not isinstance(sch, dict):
            continue
        typ, where = sch.get("type", ""), sch.get("in", "")
        scheme = str(sch.get("scheme", "")).lower()
        if typ == "basic" or (typ == "http" and scheme == "basic"):
            out.append(_f("API2-BASIC-AUTH", f"HTTP Basic 인증 사용 ({name})", "API2", Severity.MEDIUM, loc,
                          "Basic 인증은 매 요청마다 아이디·비밀번호를 그대로 보내며 만료·폐기가 어렵습니다.",
                          "토큰 기반 인증(OAuth2, 만료가 짧은 JWT)으로 바꾸고 HTTPS만 허용하세요.",
                          f"securitySchemes.{name}", "CWE-522"))
        if typ == "apiKey" and where == "query":
            out.append(_f("API2-APIKEY-IN-QUERY", f"API 키를 URL 쿼리 문자열로 전달 ({name})", "API2", Severity.MEDIUM,
                          loc, "쿼리 문자열의 키는 접근 로그, 프록시, 브라우저 기록, Referer 헤더에 남아 유출되기 쉽습니다.",
                          "API 키는 Authorization 등 요청 헤더로 전달하세요.",
                          f"securitySchemes.{name}.in = query", "CWE-598"))
        flows = sch.get("flows", {}) if typ == "oauth2" else {}
        if "implicit" in flows or sch.get("flow") == "implicit":
            out.append(_f("API2-OAUTH-IMPLICIT", f"OAuth2 Implicit 흐름 사용 ({name})", "API2", Severity.MEDIUM, loc,
                          "Implicit 흐름은 액세스 토큰이 URL 조각으로 전달되어 탈취 위험이 크며 OAuth 2.1에서 제거되었습니다.",
                          "Authorization Code + PKCE 흐름을 사용하세요.", f"securitySchemes.{name}", "CWE-522"))
        if "password" in flows or sch.get("flow") == "password":
            out.append(_f("API2-OAUTH-ROPC", f"OAuth2 Resource Owner Password 흐름 사용 ({name})", "API2", Severity.LOW,
                          loc, "클라이언트가 사용자 비밀번호를 직접 다루게 되어 피싱·유출 위험이 있고 MFA 적용이 어렵습니다.",
                          "Authorization Code + PKCE 흐름을 사용하세요.", f"securitySchemes.{name}", "CWE-522"))
    for server in spec.servers:
        if server.lower().startswith("http://") and not _is_local(server):
            out.append(_f("API8-HTTP-SERVER", "평문 HTTP 서버 주소 사용", "API8", Severity.HIGH, server,
                          "API 서버가 http:// 로 정의되어 토큰과 데이터가 암호화되지 않은 채 전송될 수 있습니다.",
                          "https:// 만 사용하고 HTTP 요청은 HTTPS로 리다이렉트하거나 차단하세요(HSTS 적용).",
                          f"servers: {server}", "CWE-319"))
    return out


def _is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".local")


# ---------------------------------------------------------------- 오퍼레이션별

def _check_operation(spec: ApiSpec, op: Operation) -> list[Finding]:
    out: list[Finding] = []
    loc = op.key
    needs_auth = spec.requires_auth(op)
    is_auth_flow = bool(AUTH_FLOW_RE.search(op.path))
    path_ids = [p for p in op.params if p.location == "path" and OBJECT_ID_RE.search(p.name)]

    # API2 / API5: 인증 없이 열린 API
    if not needs_auth and not is_auth_flow:
        if ADMIN_PATH_RE.search(op.path):
            out.append(_f("API5-ADMIN-NO-AUTH", "관리 기능 API에 인증 요구사항이 없음", "API5", Severity.HIGH, loc,
                          "관리자/내부용으로 보이는 경로가 명세상 인증 없이 호출 가능합니다.",
                          "관리 기능은 인증과 관리자 역할(권한) 검사를 모두 적용하고, 가능하면 외부망에서 분리하세요.",
                          cwe="CWE-285"))
        elif op.method not in SAFE_METHODS:
            out.append(_f("API2-WRITE-NO-AUTH", "데이터를 변경하는 API에 인증 요구사항이 없음", "API2", Severity.HIGH, loc,
                          f"{op.method} 요청은 데이터를 생성·수정·삭제하지만 명세상 인증 없이 호출할 수 있습니다.",
                          "해당 오퍼레이션(또는 전역)에 security 요구사항을 지정하고 서버에서 실제로 검증하세요.",
                          cwe="CWE-306"))
        elif path_ids:
            out.append(_f("API1-OBJECT-NO-AUTH", "개별 객체를 조회하는 API에 인증 요구사항이 없음", "API1", Severity.MEDIUM,
                          loc, f"경로 파라미터 {', '.join(p.name for p in path_ids)} 로 객체를 지정하지만 인증이 없어 "
                          "ID를 바꿔 다른 사용자의 데이터를 조회할 수 있는지 확인이 필요합니다.",
                          "공개 데이터가 아니라면 인증을 요구하고, 요청자가 해당 객체의 소유자인지 서버에서 검사하세요.",
                          cwe="CWE-639"))

    # API1: 예측 가능한 정수형 ID
    for p in path_ids:
        if p.schema.get("type") == "integer" and needs_auth:
            out.append(_f("API1-SEQUENTIAL-ID", f"순차 정수형 객체 ID 사용 ({p.name})", "API1", Severity.INFO, loc,
                          "정수 ID는 추측이 쉬워 BOLA 공격에 자주 이용됩니다. 객체별 소유권 검사가 반드시 필요합니다.",
                          "모든 객체 접근에 소유자/권한 검사를 적용하고, 외부 노출 ID는 UUID 등 추측 불가 값을 고려하세요. "
                          "`scan --token --token-b --id` 옵션으로 실제 BOLA 여부를 확인할 수 있습니다.",
                          f"{p.name}: integer", "CWE-639"))

    # API3: 응답의 민감 필드 / 요청의 권한 필드(대량 할당)
    for status, schema in op.responses.items():
        if not status.startswith("2"):
            continue
        for prop, ps in iter_properties(schema):
            if SENSITIVE_FIELD_RE.search(prop) and not ps.get("writeOnly"):
                if is_auth_flow and re.search(r"(access|refresh)_?token$", prop, re.I):
                    continue  # 로그인/토큰 발급 API의 토큰 반환은 정상
                out.append(_f("API3-SENSITIVE-RESPONSE", f"응답에 민감 정보 필드 포함 ({prop})", "API3", Severity.HIGH, loc,
                              "응답 스키마에 비밀번호·토큰·주민번호 등 민감 필드가 정의되어 클라이언트에 노출될 수 있습니다.",
                              "응답 DTO에서 민감 필드를 제거하고, 필요한 필드만 명시적으로 직렬화하세요(writeOnly 지정).",
                              f"responses.{status}: {prop}", "CWE-213"))
    if op.request_schema and op.method in ("POST", "PUT", "PATCH"):
        req = op.request_schema
        for prop, ps in iter_properties(req):
            if PRIVILEGED_FIELD_RE.search(prop) and not ps.get("readOnly"):
                if re.search(r"(^|\.)status$", prop) and not ADMIN_PATH_RE.search(op.path):
                    sev = Severity.LOW
                else:
                    sev = Severity.MEDIUM
                out.append(_f("API3-MASS-ASSIGNMENT", f"요청 본문에서 권한·상태 필드 변경 가능 ({prop})", "API3", sev, loc,
                              "클라이언트가 역할·권한·잔액 등 서버가 결정해야 할 속성을 직접 보낼 수 있으면 "
                              "대량 할당(Mass Assignment)으로 권한 상승이 일어날 수 있습니다.",
                              "요청 DTO를 허용 목록 방식으로 분리하고, 서버가 결정할 필드는 readOnly 로 지정·무시하세요.",
                              f"requestBody: {prop}", "CWE-915"))
        if _allows_extra(req):
            out.append(_f("API3-OPEN-SCHEMA", "요청 스키마가 정의되지 않은 속성을 허용함", "API3", Severity.LOW, loc,
                          "additionalProperties 가 막혀 있지 않아 문서에 없는 필드(예: role)를 보내도 받아들여질 수 있습니다.",
                          "요청 스키마에 additionalProperties: false 를 지정하고 서버에서도 알 수 없는 필드를 거부하세요.",
                          cwe="CWE-915"))

    # API4: 크기·개수 제한 없음
    for p in op.params:
        typ = p.schema.get("type")
        if p.location == "query" and PAGING_PARAM_RE.search(p.name) and typ in ("integer", "number") \
                and "maximum" not in p.schema:
            out.append(_f("API4-NO-PAGE-LIMIT", f"페이지 크기 파라미터에 최댓값 없음 ({p.name})", "API4", Severity.MEDIUM, loc,
                          "limit=1000000 같은 요청으로 대량 데이터를 한 번에 조회해 서버 자원을 고갈시킬 수 있습니다.",
                          "maximum 을 지정하고 서버에서도 상한을 강제하세요.", f"{p.name}: {typ} (maximum 없음)", "CWE-770"))
        elif typ == "string" and "maxLength" not in p.schema and "enum" not in p.schema \
                and p.schema.get("format") not in ("uuid", "date", "date-time", "email", "binary"):
            out.append(_f("API4-NO-MAXLENGTH", f"문자열 파라미터에 최대 길이 없음 ({p.name})", "API4", Severity.INFO, loc,
                          "길이 제한이 없으면 매우 큰 입력으로 처리 비용을 늘리는 공격이 가능합니다.",
                          "maxLength 를 지정하고 서버·게이트웨이에서 요청 크기를 제한하세요.", f"{p.name} ({p.location})",
                          "CWE-770"))
    for prop, ps in iter_properties(op.request_schema or {}):
        if ps.get("type") == "array" and "maxItems" not in ps:
            out.append(_f("API4-NO-MAXITEMS", f"배열 필드에 최대 개수 없음 ({prop})", "API4", Severity.LOW, loc,
                          "한 요청에 수만 개 항목을 넣어 일괄 처리 비용을 키우는 공격이 가능합니다.",
                          "maxItems 를 지정하고 서버에서 강제하세요.", f"requestBody: {prop}", "CWE-770"))
        if ps.get("format") == "binary" and "maxLength" not in ps:
            out.append(_f("API4-UPLOAD-NO-LIMIT", f"파일 업로드 크기 제한이 명시되지 않음 ({prop})", "API4", Severity.LOW,
                          loc, "업로드 크기 제한이 없으면 디스크·메모리 고갈 공격이 가능합니다.",
                          "maxLength(바이트) 를 명시하고 서버·프록시에서 업로드 크기를 제한하세요.",
                          f"requestBody: {prop}", "CWE-400"))
    if (is_auth_flow or BUSINESS_FLOW_RE.search(op.path)) and op.method not in SAFE_METHODS \
            and "429" not in op.responses:
        out.append(_f("API4-NO-RATE-LIMIT-DOC", "요청 횟수 제한(429 응답)이 정의되지 않음", "API4", Severity.LOW, loc,
                      "로그인·인증·결제 등 남용되기 쉬운 API에 속도 제한 응답(429)이 문서화되어 있지 않습니다.",
                      "사용자·IP별 속도 제한을 적용하고 429 응답과 RateLimit/Retry-After 헤더를 문서화하세요.",
                      cwe="CWE-307" if is_auth_flow else "CWE-770"))

    # API6: 민감 업무 흐름
    if BUSINESS_FLOW_RE.search(op.path) and op.method not in SAFE_METHODS and not is_auth_flow:
        out.append(_f("API6-SENSITIVE-FLOW", "자동화 남용 방지가 필요한 업무 흐름", "API6", Severity.INFO, loc,
                      "구매·예약·쿠폰·가입·후기 등은 봇에 의한 대량 자동화(매점매석, 스팸, 쿠폰 남용)의 표적이 됩니다.",
                      "기기 지문, CAPTCHA, 사람 행동 패턴 검사, 사용자당 한도 등 업무 흐름별 남용 방지책을 설계하세요.",
                      cwe="CWE-799"))

    # API7: SSRF 가능 파라미터
    params = [(p.name, p.location) for p in op.params]
    params += [(prop, "body") for prop, _ in iter_properties(op.request_schema or {})]
    for name, where in params:
        leaf = re.split(r"[.\[\]]+", name.strip("[]"))[-1] or name
        if SSRF_PARAM_RE.search(leaf):
            out.append(_f("API7-URL-PARAM", f"URL을 입력받는 파라미터 ({name})", "API7", Severity.MEDIUM, loc,
                          "서버가 이 값으로 외부 요청을 보낸다면 내부망·클라우드 메타데이터(169.254.169.254) 접근 등 "
                          "SSRF 공격에 악용될 수 있습니다.",
                          "허용 도메인 목록으로 검증하고, 사설·루프백·링크로컬 IP와 리다이렉트를 차단하세요.",
                          f"{name} ({where})", "CWE-918"))

    # API9: 폐기 예정 API
    if op.deprecated:
        out.append(_f("API9-DEPRECATED-OP", "폐기 예정(deprecated) API가 아직 노출됨", "API9", Severity.LOW, loc,
                      "폐기 예정 API는 보안 패치가 늦어지기 쉬워 공격 대상이 됩니다.",
                      "폐기 일정을 정해 Sunset 헤더로 알리고 기한 이후 제거하세요.", cwe="CWE-1059"))
    if DEBUG_PATH_RE.search(op.path):
        out.append(_f("API8-DEBUG-ENDPOINT", "디버그·테스트용으로 보이는 API가 명세에 포함됨", "API8", Severity.MEDIUM, loc,
                      "디버그·진단 API는 내부 설정이나 환경 변수를 노출할 수 있습니다.",
                      "운영 환경에서는 비활성화하거나 내부망·관리자 인증 뒤로 옮기세요.", cwe="CWE-489"))
    return out


def _allows_extra(schema: dict) -> bool:
    if not isinstance(schema, dict) or schema.get("type") not in (None, "object") or "properties" not in schema:
        return False
    return schema.get("additionalProperties", True) is not False


# ---------------------------------------------------------------- 자산 관리

def _check_inventory(spec: ApiSpec) -> list[Finding]:
    out: list[Finding] = []
    loc = spec.source or "(spec)"
    versions = set()
    for op in spec.operations:
        m = VERSION_RE.search(op.path)
        if m:
            versions.add(int(m.group(1)))
    for server in spec.servers:
        m = VERSION_RE.search(urlparse(server).path or "")
        if m:
            versions.add(int(m.group(1)))
        host = urlparse(server).hostname or ""
        if host and NONPROD_HOST_RE.search(host) and host not in ("localhost", "127.0.0.1"):
            out.append(_f("API9-NONPROD-SERVER", "개발·테스트 서버 주소가 명세에 포함됨", "API9", Severity.LOW, server,
                          "개발·스테이징 환경은 보안 설정이 약한 경우가 많아 공격 경로가 됩니다.",
                          "운영용 명세에서는 비운영 서버를 제거하고, 비운영 환경도 인증·접근 제어를 적용하세요.",
                          f"servers: {server}", "CWE-1059"))
    if len(versions) > 1:
        out.append(_f("API9-MULTIPLE-VERSIONS", "여러 API 버전이 동시에 노출됨", "API9", Severity.LOW, loc,
                      f"버전 {', '.join('v' + str(v) for v in sorted(versions))} 가 함께 노출되어 있습니다. "
                      "구버전은 보안 수정이 빠지는 경우가 많습니다.",
                      "API 자산 목록을 관리하고 구버전에 동일한 보안 통제를 적용하거나 폐기하세요.",
                      ", ".join(f"v{v}" for v in sorted(versions)), "CWE-1059"))
    callbacks = [op.key for op in spec.operations
                 if (spec.raw.get("paths", {}).get(op.path, {}).get(op.method.lower(), {}) or {}).get("callbacks")]
    if spec.raw.get("webhooks") or callbacks:
        out.append(_f("API10-WEBHOOK-CALLBACK", "외부 시스템과 주고받는 콜백·웹훅이 정의됨", "API10", Severity.INFO,
                      ", ".join(callbacks) or loc,
                      "외부(제3자) API의 응답이나 웹훅 요청을 신뢰하고 그대로 처리하면 인젝션·리다이렉트 추종 등에 노출됩니다.",
                      "외부 데이터도 사용자 입력처럼 검증하고, 웹훅은 서명(HMAC)으로 발신자를 확인하며 TLS·타임아웃·"
                      "리다이렉트 제한을 적용하세요.", cwe="CWE-20"))
    if not (spec.raw.get("info") or {}).get("version"):
        out.append(_f("API9-NO-VERSION-INFO", "명세에 API 버전 정보가 없음", "API9", Severity.INFO, loc,
                      "버전 정보가 없으면 어떤 API가 운영 중인지 추적하기 어렵습니다.",
                      "info.version 을 기재하고 API 자산 목록과 연결해 관리하세요.", cwe="CWE-1059"))
    return out
