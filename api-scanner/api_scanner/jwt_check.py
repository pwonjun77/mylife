"""JWT(JSON Web Token) 오프라인 분석.

토큰을 서버에 보내지 않고 헤더·클레임을 해석하며, HS 계열은 흔한 약한 비밀키로 서명이 맞는지 확인한다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from .models import Finding, Severity

WEAK_SECRETS = [
    "secret", "secret123", "secretkey", "secret-key", "secret_key", "your-256-bit-secret", "your_jwt_secret",
    "jwt_secret", "jwtsecret", "jwt-secret", "changeme", "change-me", "changeit", "password", "password123",
    "123456", "12345678", "admin", "test", "testing", "dev", "development", "key", "private", "default",
    "mysecret", "my-secret", "my_secret", "supersecret", "super-secret", "s3cr3t", "token", "auth", "qwerty",
    "letmein", "example", "hello", "abc123", "", "null", "undefined", "HS256", "jwt", "api", "app", "server",
]
SENSITIVE_CLAIMS = {"password", "passwd", "pwd", "secret", "ssn", "credit_card", "card_number", "cvv",
                    "private_key", "api_key", "jumin", "resident_number"}
MAX_LIFETIME = 24 * 3600


def _b64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def decode(token: str) -> tuple[dict, dict, bytes, bytes]:
    """(header, payload, 서명 대상 바이트, 서명) - JWT 형식이 아니면 ValueError."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT 형식(header.payload.signature)이 아닙니다")
    header = json.loads(_b64(parts[0]))
    payload = json.loads(_b64(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT 헤더/페이로드가 JSON 객체가 아닙니다")
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), _b64(parts[2]) if parts[2] else b""


def find_weak_secret(alg: str, signing_input: bytes, signature: bytes, extra: list[str] | None = None) -> str | None:
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg.upper())
    if not digest or not signature:
        return None
    for secret in WEAK_SECRETS + (extra or []):
        if hmac.compare_digest(hmac.new(secret.encode(), signing_input, digest).digest(), signature):
            return secret
    return None


def analyze(token: str, location: str = "--token", wordlist: list[str] | None = None,
            now: float | None = None) -> list[Finding]:
    try:
        header, payload, signing_input, signature = decode(token)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return []  # 불투명(opaque) 토큰은 분석 대상 아님
    now = time.time() if now is None else now
    out: list[Finding] = []
    alg = str(header.get("alg", ""))

    def add(rule, title, sev, desc, rec, evidence="", cwe="CWE-347"):
        out.append(Finding(rule, title, "API2", sev, location, desc, rec, evidence, cwe))

    if alg.lower() == "none" or not signature:
        add("API2-JWT-ALG-NONE", "서명 없는 JWT (alg=none)", Severity.CRITICAL,
            "서명이 없어 누구나 클레임(사용자 ID, 권한)을 바꾼 토큰을 만들 수 있습니다.",
            "서버에서 허용 알고리즘을 명시적으로 고정(예: RS256/ES256)하고 none 은 거부하세요.", f"alg={alg}")
    secret = find_weak_secret(alg, signing_input, signature, wordlist)
    if secret is not None:
        add("API2-JWT-WEAK-SECRET", "추측 가능한 JWT 서명 키", Severity.CRITICAL,
            "흔히 쓰이는 비밀키로 서명이 검증됩니다. 공격자가 임의의 토큰(관리자 등)을 위조할 수 있습니다.",
            "32바이트 이상의 무작위 키로 교체하고 키를 비밀 저장소에서 관리하세요. 비대칭 키(RS256/ES256)도 고려하세요.",
            f"alg={alg}, secret='{secret[:2]}{'*' * max(len(secret) - 2, 0)}'", "CWE-521")
    if header.get("jku") or header.get("x5u"):
        add("API2-JWT-REMOTE-KEY", "JWT 헤더에 외부 키 URL(jku/x5u) 지정", Severity.MEDIUM,
            "서버가 헤더의 URL에서 검증 키를 가져오면 공격자가 자신의 키로 서명한 토큰을 통과시킬 수 있습니다.",
            "검증 키는 서버 설정의 신뢰된 위치에서만 가져오고 헤더의 jku/x5u/jwk 는 무시하세요.",
            f"jku={header.get('jku') or header.get('x5u')}")
    if header.get("kid") and any(c in str(header["kid"]) for c in ("/", "..", "'", ";", "|")):
        add("API2-JWT-KID-INJECTION", "JWT kid 값에 경로·인젝션 문자 포함", Severity.MEDIUM,
            "kid 로 파일 경로나 DB 를 조회하는 구현이라면 경로 조작·SQL 인젝션에 악용될 수 있습니다.",
            "kid 는 허용 목록과 정확히 일치하는 값만 사용하세요.", f"kid={header['kid']}", "CWE-20")

    exp = payload.get("exp")
    iat = payload.get("iat") or payload.get("nbf")
    if not isinstance(exp, (int, float)):
        add("API2-JWT-NO-EXP", "만료 시간(exp)이 없는 JWT", Severity.HIGH,
            "만료가 없는 토큰은 한 번 유출되면 영구히 사용할 수 있습니다.",
            "액세스 토큰은 짧은 만료(예: 15분~1시간)를 두고 리프레시 토큰으로 갱신하세요.", "exp 없음", "CWE-613")
    else:
        start = iat if isinstance(iat, (int, float)) else now
        lifetime = exp - start
        if lifetime > MAX_LIFETIME:
            add("API2-JWT-LONG-LIVED", "유효 기간이 지나치게 긴 JWT", Severity.MEDIUM,
                f"토큰 유효 기간이 약 {lifetime / 3600:.0f}시간으로, 유출 시 피해 기간이 깁니다.",
                "액세스 토큰 유효 기간을 줄이고 서버 측 폐기(revocation) 수단을 마련하세요.",
                f"exp-iat = {int(lifetime)}초", "CWE-613")
        if exp < now:
            out.append(Finding("API2-JWT-EXPIRED", "제공한 JWT가 이미 만료됨", "API2", Severity.INFO, location,
                               "만료된 토큰으로는 인증이 필요한 점검 결과가 부정확할 수 있습니다. 서버가 이 토큰을 "
                               "받아들인다면 만료 검증 누락입니다(live 점검에서 확인).",
                               "유효한 토큰으로 다시 점검하세요.", f"exp={int(exp)}", "CWE-613"))
    leaked = sorted(k for k in payload if k.lower() in SENSITIVE_CLAIMS)
    if leaked:
        add("API2-JWT-SENSITIVE-CLAIM", "JWT 페이로드에 민감 정보 포함", Severity.HIGH,
            "JWT 페이로드는 암호화되지 않은 Base64 이므로 누구나 내용을 읽을 수 있습니다.",
            "민감 정보는 토큰에 넣지 말고 서버에서 조회하세요(필요 시 JWE 사용).", ", ".join(leaked), "CWE-312")
    return out


def forge_none(token: str) -> str | None:
    """같은 클레임으로 alg=none 토큰을 만든다 (서버가 none 을 허용하는지 확인용)."""
    try:
        header, payload, _, _ = decode(token)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    header = {**header, "alg": "none"}
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc(header)}.{enc(payload)}."
