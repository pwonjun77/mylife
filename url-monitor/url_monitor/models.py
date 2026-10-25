"""공통 데이터 모델: 상태(Status), 점검 대상(Target), 측정 결과(ProbeResult), 판정 결과(CheckResult)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Status(IntEnum):
    """값이 클수록 나쁜 상태. 전체 결과의 최댓값이 곧 종료코드(0/1/2)가 된다."""

    UP = 0
    WARN = 1
    DOWN = 2

    @property
    def label(self) -> str:
        return self.name

    @property
    def ko(self) -> str:
        return {Status.UP: "정상", Status.WARN: "경고", Status.DOWN: "장애"}[self]


# 원인 코드 -> 한국어 설명
REASON_KO = {
    "DNS_FAIL": "DNS 조회 실패",
    "CONN_REFUSED": "연결 거부 (포트 닫힘/서비스 중지)",
    "CONN_TIMEOUT": "연결 시간 초과",
    "CONN_ERROR": "연결 오류",
    "PROXY_ERROR": "프록시 연결 실패",
    "TLS_TIMEOUT": "TLS 핸드셰이크 시간 초과",
    "TLS_ERROR": "TLS 핸드셰이크 실패",
    "CERT_EXPIRED": "인증서 만료",
    "CERT_HOSTNAME": "인증서 호스트명 불일치",
    "CERT_INVALID": "신뢰할 수 없는 인증서",
    "HTTP_TIMEOUT": "응답 시간 초과",
    "HTTP_ERROR": "HTTP 통신 오류",
    "HTTP_5XX": "서버 오류 응답 (5xx)",
    "HTTP_4XX": "클라이언트 오류 응답 (4xx)",
    "UNEXPECTED_STATUS": "기대하지 않은 상태코드",
    "TOO_MANY_REDIRECTS": "리다이렉트 과다",
    "KEYWORD_MISSING": "필수 문구 없음",
    "KEYWORD_FOUND": "금지 문구 발견",
    "SLOW": "응답 지연",
    "CERT_EXPIRING": "인증서 만료 임박",
}


@dataclass
class Target:
    """점검 대상 1건. 기본값은 config.DEFAULTS 와 같다."""

    name: str
    group: str = "기본"
    type: str = "http"  # http | tcp
    url: str = ""
    host: str = ""
    port: int = 0
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    expect_status: str = "200-399"
    body_contains: list = field(default_factory=list)
    body_not_contains: list = field(default_factory=list)
    warn_response_ms: float = 2000
    timeout_sec: float = 10
    retries: int = 2
    retry_delay_sec: float = 3
    cert_warn_days: int = 14
    verify_tls: bool = True
    ca_file: str = ""
    follow_redirects: bool = True
    max_redirects: int = 5
    interval_sec: float = 60
    proxy: str = "auto"  # auto | none | http://프록시주소:포트
    maintenance: list = field(default_factory=list)
    enabled: bool = True

    @property
    def key(self) -> str:
        return f"{self.group}/{self.name}"

    @property
    def display(self) -> str:
        return self.url if self.type == "http" else f"tcp://{self.host}:{self.port}"


@dataclass
class ProbeResult:
    """단계별 측정값. 실패하면 error_code 가 채워지고 이후 단계 값은 None."""

    error_code: str | None = None
    error: str = ""
    http_status: int | None = None
    final_url: str = ""
    redirects: int = 0
    remote_ip: str = ""
    via_proxy: bool = False
    dns_ms: float | None = None
    connect_ms: float | None = None
    tls_ms: float | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    cert_days_left: int | None = None
    cert_not_after: str = ""
    cert_issuer: str = ""
    body: str = field(default="", repr=False)


@dataclass
class CheckResult:
    target: Target
    status: Status
    reason: str | None
    message: str
    probe: ProbeResult
    checked_at: str
    attempts: int = 1

    def to_dict(self) -> dict:
        p = asdict(self.probe)
        p.pop("body", None)
        return {
            "key": self.target.key,
            "group": self.target.group,
            "name": self.target.name,
            "target": self.target.display,
            "status": self.status.label,
            "reason": self.reason,
            "message": self.message,
            "checked_at": self.checked_at,
            "attempts": self.attempts,
            **p,
        }
