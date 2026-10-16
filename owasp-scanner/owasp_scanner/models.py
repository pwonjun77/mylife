"""공통 데이터 모델: 심각도, OWASP Top 10 분류, 점검 결과(Finding)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"알 수 없는 심각도 '{value}' (선택: {choices})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


# OWASP Top 10 (2021)
OWASP_TOP10_2021 = {
    "A01": "Broken Access Control (접근 통제 취약점)",
    "A02": "Cryptographic Failures (암호화 실패)",
    "A03": "Injection (인젝션)",
    "A04": "Insecure Design (안전하지 않은 설계)",
    "A05": "Security Misconfiguration (보안 설정 오류)",
    "A06": "Vulnerable and Outdated Components (취약하고 오래된 구성요소)",
    "A07": "Identification and Authentication Failures (식별 및 인증 실패)",
    "A08": "Software and Data Integrity Failures (소프트웨어 및 데이터 무결성 실패)",
    "A09": "Security Logging and Monitoring Failures (보안 로깅 및 모니터링 실패)",
    "A10": "Server-Side Request Forgery (서버 측 요청 위조)",
}

# OWASP Top 10 (2025) - 현재 최신판
OWASP_TOP10_2025 = {
    "A01": "Broken Access Control (접근 통제 취약점, SSRF 포함)",
    "A02": "Security Misconfiguration (보안 설정 오류)",
    "A03": "Software Supply Chain Failures (소프트웨어 공급망 실패)",
    "A04": "Cryptographic Failures (암호화 실패)",
    "A05": "Injection (인젝션)",
    "A06": "Insecure Design (안전하지 않은 설계)",
    "A07": "Authentication Failures (인증 실패)",
    "A08": "Software or Data Integrity Failures (소프트웨어 및 데이터 무결성 실패)",
    "A09": "Security Logging and Alerting Failures (보안 로깅 및 경보 실패)",
    "A10": "Mishandling of Exceptional Conditions (예외 상황 처리 미흡)",
}

STANDARDS = {"2021": OWASP_TOP10_2021, "2025": OWASP_TOP10_2025}
DEFAULT_STANDARD = "2025"

# 2021 분류 -> 2025 분류 기본 대응표 (규칙별로 owasp2025 를 지정해 덮어쓸 수 있음)
MAP_2021_TO_2025 = {
    "A01": "A01", "A02": "A04", "A03": "A05", "A04": "A06", "A05": "A02",
    "A06": "A03", "A07": "A07", "A08": "A08", "A09": "A09", "A10": "A01",
}

# 하위 호환용 별칭
OWASP_TOP10 = OWASP_TOP10_2021


@dataclass
class Finding:
    rule_id: str
    title: str
    owasp: str
    severity: Severity
    location: str
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: str = ""
    line: int | None = None
    extra: dict = field(default_factory=dict)
    owasp2025: str = ""  # 비어 있으면 MAP_2021_TO_2025 로 계산

    def __post_init__(self):
        if not self.owasp2025:
            self.owasp2025 = MAP_2021_TO_2025.get(self.owasp, self.owasp)

    def category(self, standard: str = DEFAULT_STANDARD) -> str:
        return self.owasp2025 if standard == "2025" else self.owasp

    def category_name(self, standard: str = DEFAULT_STANDARD) -> str:
        code = self.category(standard)
        return STANDARDS[standard].get(code, code)

    @property
    def owasp_name(self) -> str:
        return self.category_name("2021")

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """JSON 리포트의 findings 항목으로부터 복원한다."""
        names = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in names}
        kwargs["severity"] = Severity.parse(kwargs["severity"])
        return cls(**kwargs)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["owasp_name"] = self.owasp_name
        data["owasp2025_name"] = self.category_name("2025")
        return data


def sort_findings(findings: list[Finding], standard: str = DEFAULT_STANDARD) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.category(standard), f.location, f.line or 0))
