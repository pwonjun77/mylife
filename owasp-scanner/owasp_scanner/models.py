"""공통 데이터 모델: 심각도, OWASP Top 10 분류, 점검 결과(Finding)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
OWASP_TOP10 = {
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

    @property
    def owasp_name(self) -> str:
        return OWASP_TOP10.get(self.owasp, self.owasp)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["owasp_name"] = self.owasp_name
        return data


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.owasp, f.location, f.line or 0))
