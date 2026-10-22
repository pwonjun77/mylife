"""공통 데이터 모델: 심각도, OWASP API Security Top 10 분류, 점검 결과(Finding)."""

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


# OWASP API Security Top 10 (2023) - 현재 최신판
API_TOP10_2023 = {
    "API1": "Broken Object Level Authorization (객체 수준 권한 검증 실패, BOLA)",
    "API2": "Broken Authentication (인증 취약점)",
    "API3": "Broken Object Property Level Authorization (객체 속성 수준 권한 검증 실패)",
    "API4": "Unrestricted Resource Consumption (자원 소비 제한 없음)",
    "API5": "Broken Function Level Authorization (기능 수준 권한 검증 실패, BFLA)",
    "API6": "Unrestricted Access to Sensitive Business Flows (민감한 업무 흐름 무제한 접근)",
    "API7": "Server Side Request Forgery (서버 측 요청 위조, SSRF)",
    "API8": "Security Misconfiguration (보안 설정 오류)",
    "API9": "Improper Inventory Management (부적절한 API 자산 관리)",
    "API10": "Unsafe Consumption of APIs (안전하지 않은 외부 API 사용)",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # API1 ~ API10
    severity: Severity
    location: str  # 예: "GET /users/{id}" 또는 URL
    description: str = ""
    recommendation: str = ""
    evidence: str = ""
    cwe: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def category_name(self) -> str:
        return API_TOP10_2023.get(self.category, self.category)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        names = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in names}
        kwargs["severity"] = Severity.parse(kwargs["severity"])
        return cls(**kwargs)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["category_name"] = self.category_name
        return data


def _cat_order(code: str) -> int:
    return int(code[3:]) if code[3:].isdigit() else 99


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, _cat_order(f.category), f.location, f.rule_id))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """같은 규칙·위치의 중복 결과를 제거한다(먼저 나온 것을 유지)."""
    seen: set[tuple[str, str, str]] = set()
    result = []
    for f in findings:
        key = (f.rule_id, f.location, f.evidence)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
