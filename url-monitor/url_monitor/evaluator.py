"""측정 결과(ProbeResult)를 정상/경고/장애로 판정하고, 장애면 재시도한다."""

from __future__ import annotations

import time
from datetime import datetime

from .config import parse_status_ranges
from .models import CheckResult, ProbeResult, Status, Target
from .probe import probe


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def evaluate(t: Target, p: ProbeResult) -> tuple[Status, str | None, str]:
    """(상태, 원인 코드, 설명). 장애 조건을 먼저, 그다음 경고 조건을 본다."""
    if p.error_code:
        return Status.DOWN, p.error_code, p.error

    if t.type == "http":
        code = p.http_status or 0
        if not any(lo <= code <= hi for lo, hi in parse_status_ranges(t.expect_status)):
            reason = "HTTP_5XX" if code >= 500 else "HTTP_4XX" if code >= 400 else "UNEXPECTED_STATUS"
            return Status.DOWN, reason, f"HTTP {code} (기대값 {t.expect_status})"
        for word in t.body_contains:
            if word not in p.body:
                return Status.DOWN, "KEYWORD_MISSING", f"본문에 '{word}' 이(가) 없습니다"
        for word in t.body_not_contains:
            if word in p.body:
                return Status.DOWN, "KEYWORD_FOUND", f"본문에 '{word}' 이(가) 있습니다"

    warns = []
    if p.total_ms is not None and p.total_ms > t.warn_response_ms:
        warns.append(("SLOW", f"응답 {p.total_ms:,.0f}ms (기준 {t.warn_response_ms:,.0f}ms 초과)"))
    if p.cert_days_left is not None and p.cert_days_left <= t.cert_warn_days:
        warns.append(("CERT_EXPIRING", f"인증서 만료까지 {p.cert_days_left}일 ({p.cert_not_after})"))
    if warns:
        return Status.WARN, warns[0][0], " / ".join(m for _, m in warns)

    if t.type == "http":
        return Status.UP, None, f"HTTP {p.http_status}"
    return Status.UP, None, "포트 연결 성공"


def check_target(t: Target, sleep=time.sleep) -> CheckResult:
    """점검 1회. 장애로 판정되면 retries 번 다시 확인해 모두 실패해야 장애로 확정한다."""
    attempts = 0
    while True:
        attempts += 1
        p = probe(t)
        status, reason, message = evaluate(t, p)
        if status != Status.DOWN or attempts > t.retries:
            break
        sleep(t.retry_delay_sec)
    return CheckResult(target=t, status=status, reason=reason, message=message, probe=p,
                       checked_at=now_iso(), attempts=attempts)
