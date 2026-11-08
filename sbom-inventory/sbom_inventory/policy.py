"""버전 정책 점검 — '최소 허용 버전', '금지 소프트웨어', 'EOL' 을 JSON 으로 정의해 인벤토리와 대조.

policy.json 예:
{
  "rules": [
    {"match": "google chrome", "min_version": "131.0.6778.85", "severity": "high", "note": "CVE-2024-xxxx"},
    {"match": "openssh",       "min_version": "9.8", "type": "service", "severity": "critical"},
    {"match": "^anydesk|teamviewer", "regex": true, "forbidden": true, "severity": "medium", "note": "비인가 원격제어"},
    {"match": "windows 10", "type": "os", "eol": "2025-10-14", "severity": "high"}
  ]
}
match 는 기본적으로 정규화된 이름(소문자)에 대한 부분 문자열 비교, regex=true 면 정규식.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .models import version_lt

SEVERITY = ["info", "low", "medium", "high", "critical"]


@dataclass
class Violation:
    severity: str
    asset: str
    name: str
    version: str
    rule: str
    detail: str
    source: str


def load_policy(path: str | Path) -> list[dict]:
    rules = json.loads(Path(path).read_text(encoding="utf-8")).get("rules", [])
    for r in rules:
        if "match" not in r:
            raise ValueError(f"정책 규칙에 match 가 없음: {r}")
        r["_re"] = re.compile(r["match"] if r.get("regex") else re.escape(r["match"].lower()), re.I)
        r.setdefault("severity", "medium")
    return rules


def check(rows, rules: list[dict], today: date | None = None) -> list[Violation]:
    """rows: Store.inventory() 결과."""
    today = today or date.today()
    out: list[Violation] = []
    for row in rows:
        for r in rules:
            if r.get("type") and r["type"] != row["type"]:
                continue
            if not r["_re"].search(row["name_key"]):
                continue
            host = row["hostname"] or (json.loads(row["ips"] or "[]") or [""])[0]
            ver = row["version"] or ""

            def v(detail, _r=r):
                out.append(Violation(_r["severity"], host, row["name"], ver, _r["match"], detail, row["source"]))

            if r.get("forbidden"):
                v("금지 소프트웨어" + (f" — {r['note']}" if r.get("note") else ""))
            if r.get("min_version"):
                if not ver:
                    v(f"버전 확인 불가 (최소 {r['min_version']} 필요) — 수동 확인")
                elif version_lt(ver, r["min_version"]):
                    v(f"최소 버전 {r['min_version']} 미만" + (f" — {r['note']}" if r.get("note") else ""))
            if r.get("max_version") and ver and version_lt(r["max_version"], ver):
                v(f"허용 최대 버전 {r['max_version']} 초과(미검증 버전)")
            if r.get("eol"):
                eol = date.fromisoformat(r["eol"])
                if today >= eol:
                    v(f"지원 종료(EOL {r['eol']})")
    out.sort(key=lambda x: (-SEVERITY.index(x.severity) if x.severity in SEVERITY else 0, x.asset, x.name))
    return out
