"""점검 결과 리포트 생성 (text / json / html)."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from .models import OWASP_TOP10, Finding, Severity, sort_findings

SEVERITY_KO = {
    Severity.CRITICAL: "긴급",
    Severity.HIGH: "높음",
    Severity.MEDIUM: "중간",
    Severity.LOW: "낮음",
    Severity.INFO: "정보",
}
ANSI = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
RESET = "\033[0m"


def summarize(findings: list[Finding]) -> dict:
    sev = Counter(f.severity for f in findings)
    cat = Counter(f.owasp for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s.label: sev.get(s, 0) for s in sorted(Severity, reverse=True)},
        "by_owasp": {k: cat.get(k, 0) for k in OWASP_TOP10},
    }


def render_text(findings: list[Finding], meta: dict, color: bool = False) -> str:
    findings = sort_findings(findings)
    s = summarize(findings)
    out = []
    out.append("=" * 72)
    out.append(f" OWASP Top 10 (2021) 취약점 점검 결과 - {meta.get('mode', '')}")
    out.append("=" * 72)
    out.append(f" 대상     : {meta.get('target')}")
    out.append(f" 점검일시 : {meta.get('started')}")
    if "files_scanned" in meta:
        out.append(f" 점검파일 : {meta['files_scanned']}개")
    for note in meta.get("notes", []):
        out.append(f" 참고     : {note}")
    out.append("-" * 72)
    sev_line = "  ".join(f"{SEVERITY_KO[sv]} {s['by_severity'][sv.label]}" for sv in sorted(Severity, reverse=True))
    out.append(f" 총 {s['total']}건  |  {sev_line}")
    out.append("")
    out.append(" [OWASP 분류별]")
    for code, name in OWASP_TOP10.items():
        n = s["by_owasp"][code]
        bar = "■" * min(n, 30)
        out.append(f"  {code} {name[:48]:<48} {n:>3} {bar}")
    out.append("-" * 72)

    if not findings:
        out.append(" 탐지된 항목이 없습니다. (자동 점검의 한계상 수동 검토를 병행하세요)")
    for i, f in enumerate(findings, 1):
        tag = f"[{SEVERITY_KO[f.severity]}]"
        if color:
            tag = f"{ANSI[f.severity]}{tag}{RESET}"
        loc = f"{f.location}:{f.line}" if f.line else f.location
        out.append(f"\n{i:>3}. {tag} {f.title}")
        out.append(f"     분류 : {f.owasp} {f.owasp_name}" + (f"  /  {f.cwe}" if f.cwe else ""))
        out.append(f"     위치 : {loc}")
        if f.evidence:
            out.append(f"     근거 : {f.evidence}")
        if f.description:
            out.append(f"     설명 : {f.description}")
        if f.recommendation:
            out.append(f"     조치 : {f.recommendation}")
    out.append("")
    out.append("※ 본 결과는 자동화된 패턴/비파괴 점검 결과로 오탐·미탐이 있을 수 있으며,")
    out.append("  A04(안전하지 않은 설계) 등은 설계 검토·모의해킹 등 수동 점검이 필요합니다.")
    return "\n".join(out)


def render_json(findings: list[Finding], meta: dict) -> str:
    findings = sort_findings(findings)
    return json.dumps({
        "meta": meta,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }, ensure_ascii=False, indent=2)


_SEV_COLOR = {
    Severity.CRITICAL: "#7b1fa2",
    Severity.HIGH: "#c62828",
    Severity.MEDIUM: "#ef6c00",
    Severity.LOW: "#0277bd",
    Severity.INFO: "#616161",
}


def render_html(findings: list[Finding], meta: dict) -> str:
    findings = sort_findings(findings)
    s = summarize(findings)
    e = html.escape
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLOR[sv]}"><b>{s["by_severity"][sv.label]}</b>'
        f"<span>{SEVERITY_KO[sv]}</span></div>"
        for sv in sorted(Severity, reverse=True)
    )
    max_cat = max(s["by_owasp"].values()) or 1
    cats = "".join(
        f'<tr><td class="code">{code}</td><td>{e(name)}</td><td class="num">{s["by_owasp"][code]}</td>'
        f'<td><div class="bar" style="width:{s["by_owasp"][code] / max_cat * 100:.0f}%"></div></td></tr>'
        for code, name in OWASP_TOP10.items()
    )
    rows = []
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        rows.append(
            f'<details class="finding"><summary><span class="sev" style="background:{_SEV_COLOR[f.severity]}">'
            f"{SEVERITY_KO[f.severity]}</span><span class=\"code\">{f.owasp}</span> {e(f.title)}"
            f'<span class="loc">{e(loc)}</span></summary>'
            f"<dl><dt>분류</dt><dd>{e(f.owasp_name)} {e(f.cwe)}</dd>"
            f"<dt>규칙</dt><dd>{e(f.rule_id)}</dd>"
            + (f"<dt>근거</dt><dd><code>{e(f.evidence)}</code></dd>" if f.evidence else "")
            + f"<dt>설명</dt><dd>{e(f.description)}</dd><dt>조치</dt><dd>{e(f.recommendation)}</dd></dl></details>"
        )
    notes = "".join(f"<li>{e(n)}</li>" for n in meta.get("notes", []))
    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP 점검 리포트</title>
<style>
:root{{--bg:#f6f7f9;--fg:#1d1d1f;--card:#fff;--muted:#6b6b70;--line:#e4e4e8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16171a;--fg:#ececf0;--card:#202227;--muted:#a0a0a8;--line:#33353b}}}}
body{{font-family:-apple-system,"Segoe UI","Malgun Gothic",sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px}}
main{{max-width:960px;margin:auto}} h1{{font-size:22px;margin:0 0 4px}} .meta{{color:var(--muted);font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:18px 0}}
.card{{background:var(--card);border-radius:10px;padding:12px;display:flex;flex-direction:column;align-items:center}}
.card b{{font-size:26px}} .card span{{color:var(--muted);font-size:13px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;font-size:14px}}
td{{padding:6px 10px;border-bottom:1px solid var(--line)}} .num{{text-align:right;width:40px}}
.bar{{height:8px;background:#5c6bc0;border-radius:4px;min-width:2px}} .code{{font-family:monospace;font-weight:700}}
.finding{{background:var(--card);border-radius:10px;margin:8px 0;padding:10px 14px}}
summary{{cursor:pointer;display:flex;gap:8px;align-items:center;flex-wrap:wrap}}
.sev{{color:#fff;border-radius:6px;padding:2px 8px;font-size:12px}} .loc{{margin-left:auto;color:var(--muted);font-size:12px;word-break:break-all}}
dl{{display:grid;grid-template-columns:60px 1fr;gap:6px 10px;font-size:14px;margin:12px 0 4px}} dt{{color:var(--muted)}} dd{{margin:0;word-break:break-word}}
code{{background:var(--bg);padding:2px 4px;border-radius:4px;font-size:12px}} .foot{{color:var(--muted);font-size:12px;margin-top:20px}}
</style></head><body><main>
<h1>OWASP Top 10 (2021) 취약점 점검 리포트</h1>
<div class="meta">모드: {e(str(meta.get('mode')))} · 대상: {e(str(meta.get('target')))} · 점검일시: {e(str(meta.get('started')))} · 총 {s['total']}건</div>
<ul class="meta">{notes}</ul>
<div class="cards">{cards}</div>
<h2 style="font-size:16px">OWASP 분류별 현황</h2><table>{cats}</table>
<h2 style="font-size:16px">상세 결과</h2>
{''.join(rows) or '<p>탐지된 항목이 없습니다.</p>'}
<p class="foot">자동화된 패턴/비파괴 점검 결과로 오탐·미탐이 있을 수 있습니다. A04(안전하지 않은 설계) 등은 수동 검토가 필요합니다.</p>
</main></body></html>"""


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
