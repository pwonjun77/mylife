"""리포트 생성: 점검 결과(text / json / html), 상태 페이지, 가용률 보고서."""

from __future__ import annotations

import html
import json
import unicodedata
from collections import Counter

from .models import REASON_KO, CheckResult, Status

ANSI = {Status.UP: "\033[32m", Status.WARN: "\033[33m", Status.DOWN: "\033[1;31m"}
RESET = "\033[0m"


def _width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def _cut(s: str, n: int) -> str:
    out, w = "", 0
    for c in s:
        cw = _width(c)
        if w + cw > n - 1 and _width(s) > n:
            return out + "…"
        out, w = out + c, w + cw
    return out


def _pad(s: str, n: int, right: bool = False) -> str:
    s = _cut(s, n)
    gap = " " * max(0, n - _width(s))
    return gap + s if right else s + gap


def _num(v, unit: str = "") -> str:
    return "-" if v is None else f"{v:,.0f}{unit}"


def sort_results(results: list[CheckResult]) -> list[CheckResult]:
    """장애 → 경고 → 정상, 같은 상태는 등록 순서."""
    order = {id(r): i for i, r in enumerate(results)}
    return sorted(results, key=lambda r: (-r.status, order[id(r)]))


def summarize(results: list[CheckResult]) -> dict:
    c = Counter(r.status for r in results)
    return {"total": len(results), "up": c[Status.UP], "warn": c[Status.WARN], "down": c[Status.DOWN],
            "worst": max((r.status for r in results), default=Status.UP).label}


def _reason_text(r: CheckResult) -> str:
    if r.status == Status.UP:
        return ""
    return f"{REASON_KO.get(r.reason or '', r.reason or '')} - {r.message}"


# ---------------------------------------------------------------- text

def render_text(results: list[CheckResult], meta: dict, color: bool = False) -> str:
    s = summarize(results)
    out = [f"[{meta.get('started', '')}] 전체 {s['total']}건 · 정상 {s['up']} · 경고 {s['warn']} · 장애 {s['down']}"
           f"  (소요 {meta.get('elapsed', 0):.1f}초)", ""]
    cols = [("상태", 5), ("그룹", 12), ("이름", 16), ("코드", 5), ("응답(ms)", 9), ("인증서", 7), ("원인", 0)]
    out.append("  ".join(_pad(n, w) if w else n for n, w in cols))
    out.append("-" * 96)
    for r in sort_results(results):
        p = r.probe
        cert = "-" if p.cert_days_left is None else f"{p.cert_days_left}일"
        status = _pad(r.status.label, 5)
        if color:
            status = f"{ANSI[r.status]}{status}{RESET}"
        row = [status, _pad(r.target.group, 12), _pad(r.target.name, 16),
               _pad(str(p.http_status or ("-" if r.target.type == "http" else "TCP")), 5, right=True),
               _pad(_num(p.total_ms), 9, right=True), _pad(cert, 7, right=True), _reason_text(r)]
        out.append("  ".join(row).rstrip())
    out.append("")
    if any(r.probe.via_proxy for r in results):
        out.append("참고: 일부 대상은 프록시를 거쳐 점검했습니다(연결 시간은 프록시 기준).")
    return "\n".join(out)


def render_json(results: list[CheckResult], meta: dict) -> str:
    return json.dumps({"meta": meta, "summary": summarize(results), "results": [r.to_dict() for r in results]},
                      ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e6ea;
--up:#1a7f37;--up-bg:#dafbe1;--warn:#9a6700;--warn-bg:#fff4c5;--down:#cf222e;--down-bg:#ffe1e1}
@media (prefers-color-scheme: dark){:root{--bg:#0f1115;--card:#171a20;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2a2f37;
--up:#4ac26b;--up-bg:#12301c;--warn:#d4a72c;--warn-bg:#3a2e0a;--down:#ff7b72;--down-bg:#3d1214}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Malgun Gothic","Apple SD Gothic Neo",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--muted);margin-bottom:16px}.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted)}
.tile.up b{color:var(--up)}.tile.warn b{color:var(--warn)}.tile.down b{color:var(--down)}
.banner{border-radius:10px;padding:12px 14px;margin-bottom:16px;font-weight:600}
.banner.UP{background:var(--up-bg);color:var(--up)}.banner.WARN{background:var(--warn-bg);color:var(--warn)}
.banner.DOWN{background:var(--down-bg);color:var(--down)}
h2{font-size:16px;margin:20px 0 8px}.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:820px;word-break:keep-all}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.badge{display:inline-block;white-space:nowrap;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:700}
.badge.UP{background:var(--up-bg);color:var(--up)}.badge.WARN{background:var(--warn-bg);color:var(--warn)}
.badge.DOWN{background:var(--down-bg);color:var(--down)}.url{color:var(--muted);font-size:12px;word-break:break-all}td.g{white-space:nowrap}
.small{color:var(--muted);font-size:12px}
@media (max-width:640px){.tiles{grid-template-columns:repeat(2,1fr)}}
"""

BANNER = {Status.UP: "모든 시스템이 정상입니다", Status.WARN: "일부 시스템에 경고가 있습니다",
          Status.DOWN: "접속 장애가 있는 시스템이 있습니다"}


def _e(v) -> str:
    return html.escape("" if v is None else str(v))


def _page(title: str, body: str, refresh: int = 0) -> str:
    meta_refresh = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return (f'<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">{meta_refresh}'
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>")


def _tiles(s: dict) -> str:
    return (f'<div class="tiles"><div class="tile"><b>{s["total"]}</b><span>전체</span></div>'
            f'<div class="tile up"><b>{s["up"]}</b><span>정상</span></div>'
            f'<div class="tile warn"><b>{s["warn"]}</b><span>경고</span></div>'
            f'<div class="tile down"><b>{s["down"]}</b><span>장애</span></div></div>')


def _timing(p) -> str:
    parts = [("DNS", p.dns_ms), ("연결", p.connect_ms), ("TLS", p.tls_ms), ("첫 응답", p.ttfb_ms)]
    text = " · ".join(f"{k} {v:,.0f}" for k, v in parts if v is not None)
    return text + (" (프록시 경유)" if p.via_proxy else "")


def render_html(results: list[CheckResult], meta: dict, availability: dict | None = None,
                title: str = "URL 접속 점검 결과", refresh: int = 0) -> str:
    """availability: {대상키: 가용률 행} (상태 페이지에서 24시간 가용률 표시용)"""
    s = summarize(results)
    worst = Status[s["worst"]]
    rows = []
    for r in sort_results(results):
        p = r.probe
        cert = "-" if p.cert_days_left is None else f"{p.cert_days_left}일"
        avail = ""
        if availability is not None:
            a = availability.get(r.target.key)
            pct = "-" if not a or a["availability"] is None else f"{a['availability']:.2f}%"
            avail = f'<td class="n">{pct}</td>'
        detail = _e(_reason_text(r)) if r.status != Status.UP else _e(r.message)
        if r.probe.redirects:
            detail += f'<div class="small">리다이렉트 {p.redirects}회 → {_e(p.final_url)}</div>'
        rows.append(
            f'<tr><td><span class="badge {r.status.label}">{r.status.ko}</span></td>'
            f'<td class="g">{_e(r.target.group)}</td><td>{_e(r.target.name)}'
            f'<div class="url">{_e(r.target.display)}</div></td>'
            f'<td class="n">{_e(p.http_status or ("-" if r.target.type == "http" else "TCP"))}</td><td class="n">{_num(p.total_ms)}</td>'
            f'<td class="small">{_e(_timing(p))}</td><td class="n">{cert}</td>{avail}<td>{detail}</td></tr>'
        )
    avail_th = "<th>가용률(24h)</th>" if availability is not None else ""
    body = (f"<h1>{_e(title)}</h1><div class=\"meta\">점검 시각 {_e(meta.get('started'))}"
            f" · 소요 {meta.get('elapsed', 0):.1f}초 · 설정 {_e(meta.get('source', '-'))}</div>"
            f'<div class="banner {worst.label}">{BANNER[worst]}</div>{_tiles(s)}'
            f'<div class="wrap"><table><thead><tr><th>상태</th><th>그룹</th><th>이름</th><th>코드</th>'
            f"<th>응답(ms)</th><th>단계별(ms)</th><th>인증서</th>{avail_th}<th>내용</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")
    return _page(title, body, refresh)


# ---------------------------------------------------------------- 가용률 보고서

def render_history_text(rows: list[dict], incidents: list[dict], meta: dict) -> str:
    out = [f"가용률 보고서 - 최근 {meta['since']} (생성 {meta['generated']})", ""]
    out.append("  ".join([_pad("대상", 30), _pad("가용률", 9, True), _pad("점검", 6, True), _pad("장애", 5, True),
                          _pad("평균ms", 8, True), _pad("최대ms", 8, True), "현재"]))
    out.append("-" * 90)
    for r in rows:
        out.append("  ".join([_pad(r["target"], 30), _pad(f"{r['availability']:.2f}%", 9, True),
                              _pad(str(r["total"]), 6, True), _pad(str(r["incidents"]), 5, True),
                              _pad(_num(r["avg_ms"]), 8, True), _pad(_num(r["max_ms"]), 8, True),
                              r["current"] or "-"]))
    if incidents:
        out += ["", "장애 이력"]
        for i in incidents:
            end = i["ended_at"] or "진행 중"
            out.append(f"  {i['started_at']} ~ {end}  {i['target']}  {REASON_KO.get(i['reason'] or '', i['reason'])}")
    return "\n".join(out)


def _badge(status: str | None) -> str:
    return f'<span class="badge {status}">{Status[status].ko}</span>' if status else "-"


def render_history_html(rows: list[dict], incidents: list[dict], meta: dict) -> str:
    trs = "".join(
        f"<tr><td>{_e(r['target'])}</td><td class=\"n\">{r['availability']:.2f}%</td><td class=\"n\">{r['total']}</td>"
        f"<td class=\"n\">{r['incidents']}</td><td class=\"n\">{_num(r['avg_ms'])}</td><td class=\"n\">{_num(r['max_ms'])}</td>"
        f"<td>{_badge(r['current'])}</td></tr>"
        for r in rows
    )
    inc = "".join(
        f"<tr><td>{_e(i['target'])}</td><td>{_e(i['started_at'])}</td><td>{_e(i['ended_at'] or '진행 중')}</td>"
        f"<td>{_e(REASON_KO.get(i['reason'] or '', i['reason']))}</td><td>{_e(i['message'])}</td></tr>"
        for i in incidents
    ) or '<tr><td colspan="5">기간 내 장애가 없습니다</td></tr>'
    body = (f"<h1>가용률 보고서</h1><div class=\"meta\">최근 {_e(meta['since'])} · 생성 {_e(meta['generated'])}</div>"
            f'<div class="wrap"><table><thead><tr><th>대상</th><th>가용률</th><th>점검</th><th>장애</th><th>평균ms</th>'
            f"<th>최대ms</th><th>현재</th></tr></thead><tbody>{trs}</tbody></table></div>"
            f'<h2>장애 이력</h2><div class="wrap"><table><thead><tr><th>대상</th><th>시작</th><th>종료</th><th>원인</th>'
            f"<th>내용</th></tr></thead><tbody>{inc}</tbody></table></div>")
    return _page("가용률 보고서", body)
