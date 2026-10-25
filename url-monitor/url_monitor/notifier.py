"""알림: 상태 전이 판단과 웹훅(Slack / Teams / Google Chat / 일반) · 이메일(SMTP) 발송.

알림은 상태가 바뀔 때만 보낸다(정상→장애, 장애→복구, 정상→경고).
장애가 계속되면 repeat_every_min 분마다 다시 알린다. 한 번의 점검에서 생긴 알림은 한 메시지로 묶는다.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import urlsplit

from .config import in_maintenance
from .models import REASON_KO, CheckResult, Status
from .probe import proxy_for

KIND_KO = {"down": "장애", "still_down": "장애 지속", "recovered": "복구", "warn": "경고"}
KIND_ICON = {"down": "🔴", "still_down": "🔴", "recovered": "🟢", "warn": "🟡"}


@dataclass
class Event:
    kind: str  # down | still_down | recovered | warn
    result: CheckResult
    down_since: str = ""

    def line(self) -> str:
        r = self.result
        reason = REASON_KO.get(r.reason or "", "")
        text = f"{KIND_ICON[self.kind]} [{KIND_KO[self.kind]}] {r.target.key} - "
        if self.kind == "recovered":
            text += f"{r.message}"
            if self.down_since:
                text += f" (장애 지속 {_duration(self.down_since, r.checked_at)})"
        else:
            text += f"{reason + ': ' if reason else ''}{r.message}"
            if self.kind == "still_down" and self.down_since:
                text += f" (지속 {_duration(self.down_since, r.checked_at)})"
        return f"{text}\n    {r.target.display}"


def _duration(start: str, end: str) -> str:
    try:
        sec = int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except ValueError:
        return "?"
    h, rem = divmod(max(sec, 0), 3600)
    m, s = divmod(rem, 60)
    return f"{h}시간 {m}분" if h else f"{m}분 {s}초" if m else f"{s}초"


def decide(prev: dict | None, res: CheckResult, notify_cfg: dict, now: datetime | None = None) -> Event | None:
    """직전 상태(prev: store.state 행 또는 None)와 이번 결과로 보낼 알림을 정한다."""
    now = now or datetime.now().astimezone()
    if res.target.maintenance and in_maintenance(res.target.maintenance, now):
        return None
    cur = res.status
    old = Status[prev["status"]] if prev else None
    notify_warn = notify_cfg.get("notify_warn", True)

    if cur == Status.DOWN:
        if old != Status.DOWN:
            return Event("down", res)
        repeat = float(notify_cfg.get("repeat_every_min", 30) or 0)
        last = prev.get("last_notified_at") if prev else None
        if repeat > 0 and last and (now - datetime.fromisoformat(last)).total_seconds() >= repeat * 60:
            return Event("still_down", res, down_since=prev["since"])
        if repeat > 0 and not last:  # 장애 발생 당시 유지보수 시간 등으로 알림을 못 보낸 경우
            return Event("down", res)
        return None
    if old == Status.DOWN:
        return Event("recovered", res, down_since=prev["since"]) if notify_cfg.get("notify_recovery", True) else None
    if cur == Status.WARN and old != Status.WARN and notify_warn:
        return Event("warn", res)
    return None


def events_without_history(results: list[CheckResult], notify_cfg: dict) -> list[Event]:
    """이력 DB 없이 실행할 때: 장애/경고인 대상을 모두 알린다."""
    return [e for r in results if (e := decide(None, r, notify_cfg))]


def build_message(events: list[Event]) -> tuple[str, str]:
    """(제목, 본문)"""
    counts = {}
    for e in events:
        counts[KIND_KO[e.kind]] = counts.get(KIND_KO[e.kind], 0) + 1
    title = "[URL 모니터] " + " · ".join(f"{k} {v}건" for k, v in counts.items())
    body = "\n".join(e.line() for e in events)
    return title, body


# ---------------------------------------------------------------- 발송

def _opener_for(url: str, setting: str):
    p = urlsplit(url)
    proxy = proxy_for(p.scheme, p.hostname or "", setting)
    handler = urllib.request.ProxyHandler({p.scheme: proxy} if proxy else {})
    return urllib.request.build_opener(handler)


TEAMS_COLOR = {"down": "Attention", "still_down": "Attention", "recovered": "Good", "warn": "Warning"}
TEAMS_MAX_EVENTS = 15  # 카드 크기 제한(약 28KB) 대비


def _fact(title: str, value) -> dict:
    return {"title": title, "value": str(value)}


def teams_card(title: str, body: str, events: list[Event], link: str = "") -> dict:
    """Teams 용 Adaptive Card 메시지.

    Teams 'Workflows'(Power Automate) 웹훅과 기존 수신 웹훅(Incoming Webhook) 모두 이 형식을 받는다.
    """
    kinds = {e.kind for e in events}
    color = ("Attention" if kinds & {"down", "still_down"} else "Warning" if "warn" in kinds
             else "Good" if kinds else "Default")
    items: list[dict] = [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium",
                          "color": color, "wrap": True}]
    for e in events[:TEAMS_MAX_EVENTS]:
        r, p = e.result, e.result.probe
        facts = [_fact("주소", r.target.display), _fact("내용", r.message)]
        if r.reason:
            facts.insert(1, _fact("원인", REASON_KO.get(r.reason, r.reason)))
        if p.total_ms is not None:
            facts.append(_fact("응답", f"{p.total_ms:,.0f}ms"))
        if e.down_since:
            facts.append(_fact("장애 지속", _duration(e.down_since, r.checked_at)))
        facts.append(_fact("점검 시각", r.checked_at.replace("T", " ")[:19]))
        items.append({"type": "Container", "separator": True, "spacing": "Medium", "items": [
            {"type": "TextBlock", "wrap": True, "weight": "Bolder", "color": TEAMS_COLOR[e.kind],
             "text": f"{KIND_ICON[e.kind]} [{KIND_KO[e.kind]}] {r.target.key}"},
            {"type": "FactSet", "facts": facts},
        ]})
    if len(events) > TEAMS_MAX_EVENTS:
        items.append({"type": "TextBlock", "text": f"외 {len(events) - TEAMS_MAX_EVENTS}건", "isSubtle": True})
    if not events and body:
        items.append({"type": "TextBlock", "text": body, "wrap": True})
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "body": items, "msteams": {"width": "Full"}}
    if link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "상태 페이지 열기", "url": link}]
    return {"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def send_webhook(hook: dict, title: str, body: str, events: list[Event], proxy: str = "auto",
                 timeout: float = 10, link: str = "") -> None:
    kind = hook.get("type", "generic")
    text = f"{title}\n{body}"
    if kind == "teams":
        payload = teams_card(title, body, events, link)
    elif kind in ("slack", "googlechat"):
        payload = {"text": text}
    else:
        payload = {"title": title, "text": body,
                   "events": [{"kind": e.kind, **e.result.to_dict()} for e in events]}
    req = urllib.request.Request(hook["url"], data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    with _opener_for(hook["url"], proxy).open(req, timeout=timeout) as resp:
        resp.read()


def send_email(cfg: dict, title: str, body: str, timeout: float = 15) -> None:
    host, _, port = str(cfg["smtp"]).partition(":")
    port_n = int(port or 587)
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = cfg.get("from") or cfg.get("user") or "url-monitor@localhost"
    to = cfg["to"] if isinstance(cfg["to"], list) else [cfg["to"]]
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if port_n == 465:
        smtp = smtplib.SMTP_SSL(host, port_n, timeout=timeout, context=ctx)
    else:
        smtp = smtplib.SMTP(host, port_n, timeout=timeout)
    with smtp:
        if port_n != 465 and cfg.get("starttls", True):
            smtp.starttls(context=ctx)
        if cfg.get("user"):
            smtp.login(cfg["user"], cfg.get("password", ""))
        smtp.send_message(msg)


def send_all(notify_cfg: dict, title: str, body: str, events: list[Event] | None = None, log=None) -> bool:
    """모든 채널로 발송. 하나라도 성공하면 True. 실패는 기록만 하고 점검은 계속한다."""
    log = log or sys.stderr
    events = events or []
    ok = False
    for hook in notify_cfg.get("webhooks") or []:
        try:
            send_webhook(hook, title, body, events, notify_cfg.get("proxy", "auto"),
                         link=notify_cfg.get("status_page_url", ""))
            ok = True
        except Exception as exc:  # 알림 실패가 모니터링 자체를 멈추면 안 됨
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [알림 실패] 웹훅 {urlsplit(hook['url']).hostname}: {exc}",
                  file=log, flush=True)
    if notify_cfg.get("email"):
        try:
            send_email(notify_cfg["email"], title, body)
            ok = True
        except Exception as exc:
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [알림 실패] 이메일: {exc}", file=log, flush=True)
    return ok


def dispatch(events: list[Event], notify_cfg: dict, log=None) -> bool:
    if not events:
        return False
    title, body = build_message(events)
    return send_all(notify_cfg, title, body, events, log)


def summary_text(results: list[CheckResult]) -> str:
    """하트비트·시작 알림용 현재 상태 요약."""
    counts = {s: sum(1 for r in results if r.status == s) for s in Status}
    lines = [f"대상 {len(results)}개 · 정상 {counts[Status.UP]} · 경고 {counts[Status.WARN]} · 장애 {counts[Status.DOWN]}"]
    for r in results:
        if r.status != Status.UP:
            lines.append(f"{KIND_ICON['down' if r.status == Status.DOWN else 'warn']} {r.target.key} - {r.message}")
    return "\n".join(lines)
