"""SQLite 이력 저장: 점검 결과(checks), 장애 구간(incidents), 대상별 현재 상태(state).

state 테이블 덕분에 cron 으로 매번 새로 실행해도 '직전 상태'를 알 수 있어
상태가 바뀔 때만 알림을 보낼 수 있다.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from .models import CheckResult, Status

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  ts TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT,
  message TEXT,
  http_status INTEGER,
  dns_ms REAL, connect_ms REAL, tls_ms REAL, ttfb_ms REAL, total_ms REAL,
  cert_days_left INTEGER
);
CREATE INDEX IF NOT EXISTS idx_checks_target_ts ON checks(target, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  reason TEXT,
  message TEXT
);
CREATE TABLE IF NOT EXISTS state (
  target TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  since TEXT NOT NULL,
  last_notified_at TEXT
);
"""


def parse_since(spec: str) -> timedelta:
    """"24h", "7d", "30m" -> timedelta"""
    s = spec.strip().lower()
    units = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if len(s) < 2 or s[-1] not in units or not s[:-1].isdigit():
        raise ValueError(f"기간 형식 오류 '{spec}' (예: 30m, 24h, 7d, 4w)")
    return timedelta(**{units[s[-1]]: int(s[:-1])})


class Store:
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def get_state(self, key: str) -> dict | None:
        row = self.db.execute("SELECT * FROM state WHERE target=?", (key,)).fetchone()
        return dict(row) if row else None

    def record(self, res: CheckResult) -> dict | None:
        """결과를 저장하고 갱신 전의 state(없으면 None)를 돌려준다."""
        p = res.probe
        key = res.target.key
        prev = self.get_state(key)
        with self.db:
            self.db.execute(
                "INSERT INTO checks (target, ts, status, reason, message, http_status, dns_ms, connect_ms,"
                " tls_ms, ttfb_ms, total_ms, cert_days_left) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, res.checked_at, res.status.label, res.reason, res.message, p.http_status, p.dns_ms,
                 p.connect_ms, p.tls_ms, p.ttfb_ms, p.total_ms, p.cert_days_left),
            )
            was_down = prev is not None and prev["status"] == Status.DOWN.label
            if res.status == Status.DOWN and not was_down:
                self.db.execute("INSERT INTO incidents (target, started_at, reason, message) VALUES (?,?,?,?)",
                                (key, res.checked_at, res.reason, res.message))
            elif res.status != Status.DOWN and was_down:
                self.db.execute("UPDATE incidents SET ended_at=? WHERE target=? AND ended_at IS NULL",
                                (res.checked_at, key))
            if prev is None:
                self.db.execute("INSERT INTO state (target, status, since) VALUES (?,?,?)",
                                (key, res.status.label, res.checked_at))
            elif prev["status"] != res.status.label:
                self.db.execute("UPDATE state SET status=?, since=? WHERE target=?",
                                (res.status.label, res.checked_at, key))
        return prev

    def mark_notified(self, key: str, when: str) -> None:
        with self.db:
            self.db.execute("UPDATE state SET last_notified_at=? WHERE target=?", (when, key))

    def purge(self, retention_days: int) -> int:
        cutoff = (datetime.now().astimezone() - timedelta(days=retention_days)).isoformat(timespec="seconds")
        with self.db:
            n = self.db.execute("DELETE FROM checks WHERE ts < ?", (cutoff,)).rowcount
            self.db.execute("DELETE FROM incidents WHERE ended_at IS NOT NULL AND ended_at < ?", (cutoff,))
        return n

    def availability(self, since: timedelta, keys: list[str] | None = None) -> list[dict]:
        """기간 내 대상별 가용률·평균 응답시간·장애 횟수·현재 상태."""
        cutoff = (datetime.now().astimezone() - since).isoformat(timespec="seconds")
        rows = self.db.execute(
            "SELECT target, COUNT(*) AS total,"
            " SUM(status='UP') AS up, SUM(status='WARN') AS warn, SUM(status='DOWN') AS down,"
            " AVG(total_ms) AS avg_ms, MAX(total_ms) AS max_ms, MAX(ts) AS last_ts"
            " FROM checks WHERE ts >= ? GROUP BY target ORDER BY target",
            (cutoff,),
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            if keys is not None and d["target"] not in keys:
                continue
            d["availability"] = round((d["up"] + d["warn"]) * 100 / d["total"], 3) if d["total"] else None
            d["incidents"] = self.db.execute(
                "SELECT COUNT(*) FROM incidents WHERE target=? AND (ended_at IS NULL OR ended_at >= ?)",
                (d["target"], cutoff),
            ).fetchone()[0]
            st = self.get_state(d["target"])
            d["current"] = st["status"] if st else None
            d["since"] = st["since"] if st else None
            out.append(d)
        return out

    def incidents(self, since: timedelta) -> list[dict]:
        cutoff = (datetime.now().astimezone() - since).isoformat(timespec="seconds")
        rows = self.db.execute(
            "SELECT * FROM incidents WHERE ended_at IS NULL OR ended_at >= ? ORDER BY started_at DESC", (cutoff,)
        ).fetchall()
        return [dict(r) for r in rows]
