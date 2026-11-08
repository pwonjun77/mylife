"""SQLite 저장소 — 자산 병합(correlation) + 실행(run) 단위 스냅샷 = 버전 이력.

스키마
  runs(id, started_at, finished_at, note)
  assets(id, hostname, fqdn, serial, macs, ips, os, os_version, first_seen, last_seen, sources, extra)
  observations(run_id, asset_id, source, name, name_key, version, vendor, type, purl, cpe, props)

핵심 아이디어
  * 매 수집은 새 run 을 만들고 '그 시점에 관측된 것'을 전부 observations 에 적재한다 (불변, append-only).
    → 어떤 시점이든 재구성 가능, run 간 비교로 '설치/삭제/버전 변경' 이력이 자동으로 나온다.
    → 포렌식 관점: 특정 날짜에 어떤 PC 에 어떤 버전이 있었는지 증명할 수 있는 타임라인.
  * 자산 병합 우선순위: serial > MAC > hostname > IP(다른 식별자가 전혀 없을 때만)
    Intune(serial, MAC, 이름) ↔ 에이전트(serial, MAC, 이름, IP) ↔ Defender(이름, IP, MAC) ↔ Nmap(IP, PTR명, MAC)
    서로 다른 출처가 공통 식별자를 하나라도 공유하면 같은 자산으로 묶인다.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Asset, HostRecord, norm_name

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT, note TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT DEFAULT '', fqdn TEXT DEFAULT '', serial TEXT DEFAULT '',
  macs TEXT DEFAULT '[]', ips TEXT DEFAULT '[]', os TEXT DEFAULT '', os_version TEXT DEFAULT '',
  first_seen TEXT, last_seen TEXT, sources TEXT DEFAULT '[]', extra TEXT DEFAULT '{}');
CREATE INDEX IF NOT EXISTS ix_assets_host ON assets(hostname);
CREATE INDEX IF NOT EXISTS ix_assets_serial ON assets(serial);
CREATE TABLE IF NOT EXISTS observations(
  run_id INTEGER NOT NULL REFERENCES runs(id), asset_id INTEGER NOT NULL REFERENCES assets(id),
  source TEXT NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL, version TEXT DEFAULT '',
  vendor TEXT DEFAULT '', type TEXT DEFAULT 'application', purl TEXT DEFAULT '', cpe TEXT DEFAULT '',
  props TEXT DEFAULT '{}');
CREATE INDEX IF NOT EXISTS ix_obs_run ON observations(run_id, asset_id);
CREATE INDEX IF NOT EXISTS ix_obs_key ON observations(name_key);
-- 출처별 '마지막으로 관측된 run' (현재 인벤토리 계산용)
CREATE TABLE IF NOT EXISTS asset_source_runs(
  asset_id INTEGER NOT NULL, source TEXT NOT NULL, run_id INTEGER NOT NULL, PRIMARY KEY(asset_id, source, run_id));
"""


def asset_label(row) -> str:
    ips = json.loads(row["ips"] or "[]")
    return row["hostname"] or (ips[0] if ips else "") or row["serial"] or f"asset#{row['id']}"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Change:
    asset: str
    name: str
    kind: str          # added | removed | changed
    old: str = ""
    new: str = ""
    source: str = ""


class Store:
    def __init__(self, path: str | Path = "inventory.db"):
        new = not Path(path).exists()
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        if new and str(path) != ":memory:":
            try:  # 인벤토리는 공격자에게 '취약 버전 지도'가 되므로 소유자만 읽게 한다
                os.chmod(path, 0o600)
            except OSError:
                pass

    # ------------------------------------------------------------ runs
    def begin_run(self, note: str = "") -> int:
        cur = self.db.execute("INSERT INTO runs(started_at, note) VALUES(?, ?)", (utcnow(), note))
        self.db.commit()
        return int(cur.lastrowid)

    def end_run(self, run_id: int) -> None:
        self.db.execute("UPDATE runs SET finished_at=? WHERE id=?", (utcnow(), run_id))
        self.db.commit()

    def runs(self) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT r.*, (SELECT group_concat(DISTINCT source) FROM observations o WHERE o.run_id=r.id) AS sources,"
            " (SELECT count(DISTINCT asset_id) FROM asset_source_runs s WHERE s.run_id=r.id) AS assets,"
            " (SELECT count(*) FROM observations o WHERE o.run_id=r.id) AS obs FROM runs r ORDER BY r.id"))

    def latest_run_id(self, offset: int = 0) -> int | None:
        row = self.db.execute("SELECT id FROM runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1 OFFSET ?",
                              (offset,)).fetchone()
        return row["id"] if row else None

    # ------------------------------------------------------------ correlation
    def _find_asset(self, a: Asset) -> int | None:
        if a.serial:
            r = self.db.execute("SELECT id FROM assets WHERE serial=?", (a.serial,)).fetchone()
            if r:
                return r["id"]
        for mac in a.macs:
            r = self.db.execute("SELECT id FROM assets WHERE macs LIKE ?", (f'%"{mac}"%',)).fetchone()
            if r:
                return r["id"]
        if a.hostname:
            r = self.db.execute("SELECT id FROM assets WHERE hostname=?", (a.hostname,)).fetchone()
            if r:
                return r["id"]
        if not (a.serial or a.macs or a.hostname):
            # IP 만 있는 레코드(PTR 없는 nmap 결과): IP 만 가진 기존 자산 또는 IP 가 일치하는 자산과 병합
            for ip in a.ips:
                r = self.db.execute("SELECT id FROM assets WHERE ips LIKE ? ORDER BY last_seen DESC",
                                    (f'%"{ip}"%',)).fetchone()
                if r:
                    return r["id"]
        return None

    def upsert_asset(self, rec: HostRecord) -> int:
        a = rec.asset.normalized()
        now = utcnow()
        aid = self._find_asset(a)
        if aid is None:
            cur = self.db.execute(
                "INSERT INTO assets(hostname,fqdn,serial,macs,ips,os,os_version,first_seen,last_seen,sources,extra)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (a.hostname, a.fqdn, a.serial, json.dumps(a.macs), json.dumps(a.ips), a.os, a.os_version,
                 now, now, json.dumps([rec.source]), json.dumps({rec.source: a.extra}, default=str)))
            return int(cur.lastrowid)
        row = self.db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
        macs = sorted(set(json.loads(row["macs"])) | set(a.macs))
        # IP 는 DHCP 로 바뀌므로 '최근 관측값'으로 교체하되, 이번 레코드에 IP 가 없으면 유지
        ips = a.ips or json.loads(row["ips"])
        sources = sorted(set(json.loads(row["sources"])) | {rec.source})
        extra = json.loads(row["extra"] or "{}")
        extra[rec.source] = a.extra
        # OS 정보 신뢰도: agent/intune/defender > nmap 추정
        os_name, os_ver = row["os"], row["os_version"]
        if a.os and (rec.source != "nmap" or not os_name):
            os_name, os_ver = a.os, a.os_version or os_ver
        self.db.execute(
            "UPDATE assets SET hostname=?, fqdn=?, serial=?, macs=?, ips=?, os=?, os_version=?, last_seen=?,"
            " sources=?, extra=? WHERE id=?",
            (row["hostname"] or a.hostname, a.fqdn or row["fqdn"], row["serial"] or a.serial, json.dumps(macs),
             json.dumps(ips), os_name, os_ver, now, json.dumps(sources), json.dumps(extra, default=str), aid))
        return aid

    def ingest(self, run_id: int, records: list[HostRecord]) -> int:
        n = 0
        for rec in records:
            aid = self.upsert_asset(rec)
            self.db.execute("INSERT OR IGNORE INTO asset_source_runs VALUES(?,?,?)", (aid, rec.source, run_id))
            seen = set()
            for c in rec.components:
                k = (c.key, c.version, c.type, c.props.get("port", ""))
                if not c.name or k in seen:
                    continue
                seen.add(k)
                self.db.execute(
                    "INSERT INTO observations(run_id,asset_id,source,name,name_key,version,vendor,type,purl,cpe,props)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, aid, rec.source, c.name, norm_name(c.name), c.version, c.vendor, c.type, c.purl, c.cpe,
                     json.dumps(c.props, ensure_ascii=False, default=str)))
                n += 1
        self.db.commit()
        return n

    # ------------------------------------------------------------ queries
    def assets(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM assets ORDER BY hostname, id"))

    def asset(self, ref: str) -> sqlite3.Row | None:
        if ref.isdigit():
            return self.db.execute("SELECT * FROM assets WHERE id=?", (int(ref),)).fetchone()
        return self.db.execute("SELECT * FROM assets WHERE hostname=? OR serial=? OR ips LIKE ?",
                               (ref.lower().split(".")[0], ref.upper(), f'%"{ref}"%')).fetchone()

    def inventory(self, run_id: int | None = None, asset_id: int | None = None) -> list[sqlite3.Row]:
        """run_id 시점의 인벤토리. 출처마다 그 시점까지 '가장 최근 관측' run 의 결과를 사용한다.

        (예: nmap 은 매일, 에이전트는 주 1회 수집해도 둘 다 반영된 '현재 상태'가 나온다.)
        """
        run_id = run_id or self.latest_run_id() or 0
        q = """
        WITH last AS (
          SELECT asset_id, source, max(run_id) AS run_id FROM asset_source_runs WHERE run_id <= ?
          GROUP BY asset_id, source)
        SELECT o.*, a.hostname, a.ips, a.serial FROM observations o
          JOIN last l ON o.asset_id=l.asset_id AND o.source=l.source AND o.run_id=l.run_id
          JOIN assets a ON a.id=o.asset_id
        """
        args: list = [run_id]
        if asset_id is not None:
            q += " WHERE o.asset_id=?"
            args.append(asset_id)
        return list(self.db.execute(q + " ORDER BY a.hostname, o.name_key", args))

    def diff(self, old_run: int, new_run: int) -> list[Change]:
        """두 시점의 인벤토리 비교. 양쪽 시점 모두에 관측된 (자산, 출처) 조합만 비교해
        '이번에 그 출처로 수집되지 않은 자산'이 대량 삭제로 보이는 오탐을 막는다."""
        def snap(run):
            d: dict[tuple, set] = {}
            for r in self.inventory(run):
                if r["type"] == "service":   # 서비스는 포트 단위로 구분
                    key = (r["asset_id"], r["source"], r["name_key"] + "@" + json.loads(r["props"]).get("port", ""))
                else:
                    key = (r["asset_id"], r["source"], r["name_key"])
                d.setdefault(key, set()).add(r["version"])
            return d
        a, b = snap(old_run), snap(new_run)
        scope = {(k[0], k[1]) for k in a} & {(k[0], k[1]) for k in b}
        names = {r["id"]: asset_label(r) for r in self.assets()}
        label = names.__getitem__
        out: list[Change] = []
        for k in sorted(set(a) | set(b), key=lambda x: (label(x[0]), x[2])):
            if (k[0], k[1]) not in scope:
                continue
            va, vb = a.get(k), b.get(k)
            disp = k[2]
            if va is None:
                out.append(Change(label(k[0]), disp, "added", new=", ".join(sorted(vb)), source=k[1]))
            elif vb is None:
                out.append(Change(label(k[0]), disp, "removed", old=", ".join(sorted(va)), source=k[1]))
            elif va != vb:
                out.append(Change(label(k[0]), disp, "changed", ", ".join(sorted(va)), ", ".join(sorted(vb)), k[1]))
        return out

    def history(self, pattern: str) -> list[sqlite3.Row]:
        """소프트웨어 하나의 버전 분포가 run 별로 어떻게 변해 왔는지 (패치 진행률 추적)."""
        return list(self.db.execute(
            "SELECT o.run_id, r.started_at, o.name, o.version, count(DISTINCT o.asset_id) AS hosts"
            " FROM observations o JOIN runs r ON r.id=o.run_id WHERE o.name_key LIKE ?"
            " GROUP BY o.run_id, o.name_key, o.version ORDER BY o.run_id, o.name_key, o.version",
            (f"%{norm_name(pattern)}%",)))
