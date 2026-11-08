"""출력: CycloneDX 1.6 JSON SBOM, CSV, HTML 보고서."""

from __future__ import annotations

import csv
import html
import io
import json
import uuid
from collections import Counter, defaultdict

from . import __version__
from .store import Store, asset_label, utcnow

_CDX_TYPE = {"application": "application", "library": "library", "os": "operating-system",
             "service": "application", "firmware": "firmware"}


def _cdx_component(row, ref: str) -> dict:
    props = json.loads(row["props"] or "{}")
    c = {"type": _CDX_TYPE.get(row["type"], "application"), "bom-ref": ref, "name": row["name"]}
    if row["version"]:
        c["version"] = row["version"]
    if row["vendor"]:
        c["publisher"] = row["vendor"]
    if row["purl"]:
        c["purl"] = row["purl"]
    if row["cpe"]:
        c["cpe"] = row["cpe"]
    plist = [{"name": "inventory:source", "value": row["source"]}]
    plist += [{"name": f"inventory:{k}", "value": str(v)} for k, v in sorted(props.items()) if v not in ("", None)]
    c["properties"] = plist
    return c


def _cdx_device(a) -> dict:
    props = [{"name": f"inventory:{k}", "value": v} for k, v in (
        ("hostname", a["hostname"]), ("fqdn", a["fqdn"]), ("serial", a["serial"]),
        ("macs", ",".join(json.loads(a["macs"]))), ("ips", ",".join(json.loads(a["ips"]))),
        ("os", f'{a["os"]} {a["os_version"]}'.strip()), ("sources", ",".join(json.loads(a["sources"]))),
        ("first_seen", a["first_seen"]), ("last_seen", a["last_seen"])) if v]
    return {"type": "device", "bom-ref": f"asset-{a['id']}", "name": asset_label(a), "properties": props}


def cyclonedx(store: Store, run_id: int | None = None, asset_ref: str | None = None) -> dict:
    """asset_ref 지정 시 단일 장비 SBOM(metadata.component=장비), 아니면 전사 SBOM(장비별 중첩 components)."""
    run_id = run_id or store.latest_run_id()
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": utcnow(),
                     "tools": {"components": [{"type": "application", "name": "sbom-inventory",
                                               "version": __version__}]},
                     "properties": [{"name": "inventory:run_id", "value": str(run_id)}]},
        "components": [],
    }
    if asset_ref:
        a = store.asset(asset_ref)
        if a is None:
            raise KeyError(f"자산을 찾을 수 없음: {asset_ref}")
        bom["metadata"]["component"] = _cdx_device(a)
        bom["components"] = [_cdx_component(r, f"asset-{a['id']}:{i}")
                             for i, r in enumerate(store.inventory(run_id, a["id"]))]
        return bom
    by_asset = defaultdict(list)
    for r in store.inventory(run_id):
        by_asset[r["asset_id"]].append(r)
    for a in store.assets():
        if a["id"] not in by_asset:
            continue
        dev = _cdx_device(a)
        dev["components"] = [_cdx_component(r, f"asset-{a['id']}:{i}") for i, r in enumerate(by_asset[a["id"]])]
        bom["components"].append(dev)
    bom["metadata"]["component"] = {"type": "device", "bom-ref": "org", "name": "corporate-network"}
    return bom


def to_csv(rows) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["hostname", "ips", "serial", "source", "type", "name", "version", "vendor", "purl", "cpe", "port"])
    for r in rows:
        w.writerow([r["hostname"], ",".join(json.loads(r["ips"] or "[]")), r["serial"], r["source"], r["type"],
                    r["name"], r["version"], r["vendor"], r["purl"], r["cpe"],
                    json.loads(r["props"] or "{}").get("port", "")])
    return buf.getvalue()


def html_report(store: Store, violations=None, changes=None, run_id: int | None = None) -> str:
    e = html.escape
    run_id = run_id or store.latest_run_id()
    rows = store.inventory(run_id)
    assets = store.assets()
    sw = Counter((r["name"], r["version"]) for r in rows if r["type"] != "service")
    svc = Counter((r["name"], r["version"], json.loads(r["props"]).get("port", "")) for r in rows
                  if r["type"] == "service")
    src = Counter(s for a in assets for s in json.loads(a["sources"]))
    only_nmap = [a for a in assets if json.loads(a["sources"]) == ["nmap"]]

    def table(head, body):
        return ("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" +
                "".join("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in row) + "</tr>" for row in body) +
                "</table>")

    parts = [f"<h1>사내 소프트웨어 인벤토리 (run #{run_id})</h1><p>생성: {e(utcnow())}</p>",
             "<div class=cards>" + "".join(f"<div><b>{v}</b><span>{e(k)}</span></div>" for k, v in [
                 ("자산", len(assets)), ("관측 레코드", len(rows)), ("소프트웨어 종류", len({k[0] for k in sw})),
                 ("정책 위반", len(violations or [])), ("미관리 장비(Nmap만)", len(only_nmap))]) + "</div>",
             "<h2>출처별 자산 수</h2>" + table(["출처", "자산"], src.most_common())]
    if violations:
        parts.append("<h2>정책 위반</h2>" + table(["심각도", "자산", "소프트웨어", "버전", "사유", "출처"],
                     [(v.severity, v.asset, v.name, v.version, v.detail, v.source) for v in violations]))
    if changes:
        parts.append("<h2>변경 이력 (이전 run 대비)</h2>" + table(["자산", "항목", "변경", "이전", "이후", "출처"],
                     [(c.asset, c.name, c.kind, c.old, c.new, c.source) for c in changes]))
    if only_nmap:
        parts.append("<h2>미관리 장비 — Intune/Defender/에이전트에 없음 (섀도 IT 후보)</h2>" + table(
            ["IP", "hostname", "MAC", "OS 추정"],
            [(",".join(json.loads(a["ips"])), a["hostname"], ",".join(json.loads(a["macs"])), a["os"])
             for a in only_nmap]))
    parts.append("<h2>네트워크 노출 서비스 (Nmap)</h2>" + table(["제품", "버전", "포트", "호스트 수"],
                 [(n, v, p, c) for (n, v, p), c in svc.most_common(200)]))
    parts.append("<h2>설치 소프트웨어 상위 300</h2>" + table(["이름", "버전", "설치 수"],
                 [(n, v, c) for (n, v), c in sw.most_common(300)]))
    css = ("body{font-family:system-ui,'Malgun Gothic',sans-serif;margin:24px;color:#1f2328;background:#fff}"
           "table{border-collapse:collapse;width:100%;margin:8px 0 24px;font-size:13px}"
           "th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left}th{background:#f6f8fa}"
           ".cards{display:flex;gap:12px;flex-wrap:wrap}.cards div{border:1px solid #d0d7de;border-radius:8px;"
           "padding:12px 16px;min-width:120px}.cards b{display:block;font-size:24px}.cards span{color:#59636e}")
    return (f"<!doctype html><html lang=ko><head><meta charset=utf-8><title>SBOM Inventory</title>"
            f"<style>{css}</style></head><body>{''.join(parts)}</body></html>")
