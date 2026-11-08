"""명령행 인터페이스.

  python -m sbom_inventory nmap 10.10.0.0/24 --os           # 네트워크 스캔 → 새 run
  python -m sbom_inventory nmap --from-xml scan.xml          # 기존 nmap XML import
  python -m sbom_inventory intune [--mode export]            # Intune 탐지 앱
  python -m sbom_inventory defender                          # Defender TVM 인벤토리
  python -m sbom_inventory import \\\\fileserver\\sbom$       # 에이전트 JSON
  python -m sbom_inventory run -c config.json                # 위 수집을 한 run 으로 + 보고서 생성 (스케줄러용)
  python -m sbom_inventory runs | assets | show PC-001 | history chrome | diff
  python -m sbom_inventory policy policy.json --fail-on high
  python -m sbom_inventory export cyclonedx -o sbom.cdx.json [--asset PC-001]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .collectors import agent_import, graph, nmap_scan
from .export import cyclonedx, html_report, to_csv
from .policy import SEVERITY, check, load_policy
from .store import Store, asset_label

SCAN_WARNING = ("[주의] 네트워크 스캔은 사전에 승인된 사내 대역에만 수행하세요. IPS/EDR 경보가 발생할 수 있으므로\n"
                "       보안관제(SOC) 및 망 운영 부서와 일정·출발지 IP 를 공유하세요. (-y 로 확인 생략)\n")


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _confirm(args) -> bool:
    if args.yes:
        return True
    log(SCAN_WARNING)
    try:
        return input("계속할까요? [y/N] ").strip().lower() == "y"
    except EOFError:
        return False


def _collect(store: Store, records, note: str, run_id: int | None = None) -> int:
    rid = run_id or store.begin_run(note)
    n = store.ingest(rid, records)
    if run_id is None:
        store.end_run(rid)
    log(f"run #{rid}: 호스트 {len(records)}대, 관측 {n}건 저장 ({note})")
    return rid


def _nmap_records(cfg: dict, from_xml: str | None = None, keep_xml: str | None = None):
    if from_xml:
        return nmap_scan.parse_nmap_xml(from_xml)
    kw = {k: cfg[k] for k in ("ports", "top_ports", "os_detect", "timing", "exclude", "extra_args", "nmap_path")
          if cfg.get(k) is not None}
    return nmap_scan.run_nmap(cfg["targets"], keep_xml=keep_xml, **kw)


def _client(resource: str) -> graph.ApiClient:
    return graph.ApiClient(*graph.credentials_from_env(), resource=resource)


# ---------------------------------------------------------------- commands

def cmd_nmap(args, store):
    if not args.from_xml:
        if not args.targets and not args.targets_file:
            raise SystemExit("스캔 대상을 지정하세요 (예: 10.0.0.0/24) 또는 --from-xml")
        if not _confirm(args):
            return 1
    targets = list(args.targets)
    if args.targets_file:
        targets += [ln.strip() for ln in Path(args.targets_file).read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")]
    cfg = {"targets": targets, "ports": args.ports, "top_ports": args.top_ports, "os_detect": args.os,
           "timing": args.timing, "exclude": args.exclude}
    _collect(store, _nmap_records(cfg, args.from_xml, args.keep_xml), "nmap")
    return 0


def cmd_intune(args, store):
    _collect(store, graph.collect_intune(_client(graph.GRAPH), args.mode, log), f"intune:{args.mode}")
    return 0


def cmd_defender(args, store):
    _collect(store, graph.collect_defender(_client(graph.MDE), log), "defender")
    return 0


def cmd_import(args, store):
    recs, errs = agent_import.import_dir(args.path, verify_hash=args.verify_hash)
    for e in errs:
        log(f"[건너뜀] {e}")
    _collect(store, recs, f"agent:{args.path}")
    return 0 if not errs else 2


def cmd_run(args, store):
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    rid = store.begin_run(f"run:{args.config}")
    failed = []

    def step(name, fn):
        try:
            _collect(store, fn(), name, rid)
        except Exception as e:  # noqa: BLE001 - 한 수집기 실패가 나머지를 막지 않도록
            failed.append(name)
            log(f"[실패] {name}: {e}")

    for d in cfg.get("agent_dirs", []):
        def _imp(d=d):
            recs, errs = agent_import.import_dir(d, verify_hash=cfg.get("verify_hash", False))
            for e in errs:
                log(f"[건너뜀] {e}")
            return recs
        step(f"agent:{d}", _imp)
    if cfg.get("intune", {}).get("enabled"):
        step("intune", lambda: graph.collect_intune(_client(graph.GRAPH), cfg["intune"].get("mode", "per-app"), log))
    if cfg.get("defender", {}).get("enabled"):
        step("defender", lambda: graph.collect_defender(_client(graph.MDE), log))
    if cfg.get("nmap", {}).get("targets"):
        step("nmap", lambda: _nmap_records(cfg["nmap"]))
    store.end_run(rid)

    out = Path(cfg.get("reports_dir", "reports"))
    out.mkdir(parents=True, exist_ok=True)
    prev = store.latest_run_id(offset=1)
    changes = store.diff(prev, rid) if prev else []
    viol = check(store.inventory(rid), load_policy(cfg["policy"])) if cfg.get("policy") else []
    (out / f"sbom-run{rid}.cdx.json").write_text(json.dumps(cyclonedx(store, rid), ensure_ascii=False, indent=1),
                                                 encoding="utf-8")
    (out / f"report-run{rid}.html").write_text(html_report(store, viol, changes, rid), encoding="utf-8")
    log(f"run #{rid} 완료: 변경 {len(changes)}건, 정책 위반 {len(viol)}건 → {out}/")
    return 1 if failed else 0


def cmd_runs(args, store):
    for r in store.runs():
        print(f"#{r['id']:<4} {r['started_at']}  자산 {r['assets'] or 0:>5}  관측 {r['obs'] or 0:>7}  "
              f"{r['sources'] or '-':<24} {r['note']}")
    return 0


def cmd_assets(args, store):
    print(f"{'ID':>4}  {'HOSTNAME':<20} {'IP':<16} {'SERIAL':<14} {'OS':<28} SOURCES")
    for a in store.assets():
        ips = json.loads(a["ips"])
        print(f"{a['id']:>4}  {a['hostname'][:20]:<20} {(ips[0] if ips else '')[:16]:<16} {a['serial'][:14]:<14} "
              f"{(a['os'] + ' ' + a['os_version']).strip()[:28]:<28} {','.join(json.loads(a['sources']))}")
    return 0


def cmd_show(args, store):
    a = store.asset(args.asset)
    if a is None:
        log(f"자산 없음: {args.asset}")
        return 1
    print(f"[{asset_label(a)}] serial={a['serial']} macs={a['macs']} ips={a['ips']} os={a['os']} {a['os_version']}")
    print(f"  sources={a['sources']} first_seen={a['first_seen']} last_seen={a['last_seen']}")
    for r in store.inventory(args.run, a["id"]):
        port = json.loads(r["props"]).get("port", "")
        print(f"  {r['source']:<9} {r['type']:<11} {r['name'][:50]:<50} {r['version'][:24]:<24} {port}")
    return 0


def cmd_diff(args, store):
    new = args.to or store.latest_run_id()
    old = args.from_ or store.latest_run_id(offset=1)
    if not (old and new):
        log("비교할 run 이 2개 이상 필요합니다")
        return 1
    changes = store.diff(old, new)
    print(f"run #{old} → #{new}: {len(changes)}건 변경")
    mark = {"added": "+", "removed": "-", "changed": "~"}
    for c in changes:
        ver = c.new if c.kind == "added" else c.old if c.kind == "removed" else f"{c.old} → {c.new}"
        print(f"  {mark[c.kind]} {c.asset:<20} {c.name[:48]:<48} {ver}  [{c.source}]")
    return 0


def cmd_history(args, store):
    rows = store.history(args.name)
    if not rows:
        log("기록 없음")
        return 1
    cur = None
    for r in rows:
        if r["run_id"] != cur:
            cur = r["run_id"]
            print(f"run #{cur} ({r['started_at']})")
        print(f"   {r['name'][:48]:<48} {r['version'] or '(버전없음)':<24} {r['hosts']}대")
    return 0


def cmd_policy(args, store):
    viol = check(store.inventory(args.run), load_policy(args.policy))
    for v in viol:
        print(f"[{v.severity.upper():<8}] {v.asset:<20} {v.name[:40]:<40} {v.version:<20} {v.detail}")
    print(f"총 {len(viol)}건")
    if args.fail_on and any(SEVERITY.index(v.severity) >= SEVERITY.index(args.fail_on) for v in viol):
        return 1
    return 0


def cmd_export(args, store):
    if args.format == "cyclonedx":
        text = json.dumps(cyclonedx(store, args.run, args.asset), ensure_ascii=False, indent=1)
    elif args.format == "csv":
        a = store.asset(args.asset) if args.asset else None
        text = to_csv(store.inventory(args.run, a["id"] if a else None))
    else:
        viol = check(store.inventory(args.run), load_policy(args.policy)) if args.policy else None
        prev = store.latest_run_id(offset=1)
        changes = store.diff(prev, args.run or store.latest_run_id()) if prev else None
        text = html_report(store, viol, changes, args.run)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        log(f"저장: {args.output}")
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sbom-inventory", description="Nmap + Microsoft 365 기반 사내 SBOM/버전 관리")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--db", default="inventory.db", help="SQLite DB 경로 (기본: inventory.db)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("nmap", help="Nmap 스캔(또는 XML import)")
    s.add_argument("targets", nargs="*", help="IP / CIDR / 범위 / 호스트명")
    s.add_argument("--targets-file", help="대상 목록 파일 (한 줄에 하나)")
    s.add_argument("--from-xml", help="이미 실행한 nmap -oX 결과 파일을 import")
    s.add_argument("--keep-xml", help="스캔 원본 XML 저장 경로 (증적 보존)")
    s.add_argument("-p", "--ports", help="포트 지정 (예: 22,80,443,1-1024)")
    s.add_argument("--top-ports", type=int, default=1000)
    s.add_argument("--os", action="store_true", help="OS 탐지(-O, root 권한 필요)")
    s.add_argument("--timing", type=int, default=3, choices=range(0, 6), help="-T 타이밍 (기본 3)")
    s.add_argument("--exclude", help="제외 대상 (쉼표 구분)")
    s.add_argument("-y", "--yes", action="store_true", help="스캔 확인 질문 생략")
    s.set_defaults(func=cmd_nmap)

    s = sub.add_parser("intune", help="Intune 탐지 앱 수집 (Graph)")
    s.add_argument("--mode", choices=["per-app", "export"], default="per-app",
                   help="per-app: v1.0 API 앱별 조회 / export: 보고서 내보내기 CSV (대규모 권장)")
    s.set_defaults(func=cmd_intune)

    s = sub.add_parser("defender", help="Defender for Endpoint TVM 소프트웨어 인벤토리 수집")
    s.set_defaults(func=cmd_defender)

    s = sub.add_parser("import", help="에이전트 JSON(디렉터리/파일) import")
    s.add_argument("path")
    s.add_argument("--verify-hash", action="store_true", help=".sha256 파일과 대조")
    s.set_defaults(func=cmd_import)

    s = sub.add_parser("run", help="설정 파일의 모든 수집기를 한 run 으로 실행 + 보고서 생성")
    s.add_argument("-c", "--config", required=True)
    s.set_defaults(func=cmd_run)

    sub.add_parser("runs", help="실행 이력").set_defaults(func=cmd_runs)
    sub.add_parser("assets", help="자산 목록").set_defaults(func=cmd_assets)

    s = sub.add_parser("show", help="자산 하나의 SBOM")
    s.add_argument("asset", help="자산 ID / hostname / serial / IP")
    s.add_argument("--run", type=int)
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("diff", help="두 run 사이 설치/삭제/버전 변경")
    s.add_argument("--from", dest="from_", type=int)
    s.add_argument("--to", type=int)
    s.set_defaults(func=cmd_diff)

    s = sub.add_parser("history", help="소프트웨어 버전 분포의 run 별 추이")
    s.add_argument("name")
    s.set_defaults(func=cmd_history)

    s = sub.add_parser("policy", help="버전 정책 점검")
    s.add_argument("policy")
    s.add_argument("--run", type=int)
    s.add_argument("--fail-on", choices=SEVERITY)
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("export", help="SBOM/보고서 내보내기")
    s.add_argument("format", choices=["cyclonedx", "csv", "html"])
    s.add_argument("--asset")
    s.add_argument("--run", type=int)
    s.add_argument("--policy", help="html 보고서에 포함할 정책 파일")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_export)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    try:
        return args.func(args, store)
    except (graph.AuthError, RuntimeError, ValueError, KeyError) as e:
        log(f"오류: {e}")
        return 2
