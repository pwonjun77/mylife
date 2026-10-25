"""명령행 인터페이스.

사용 예:
    python -m url_monitor check examples/targets.json
    python -m url_monitor check examples/targets.csv -f html -o report.html
    python -m url_monitor check --url https://www.example.com
    python -m url_monitor check targets.json --db monitor.db --notify      # cron 용: 상태 바뀔 때만 알림
    python -m url_monitor watch targets.json --db monitor.db --status-page status.html
    python -m url_monitor report --db monitor.db --since 7d -f html -o weekly.html
    python -m url_monitor validate targets.json

종료코드: 0 전체 정상, 1 경고 있음, 2 장애 있음, 3 설정·실행 오류
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config, target_from_url
from .models import Status
from .report import render_history_html, render_history_text, render_html, render_json, render_text
from .scheduler import check_all, process_results, watch
from .store import Store, parse_since

EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="url-monitor", description="등록한 URL의 접속 이상 여부 점검 도구")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="등록된 모든 대상을 1회 점검")
    c.add_argument("config", nargs="?", help="설정 파일 (.json / .csv / .toml)")
    c.add_argument("--url", action="append", default=[], help="설정 파일 없이 점검할 URL (여러 번 지정 가능)")
    c.add_argument("--group", action="append", default=[], help="이 그룹만 점검 (여러 번 지정 가능)")
    c.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    c.add_argument("-o", "--output", help="결과 저장 파일 (생략 시 화면 출력)")
    c.add_argument("--db", help="이력 DB(SQLite) 경로. 지정하면 결과를 저장하고 상태 전이를 추적")
    c.add_argument("--notify", action="store_true", help="설정 파일의 notify 로 알림 발송")
    c.add_argument("--workers", type=int, help="동시 점검 수 (기본: 설정값 또는 20)")
    c.add_argument("--timeout", type=float, help="모든 대상의 timeout_sec 덮어쓰기")
    c.add_argument("--no-retry", action="store_true", help="장애 시 재시도하지 않음 (빠른 확인용)")
    c.add_argument("--no-color", action="store_true")

    w = sub.add_parser("watch", help="주기 점검 (상주 실행, Ctrl+C 로 종료)")
    w.add_argument("config")
    w.add_argument("--db", default="monitor.db", help="이력 DB 경로 (기본 monitor.db)")
    w.add_argument("--status-page", help="결과가 나올 때마다 갱신할 상태 페이지 HTML 경로")
    w.add_argument("--no-notify", action="store_true", help="알림을 보내지 않음")
    w.add_argument("--workers", type=int)
    w.add_argument("--rounds", type=int, default=0, help=argparse.SUPPRESS)  # 테스트용: N회 점검 후 종료
    w.add_argument("-q", "--quiet", action="store_true", help="화면에 변화만 출력")

    r = sub.add_parser("report", help="이력 DB로 가용률 보고서 생성")
    r.add_argument("--db", default="monitor.db")
    r.add_argument("--since", default="7d", help="기간 (예: 24h, 7d, 4w)")
    r.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    r.add_argument("-o", "--output")

    v = sub.add_parser("validate", help="설정 파일 검사 (URL 형식, 환경변수, 중복 등)")
    v.add_argument("config")
    return p


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"저장했습니다: {output}", file=sys.stderr)
    else:
        print(text)


def _write_atomic(path: str, text: str) -> None:
    tmp = Path(path + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _exit_code(results) -> int:
    return int(max((r.status for r in results), default=Status.UP))


def cmd_check(args) -> int:
    if not args.config and not args.url:
        print("설정 파일 또는 --url 을 지정하세요.", file=sys.stderr)
        return EXIT_ERROR
    notify, settings, source = {}, {"workers": 20, "retention_days": 90}, "--url"
    targets = []
    if args.config:
        cfg = load_config(args.config)
        targets, notify, settings, source = cfg.targets, cfg.notify, cfg.settings, cfg.source
    targets += [target_from_url(u) for u in args.url]
    if args.group:
        targets = [t for t in targets if t.group in args.group]
        if not targets:
            print(f"그룹 {args.group} 에 해당하는 대상이 없습니다.", file=sys.stderr)
            return EXIT_ERROR
    for t in targets:
        if args.timeout:
            t.timeout_sec = args.timeout
        if args.no_retry:
            t.retries = 0
    if args.notify and not notify:
        print("[안내] 설정 파일에 notify 항목이 없어 알림을 보내지 않습니다.", file=sys.stderr)

    started = datetime.now().astimezone()
    t0 = time.perf_counter()
    results = check_all(targets, args.workers or settings["workers"])
    meta = {"started": started.strftime("%Y-%m-%d %H:%M:%S"), "elapsed": round(time.perf_counter() - t0, 2),
            "source": source, "tool": f"url-monitor {__version__}"}

    store = Store(args.db) if args.db else None
    try:
        events = process_results(results, store, notify if args.notify else None)
        if store:
            store.purge(int(settings["retention_days"]))
    finally:
        if store:
            store.close()
    if events:
        print(f"[알림] {len(events)}건의 상태 변화를 알렸습니다.", file=sys.stderr)

    if args.format == "json":
        _write(render_json(results, meta), args.output)
    elif args.format == "html":
        _write(render_html(results, meta), args.output)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        _write(render_text(results, meta, color), args.output)
    return _exit_code(results)


def cmd_watch(args) -> int:
    cfg = load_config(args.config)
    store = Store(args.db)
    notify = None if args.no_notify else (cfg.notify or None)
    n = len([t for t in cfg.targets if t.enabled])
    print(f"[{datetime.now():%H:%M:%S}] {n}개 대상 주기 점검 시작 (DB {args.db}"
          f"{', 알림 켜짐' if notify else ', 알림 꺼짐'}). Ctrl+C 로 종료합니다.", file=sys.stderr)
    last_status: dict[str, Status] = {}

    def on_cycle(results, latest):
        for r in results:
            changed = last_status.get(r.target.key) != r.status
            last_status[r.target.key] = r.status
            if changed or not args.quiet:
                ms = "-" if r.probe.total_ms is None else f"{r.probe.total_ms:,.0f}ms"
                print(f"[{datetime.now():%H:%M:%S}] {r.status.label:<4} {r.target.key}  {ms}  {r.message}", flush=True)
        if args.status_page:
            rows = {a["target"]: a for a in store.availability(parse_since("24h"))}
            meta = {"started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "elapsed": 0, "source": cfg.source}
            ordered = [latest[t.key] for t in cfg.targets if t.key in latest]
            _write_atomic(args.status_page, render_html(ordered, meta, rows, title="시스템 상태", refresh=30))

    try:
        watch(cfg.targets, store, notify, args.workers or cfg.settings["workers"], on_cycle=on_cycle,
              max_rounds=args.rounds, retention_days=int(cfg.settings["retention_days"]))
    finally:
        store.close()
    return 0


def cmd_report(args) -> int:
    if not Path(args.db).is_file():
        print(f"이력 DB가 없습니다: {args.db} (check --db 또는 watch 로 먼저 점검하세요)", file=sys.stderr)
        return EXIT_ERROR
    since = parse_since(args.since)
    store = Store(args.db)
    try:
        rows, incidents = store.availability(since), store.incidents(since)
    finally:
        store.close()
    meta = {"since": args.since, "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    if args.format == "json":
        import json
        _write(json.dumps({"meta": meta, "targets": rows, "incidents": incidents}, ensure_ascii=False, indent=2), args.output)
    elif args.format == "html":
        _write(render_history_html(rows, incidents, meta), args.output)
    else:
        _write(render_history_text(rows, incidents, meta), args.output)
    return 0


def cmd_validate(args) -> int:
    cfg = load_config(args.config)
    groups: dict[str, int] = {}
    for t in cfg.targets:
        groups[t.group] = groups.get(t.group, 0) + 1
    print(f"설정 정상: 대상 {len(cfg.targets)}개 ({', '.join(f'{g} {n}' for g, n in groups.items())})")
    channels = len(cfg.notify.get("webhooks") or []) + (1 if cfg.notify.get("email") else 0)
    print(f"알림 채널 {channels}개" if channels else "알림 채널 없음 (notify 미설정)")
    insecure = [t.key for t in cfg.targets if t.type == "http" and not t.verify_tls]
    if insecure:
        print(f"[주의] 인증서 검증을 끈 대상: {', '.join(insecure)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"check": cmd_check, "watch": cmd_watch, "report": cmd_report, "validate": cmd_validate}
    try:
        return handlers[args.cmd](args)
    except ConfigError as exc:
        print("설정 오류:", file=sys.stderr)
        for e in exc.errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return EXIT_ERROR
