"""명령행 인터페이스.

사용 예:
    python -m url_monitor check examples/targets.json
    python -m url_monitor check examples/targets.csv -f html -o report.html
    python -m url_monitor check --url https://www.example.com
    python -m url_monitor check targets.json --db monitor.db --notify      # cron 용: 상태 바뀔 때만 알림
    python -m url_monitor watch targets.json --db monitor.db --status-page status.html
    python -m url_monitor report --db monitor.db --since 7d -f html -o weekly.html
    python -m url_monitor validate targets.json
    python -m url_monitor notify-test targets.json --teams-webhook env:URLMON_TEAMS_WEBHOOK
    pythonw -m url_monitor watch targets.json --env-file url-monitor.env --log-file monitor.log --keep-awake

종료코드: 0 전체 정상, 1 경고 있음, 2 장애 있음, 3 설정·실행 오류
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .background import RotatingLog, allow_sleep, keep_awake
from .config import Config, ConfigError, load_config, load_env_file, resolve_env, target_from_url
from .models import Status
from .notifier import send_all, summary_text
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
    _common(c)

    w = sub.add_parser("watch", help="주기 점검 (상주 실행, Ctrl+C 로 종료)")
    w.add_argument("config")
    w.add_argument("--db", default="monitor.db", help="이력 DB 경로 (기본 monitor.db)")
    w.add_argument("--status-page", help="결과가 나올 때마다 갱신할 상태 페이지 HTML 경로")
    w.add_argument("--no-notify", action="store_true", help="알림을 보내지 않음")
    w.add_argument("--workers", type=int)
    w.add_argument("--rounds", type=int, default=0, help=argparse.SUPPRESS)  # 테스트용: N회 점검 후 종료
    w.add_argument("-q", "--quiet", action="store_true", help="화면에 변화만 출력")
    w.add_argument("--log-file", help="출력을 이 파일로 기록 (5MB 단위 순환). 창 없이 실행할 때 사용")
    w.add_argument("--keep-awake", action="store_true",
                   help="실행 중 PC 절전 방지 (Windows, 화면 꺼짐·잠금은 허용)")
    w.add_argument("--notify-start", action="store_true", help="첫 점검이 끝나면 '모니터링 시작' 알림 (재부팅 후 동작 확인용)")
    w.add_argument("--heartbeat-hours", type=float, help="N시간마다 '정상 동작 중' 요약 알림 (0=끔)")
    _common(w)

    r = sub.add_parser("report", help="이력 DB로 가용률 보고서 생성")
    r.add_argument("--db", default="monitor.db")
    r.add_argument("--since", default="7d", help="기간 (예: 24h, 7d, 4w)")
    r.add_argument("-f", "--format", choices=["text", "json", "html"], default="text")
    r.add_argument("-o", "--output")

    v = sub.add_parser("validate", help="설정 파일 검사 (URL 형식, 환경변수, 중복 등)")
    v.add_argument("config")
    _common(v)

    n = sub.add_parser("notify-test", help="알림 채널(Teams 등)로 시험 메시지 발송")
    n.add_argument("config", nargs="?", help="설정 파일 (생략하면 --teams-webhook 만 사용)")
    _common(n)
    return p


def _common(sp) -> None:
    sp.add_argument("--env-file", help="KEY=VALUE 형식 환경변수 파일 (웹훅 주소 등 비밀값 보관용)")
    sp.add_argument("--teams-webhook", help="Teams 웹훅 주소 추가. env:변수명 형식 가능")


def _apply_common(args, cfg: Config | None) -> Config:
    """--env-file 은 설정 로드 전에, --teams-webhook 은 로드 후에 적용한다."""
    if cfg is None:
        cfg = Config(targets=[], source="-")
    url = getattr(args, "teams_webhook", None)
    if url:
        errors: list[str] = []
        url = resolve_env(url, errors, "--teams-webhook")
        if not errors and not url.startswith(("http://", "https://")):
            errors.append("--teams-webhook: http(s) 주소가 아닙니다")
        if errors:
            raise ConfigError(errors)
        hooks = cfg.notify.setdefault("webhooks", [])
        if not any(h.get("url") == url for h in hooks):
            hooks.append({"type": "teams", "url": url})
    return cfg


def _load(args, path: str | None) -> Config:
    if getattr(args, "env_file", None):
        load_env_file(args.env_file)
    return _apply_common(args, load_config(path) if path else None)


def _write(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"저장했습니다: {output}", file=sys.stderr)
    else:
        print(text)


def _write_atomic(path: str, text: str) -> None:
    tmp = Path(path + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        tmp.replace(path)
    except PermissionError:  # Windows: 다른 프로그램이 파일을 잡고 있으면 다음 갱신 때 다시 시도
        pass


def _exit_code(results) -> int:
    return int(max((r.status for r in results), default=Status.UP))


def cmd_check(args) -> int:
    if not args.config and not args.url:
        print("설정 파일 또는 --url 을 지정하세요.", file=sys.stderr)
        return EXIT_ERROR
    cfg = _load(args, args.config)
    targets, notify, settings = list(cfg.targets), cfg.notify, cfg.settings
    source = cfg.source if args.config else "--url"
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
    if not args.log_file:
        return _watch(args)
    log = RotatingLog(args.log_file)
    saved = sys.stdout, sys.stderr
    sys.stdout = sys.stderr = log  # pythonw 로 실행하면 원래 None 이라 출력이 사라짐
    try:
        return _watch(args)
    except Exception as exc:  # 창 없이 실행 중이므로 치명적 오류도 로그에 남기고 종료코드로 알림(작업 스케줄러 재시작)
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [치명적 오류] {type(exc).__name__}: {exc}", file=log)
        raise
    finally:
        sys.stdout, sys.stderr = saved
        log.close()


def _watch(args) -> int:
    cfg = _load(args, args.config)
    store = Store(args.db)
    if args.notify_start:
        cfg.notify["notify_start"] = True
    if args.heartbeat_hours is not None:
        cfg.notify["heartbeat_hours"] = args.heartbeat_hours
    has_channel = cfg.notify.get("webhooks") or cfg.notify.get("email")
    notify = None if args.no_notify or not has_channel else cfg.notify
    n = len([t for t in cfg.targets if t.enabled])
    awake = keep_awake() if args.keep_awake else False
    if args.keep_awake and not awake:
        print("[안내] --keep-awake 는 Windows 에서만 동작합니다.", file=sys.stderr)
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {n}개 대상 주기 점검 시작 (DB {args.db}"
          f"{', 알림 켜짐' if notify else ', 알림 꺼짐'}{', 절전 방지' if awake else ''}). Ctrl+C 로 종료합니다.",
          file=sys.stderr, flush=True)
    last_status: dict[str, Status] = {}
    heartbeat_sec = float((notify or {}).get("heartbeat_hours", 0) or 0) * 3600
    state = {"started_sent": not (notify or {}).get("notify_start"), "last_beat": time.monotonic()}

    def on_cycle(results, latest):
        for r in results:
            changed = last_status.get(r.target.key) != r.status
            last_status[r.target.key] = r.status
            if changed or not args.quiet:
                ms = "-" if r.probe.total_ms is None else f"{r.probe.total_ms:,.0f}ms"
                print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {r.status.label:<4} {r.target.key}  {ms}  {r.message}",
                      flush=True)
        ordered = [latest[t.key] for t in cfg.targets if t.key in latest]
        if notify and len(latest) == n:
            # 시작 알림은 첫 바퀴가 끝난 뒤(현재 상태 요약 포함), 하트비트는 heartbeat_hours 마다
            if not state["started_sent"]:
                send_all(notify, "[URL 모니터] 모니터링 시작", summary_text(ordered))
                state["started_sent"] = True
                state["last_beat"] = time.monotonic()
            elif heartbeat_sec and time.monotonic() - state["last_beat"] >= heartbeat_sec:
                send_all(notify, "[URL 모니터] 정상 동작 중 (정기 보고)", summary_text(ordered))
                state["last_beat"] = time.monotonic()
        if args.status_page:
            rows = {a["target"]: a for a in store.availability(parse_since("24h"))}
            meta = {"started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "elapsed": 0, "source": cfg.source}
            _write_atomic(args.status_page, render_html(ordered, meta, rows, title="시스템 상태", refresh=30))

    try:
        watch(cfg.targets, store, notify, args.workers or cfg.settings["workers"], on_cycle=on_cycle,
              max_rounds=args.rounds, retention_days=int(cfg.settings["retention_days"]))
    finally:
        store.close()
        if awake:
            allow_sleep()
    return 0


def cmd_notify_test(args) -> int:
    cfg = _load(args, args.config)
    hooks = cfg.notify.get("webhooks") or []
    if not hooks and not cfg.notify.get("email"):
        print("알림 채널이 없습니다. 설정 파일의 notify 또는 --teams-webhook 을 지정하세요.", file=sys.stderr)
        return EXIT_ERROR
    import socket
    body = (f"URL 모니터 알림 시험 메시지입니다.\n보낸 곳: {socket.gethostname()} · "
            f"{datetime.now():%Y-%m-%d %H:%M:%S} · 대상 {len(cfg.targets)}개")
    ok = send_all(cfg.notify, "[URL 모니터] 알림 시험", body)
    channels = len(hooks) + (1 if cfg.notify.get("email") else 0)
    print(f"{'발송 성공' if ok else '발송 실패'} (채널 {channels}개)" + ("" if ok else " - 위 오류를 확인하세요"))
    return 0 if ok else EXIT_ERROR


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
    cfg = _load(args, args.config)
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
    handlers = {"check": cmd_check, "watch": cmd_watch, "report": cmd_report, "validate": cmd_validate,
                "notify-test": cmd_notify_test}
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
