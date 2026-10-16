"""명령행 인터페이스.

사용 예:
    python -m owasp_scanner code ./my-project
    python -m owasp_scanner deps ./my-project --osv
    python -m owasp_scanner web https://example.com --format html -o report.html
    python -m owasp_scanner rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .deps_scan import scan_dependencies
from .models import OWASP_TOP10, Finding, Severity
from .report import now_str, render_html, render_json, render_text
from .rules import RULES
from .static_scan import scan_path
from .web_scan import scan_url

WEB_WARNING = (
    "[주의] 웹 점검은 반드시 소유하거나 서면 허가를 받은 대상에만 수행하세요.\n"
    "       허가 없는 점검은 정보통신망법 등 관련 법률 위반이 될 수 있습니다.\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="owasp-scanner", description="OWASP Top 10 (2021) 기준 취약점 점검 도구")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--format", choices=["text", "json", "html"], default="text", help="출력 형식 (기본: text)")
    common.add_argument("-o", "--output", help="결과를 저장할 파일 경로 (생략 시 표준 출력)")
    common.add_argument("--min-severity", default="info", help="이 심각도 이상만 표시 (info/low/medium/high/critical)")
    common.add_argument("--fail-on", default=None,
                        help="이 심각도 이상 결과가 있으면 종료코드 1 반환 (CI 연동용, 예: high)")
    common.add_argument("--owasp", default=None, help="특정 분류만 표시 (예: A03,A05)")
    common.add_argument("--no-color", action="store_true", help="텍스트 출력 색상 비활성화")

    c = sub.add_parser("code", parents=[common], help="소스코드 정적 점검 (SAST)")
    c.add_argument("path", help="점검할 디렉터리 또는 파일")
    c.add_argument("--exclude", action="append", default=[], help="제외할 디렉터리 이름 (반복 지정 가능)")
    c.add_argument("--with-deps", action="store_true", help="의존성 점검(A06)도 함께 수행")
    c.add_argument("--osv", action="store_true", help="의존성 점검 시 OSV.dev 취약점 DB 조회 (네트워크 필요)")

    d = sub.add_parser("deps", parents=[common], help="의존성 점검 (A06, requirements.txt / package.json)")
    d.add_argument("path", help="점검할 디렉터리 또는 파일")
    d.add_argument("--osv", action="store_true", help="OSV.dev 취약점 DB 조회 (네트워크 필요)")

    w = sub.add_parser("web", parents=[common], help="웹 애플리케이션 비파괴 점검 (DAST, passive)")
    w.add_argument("url", help="점검 대상 URL (예: https://example.com)")
    w.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    w.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략 (테스트 서버용)")
    w.add_argument("--no-paths", action="store_true", help="민감 파일 노출 경로 점검 생략")
    w.add_argument("-y", "--yes", action="store_true", help="점검 권한 확인 프롬프트 생략")

    sub.add_parser("rules", help="정적 점검 규칙 목록 출력")
    return p


def _filter(findings: list[Finding], args) -> list[Finding]:
    min_sev = Severity.parse(args.min_severity)
    result = [f for f in findings if f.severity >= min_sev]
    if args.owasp:
        wanted = {c.strip().upper() for c in args.owasp.split(",") if c.strip()}
        result = [f for f in result if f.owasp in wanted]
    return result


def _emit(findings: list[Finding], meta: dict, args) -> None:
    if args.format == "json":
        text = render_json(findings, meta)
    elif args.format == "html":
        text = render_html(findings, meta)
    else:
        use_color = not args.no_color and not args.output and sys.stdout.isatty()
        text = render_text(findings, meta, color=use_color)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"결과 저장: {args.output} ({len(findings)}건)", file=sys.stderr)
    else:
        print(text)


def _confirm_authorized(target: str) -> bool:
    sys.stderr.write(WEB_WARNING)
    if not sys.stdin.isatty():
        sys.stderr.write("대화형 터미널이 아니므로 -y/--yes 옵션으로 점검 권한을 확인해 주세요.\n")
        return False
    answer = input(f"'{target}'에 대한 점검 권한이 있습니까? [y/N] ").strip().lower()
    return answer in ("y", "yes", "예", "ㅇ")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        for r in RULES:
            print(f"{r.id:<28} {r.owasp}  {r.severity.label:<8} {r.cwe:<8} {r.title}")
        print(f"\n총 {len(RULES)}개 규칙 / 분류: " + ", ".join(OWASP_TOP10))
        return 0

    try:
        if args.fail_on:
            Severity.parse(args.fail_on)
        Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

    meta = {"mode": args.command, "started": now_str(), "notes": []}
    try:
        if args.command == "code":
            findings, count = scan_path(args.path, set(args.exclude))
            meta.update(target=str(Path(args.path).resolve()), files_scanned=count)
            if args.with_deps:
                dep_findings, deps, err = scan_dependencies(args.path, args.osv)
                findings += dep_findings
                meta["notes"].append(f"의존성 {len(deps)}개 확인")
                if err:
                    meta["notes"].append(err)
        elif args.command == "deps":
            findings, deps, err = scan_dependencies(args.path, args.osv)
            meta.update(target=str(Path(args.path).resolve()), dependencies=len(deps))
            meta["notes"].append(f"의존성 {len(deps)}개 확인" + ("" if args.osv else " (OSV 조회는 --osv 옵션 사용)"))
            if err:
                meta["notes"].append(err)
        else:  # web
            if not args.yes and not _confirm_authorized(args.url):
                print("점검을 취소했습니다.", file=sys.stderr)
                return 2
            findings, notes = scan_url(args.url, args.timeout, args.insecure, not args.no_paths)
            meta.update(target=args.url)
            meta["notes"].extend(notes)
    except (FileNotFoundError, ConnectionError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

    findings = _filter(findings, args)
    _emit(findings, meta, args)

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
