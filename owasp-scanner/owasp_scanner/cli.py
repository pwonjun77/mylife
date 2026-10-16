"""명령행 인터페이스.

사용 예:
    python -m owasp_scanner code ./my-project
    python -m owasp_scanner deps ./my-project --osv
    python -m owasp_scanner web https://example.com --format html -o report.html
    python -m owasp_scanner code ./my-project --ai-review          # Claude로 오탐 검토
    python -m owasp_scanner review report.json                      # 저장된 JSON 리포트를 Claude로 검토
    python -m owasp_scanner rules
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import ai_review
from .deps_scan import scan_dependencies
from .models import DEFAULT_STANDARD, MAP_2021_TO_2025, STANDARDS, Finding, Severity
from .report import now_str, render_html, render_json, render_text
from .rules import RULES
from .static_scan import scan_path
from .web_scan import scan_url

WEB_WARNING = (
    "[주의] 웹 점검은 반드시 소유하거나 서면 허가를 받은 대상에만 수행하세요.\n"
    "       허가 없는 점검은 정보통신망법 등 관련 법률 위반이 될 수 있습니다.\n"
)
AI_WARNING = (
    "[안내] AI 검토는 탐지된 줄 주변의 소스코드(비밀값은 **** 로 가림)를 Anthropic Claude API로 전송합니다.\n"
    "       회사 코드라면 외부 전송이 허용되는지 먼저 확인하세요. 결과 1건당 API 요청 1회가 발생합니다(유료).\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="owasp-scanner", description="OWASP Top 10 (2025 / 2021) 기준 취약점 점검 도구")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--format", choices=["text", "json", "html"], default="text", help="출력 형식 (기본: text)")
    common.add_argument("-o", "--output", help="결과를 저장할 파일 경로 (생략 시 표준 출력)")
    common.add_argument("--min-severity", default="info", help="이 심각도 이상만 표시 (info/low/medium/high/critical)")
    common.add_argument("--fail-on", default=None,
                        help="이 심각도 이상 결과가 있으면 종료코드 1 반환 (CI 연동용, 예: high)")
    common.add_argument("--standard", choices=sorted(STANDARDS), default=DEFAULT_STANDARD,
                        help=f"분류 기준 OWASP Top 10 판 (기본: {DEFAULT_STANDARD})")
    common.add_argument("--owasp", default=None, help="선택한 기준의 특정 분류만 표시 (예: A03,A05)")
    common.add_argument("--no-color", action="store_true", help="텍스트 출력 색상 비활성화")

    ai = argparse.ArgumentParser(add_help=False)
    g = ai.add_argument_group("AI 오탐 검토 (Claude, 'pip install anthropic' 필요)")
    g.add_argument("--ai-review", action="store_true", help="각 결과를 Claude에게 보내 실제 취약점/오탐 여부를 판정")
    g.add_argument("--ai-model", default=ai_review.DEFAULT_MODEL, help=f"검토에 쓸 Claude 모델 (기본: {ai_review.DEFAULT_MODEL})")
    g.add_argument("--ai-max", type=int, default=30, help="검토할 최대 결과 수, 심각도 높은 순 (기본: 30)")
    g.add_argument("--ai-context", type=int, default=ai_review.CONTEXT_LINES,
                   help=f"탐지된 줄 앞뒤로 보낼 코드 줄 수 (기본: {ai_review.CONTEXT_LINES})")
    g.add_argument("--ai-yes", action="store_true", help="코드 전송 확인 질문 생략")
    g.add_argument("--hide-fp", action="store_true", help="AI가 오탐으로 판정한 결과는 출력에서 숨김")
    g.add_argument("--expected", metavar="LABELS.json",
                   help="정답 라벨 파일과 비교해 스캐너 정밀도와 AI 판정 정확도를 계산 (오탐 테스트용)")

    c = sub.add_parser("code", parents=[common, ai], help="소스코드 정적 점검 (SAST)")
    c.add_argument("path", help="점검할 디렉터리 또는 파일")
    c.add_argument("--exclude", action="append", default=[], help="제외할 디렉터리 이름 (반복 지정 가능)")
    c.add_argument("--with-deps", action="store_true", help="의존성·공급망 점검도 함께 수행")
    c.add_argument("--osv", action="store_true", help="의존성 점검 시 OSV.dev 취약점 DB 조회 (네트워크 필요)")

    d = sub.add_parser("deps", parents=[common, ai], help="의존성·공급망 점검 (requirements.txt / package.json)")
    d.add_argument("path", help="점검할 디렉터리 또는 파일")
    d.add_argument("--exclude", action="append", default=[], help="제외할 디렉터리 이름 (반복 지정 가능)")
    d.add_argument("--osv", action="store_true", help="OSV.dev 취약점 DB 조회 (네트워크 필요)")

    w = sub.add_parser("web", parents=[common, ai], help="웹 애플리케이션 비파괴 점검 (DAST, passive)")
    w.add_argument("url", help="점검 대상 URL (예: https://example.com)")
    w.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    w.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략 (테스트 서버용)")
    w.add_argument("--no-paths", action="store_true", help="민감 파일 노출 경로 점검 생략")
    w.add_argument("-y", "--yes", action="store_true", help="점검 권한 확인 프롬프트 생략")

    rv = sub.add_parser("review", parents=[common, ai], help="저장된 JSON 리포트를 Claude로 오탐 검토")
    rv.add_argument("report", help="'-f json' 으로 저장한 점검 결과 파일")
    rv.add_argument("--root", help="소스코드 위치 (생략 시 리포트에 기록된 대상 경로)")

    r = sub.add_parser("rules", help="정적 점검 규칙 목록 출력")
    r.add_argument("--standard", choices=sorted(STANDARDS), default=DEFAULT_STANDARD)
    return p


def _filter(findings: list[Finding], args) -> list[Finding]:
    min_sev = Severity.parse(args.min_severity)
    result = [f for f in findings if f.severity >= min_sev]
    if args.owasp:
        wanted = {c.strip().upper() for c in args.owasp.split(",") if c.strip()}
        result = [f for f in result if f.category(args.standard) in wanted]
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


def _confirm_ai() -> bool:
    sys.stderr.write(AI_WARNING)
    if not sys.stdin.isatty():
        sys.stderr.write("대화형 터미널이 아니므로 --ai-yes 옵션으로 코드 전송에 동의해 주세요.\n")
        return False
    return input("계속할까요? [y/N] ").strip().lower() in ("y", "yes", "예", "ㅇ")


def _run_ai(findings: list[Finding], meta: dict, args, root: Path | None) -> list[Finding] | None:
    """AI 검토 및 라벨 평가를 수행한다. 계속할 수 없으면 None."""
    if args.ai_review:
        if not args.ai_yes and not _confirm_ai():
            print("AI 검토를 취소했습니다.", file=sys.stderr)
            return None

        def progress(done, total, f):
            print(f"\rAI 검토 중... {done}/{total}", end="" if done < total else "\n", file=sys.stderr, flush=True)

        try:
            reviewed = ai_review.review_findings(findings, root, model=args.ai_model, max_items=args.ai_max,
                                                 context_lines=args.ai_context, progress=progress)
        except ai_review.AIReviewError as exc:
            print(f"\n오류: {exc}", file=sys.stderr)
            return None
        counts = ai_review.ai_summary(findings)
        meta["ai_review"] = {"model": args.ai_model, "reviewed": reviewed, **counts}
        meta["notes"].append(
            f"AI 검토({args.ai_model}): {reviewed}건 검토 - 실제 취약점 {counts['true_positive']}, "
            f"오탐 {counts['false_positive']}, 수동 확인 필요 {counts['needs_review']}"
            + (f", 미검토 {counts['not_reviewed']}" if counts["not_reviewed"] else ""))
    if args.expected:
        try:
            result = ai_review.evaluate(findings, ai_review.load_labels(args.expected))
        except (OSError, ValueError, KeyError) as exc:
            print(f"오류: 라벨 파일을 읽을 수 없습니다: {exc}", file=sys.stderr)
            return None
        meta["evaluation"] = result
        meta["notes"].extend(ai_review.evaluation_notes(result))
    if args.ai_review and args.hide_fp:
        hidden = [f for f in findings if f.extra.get("ai", {}).get("verdict") == "false_positive"]
        if hidden:
            meta["notes"].append(f"AI가 오탐으로 판정한 {len(hidden)}건은 숨김(--hide-fp)")
        hidden_ids = {id(f) for f in hidden}
        findings = [f for f in findings if id(f) not in hidden_ids]
    return findings


def _load_report(path: str) -> tuple[list[Finding], dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = [Finding.from_dict(item) for item in data.get("findings", [])]
    return findings, data.get("meta", {})


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        print(f"{'규칙 ID':<26} 2025 2021 {'심각도':<6} {'CWE':<8} 제목")
        for r in RULES:
            code2025 = r.owasp2025 or MAP_2021_TO_2025[r.owasp]
            print(f"{r.id:<28} {code2025}  {r.owasp}  {r.severity.label:<8} {r.cwe:<8} {r.title}")
        print(f"\n총 {len(RULES)}개 규칙 / OWASP Top 10:{args.standard}")
        for code, name in STANDARDS[args.standard].items():
            print(f"  {code} {name}")
        return 0

    try:
        if args.fail_on:
            Severity.parse(args.fail_on)
        Severity.parse(args.min_severity)
    except ValueError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 2

    meta = {"mode": args.command, "standard": args.standard, "started": now_str(), "notes": []}
    try:
        if args.command == "code":
            findings, count = scan_path(args.path, set(args.exclude))
            meta.update(target=str(Path(args.path).resolve()), files_scanned=count)
            if args.with_deps:
                dep_findings, deps, err = scan_dependencies(args.path, args.osv, exclude_dirs=set(args.exclude))
                findings += dep_findings
                meta["notes"].append(f"의존성 {len(deps)}개 확인")
                if err:
                    meta["notes"].append(err)
        elif args.command == "deps":
            findings, deps, err = scan_dependencies(args.path, args.osv, exclude_dirs=set(args.exclude))
            meta.update(target=str(Path(args.path).resolve()), dependencies=len(deps))
            meta["notes"].append(f"의존성 {len(deps)}개 확인" + ("" if args.osv else " (OSV 조회는 --osv 옵션 사용)"))
            if err:
                meta["notes"].append(err)
        elif args.command == "review":
            try:
                findings, old_meta = _load_report(args.report)
            except (OSError, ValueError, KeyError) as exc:
                print(f"오류: 리포트 파일을 읽을 수 없습니다: {exc}", file=sys.stderr)
                return 2
            meta.update(target=args.root or old_meta.get("target"), source_report=args.report,
                        reviewed_mode=old_meta.get("mode"))
            if not args.ai_review and not args.expected:
                args.ai_review = True  # review 명령은 기본으로 AI 검토 수행
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
    root = None
    if args.command in ("code", "deps", "review") and meta.get("target"):
        root = Path(meta["target"])
        if args.command == "review" and not root.exists():
            meta["notes"].append(f"소스 경로 {root} 가 없어 코드 문맥 없이 검토합니다(--root 로 지정 가능)")
            root = None
    findings = _run_ai(findings, meta, args, root)
    if findings is None:
        return 2
    _emit(findings, meta, args)

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
