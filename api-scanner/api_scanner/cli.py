"""명령행 인터페이스.

사용 예:
    python3 -m api_scanner spec openapi.json                    # 명세 정적 점검
    python3 -m api_scanner spec https://api.example.com/openapi.json -f html -o report.html
    python3 -m api_scanner jwt "eyJhbGciOi..."                  # JWT 토큰 분석(오프라인)
    python3 -m api_scanner live openapi.json --base https://api.example.com --token <JWT>
    python3 -m api_scanner rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import API_TOP10_2023, Finding, Severity
from .report import now_str, render_html, render_json, render_text
from .spec import SpecError, base_url, load_spec

LIVE_WARNING = (
    "[주의] live 점검은 실제 서버에 요청을 보냅니다. 반드시 소유하거나 서면 허가를 받은 대상에만 수행하세요.\n"
    "       허가 없는 점검은 정보통신망법 등 관련 법률 위반이 될 수 있습니다. (읽기 전용 메서드만 사용합니다)\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="api-scanner",
                                description="OWASP API Security Top 10:2023 기준 API 취약점 점검 도구")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--format", choices=["text", "json", "html"], default="text", help="출력 형식 (기본: text)")
    common.add_argument("-o", "--output", help="결과를 저장할 파일 경로 (생략 시 표준 출력)")
    common.add_argument("--min-severity", default="info", help="이 심각도 이상만 표시 (info/low/medium/high/critical)")
    common.add_argument("--fail-on", default=None, help="이 심각도 이상 결과가 있으면 종료코드 1 반환 (CI 연동용)")
    common.add_argument("--category", default=None, help="특정 분류만 표시 (예: API1,API2)")
    common.add_argument("--no-color", action="store_true", help="텍스트 출력 색상 비활성화")

    sp = sub.add_parser("spec", parents=[common], help="OpenAPI/Swagger 명세 정적 점검 (서버에 요청하지 않음)")
    sp.add_argument("source", help="OpenAPI/Swagger 파일 경로 또는 URL (JSON은 설치 없이, YAML은 pyyaml 필요)")
    sp.add_argument("--token", help="명세에 더해 함께 분석할 JWT 토큰")

    jw = sub.add_parser("jwt", parents=[common], help="JWT 토큰 오프라인 분석 (서버에 보내지 않음)")
    jw.add_argument("token", help="분석할 JWT 문자열")
    jw.add_argument("--wordlist", help="추가 약한 비밀키 후보 파일 (한 줄에 하나)")

    lv = sub.add_parser("live", parents=[common], help="실제 서버 비파괴 점검 (authorized, 읽기 전용 메서드만)")
    lv.add_argument("source", help="OpenAPI/Swagger 파일 경로 또는 URL")
    lv.add_argument("--base", help="점검 대상 기본 URL (생략 시 명세의 servers 사용)")
    lv.add_argument("--token", help="사용자 A의 Bearer 토큰(JWT 등)")
    lv.add_argument("--token-b", dest="token_b", help="BOLA 교차 점검용 사용자 B의 토큰")
    lv.add_argument("--id", dest="sample_id", help="경로 파라미터({id} 등)에 넣을 샘플 값")
    lv.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    lv.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략 (테스트 서버용)")
    lv.add_argument("-y", "--yes", action="store_true", help="점검 권한 확인 프롬프트 생략")

    r = sub.add_parser("rules", help="점검 분류(OWASP API Top 10:2023) 목록 출력")
    return p


def _filter(findings: list[Finding], args) -> list[Finding]:
    min_sev = Severity.parse(args.min_severity)
    result = [f for f in findings if f.severity >= min_sev]
    if getattr(args, "category", None):
        wanted = {c.strip().upper() for c in args.category.split(",") if c.strip()}
        result = [f for f in result if f.category.upper() in wanted]
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


def _exit_code(findings: list[Finding], args) -> int:
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 1
    return 0


def _confirm_live(target: str) -> bool:
    sys.stderr.write(LIVE_WARNING)
    if not sys.stdin.isatty():
        sys.stderr.write("대화형 터미널이 아니므로 -y/--yes 옵션으로 점검 권한을 확인해 주세요.\n")
        return False
    answer = input(f"'{target}'에 대한 점검 권한이 있습니까? [y/N] ").strip().lower()
    return answer in ("y", "yes", "예", "ㅇ")


def _cmd_spec(args) -> int:
    from .jwt_check import analyze as jwt_analyze
    from .spec_scan import scan_spec
    try:
        spec = load_spec(args.source)
    except (SpecError, OSError, ValueError) as exc:
        print(f"[오류] 명세를 읽지 못했습니다: {exc}", file=sys.stderr)
        return 2
    findings = scan_spec(spec)
    if args.token:
        findings += jwt_analyze(args.token)
    findings = _filter(findings, args)
    meta = {"mode": "spec (명세 정적 점검)", "target": args.source, "started": now_str(),
            "operations": len(spec.operations),
            "notes": [f"명세 제목: {spec.title}" if spec.title else "", f"OpenAPI {spec.version}"]}
    meta["notes"] = [n for n in meta["notes"] if n]
    _emit(findings, meta, args)
    return _exit_code(findings, args)


def _cmd_jwt(args) -> int:
    from .jwt_check import analyze as jwt_analyze
    wordlist = None
    if args.wordlist:
        wordlist = [l.strip() for l in Path(args.wordlist).read_text(encoding="utf-8").splitlines() if l.strip()]
    findings = jwt_analyze(args.token, wordlist=wordlist)
    if not findings:
        print("JWT 형식이 아니거나(불투명 토큰) 분석할 문제를 찾지 못했습니다.", file=sys.stderr)
    findings = _filter(findings, args)
    meta = {"mode": "jwt (토큰 오프라인 분석)", "target": "제공된 JWT", "started": now_str(),
            "notes": ["토큰은 서버로 전송되지 않고 로컬에서만 분석됩니다."]}
    _emit(findings, meta, args)
    return _exit_code(findings, args)


def _cmd_live(args) -> int:
    from .jwt_check import analyze as jwt_analyze
    from .live_scan import LiveScanner
    from .spec_scan import scan_spec
    try:
        spec = load_spec(args.source)
    except (SpecError, OSError, ValueError) as exc:
        print(f"[오류] 명세를 읽지 못했습니다: {exc}", file=sys.stderr)
        return 2
    base = base_url(spec, args.base)
    if not base:
        print("[오류] 점검 대상 URL을 알 수 없습니다. --base 로 지정하세요.", file=sys.stderr)
        return 2
    if not args.yes and not _confirm_live(base):
        print("점검을 취소했습니다.", file=sys.stderr)
        return 2
    findings = list(scan_spec(spec))  # 명세 정적 점검도 함께 포함
    for tok in (args.token, args.token_b):
        if tok:
            findings += jwt_analyze(tok)
    scanner = LiveScanner(spec, base, token=args.token, token_b=args.token_b,
                          sample_id=args.sample_id, timeout=args.timeout, insecure=args.insecure)
    findings += scanner.run()
    findings = _filter(findings, args)
    note = "읽기 전용 메서드(GET/HEAD/OPTIONS)만 사용했습니다."
    if not (args.token and args.token_b):
        note += " BOLA 교차 점검은 --token 과 --token-b 를 모두 지정해야 수행됩니다."
    meta = {"mode": "live (실서버 비파괴 점검)", "target": base, "started": now_str(),
            "operations": len(spec.operations), "notes": [note]}
    _emit(findings, meta, args)
    return _exit_code(findings, args)


def _cmd_rules(args) -> int:
    print("OWASP API Security Top 10:2023 분류:\n")
    for code, name in API_TOP10_2023.items():
        print(f"  {code:<6} {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"spec": _cmd_spec, "jwt": _cmd_jwt, "live": _cmd_live, "rules": _cmd_rules}[args.command](args)
    except KeyboardInterrupt:
        print("\n중단되었습니다.", file=sys.stderr)
        return 130
