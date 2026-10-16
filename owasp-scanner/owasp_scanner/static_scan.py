"""소스코드 정적 점검(SAST) 엔진."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .models import Finding
from .rules import RULES, Rule

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor", "site-packages",
    ".idea", ".vscode", "coverage", ".next",
}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB 초과 파일은 생성물/바이너리로 보고 건너뜀
MAX_LINE_LENGTH = 2000  # 압축(minified)된 긴 줄은 건너뜀

# 줄 끝에 이 주석이 있으면 해당 줄의 탐지를 무시한다.
SUPPRESS_RE = re.compile(r"(#|//|/\*|<!--)\s*(nosec|owasp-ignore)\b", re.I)
# 파일 앞부분 5줄 안에 이 표시가 있으면 파일 전체를 건너뛴다(규칙 정의 파일 등).
IGNORE_FILE_RE = re.compile(r"owasp-ignore-file", re.I)
COMMENT_RE = re.compile(r"^\s*(#|//|\*|/\*|<!--)")


def _suffix(path: Path) -> str:
    # ".env", ".env.local" 같은 파일은 .env로 취급
    if path.name.startswith(".env"):
        return ".env"
    return path.suffix.lower()


def iter_files(root: Path, exclude_dirs: set[str]) -> list[Path]:
    if root.is_file():
        return [root]
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return sorted(files)


def scan_text(text: str, location: str, suffix: str, rules: list[Rule] = RULES) -> list[Finding]:
    applicable = [r for r in rules if suffix in r.extensions]
    if not applicable or IGNORE_FILE_RE.search("\n".join(text.splitlines()[:5])):
        return []
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH or not line.strip():
            continue
        if SUPPRESS_RE.search(line):
            continue
        is_comment = bool(COMMENT_RE.match(line))
        for rule in applicable:
            # 주석에 있는 코드 예시는 무시하되, 비밀정보/키는 주석이어도 위험하므로 탐지
            if is_comment and not rule.id.startswith(("A02-HARDCODED", "A02-CLOUD", "A02-PRIVATE")):
                continue
            if not rule.pattern.search(line):
                continue
            if rule.exclude and rule.exclude.search(line):
                continue
            findings.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                owasp=rule.owasp,
                severity=rule.severity,
                location=location,
                line=lineno,
                description=rule.description,
                recommendation=rule.recommendation,
                evidence=_mask(line.strip())[:200],
                cwe=rule.cwe,
            ))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """같은 줄에서 SQLI와 SQLI-CONCAT이 모두 걸리면 더 심각한 하나만 남긴다."""
    by_line: dict[tuple[str, int | None, str], Finding] = {}
    for f in findings:
        group = f.rule_id.split("-")[1] if "-" in f.rule_id else f.rule_id
        key = (f.location, f.line, f.owasp + group)
        if key not in by_line or f.severity > by_line[key].severity:
            by_line[key] = f
    return list(by_line.values())


_SECRET_VALUE_RE = re.compile(
    r"((?:password|passwd|pwd|secret|key|token)\w*['\"]?\s*[:=]\s*['\"])([^'\"]{2})([^'\"]*)(['\"])", re.I
)
_KEY_RE = re.compile(r"\b(AKIA|AIza|gh[pousr]_|xox[baprs]-|sk_live_)([A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]+")


def _mask(line: str) -> str:
    """증거(evidence)로 출력할 때 비밀값을 가린다."""
    line = _SECRET_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}****{m.group(4)}", line)
    return _KEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}****", line)


def scan_path(target: str | os.PathLike, exclude_dirs: set[str] | None = None,
              rules: list[Rule] = RULES) -> tuple[list[Finding], int]:
    """경로를 점검하고 (결과 목록, 점검한 파일 수)를 반환한다."""
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"경로를 찾을 수 없습니다: {root}")
    exclude = DEFAULT_EXCLUDE_DIRS | (exclude_dirs or set())
    findings: list[Finding] = []
    scanned = 0
    for path in iter_files(root, exclude):
        suffix = _suffix(path)
        if not any(suffix in r.extensions for r in rules):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        rel = str(path.relative_to(root)) if root.is_dir() else str(path)
        findings.extend(scan_text(text, rel, suffix, rules))
    return findings, scanned
