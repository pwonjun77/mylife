"""의존성 점검 (A06 Vulnerable and Outdated Components).

- requirements*.txt 와 package.json 을 파싱한다.
- 공급망(2025 A03): Git/URL 의존성, npm 설치 스크립트, lock 파일 누락을 점검한다.
- 버전 미고정(unpinned) 의존성을 경고한다.
- --osv 옵션 사용 시 OSV.dev 공개 취약점 DB에 조회한다(네트워크 필요).
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, Severity
from .static_scan import DEFAULT_EXCLUDE_DIRS

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


@dataclass
class Dependency:
    name: str
    version: str | None  # 정확히 고정된 버전만 기록, 범위 지정이면 None
    spec: str
    ecosystem: str  # "PyPI" | "npm"
    source: str


_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(text: str, source: str) -> list[Dependency]:
    deps = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        line = line.split(";", 1)[0].strip()  # 환경 마커 제거
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name, spec = m.group(1), m.group(3).strip()
        pinned = re.fullmatch(r"===?\s*([A-Za-z0-9.\-+!]+)", spec)
        deps.append(Dependency(name, pinned.group(1) if pinned else None, spec, "PyPI", source))
    return deps


def parse_package_json(text: str, source: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            pinned = re.fullmatch(r"v?=?(\d+\.\d+\.\d+[A-Za-z0-9.\-+]*)", spec)
            deps.append(Dependency(name, pinned.group(1) if pinned else None, spec, "npm", source))
    return deps


def collect_dependencies(root: Path, exclude_dirs: set[str] = frozenset()) -> list[Dependency]:
    deps: list[Dependency] = []
    paths = [root] if root.is_file() else []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS | exclude_dirs]
            paths.extend(Path(dirpath) / f for f in filenames)
    for path in sorted(paths):
        rel = str(path.relative_to(root)) if root.is_dir() else str(path)
        name = path.name.lower()
        try:
            if re.fullmatch(r"requirements.*\.txt", name):
                deps += parse_requirements(path.read_text(encoding="utf-8", errors="ignore"), rel)
            elif name == "package.json":
                deps += parse_package_json(path.read_text(encoding="utf-8", errors="ignore"), rel)
        except OSError:
            continue
    return deps


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


def check_npm_supply_chain(root: Path, exclude_dirs: set[str] = frozenset()) -> list[Finding]:
    """package.json 별 lock 파일 존재 여부와 설치 시 실행되는 스크립트를 점검한다."""
    manifests = [root] if root.is_file() and root.name == "package.json" else []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS | exclude_dirs]
            if "package.json" in filenames:
                manifests.append(Path(dirpath) / "package.json")
    findings = []
    for path in sorted(manifests):
        rel = str(path.relative_to(root)) if root.is_dir() else str(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            continue
        has_deps = any(data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies"))
        if has_deps and not any((path.parent / lock).exists() for lock in NPM_LOCKFILES):
            findings.append(Finding(
                "A08-NO-LOCKFILE", "npm lock 파일 없음", "A08", Severity.LOW, rel,
                "lock 파일이 없으면 설치할 때마다 하위 의존성 버전이 달라져, 침해된 패키지 버전이 유입될 수 있습니다.",
                "package-lock.json 등 lock 파일을 커밋하고 CI에서는 npm ci 로 설치하세요.",
                "lock 파일 없음", "CWE-1357", owasp2025="A03",
            ))
        for hook in INSTALL_HOOKS:
            cmd = (data.get("scripts") or {}).get(hook)
            if cmd:
                findings.append(Finding(
                    "A08-INSTALL-SCRIPT", f"설치 시 자동 실행되는 스크립트 ({hook})", "A08", Severity.INFO, rel,
                    "설치 훅 스크립트는 공급망 공격에서 악성 코드 실행 경로로 자주 악용됩니다.",
                    "스크립트 내용을 검토하고, 필요 없으면 제거하거나 npm install --ignore-scripts 사용을 검토하세요.",
                    f"{hook}: {cmd}"[:150], "CWE-506", owasp2025="A03",
                ))
    return findings


def _is_wide_range(dep: Dependency) -> bool:
    spec = dep.spec.strip()
    if dep.ecosystem == "PyPI":
        return spec == "" or (">" in spec and "<" not in spec)
    return spec in ("*", "", "latest", "x") or spec.startswith(">")


def _osv_severity(vuln: dict) -> Severity:
    text = json.dumps(vuln.get("database_specific", {})).upper()
    for keyword, level in (("CRITICAL", Severity.CRITICAL), ("HIGH", Severity.HIGH),
                           ("MODERATE", Severity.MEDIUM), ("MEDIUM", Severity.MEDIUM), ("LOW", Severity.LOW)):
        if keyword in text:
            return level
    return Severity.HIGH


def _http_json(url: str, payload: dict | None, timeout: float) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - 고정된 OSV 주소
        return json.loads(resp.read().decode())


def query_osv(deps: list[Dependency], timeout: float = 15.0) -> list[Finding]:
    pinned = [d for d in deps if d.version]
    if not pinned:
        return []
    queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in pinned]
    result = _http_json(OSV_BATCH_URL, {"queries": queries}, timeout)
    findings = []
    details_cache: dict[str, dict] = {}
    for dep, res in zip(pinned, result.get("results", [])):
        for v in res.get("vulns", []) or []:
            vid = v["id"]
            if vid not in details_cache:
                try:
                    details_cache[vid] = _http_json(OSV_VULN_URL + vid, None, timeout)
                except Exception:  # 상세 조회 실패 시 ID만 보고
                    details_cache[vid] = {"id": vid}
            detail = details_cache[vid]
            aliases = ", ".join(a for a in detail.get("aliases", []) if a.startswith("CVE-"))
            findings.append(Finding(
                rule_id=f"A06-{vid}",
                title=f"{dep.name}=={dep.version} 알려진 취약점 {vid}" + (f" ({aliases})" if aliases else ""),
                owasp="A06",
                severity=_osv_severity(detail),
                location=dep.source,
                description=detail.get("summary") or "OSV 데이터베이스에 등록된 취약점이 있습니다.",
                recommendation=f"{dep.name} 패키지를 패치된 버전으로 업그레이드하세요. 상세: https://osv.dev/vulnerability/{vid}",
                evidence=f"{dep.name} {dep.spec}",
                cwe="CWE-1104",
            ))
    return findings


def scan_dependencies(target: str | os.PathLike, use_osv: bool = False, timeout: float = 15.0,
                      exclude_dirs: set[str] | None = None) -> tuple[list[Finding], list[Dependency], str | None]:
    """(결과, 수집된 의존성, OSV 오류 메시지) 반환."""
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"경로를 찾을 수 없습니다: {root}")
    exclude = exclude_dirs or set()
    deps = collect_dependencies(root, exclude)
    findings: list[Finding] = []
    for dep in deps:
        if dep.spec.startswith(("git", "http", "file:", "github:")) or "://" in dep.spec:
            findings.append(Finding(
                "A08-UNVERIFIED-SOURCE", f"{dep.name}: 레지스트리 외부 소스에서 설치", "A08", Severity.MEDIUM,
                dep.source, "Git/URL 의존성은 무결성 검증 및 취약점 추적이 어렵습니다.",
                "공식 레지스트리의 고정 버전을 사용하거나 커밋 해시로 고정하세요.", f"{dep.name} {dep.spec}", "CWE-494",
                owasp2025="A03",
            ))
        elif _is_wide_range(dep):
            findings.append(Finding(
                "A06-UNPINNED", f"{dep.name}: 버전 미고정 의존성", "A06", Severity.LOW,
                dep.source, "버전 범위가 열려 있어 검증되지 않은 버전이나 악성 업데이트가 설치될 수 있습니다.",
                "lock 파일(poetry.lock, package-lock.json 등)을 사용하거나 정확한 버전을 고정하세요.",
                f"{dep.name} {dep.spec or '(버전 지정 없음)'}", "CWE-1104",
            ))
    findings += check_npm_supply_chain(root, exclude)
    osv_error = None
    if use_osv:
        try:
            findings += query_osv(deps, timeout)
        except Exception as exc:
            osv_error = f"OSV 조회 실패: {exc}"
    return findings, deps, osv_error
