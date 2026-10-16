"""의존성 점검 (A06 Vulnerable and Outdated Components).

- requirements*.txt 와 package.json 을 파싱한다.
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


def collect_dependencies(root: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    paths = [root] if root.is_file() else []
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS]
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


def scan_dependencies(target: str | os.PathLike, use_osv: bool = False,
                      timeout: float = 15.0) -> tuple[list[Finding], list[Dependency], str | None]:
    """(결과, 수집된 의존성, OSV 오류 메시지) 반환."""
    root = Path(target)
    if not root.exists():
        raise FileNotFoundError(f"경로를 찾을 수 없습니다: {root}")
    deps = collect_dependencies(root)
    findings: list[Finding] = []
    for dep in deps:
        if dep.spec.startswith(("git", "http", "file:", "github:")) or "://" in dep.spec:
            findings.append(Finding(
                "A08-UNVERIFIED-SOURCE", f"{dep.name}: 레지스트리 외부 소스에서 설치", "A08", Severity.MEDIUM,
                dep.source, "Git/URL 의존성은 무결성 검증 및 취약점 추적이 어렵습니다.",
                "공식 레지스트리의 고정 버전을 사용하거나 커밋 해시로 고정하세요.", f"{dep.name} {dep.spec}", "CWE-494",
            ))
        elif _is_wide_range(dep):
            findings.append(Finding(
                "A06-UNPINNED", f"{dep.name}: 버전 미고정 의존성", "A06", Severity.LOW,
                dep.source, "버전 범위가 열려 있어 검증되지 않은 버전이나 악성 업데이트가 설치될 수 있습니다.",
                "lock 파일(poetry.lock, package-lock.json 등)을 사용하거나 정확한 버전을 고정하세요.",
                f"{dep.name} {dep.spec or '(버전 지정 없음)'}", "CWE-1104",
            ))
    osv_error = None
    if use_osv:
        try:
            findings += query_osv(deps, timeout)
        except Exception as exc:
            osv_error = f"OSV 조회 실패: {exc}"
    return findings, deps, osv_error
