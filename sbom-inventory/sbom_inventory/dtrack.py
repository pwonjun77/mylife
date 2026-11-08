"""OWASP Dependency-Track 업로드 (REST API v1, Dependency-Track 4.x).

흐름
  1) (선택) 상위 프로젝트(예: corporate-network) 확인/생성 → 포트폴리오를 장비 단위 하위 프로젝트로 구성
  2) 자산마다 장비 단위 CycloneDX BOM 생성 → PUT /api/v1/bom  (autoCreate, base64 BOM)
       응답 token 으로 GET /api/v1/event/token/{token} 를 폴링해 BOM 처리 완료 대기
  3) (선택) GET /api/v1/finding/project/{uuid} 로 취약점 결과 회수

왜 장비 1대 = 프로젝트 1개인가
  Dependency-Track 은 '프로젝트' 단위로 취약점/정책/메트릭을 계산한다. 전사 BOM 하나로 올리면
  어느 PC 에 취약 버전이 있는지 구분이 안 되므로, hostname 을 프로젝트명으로 쓰고 상위 프로젝트로 묶는다.

인증: 환경변수 DTRACK_API_KEY (X-Api-Key 헤더). 팀 권한:
  BOM_UPLOAD, PROJECT_CREATION_UPLOAD(autoCreate), VIEW_PORTFOLIO, VIEW_VULNERABILITY(결과 조회),
  PORTFOLIO_MANAGEMENT(상위 프로젝트 자동 생성 시에만)

주의: Dependency-Track 은 업로드할 때마다 프로젝트 컴포넌트를 '교체'한다(현재 상태 뷰).
     시점별 이력은 이 도구의 SQLite(run)에 남고, --version-from-run 을 쓰면 DT 에도 run 별 버전으로 남는다.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from .export import cyclonedx
from .store import Store, asset_label

UA = "sbom-inventory/0.1"


class DTrackError(RuntimeError):
    pass


@dataclass
class UploadResult:
    asset: str
    project: str
    version: str
    components: int
    token: str = ""
    uuid: str = ""
    processed: bool = False
    findings: list[dict] = field(default_factory=list)
    error: str = ""


class DTrackClient:
    def __init__(self, url: str, api_key: str, ca_bundle: str | None = None, timeout: int = 60,
                 opener: Callable | None = None):
        self.base = url.rstrip("/")
        if self.base.endswith("/api"):
            self.base = self.base[:-4]
        self._key = api_key
        self.timeout = timeout
        self._ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else None
        self._open = opener

    def __repr__(self) -> str:  # API 키가 로그에 남지 않게
        return f"DTrackClient({self.base})"

    def request(self, method: str, path: str, body: dict | None = None, ok404: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "X-Api-Key": self._key, "Accept": "application/json", "User-Agent": UA,
            **({"Content-Type": "application/json"} if data is not None else {})})
        try:
            if self._open:
                resp = self._open(req, timeout=self.timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx)
            with resp as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return None
            msg = e.read().decode(errors="replace")[:300]
            hint = {401: " (API 키 확인)", 403: " (팀 권한 확인: BOM_UPLOAD / PROJECT_CREATION_UPLOAD 등)"}.get(e.code, "")
            raise DTrackError(f"{method} {path} → HTTP {e.code}{hint}: {msg}") from None
        except urllib.error.URLError as e:
            raise DTrackError(f"{self.base} 연결 실패: {e.reason}") from None

    # ---------------------------------------------------------------- API
    def version(self) -> dict:
        return self.request("GET", "/api/version")

    def lookup(self, name: str, version: str) -> dict | None:
        q = urllib.parse.urlencode({"name": name, "version": version})
        return self.request("GET", f"/api/v1/project/lookup?{q}", ok404=True)

    def ensure_project(self, name: str, version: str, description: str = "") -> dict:
        p = self.lookup(name, version)
        if p:
            return p
        return self.request("PUT", "/api/v1/project", {
            "name": name, "version": version, "classifier": "NONE", "active": True, "description": description})

    def upload_bom(self, bom: dict, name: str, version: str, parent: tuple[str, str] | None = None,
                   tags: list[str] | None = None, is_latest: bool = False) -> str:
        body = {"projectName": name, "projectVersion": version, "autoCreate": True,
                "bom": base64.b64encode(json.dumps(bom, ensure_ascii=False).encode()).decode()}
        if parent:
            body["parentName"], body["parentVersion"] = parent
        if tags:
            body["projectTags"] = [{"name": t} for t in tags]
        if is_latest:
            body["isLatest"] = True
        return self.request("PUT", "/api/v1/bom", body).get("token", "")

    def wait(self, token: str, timeout: int = 300, interval: float = 2.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            st = self.request("GET", f"/api/v1/event/token/{token}", ok404=True)
            if st is None:  # 4.x 초기 버전 호환
                st = self.request("GET", f"/api/v1/bom/token/{token}")
            if not st.get("processing"):
                return True
            time.sleep(interval)
        return False

    def findings(self, uuid: str) -> list[dict]:
        return self.request("GET", f"/api/v1/finding/project/{uuid}") or []


def _tags(a) -> list[str]:
    tags = [f"source-{s}" for s in json.loads(a["sources"])]
    if a["os"]:
        tags.append("os-" + a["os"].split()[0].lower())
    if json.loads(a["sources"]) == ["nmap"]:
        tags.append("unmanaged")
    return tags


def push(store: Store, client: DTrackClient, *, run_id: int | None = None, assets: list[str] | None = None,
         parent: str | None = "corporate-network", project_version: str = "current", version_from_run: bool = False,
         prefix: str = "", wait: bool = True, fetch_findings: bool = False, tags: bool = True,
         dry_run: bool = False, log: Callable[[str], None] = print) -> list[UploadResult]:
    run_id = run_id or store.latest_run_id()
    if run_id is None:
        raise DTrackError("업로드할 run 이 없습니다 (먼저 수집을 실행하세요)")
    version = f"run-{run_id}" if version_from_run else project_version
    rows = [store.asset(x) for x in assets] if assets else store.assets()
    if any(r is None for r in rows):
        raise DTrackError(f"자산을 찾을 수 없음: {[x for x, r in zip(assets or [], rows) if r is None]}")

    parent_ref = None
    if parent and not dry_run:
        try:
            client.ensure_project(parent, "current", "sbom-inventory 가 관리하는 사내 장비 포트폴리오")
            parent_ref = (parent, "current")
        except DTrackError as e:
            log(f"[경고] 상위 프로젝트 '{parent}' 준비 실패 → 상위 없이 업로드합니다: {e}")

    results: list[UploadResult] = []
    for a in rows:
        bom = cyclonedx(store, run_id, str(a["id"]))
        name = prefix + asset_label(a)
        res = UploadResult(asset=asset_label(a), project=name, version=version, components=len(bom["components"]))
        if not bom["components"]:
            res.error = "컴포넌트 없음 — 건너뜀"
            results.append(res)
            continue
        if dry_run:
            results.append(res)
            continue
        try:
            res.token = client.upload_bom(bom, name, version, parent_ref, _tags(a) if tags else None,
                                          is_latest=version_from_run)
            if wait or fetch_findings:
                res.processed = client.wait(res.token)
            p = client.lookup(name, version)
            res.uuid = (p or {}).get("uuid", "")
            if fetch_findings and res.uuid:
                res.findings = client.findings(res.uuid)
        except DTrackError as e:
            res.error = str(e)
        log(f"  {'OK ' if not res.error else 'ERR'} {name:<28} {version:<10} 컴포넌트 {res.components:>5}"
            f"{'  취약점 ' + str(len(res.findings)) if fetch_findings else ''}{'  ' + res.error if res.error else ''}")
        results.append(res)
    return results


def client_from_env(url: str | None, ca_bundle: str | None = None) -> DTrackClient:
    url = url or os.environ.get("DTRACK_URL", "")
    key = os.environ.get("DTRACK_API_KEY", "")
    if not url:
        raise DTrackError("Dependency-Track 주소를 --url 또는 DTRACK_URL 로 지정하세요 (예: https://dtrack.corp.local)")
    if not key:
        raise DTrackError("환경변수 DTRACK_API_KEY 를 설정하세요 (Administration > Access Management > Teams > API Keys)")
    host = urllib.parse.urlparse(url).hostname or ""
    if url.startswith("http://") and host not in ("localhost", "127.0.0.1", "::1"):
        print(f"[경고] {url} 는 평문 HTTP 입니다. API 키와 인벤토리가 암호화 없이 전송됩니다.", flush=True)
    return DTrackClient(url, key, ca_bundle or os.environ.get("DTRACK_CA_BUNDLE"))
