"""Microsoft 365 수집기 — Intune(Microsoft Graph) / Defender for Endpoint API.

인증: Entra ID 앱 등록 + OAuth2 client credentials (앱 전용, 사용자 로그인 없음).
     비밀값은 명령행/설정파일이 아니라 환경변수로만 받는다 (프로세스 목록·셸 히스토리 노출 방지).
       SBOM_TENANT_ID, SBOM_CLIENT_ID, SBOM_CLIENT_SECRET

필요 권한 (Application, 관리자 동의, 모두 읽기 전용):
  Intune   : Microsoft Graph > DeviceManagementManagedDevices.Read.All
             (+ export 모드는 DeviceManagementConfiguration.Read.All 또는 Reports 권한이 추가로 필요할 수 있음)
  Defender : WindowsDefenderATP > Machine.Read.All, Software.Read.All

수집 경로:
  intune  per-app : GET /deviceManagement/detectedApps → 앱별 /managedDevices  (v1.0, 소~중규모)
  intune  export  : POST /deviceManagement/reports/exportJobs (AppInvRawData) → CSV zip 다운로드 (대규모 권장)
  defender        : GET /api/machines (IP·DNS명) + /api/machines/SoftwareInventoryByMachine (TVM 인벤토리)
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Callable, Iterator

from ..models import Asset, Component, HostRecord, make_purl

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"
MDE = "https://api.security.microsoft.com"
UA = "sbom-inventory/0.1"


class AuthError(RuntimeError):
    pass


def credentials_from_env() -> tuple[str, str, str]:
    t, c, s = (os.environ.get(k, "") for k in ("SBOM_TENANT_ID", "SBOM_CLIENT_ID", "SBOM_CLIENT_SECRET"))
    if not (t and c and s):
        raise AuthError("환경변수 SBOM_TENANT_ID / SBOM_CLIENT_ID / SBOM_CLIENT_SECRET 를 설정하세요")
    return t, c, s


class ApiClient:
    """토큰 발급 + 페이지네이션(@odata.nextLink) + 429/5xx 재시도를 처리하는 최소 HTTP 클라이언트."""

    def __init__(self, tenant: str, client_id: str, secret: str, resource: str,
                 opener: Callable | None = None, max_retries: int = 5):
        self.tenant, self.client_id, self._secret = tenant, client_id, secret
        self.resource = resource
        self._token: str | None = None
        self._exp = 0.0
        self._open = opener or urllib.request.urlopen
        self.max_retries = max_retries

    def __repr__(self) -> str:  # 비밀값이 로그/트레이스백에 찍히지 않도록
        return f"ApiClient(tenant={self.tenant}, client_id={self.client_id}, resource={self.resource})"

    def token(self) -> str:
        if self._token and time.time() < self._exp - 120:
            return self._token
        body = urllib.parse.urlencode({
            "client_id": self.client_id, "client_secret": self._secret,
            "grant_type": "client_credentials", "scope": f"{self.resource}/.default",
        }).encode()
        req = urllib.request.Request(f"{LOGIN}/{self.tenant}/oauth2/v2.0/token", data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA})
        try:
            with self._open(req, timeout=30) as r:
                tok = json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise AuthError(f"토큰 발급 실패 HTTP {e.code}: {detail}") from None
        self._token = tok["access_token"]
        self._exp = time.time() + int(tok.get("expires_in", 3600))
        return self._token

    def request(self, method: str, url: str, body: dict | None = None, raw: bool = False):
        if not url.startswith("http"):
            url = self.resource + url
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(self.max_retries + 1):
            headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json", "User-Agent": UA}
            if data is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with self._open(req, timeout=120) as r:
                    payload = r.read()
                    return payload if raw else (json.loads(payload) if payload else {})
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    wait = int(e.headers.get("Retry-After", 0) or 0) if e.headers else 0
                    time.sleep(max(wait, 2 ** attempt))
                    continue
                if e.code == 401 and attempt == 0:
                    self._token = None
                    continue
                raise RuntimeError(f"{method} {url} → HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from None
        raise RuntimeError(f"{method} {url}: 재시도 한도 초과")

    def get_all(self, url: str) -> Iterator[dict]:
        while url:
            page = self.request("GET", url)
            yield from page.get("value", [])
            url = page.get("@odata.nextLink", "")


# ======================================================================== Intune

def _device_asset(d: dict) -> Asset:
    return Asset(
        hostname=d.get("deviceName", ""), serial=d.get("serialNumber", ""),
        macs=[d.get("wiFiMacAddress", ""), d.get("ethernetMacAddress", "")],
        os=d.get("operatingSystem", ""), os_version=d.get("osVersion", ""),
        extra={k: d.get(k) for k in ("id", "azureADDeviceId", "userPrincipalName", "manufacturer", "model",
                                     "lastSyncDateTime", "complianceState") if d.get(k)},
    )


def _app_component(app: dict, source: str = "intune") -> Component:
    name, ver, pub = app.get("displayName", ""), app.get("version", ""), app.get("publisher", "") or ""
    return Component(name=name, version=ver, vendor=pub, type="application",
                     purl=make_purl("generic", name, ver, namespace=pub),
                     props={"platform": app.get("platform", ""), "evidence": f"{source} detectedApps"})


DEVICE_SELECT = ("id,deviceName,serialNumber,operatingSystem,osVersion,wiFiMacAddress,ethernetMacAddress,"
                 "azureADDeviceId,userPrincipalName,manufacturer,model,lastSyncDateTime,complianceState")


def collect_intune(client: ApiClient, mode: str = "per-app", progress: Callable[[str], None] = lambda s: None
                   ) -> list[HostRecord]:
    devices = {d["id"]: d for d in client.get_all(f"/v1.0/deviceManagement/managedDevices?$select={DEVICE_SELECT}")}
    progress(f"Intune 관리 장비 {len(devices)}대")
    by_dev: dict[str, list[Component]] = {i: [] for i in devices}

    if mode == "export":
        for row in _intune_export(client, progress):
            did = row.get("DeviceId", "")
            if did not in by_dev:
                continue
            by_dev[did].append(_app_component({
                "displayName": row.get("ApplicationName", ""),
                "version": row.get("ApplicationVersion", "") or row.get("ApplicationShortVersion", ""),
                "publisher": row.get("ApplicationPublisher", ""), "platform": row.get("Platform", ""),
            }))
    else:
        apps = list(client.get_all("/v1.0/deviceManagement/detectedApps?$top=50"))
        progress(f"Intune 탐지 앱 {len(apps)}종 — 앱별 설치 장비 조회 중")
        for i, app in enumerate(apps, 1):
            comp_proto = app
            for d in client.get_all(f"/v1.0/deviceManagement/detectedApps/{app['id']}/managedDevices?$select=id"):
                if d.get("id") in by_dev:
                    by_dev[d["id"]].append(_app_component(comp_proto))
            if i % 100 == 0:
                progress(f"  {i}/{len(apps)}")

    return [HostRecord(source="intune", asset=_device_asset(devices[i]), components=c) for i, c in by_dev.items()]


def _intune_export(client: ApiClient, progress, timeout: int = 900) -> Iterator[dict]:
    """Intune 보고서 내보내기(AppInvRawData) — 장비×앱 원시 데이터를 CSV(zip) 한 번에 받는다."""
    job = client.request("POST", "/beta/deviceManagement/reports/exportJobs",
                         {"reportName": "AppInvRawData", "format": "csv", "localizationType": "replaceLocalizableValues"})
    jid, start = job["id"], time.time()
    while True:
        st = client.request("GET", f"/beta/deviceManagement/reports/exportJobs('{jid}')")
        if st.get("status") == "completed":
            break
        if st.get("status") == "failed" or time.time() - start > timeout:
            raise RuntimeError(f"Intune export job 실패/시간초과: {st.get('status')}")
        progress("  export job 대기 중...")
        time.sleep(10)
    # 다운로드 URL 은 SAS 서명된 Blob URL → Authorization 헤더 없이 받는다.
    with client._open(urllib.request.Request(st["url"], headers={"User-Agent": UA}), timeout=300) as r:
        blob = r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for name in z.namelist():
            if name.lower().endswith(".csv"):
                text = z.read(name).decode("utf-8-sig", errors="replace")
                yield from csv.DictReader(io.StringIO(text))


# ======================================================================== Defender for Endpoint (TVM)

def collect_defender(client: ApiClient, progress: Callable[[str], None] = lambda s: None) -> list[HostRecord]:
    machines = {m["id"]: m for m in client.get_all("/api/machines")}
    progress(f"Defender 장비 {len(machines)}대")
    recs: dict[str, HostRecord] = {}
    for mid, m in machines.items():
        ips = [m.get("lastIpAddress", "")] + [ip.get("ipAddress", "") for ip in (m.get("ipAddresses") or [])]
        macs = [ip.get("macAddress", "") for ip in (m.get("ipAddresses") or [])]
        recs[mid] = HostRecord(source="defender", asset=Asset(
            hostname=m.get("computerDnsName", ""), fqdn=m.get("computerDnsName", ""),
            ips=[i for i in ips if i], macs=macs, os=m.get("osPlatform", ""),
            os_version=str(m.get("osBuild") or m.get("version") or ""),
            extra={"mde_id": mid, "aadDeviceId": m.get("aadDeviceId"), "riskScore": m.get("riskScore"),
                   "lastSeen": m.get("lastSeen")}))

    n = 0
    for row in client.get_all("/api/machines/SoftwareInventoryByMachine?pageSize=50000"):
        rec = recs.get(row.get("deviceId", ""))
        if rec is None:
            continue
        name, ver, vendor = row.get("softwareName", ""), row.get("softwareVersion", ""), row.get("softwareVendor", "")
        rec.components.append(Component(
            name=name.replace("_", " "), version=ver or "", vendor=vendor or "", type="application",
            purl=make_purl("generic", name, ver or "", namespace=vendor or ""),
            # Defender 는 소프트웨어를 cpe 스타일 vendor/product 로 식별 → CPE 2.3 로 구성 가능
            cpe=f"cpe:2.3:a:{vendor}:{name}:{ver or '*'}:*:*:*:*:*:*:*" if vendor and name else "",
            props={k: str(row[k]) for k in ("numberOfWeaknesses", "endOfSupportStatus", "endOfSupportDate",
                                             "diskPaths", "registryPaths") if row.get(k) not in (None, "", [])}
                  | {"evidence": "defender TVM"}))
        n += 1
    progress(f"Defender 소프트웨어 레코드 {n}건")
    return list(recs.values())
