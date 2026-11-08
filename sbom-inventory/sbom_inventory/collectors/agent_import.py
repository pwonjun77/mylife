"""에이전트(스크립트) 결과 수집기.

agents/collect-windows.ps1, agents/collect-linux.sh 가 각 호스트에서 만든 JSON 파일을 읽는다.
배포 방법: Intune 플랫폼 스크립트/Remediation, GPO 시작 스크립트, SCCM 없이 schtasks, Ansible/cron 등.
결과 파일은 수집 공유폴더(\\\\fileserver\\sbom$)나 Blob 에 모아 두고 이 모듈로 일괄 import 한다.

무결성: 공유폴더는 '모든 PC 쓰기 가능'이 되기 쉬워 위·변조된 JSON 이 들어올 수 있다.
  - JSON 크기 제한, 스키마 검사, 패키지 수 제한
  - (선택) 에이전트가 함께 쓴 .sha256 파일과 대조 → 전송 중 손상 탐지
  - 강한 보증이 필요하면 HMAC 키/코드서명 기반 검증을 추가 (README '보안 고려사항' 참고)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..models import Asset, Component, HostRecord, make_purl

SCHEMA = "sbom-inventory-agent/1"
MAX_BYTES = 20 * 1024 * 1024
MAX_PACKAGES = 50000

_PURL_TYPE = {"dpkg": "deb", "rpm": "rpm", "apk": "apk", "pip": "pypi", "npm": "npm", "brew": "brew"}


def parse_agent_json(data: dict, origin: str = "") -> HostRecord:
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{origin}: schema 가 {SCHEMA} 가 아님")
    h = data.get("host") or {}
    if not isinstance(h, dict) or not h.get("hostname"):
        raise ValueError(f"{origin}: host.hostname 누락")
    pkgs = data.get("packages") or []
    if not isinstance(pkgs, list) or len(pkgs) > MAX_PACKAGES:
        raise ValueError(f"{origin}: packages 형식 오류 또는 개수 초과")

    asset = Asset(hostname=str(h.get("hostname", "")), fqdn=str(h.get("fqdn", "") or ""),
                  serial=str(h.get("serial", "") or ""), macs=[str(m) for m in h.get("macs") or []],
                  ips=[str(i) for i in h.get("ips") or []], os=str(h.get("os", "") or ""),
                  os_version=str(h.get("os_version", "") or ""),
                  extra={"collected_at": data.get("collected_at", ""), "agent_file": origin})
    distro = str(h.get("distro_id", "") or "").lower()
    comps = []
    if asset.os:
        comps.append(Component(name=asset.os, version=asset.os_version, type="os", props={"evidence": "agent"}))
    for p in pkgs:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        name, ver = str(p["name"])[:256], str(p.get("version", "") or "")[:128]
        src = str(p.get("source", "") or "")
        ptype = _PURL_TYPE.get(src, "generic")
        ns = distro if ptype in ("deb", "rpm", "apk") else str(p.get("vendor", "") or "")
        comps.append(Component(
            name=name, version=ver, vendor=str(p.get("vendor", "") or "")[:256],
            type="library" if src in ("pip", "npm") else "application",
            purl=make_purl(ptype, name, ver, namespace=ns, qualifiers={"arch": p.get("arch", "")}),
            props={k: str(p[k])[:512] for k in ("source", "arch", "install_date", "install_location", "scope")
                   if p.get(k)} | {"evidence": "agent"},
        ))
    return HostRecord(source="agent", asset=asset, components=comps)


def import_dir(path: str | Path, verify_hash: bool = False) -> tuple[list[HostRecord], list[str]]:
    """디렉터리의 *.json 을 모두 읽는다. (레코드 목록, 오류 메시지 목록) 반환."""
    recs, errors = [], []
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.json"))
    for f in files:
        try:
            if f.stat().st_size > MAX_BYTES:
                raise ValueError("파일 크기 초과")
            raw = f.read_bytes()
            if verify_hash:
                h = f.with_suffix(f.suffix + ".sha256")
                if not h.exists():
                    raise ValueError("sha256 파일 없음")
                expected = h.read_text().split()[0].strip().lower()
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise ValueError("sha256 불일치 (손상 또는 변조)")
            recs.append(parse_agent_json(json.loads(raw.decode("utf-8-sig")), origin=f.name))
        except Exception as e:  # noqa: BLE001 - 파일 하나의 오류가 전체 import 를 멈추지 않게
            errors.append(f"{f}: {e}")
    return recs, errors
