"""Nmap 기반 네트워크 수집기 (agentless).

동작:
  1) nmap -sV (서비스/버전 탐지) [-O (OS 탐지, root 필요)] -oX <xml> 실행
  2) XML 을 파싱해 호스트별 HostRecord 생성
     - 열린 포트의 서비스(product/version/CPE)를 type="service" 컴포넌트로 기록
     - OS 탐지 결과(osmatch)는 type="os" 컴포넌트로 기록

한계: 원격에서 보이는 것은 '네트워크에 노출된 서비스'뿐이다. 설치된 데스크톱 앱(Office, 브라우저 등)은
보이지 않으므로 Intune/Defender/에이전트 수집과 병행해야 SBOM 이 완성된다.
반대로 Intune 에 등록되지 않은 장비(서버, 프린터, NAS, IoT, 개인장비 = 섀도 IT)는 Nmap 만 찾을 수 있다.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Asset, Component, HostRecord, cpe22_to_23, make_purl

# 대상 문자열 검증: 인자 주입('--script=...', '-iL /etc/shadow' 등)을 막기 위해 허용 형식만 통과시킨다.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/,_*]*$")


def validate_target(t: str) -> str:
    t = t.strip()
    if not t or t.startswith("-") or not _TARGET_RE.match(t):
        raise ValueError(f"허용되지 않는 스캔 대상 형식: {t!r}")
    if "/" in t:  # CIDR 이면 대역 크기 확인 (실수로 /8 전체 스캔 방지)
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.version == 4 and net.prefixlen < 16:
                raise ValueError(f"{t}: /16 보다 큰 대역은 나눠서 스캔하세요 (실수 방지)")
        except ValueError as e:
            if "나눠서" in str(e):
                raise
    return t


def build_command(targets: list[str], *, nmap_path: str = "nmap", ports: str | None = None,
                  top_ports: int | None = 1000, os_detect: bool = False, timing: int = 3,
                  version_intensity: int = 5, exclude: str | None = None, extra_args: list[str] | None = None,
                  out_xml: str) -> list[str]:
    cmd = [nmap_path, "-sV", f"--version-intensity={int(version_intensity)}", f"-T{int(timing)}",
           "--open", "-oX", out_xml]
    if ports:
        if not re.fullmatch(r"[0-9TU:,\-]+", ports):
            raise ValueError(f"포트 형식 오류: {ports}")
        cmd += ["-p", ports]
    elif top_ports:
        cmd += ["--top-ports", str(int(top_ports))]
    if os_detect:
        cmd.append("-O")
    if exclude:
        cmd += ["--exclude", ",".join(validate_target(x) for x in exclude.split(","))]
    if extra_args:
        cmd += list(extra_args)
    cmd += [validate_target(t) for t in targets]
    return cmd


def run_nmap(targets: list[str], *, keep_xml: str | None = None, **kw) -> list[HostRecord]:
    nmap = kw.get("nmap_path", "nmap")
    if not shutil.which(nmap):
        raise RuntimeError("nmap 실행 파일을 찾을 수 없습니다 (apt install nmap / https://nmap.org/download)")
    with tempfile.TemporaryDirectory() as td:
        out = keep_xml or str(Path(td) / "scan.xml")
        cmd = build_command(targets, out_xml=out, **kw)
        # shell=False + 리스트 인자 → 셸 인젝션 불가
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"nmap 실패 (rc={proc.returncode}): {proc.stderr.strip()[:500]}")
        return parse_nmap_xml(out)


def parse_nmap_xml(path: str | Path) -> list[HostRecord]:
    data = Path(path).read_bytes()
    # 외부에서 받은 XML 을 import 할 수도 있으므로 엔티티 선언(XXE / billion laughs)을 거부한다.
    if b"<!ENTITY" in data:
        raise ValueError("XML 에 ENTITY 선언이 있어 거부합니다")
    root = ET.fromstring(data)
    records: list[HostRecord] = []
    scan_args = root.get("args", "")
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        a = Asset(extra={"nmap_args": scan_args})
        for addr in h.findall("address"):
            t = addr.get("addrtype")
            if t in ("ipv4", "ipv6"):
                a.ips.append(addr.get("addr", ""))
            elif t == "mac":
                a.macs.append(addr.get("addr", ""))
                if addr.get("vendor"):
                    a.extra["mac_vendor"] = addr.get("vendor")
        for hn in h.findall("hostnames/hostname"):
            name = hn.get("name", "")
            if name and not a.fqdn:
                a.fqdn = name
                a.hostname = name

        comps: list[Component] = []
        best_os = None
        for om in h.findall("os/osmatch"):
            if best_os is None or int(om.get("accuracy", 0)) > int(best_os.get("accuracy", 0)):
                best_os = om
        if best_os is not None:
            a.os = best_os.get("name", "")
            oc = best_os.find("osclass")
            cpe = oc.findtext("cpe", "") if oc is not None else ""
            comps.append(Component(name=a.os, type="os", cpe=cpe22_to_23(cpe),
                                   props={"accuracy": best_os.get("accuracy", ""), "evidence": "nmap -O"}))

        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            if svc is None:
                continue
            proto, port = p.get("protocol", "tcp"), p.get("portid", "")
            product = svc.get("product", "")
            version = svc.get("version", "")
            cpes = [c.text or "" for c in svc.findall("cpe")]
            app_cpe = next((c for c in cpes if c.startswith("cpe:/a:")), "")
            if not a.os and svc.get("ostype"):
                a.os = svc.get("ostype", "")
            vendor = app_cpe.split(":")[2] if app_cpe.count(":") >= 3 else ""
            name = product or svc.get("name", "unknown")
            comps.append(Component(
                name=name, version=version, vendor=vendor, type="service",
                cpe=cpe22_to_23(app_cpe),
                purl=make_purl("generic", name, version, namespace=vendor) if product else "",
                props={"port": f"{port}/{proto}", "service": svc.get("name", ""),
                       "extrainfo": svc.get("extrainfo", ""), "method": svc.get("method", ""),
                       "conf": svc.get("conf", ""), "evidence": "nmap -sV"},
            ))
        records.append(HostRecord(source="nmap", asset=a, components=comps))
    return records
