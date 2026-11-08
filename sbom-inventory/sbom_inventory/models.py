"""공통 데이터 모델과 정규화 유틸리티.

출처(nmap / intune / defender / agent)마다 표기가 제각각인 값을
하나의 형태로 맞춰야 자산 병합과 버전 비교가 가능하다.
  - hostname : 소문자 + 도메인 제거(short name) → 'PC-001.corp.local' == 'pc-001'
  - MAC      : 구분자 제거 후 aa:bb:cc:dd:ee:ff 형식
  - 소프트웨어명 : 소문자, 공백 정리, '(x64)' 같은 아키텍처 꼬리표 제거
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote

# ---------------------------------------------------------------- 식별자 정규화

_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_JUNK_MACS = {"000000000000", "ffffffffffff"}
_JUNK_SERIALS = {"", "0", "none", "default string", "to be filled by o.e.m.", "system serial number",
                 "not specified", "not applicable", "unknown", "123456789", "0123456789"}


def norm_hostname(name: str | None) -> str:
    if not name:
        return ""
    name = name.strip().lower().rstrip(".")
    # IP 주소가 hostname 자리에 들어온 경우는 hostname 으로 취급하지 않는다.
    if re.fullmatch(r"[0-9.]+", name) or ":" in name:
        return ""
    return name.split(".", 1)[0]


def norm_mac(mac: str | None) -> str:
    if not mac:
        return ""
    raw = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if not _MAC_RE.match(raw) or raw in _JUNK_MACS:
        return ""
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2))


def norm_serial(serial: str | None) -> str:
    """가상머신/조립PC 의 '쓰레기' 시리얼은 버린다 — 그대로 쓰면 서로 다른 PC 가 한 자산으로 병합된다."""
    if not serial:
        return ""
    s = serial.strip()
    return "" if s.lower() in _JUNK_SERIALS else s.upper()


# ---------------------------------------------------------------- 소프트웨어명 정규화

_ARCH_TAIL = re.compile(r"\s*\((?:x64|x86|64-bit|32-bit|amd64|arm64)[^)]*\)\s*$", re.I)
_VERSION_TAIL = re.compile(r"\s+v?\d+(?:\.\d+){1,}\s*$")


def norm_name(name: str) -> str:
    n = (name or "").strip()
    n = _ARCH_TAIL.sub("", n)
    n = re.sub(r"\s+", " ", n).lower()
    return n


def norm_name_loose(name: str) -> str:
    """'7-Zip 23.01' 처럼 이름에 버전이 붙은 경우까지 제거한 비교용 키 (정책 매칭/이력 조회에 사용)."""
    return _VERSION_TAIL.sub("", norm_name(name))


# ---------------------------------------------------------------- 버전 비교

_TOKEN = re.compile(r"\d+|[a-z]+", re.I)
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1, "pre": -1}


def version_key(v: str) -> tuple:
    """버전 문자열 → 비교용 토큰 튜플.

    토큰 → (등급, 값): 숫자 (2, n) / 사전배포(alpha·beta·rc) (0, 음수) / 기타 문자(OpenSSH 'p1' 같은 패치 표기) (3, 0)
    '1.9.9' < '1.10.0',  '2.0' == '2.0.0',  '1.0rc1' < '1.0' < '1.0.1',  '8.2' < '8.2p1'
    """
    parts: list[tuple[int, int]] = []
    for tok in _TOKEN.findall(v or ""):
        if tok.isdigit():
            parts.append((2, int(tok)))
        elif tok.lower() in _PRE:
            parts.append((0, _PRE[tok.lower()]))
        else:
            parts.append((3, 0))
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    """짧은 쪽은 0 (2, 0) 으로 채워 비교 → '2.0' == '2.0.0'."""
    ka, kb = version_key(a), version_key(b)
    n = max(len(ka), len(kb))
    pad = ((2, 0),)
    return ka + pad * (n - len(ka)) < kb + pad * (n - len(kb))


# ---------------------------------------------------------------- 모델

@dataclass
class Asset:
    hostname: str = ""
    fqdn: str = ""
    serial: str = ""
    macs: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    os: str = ""
    os_version: str = ""
    extra: dict = field(default_factory=dict)  # 출처별 부가 정보 (intune id, 사용자, 모델명 등)

    def normalized(self) -> "Asset":
        return Asset(
            hostname=norm_hostname(self.hostname or self.fqdn),
            fqdn=(self.fqdn or "").lower().rstrip("."),
            serial=norm_serial(self.serial),
            macs=sorted({m for m in (norm_mac(x) for x in self.macs) if m}),
            ips=sorted({ip.strip() for ip in self.ips if ip and ip.strip()}),
            os=self.os or "",
            os_version=self.os_version or "",
            extra=dict(self.extra),
        )

    def label(self) -> str:
        return self.hostname or (self.ips[0] if self.ips else "") or self.serial or "(unknown)"


@dataclass
class Component:
    name: str
    version: str = ""
    vendor: str = ""
    type: str = "application"   # application | library | os | service | firmware
    purl: str = ""
    cpe: str = ""
    props: dict = field(default_factory=dict)  # 포트, 설치 경로, 레지스트리 키 등 증적(evidence)

    @property
    def key(self) -> str:
        return norm_name(self.name)


@dataclass
class HostRecord:
    source: str          # nmap | intune | defender | agent
    asset: Asset
    components: list[Component] = field(default_factory=list)


# ---------------------------------------------------------------- 식별자 문자열(purl / CPE)

def make_purl(ptype: str, name: str, version: str = "", namespace: str = "", qualifiers: dict | None = None) -> str:
    """Package URL (https://github.com/package-url/purl-spec)."""
    if not name:
        return ""
    s = f"pkg:{ptype}/"
    if namespace:
        s += quote(namespace.lower(), safe="") + "/"
    # generic(Windows 앱 등)은 표준 이름이 없으므로 '7-Zip 23.01 (x64)' → '7-zip' 처럼 정리해 버전 간 동일 키를 유지
    s += quote(norm_name_loose(name) if ptype == "generic" else name, safe="")
    if version:
        s += "@" + quote(version, safe="")
    if qualifiers:
        q = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(qualifiers.items()) if v)
        if q:
            s += "?" + q
    return s


def cpe22_to_23(cpe: str) -> str:
    """nmap 이 출력하는 CPE 2.2 URI(cpe:/a:apache:http_server:2.4.41)를 CPE 2.3 형식으로 변환."""
    if not cpe or not cpe.startswith("cpe:/"):
        return cpe or ""
    parts = cpe[5:].split(":")
    parts += ["*"] * (11 - len(parts))
    parts = [p if p else "*" for p in parts[:11]]
    return "cpe:2.3:" + ":".join(parts)
