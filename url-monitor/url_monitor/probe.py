"""단계별 접속 측정: DNS -> TCP 연결 -> TLS 핸드셰이크(인증서) -> HTTP 응답 -> 본문.

각 단계의 소요 시간을 따로 기록해 '어디서 실패/지연되는지'를 알 수 있게 한다.
HTTPS_PROXY / HTTP_PROXY 환경변수가 있고 대상이 NO_PROXY 에 해당하지 않으면 프록시를 거친다.
이때 DNS/TCP/TLS 시간은 프록시 연결 기준이므로 dns_ms 는 비워 두고 via_proxy=True 로 표시한다.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import unquote, urljoin, urlsplit

from . import __version__
from .models import ProbeResult, Target

USER_AGENT = f"url-monitor/{__version__}"
MAX_BODY = 256 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}


class ProbeError(Exception):
    def __init__(self, code: str, msg: str):
        self.code = code
        super().__init__(msg)


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


# ---------------------------------------------------------------- 프록시

def _bypass(host: str, no_proxy: str) -> bool:
    """NO_PROXY 규칙(도메인, .도메인, *, IP, CIDR) 에 해당하면 True."""
    host = host.lower().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and ip.is_loopback:
        return True
    if host == "localhost":
        return True
    for rule in (r.strip().lower() for r in no_proxy.split(",")):
        if not rule:
            continue
        if rule == "*":
            return True
        if ip is not None:
            try:
                if ip in ipaddress.ip_network(rule, strict=False):
                    return True
            except ValueError:
                pass
            continue
        rule = rule.lstrip("*")
        if rule.startswith("."):
            if host.endswith(rule) or host == rule[1:]:
                return True
        elif host == rule or host.endswith("." + rule):
            return True
    return False


def proxy_for(scheme: str, host: str, setting: str = "auto") -> str | None:
    """사용할 프록시 URL. setting: auto(환경변수) | none | 명시 URL."""
    if setting == "none":
        return None
    if setting and setting != "auto":
        return None if _bypass(host, "") else setting
    env = os.environ
    proxy = env.get(f"{scheme}_proxy") or env.get(f"{scheme.upper()}_PROXY")
    if not proxy:
        return None
    if _bypass(host, env.get("no_proxy") or env.get("NO_PROXY") or ""):
        return None
    return proxy


def _proxy_auth(proxy: str) -> dict:
    p = urlsplit(proxy)
    if not p.username:
        return {}
    cred = f"{unquote(p.username)}:{unquote(p.password or '')}".encode()
    return {"Proxy-Authorization": "Basic " + base64.b64encode(cred).decode()}


# ---------------------------------------------------------------- TLS

def _tls_context(t: Target) -> ssl.SSLContext:
    if not t.verify_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=t.ca_file or None)


def _cert_error(exc: ssl.SSLCertVerificationError) -> ProbeError:
    code = getattr(exc, "verify_code", None)
    msg = getattr(exc, "verify_message", "") or str(exc)
    if code == 10:
        return ProbeError("CERT_EXPIRED", f"인증서가 만료되었습니다 ({msg})")
    if code == 62 or "hostname" in msg.lower() or "match" in msg.lower():
        return ProbeError("CERT_HOSTNAME", f"인증서 호스트명 불일치 ({msg})")
    return ProbeError("CERT_INVALID", f"인증서 검증 실패 ({msg})")


def _read_cert(sock, r: ProbeResult) -> None:
    try:
        cert = sock.getpeercert()
    except (ValueError, AttributeError):
        return
    if not cert or "notAfter" not in cert:  # verify_tls=False 이면 파싱된 인증서를 얻을 수 없음
        return
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    r.cert_days_left = int((expires - time.time()) // 86400)
    r.cert_not_after = datetime.fromtimestamp(expires, timezone.utc).strftime("%Y-%m-%d")
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    r.cert_issuer = issuer.get("organizationName") or issuer.get("commonName", "")


# ---------------------------------------------------------------- 연결

def _connect_direct(host: str, port: int, t: Target, r: ProbeResult, record: bool) -> socket.socket:
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise ProbeError("DNS_FAIL", f"'{host}' 주소를 찾을 수 없습니다 ({exc})") from exc
    if record:
        r.dns_ms = _ms(start)

    last: Exception | None = None
    for family, stype, proto, _, addr in infos:
        start = time.perf_counter()
        sock = socket.socket(family, stype, proto)
        sock.settimeout(t.timeout_sec)
        try:
            sock.connect(addr)
        except (TimeoutError, socket.timeout) as exc:
            sock.close()
            last = ProbeError("CONN_TIMEOUT", f"{addr[0]}:{port} 연결 시간 초과({t.timeout_sec:g}초)")
            continue
        except ConnectionRefusedError:
            sock.close()
            last = ProbeError("CONN_REFUSED", f"{addr[0]}:{port} 연결 거부")
            continue
        except OSError as exc:
            sock.close()
            last = ProbeError("CONN_ERROR", f"{addr[0]}:{port} 연결 오류 ({exc})")
            continue
        if record:
            r.connect_ms = _ms(start)
            r.remote_ip = addr[0]
        return sock
    raise last or ProbeError("CONN_ERROR", "연결할 주소가 없습니다")


def _open_http(url: str, t: Target, r: ProbeResult, record: bool):
    """연결을 맺고 (connection, 요청 경로, 추가 헤더) 를 돌려준다."""
    parts = urlsplit(url)
    scheme, host = parts.scheme, parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    proxy = proxy_for(scheme, host, t.proxy)
    extra: dict = {}

    if proxy:
        if record:
            r.via_proxy = True
        p = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        start = time.perf_counter()
        if scheme == "https":
            conn = http.client.HTTPSConnection(p.hostname, p.port or 8080, timeout=t.timeout_sec, context=_tls_context(t))
            conn.set_tunnel(host, port, headers=_proxy_auth(proxy))
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 8080, timeout=t.timeout_sec)
            path = url
            extra = _proxy_auth(proxy)
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as exc:
            raise _cert_error(exc) from exc
        except ssl.SSLError as exc:
            raise ProbeError("TLS_ERROR", f"TLS 핸드셰이크 실패 ({exc})") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ProbeError("CONN_TIMEOUT", f"프록시 경유 연결 시간 초과({t.timeout_sec:g}초)") from exc
        except OSError as exc:
            raise ProbeError("PROXY_ERROR", f"프록시({p.hostname}:{p.port}) 경유 연결 실패 ({exc})") from exc
        if record:
            r.connect_ms = _ms(start)
            if scheme == "https":
                _read_cert(conn.sock, r)
        return conn, path, extra

    sock = _connect_direct(host, port, t, r, record)
    if scheme == "https":
        start = time.perf_counter()
        try:
            sock = _tls_context(t).wrap_socket(sock, server_hostname=host)
        except ssl.SSLCertVerificationError as exc:
            sock.close()
            raise _cert_error(exc) from exc
        except (TimeoutError, socket.timeout) as exc:
            sock.close()
            raise ProbeError("TLS_TIMEOUT", f"TLS 핸드셰이크 시간 초과({t.timeout_sec:g}초)") from exc
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            raise ProbeError("TLS_ERROR", f"TLS 핸드셰이크 실패 ({exc})") from exc
        if record:
            r.tls_ms = _ms(start)
            _read_cert(sock, r)
        conn = http.client.HTTPSConnection(host, port, timeout=t.timeout_sec)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=t.timeout_sec)
    conn.sock = sock
    return conn, path, extra


def _decode(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    for part in content_type.split(";"):
        k, _, v = part.strip().partition("=")
        if k.lower() == "charset" and v:
            charset = v.strip("\"' ")
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _request_once(url: str, t: Target, r: ProbeResult, record: bool):
    conn, path, extra = _open_http(url, t, r, record)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close", **extra, **t.headers}
    try:
        start = time.perf_counter()
        conn.request(t.method, path, headers=headers)
        resp = conn.getresponse()
        if record:
            r.ttfb_ms = _ms(start)
        raw = b"" if t.method == "HEAD" else resp.read(MAX_BODY)
        return resp.status, resp.getheader("Location"), _decode(raw, resp.getheader("Content-Type") or "")
    except (TimeoutError, socket.timeout) as exc:
        raise ProbeError("HTTP_TIMEOUT", f"{t.timeout_sec:g}초 안에 응답이 없습니다") from exc
    except (http.client.HTTPException, OSError) as exc:
        raise ProbeError("HTTP_ERROR", f"HTTP 통신 오류 ({type(exc).__name__}: {exc})") from exc
    finally:
        conn.close()


# ---------------------------------------------------------------- 진입점

def probe_http(t: Target) -> ProbeResult:
    r = ProbeResult(final_url=t.url)
    url = t.url
    start = time.perf_counter()
    try:
        for hop in range(t.max_redirects + 1):
            status, location, body = _request_once(url, t, r, record=(hop == 0))
            r.http_status = status
            r.final_url = url
            r.body = body
            if t.follow_redirects and status in REDIRECT_CODES and location:
                if hop == t.max_redirects:
                    raise ProbeError("TOO_MANY_REDIRECTS", f"리다이렉트가 {t.max_redirects}회를 넘습니다")
                url = urljoin(url, location)
                r.redirects += 1
                continue
            break
    except ProbeError as exc:
        r.error_code, r.error = exc.code, str(exc)
    r.total_ms = _ms(start)
    return r


def probe_tcp(t: Target) -> ProbeResult:
    r = ProbeResult(final_url=t.display)
    start = time.perf_counter()
    try:
        _connect_direct(t.host, t.port, t, r, record=True).close()
    except ProbeError as exc:
        r.error_code, r.error = exc.code, str(exc)
    r.total_ms = _ms(start)
    return r


def probe(t: Target) -> ProbeResult:
    return probe_tcp(t) if t.type == "tcp" else probe_http(t)
