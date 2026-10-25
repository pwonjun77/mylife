"""설정 파일(JSON / CSV / TOML) 로드와 검증.

JSON 구조:
    {
      "defaults": {...},                       # 모든 대상에 적용할 기본값
      "groups":   {"그룹명": [대상, ...]},      # 그룹별 대상 목록
      "targets":  [대상, ...],                  # (선택) 그룹 없이 나열
      "include_csv": ["targets.csv"],          # (선택) CSV 목록 포함, 설정 파일 기준 상대경로
      "notify":   {...},                       # 알림 설정
      "settings": {"workers": 20, "retention_days": 90}
    }
문자열 값이 "env:변수명" 이면 환경변수에서 읽는다(비밀값을 파일에 쓰지 않기 위함).
"""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

from .models import Target

DEFAULTS = {f.name: f.default for f in fields(Target) if f.name not in ("name", "group") and not callable(f.default_factory)}
TARGET_KEYS = {f.name for f in fields(Target)}
SETTINGS_DEFAULTS = {"workers": 20, "retention_days": 90}
NOTIFY_KEYS = {"webhooks", "email", "repeat_every_min", "notify_warn", "notify_recovery", "proxy",
               "notify_start", "heartbeat_hours", "status_page_url"}

INT_KEYS = {"port", "retries", "cert_warn_days", "max_redirects"}
FLOAT_KEYS = {"warn_response_ms", "timeout_sec", "retry_delay_sec", "interval_sec"}
BOOL_KEYS = {"verify_tls", "follow_redirects", "enabled"}
LIST_KEYS = {"body_contains", "body_not_contains"}
DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


@dataclass
class Config:
    targets: list[Target]
    notify: dict = field(default_factory=dict)
    settings: dict = field(default_factory=lambda: dict(SETTINGS_DEFAULTS))
    source: str = ""


# ---------------------------------------------------------------- 값 변환

def load_env_file(path: str | Path) -> list[str]:
    """KEY=VALUE 형식 파일을 환경변수로 읽는다(이미 있는 변수는 덮어쓰지 않음). 읽은 키 목록을 돌려준다.

    Windows 작업 스케줄러로 실행하면 사용자 환경변수가 보이지 않으므로,
    Teams 웹훅 주소 같은 비밀값을 접근 권한을 제한한 파일에 두고 이 함수로 읽는다.
    """
    path = Path(path)
    if not path.is_file():
        raise ConfigError([f"환경변수 파일이 없습니다: {path}"])
    keys = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:]
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ConfigError([f"{path.name}:{lineno}: KEY=VALUE 형식이 아닙니다"])
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)
        keys.append(key)
    return keys

def resolve_env(value, errors: list[str], where: str):
    """"env:NAME" 문자열을 환경변수 값으로 바꾼다(dict/list 는 재귀)."""
    if isinstance(value, str) and value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            errors.append(f"{where}: 환경변수 {name} 이(가) 설정되지 않았습니다")
            return ""
        return os.environ[name]
    if isinstance(value, dict):
        return {k: resolve_env(v, errors, f"{where}.{k}") for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env(v, errors, where) for v in value]
    return value


def parse_status_ranges(spec) -> list[tuple[int, int]]:
    """"200-399", "200,204", "2xx", 200, [200, "3xx"] -> [(lo, hi), ...]"""
    items = spec if isinstance(spec, list) else str(spec).split(",")
    ranges = []
    for raw in items:
        s = str(raw).strip().lower()
        if not s:
            continue
        if re.fullmatch(r"[1-5]xx", s):
            lo = int(s[0]) * 100
            ranges.append((lo, lo + 99))
        elif re.fullmatch(r"\d{3}-\d{3}", s):
            lo, hi = (int(x) for x in s.split("-"))
            if lo > hi:
                raise ValueError(f"잘못된 상태코드 범위 '{raw}'")
            ranges.append((lo, hi))
        elif re.fullmatch(r"\d{3}", s):
            ranges.append((int(s), int(s)))
        else:
            raise ValueError(f"잘못된 상태코드 형식 '{raw}' (예: 200, 200-399, 2xx)")
    if not ranges:
        raise ValueError("expect_status 가 비어 있습니다")
    return ranges


def _to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on", "예"):
        return True
    if s in ("0", "false", "no", "n", "off", "아니오"):
        return False
    raise ValueError(f"참/거짓 값이 아닙니다: '{v}'")


def _parse_hhmm(s: str) -> int:
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", str(s).strip())
    if not m or int(m.group(1)) > 24 or int(m.group(2)) > 59:
        raise ValueError(f"시각 형식은 HH:MM 입니다: '{s}'")
    return int(m.group(1)) * 60 + int(m.group(2))


def parse_days(spec: str) -> set[int]:
    """"*", "Mon-Fri", "Sat,Sun", "월-금" -> 요일 번호 집합(월=0)."""
    ko = {"월": "mon", "화": "tue", "수": "wed", "목": "thu", "금": "fri", "토": "sat", "일": "sun"}
    s = str(spec or "*").strip().lower()
    if s in ("*", "", "all", "매일"):
        return set(range(7))
    days: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        for k, v in ko.items():
            part = part.replace(k, v)
        ends = [p.strip()[:3] for p in part.split("-")]
        if any(e not in DAY_NAMES for e in ends) or len(ends) > 2:
            raise ValueError(f"요일 형식 오류 '{spec}' (예: Mon-Fri, Sat,Sun, *)")
        a = DAY_NAMES.index(ends[0])
        b = DAY_NAMES.index(ends[-1])
        i = a
        while True:
            days.add(i)
            if i == b:
                break
            i = (i + 1) % 7
    return days


def _check_maintenance(windows, where: str, errors: list[str]) -> list:
    if not isinstance(windows, list):
        errors.append(f"{where}.maintenance: 목록이어야 합니다")
        return []
    for i, w in enumerate(windows):
        try:
            if not isinstance(w, dict):
                raise ValueError('{"days": "Sun", "start": "02:00", "end": "04:00"} 형식이어야 합니다')
            parse_days(w.get("days", "*"))
            _parse_hhmm(w["start"])
            _parse_hhmm(w["end"])
        except (ValueError, KeyError) as exc:
            errors.append(f"{where}.maintenance[{i}]: {exc}")
    return windows


def in_maintenance(windows: list, now) -> bool:
    """now(datetime) 가 유지보수 시간대 안이면 True. end < start 이면 자정을 넘는 구간."""
    minute = now.hour * 60 + now.minute
    for w in windows:
        days = parse_days(w.get("days", "*"))
        start, end = _parse_hhmm(w["start"]), _parse_hhmm(w["end"])
        if start <= end:
            if now.weekday() in days and start <= minute < end:
                return True
        else:
            if now.weekday() in days and minute >= start:
                return True
            if (now.weekday() - 1) % 7 in days and minute < end:
                return True
    return False


# ---------------------------------------------------------------- 대상 생성

def build_target(raw: dict, defaults: dict, group: str, where: str, errors: list[str]) -> Target | None:
    unknown = set(raw) - TARGET_KEYS
    if unknown:
        errors.append(f"{where}: 알 수 없는 항목 {sorted(unknown)}")
    merged = {**DEFAULTS, "headers": {}, "body_contains": [], "body_not_contains": [], "maintenance": []}
    merged.update({k: v for k, v in defaults.items() if k in TARGET_KEYS})
    merged.update({k: v for k, v in raw.items() if k in TARGET_KEYS})
    merged["group"] = raw.get("group") or group
    merged = resolve_env(merged, errors, where)

    n_err = len(errors)
    try:
        for k in INT_KEYS:
            if merged.get(k) not in (None, ""):
                merged[k] = int(merged[k])
        for k in FLOAT_KEYS:
            merged[k] = float(merged[k])
        for k in BOOL_KEYS:
            merged[k] = _to_bool(merged[k])
    except (TypeError, ValueError) as exc:
        errors.append(f"{where}: 숫자/참거짓 값 오류 - {exc}")
        return None
    for k in LIST_KEYS:
        v = merged.get(k) or []
        merged[k] = [v] if isinstance(v, str) else list(v)
    if not isinstance(merged.get("headers"), dict):
        errors.append(f"{where}.headers: 객체(dict)여야 합니다")
        merged["headers"] = {}

    ttype = str(merged.get("type") or "http").lower()
    merged["type"] = ttype
    if ttype == "http":
        url = str(merged.get("url") or "").strip()
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            errors.append(f"{where}: url 은 http:// 또는 https:// 로 시작해야 합니다 ('{url}')")
        merged["url"] = url
        merged.setdefault("name", "")
        if not merged.get("name"):
            merged["name"] = parts.hostname or url
        try:
            parse_status_ranges(merged["expect_status"])
        except ValueError as exc:
            errors.append(f"{where}: {exc}")
        merged["method"] = str(merged["method"]).upper()
        if merged["method"] not in ("GET", "HEAD"):
            errors.append(f"{where}: method 는 GET 또는 HEAD 만 허용합니다(비파괴 점검)")
    elif ttype == "tcp":
        if not merged.get("host") or not merged.get("port"):
            errors.append(f"{where}: tcp 점검에는 host 와 port 가 필요합니다")
        if not merged.get("name"):
            merged["name"] = f"{merged.get('host')}:{merged.get('port')}"
    else:
        errors.append(f"{where}: type 은 http 또는 tcp 입니다 ('{ttype}')")

    if merged["timeout_sec"] <= 0:
        errors.append(f"{where}: timeout_sec 는 0보다 커야 합니다")
    if merged["interval_sec"] < 5:
        errors.append(f"{where}: interval_sec 는 5초 이상이어야 합니다(대상 서버 부담 방지)")
    if merged["retries"] < 0:
        errors.append(f"{where}: retries 는 0 이상이어야 합니다")
    merged["maintenance"] = _check_maintenance(merged.get("maintenance") or [], where, errors)
    if merged.get("ca_file") and not Path(merged["ca_file"]).is_file():
        errors.append(f"{where}: ca_file '{merged['ca_file']}' 이(가) 없습니다")

    if len(errors) > n_err:
        return None
    return Target(**{k: v for k, v in merged.items() if k in TARGET_KEYS})


def target_from_url(url: str, **overrides) -> Target:
    errors: list[str] = []
    t = build_target({"url": url, **overrides}, {}, "기본", "--url", errors)
    if errors:
        raise ConfigError(errors)
    return t


# ---------------------------------------------------------------- 파일 로드

def _load_csv(path: Path, defaults: dict, errors: list[str]) -> list[Target]:
    targets = []
    try:
        with path.open(encoding="utf-8-sig", newline="") as fh:  # 엑셀에서 저장한 BOM 포함 CSV 대응
            reader = csv.DictReader(fh)
            if not reader.fieldnames or not ({"url", "host"} & set(reader.fieldnames)):
                errors.append(f"{path.name}: 첫 줄에 url (또는 type,host,port) 열이 있어야 합니다")
                return []
            for lineno, row in enumerate(reader, start=2):
                raw = {k.strip(): v.strip() for k, v in row.items() if k and v and v.strip()}
                if not raw or raw.get("url", "").startswith("#"):
                    continue
                for k in LIST_KEYS:
                    if k in raw:
                        raw[k] = [s for s in raw[k].split("|") if s]
                group = raw.pop("group", "") or "기본"
                t = build_target(raw, defaults, group, f"{path.name}:{lineno}", errors)
                if t:
                    targets.append(t)
    except OSError as exc:
        errors.append(f"{path}: 파일을 읽을 수 없습니다 - {exc}")
    return targets


def _load_mapping(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".toml":
        try:
            import tomllib
        except ImportError as exc:  # Python 3.10
            raise ConfigError(["TOML 설정은 Python 3.11 이상에서 지원합니다. JSON 을 사용하세요."]) from exc
        return tomllib.loads(text)
    return json.loads(text)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    errors: list[str] = []
    if not path.is_file():
        raise ConfigError([f"설정 파일이 없습니다: {path}"])

    if path.suffix.lower() == ".csv":
        targets = _load_csv(path, {}, errors)
        data: dict = {}
    else:
        try:
            data = _load_mapping(path)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ConfigError([f"{path.name}: 설정 파일 형식 오류 - {exc}"]) from exc
        if not isinstance(data, dict):
            raise ConfigError([f"{path.name}: 최상위는 객체여야 합니다"])
        unknown = set(data) - {"defaults", "groups", "targets", "include_csv", "notify", "settings"}
        if unknown:
            errors.append(f"{path.name}: 알 수 없는 최상위 항목 {sorted(unknown)}")
        defaults = data.get("defaults") or {}
        bad = set(defaults) - TARGET_KEYS
        if bad:
            errors.append(f"defaults: 알 수 없는 항목 {sorted(bad)}")
        targets = []
        for gname, items in (data.get("groups") or {}).items():
            for i, raw in enumerate(items or []):
                where = f"groups.{gname}[{i}]"
                t = build_target(raw, defaults, gname, where, errors) if isinstance(raw, dict) else None
                if t is None and not isinstance(raw, dict):
                    errors.append(f"{where}: 객체여야 합니다")
                if t:
                    targets.append(t)
        for i, raw in enumerate(data.get("targets") or []):
            if isinstance(raw, str):
                raw = {"url": raw}
            t = build_target(raw, defaults, raw.get("group") or "기본", f"targets[{i}]", errors)
            if t:
                targets.append(t)
        for rel in data.get("include_csv") or []:
            targets += _load_csv((path.parent / rel), defaults, errors)

    seen: set[str] = set()
    for t in targets:
        if t.key in seen:
            errors.append(f"중복된 대상 '{t.key}' (같은 그룹 안에서 name 은 고유해야 합니다)")
        seen.add(t.key)
    if not targets and not errors:
        errors.append("점검 대상이 하나도 없습니다")

    notify = data.get("notify") or {}
    bad = set(notify) - NOTIFY_KEYS
    if bad:
        errors.append(f"notify: 알 수 없는 항목 {sorted(bad)}")
    notify = resolve_env(notify, errors, "notify")
    for i, hook in enumerate(notify.get("webhooks") or []):
        if not isinstance(hook, dict) or not str(hook.get("url", "")).startswith(("http://", "https://")):
            errors.append(f"notify.webhooks[{i}]: url 이 필요합니다")
        elif hook.get("type", "generic") not in ("slack", "teams", "googlechat", "generic"):
            errors.append(f"notify.webhooks[{i}]: type 은 slack, teams, googlechat, generic 중 하나입니다")
    try:
        float(notify.get("heartbeat_hours", 0) or 0)
    except (TypeError, ValueError):
        errors.append("notify.heartbeat_hours: 숫자여야 합니다")
    email = notify.get("email")
    if email and (not email.get("smtp") or not email.get("to")):
        errors.append("notify.email: smtp 와 to 가 필요합니다")

    settings = {**SETTINGS_DEFAULTS, **(data.get("settings") or {})}
    if errors:
        raise ConfigError(errors)
    return Config(targets=targets, notify=notify, settings=settings, source=str(path))
