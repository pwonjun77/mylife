"""OpenAPI 3.x / Swagger 2.0 명세 로딩 및 정규화.

JSON 은 표준 라이브러리로 읽고, YAML 은 PyYAML 이 설치된 경우에만 읽는다.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class SpecError(ValueError):
    pass


@dataclass
class Param:
    name: str
    location: str  # path / query / header / cookie / body
    schema: dict = field(default_factory=dict)
    required: bool = False


@dataclass
class Operation:
    method: str  # 대문자
    path: str
    params: list[Param] = field(default_factory=list)
    request_schema: dict | None = None
    responses: dict = field(default_factory=dict)  # status -> 해석된 schema (없으면 {})
    security: list | None = None  # None 이면 전역 security 상속
    deprecated: bool = False
    tags: list[str] = field(default_factory=list)
    operation_id: str = ""

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class ApiSpec:
    raw: dict
    version: str  # "2.0" 또는 "3.x"
    title: str
    servers: list[str]
    security_schemes: dict
    global_security: list
    operations: list[Operation]
    source: str = ""

    def effective_security(self, op: Operation) -> list:
        return self.global_security if op.security is None else op.security

    def requires_auth(self, op: Operation) -> bool:
        """보안 요구사항이 하나라도 있고, 빈 요구사항({})으로 '선택적 인증'이 아닌 경우."""
        sec = self.effective_security(op)
        return bool(sec) and all(req for req in sec)


def load_spec(source: str, timeout: float = 10.0) -> ApiSpec:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "api-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - 사용자가 지정한 명세 URL
            text = resp.read().decode("utf-8", errors="replace")
    else:
        text = Path(source).read_text(encoding="utf-8")
    spec = parse_spec(text, source)
    spec.source = source
    return spec


def parse_spec(text: str, source: str = "") -> ApiSpec:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise SpecError("YAML 명세를 읽으려면 'pip install pyyaml' 이 필요합니다 (JSON 명세는 설치 없이 가능).") from exc
        raw = yaml.safe_load(text)
    if not isinstance(raw, dict) or not ("openapi" in raw or "swagger" in raw):
        raise SpecError(f"OpenAPI/Swagger 명세가 아닙니다: {source}")
    return _normalize(raw, source)


def _resolver(raw: dict):
    def resolve(node, depth: int = 0):
        if depth > 12:
            return {}
        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/"):
                target = raw
                for part in node["$ref"][2:].split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    target = target.get(part, {}) if isinstance(target, dict) else {}
                return resolve(target, depth + 1)
            return {k: resolve(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [resolve(v, depth + 1) for v in node]
        return node
    return resolve


def _normalize(raw: dict, source: str) -> ApiSpec:
    resolve = _resolver(raw)
    is_v2 = "swagger" in raw
    version = "2.0" if is_v2 else str(raw.get("openapi", "3"))

    if is_v2:
        scheme = (raw.get("schemes") or ["https"])[0]
        host = raw.get("host", "")
        servers = [f"{scheme}://{host}{raw.get('basePath', '')}"] if host else []
        servers += [f"{s}://{host}{raw.get('basePath', '')}" for s in (raw.get("schemes") or [])[1:] if host]
        schemes = raw.get("securityDefinitions", {}) or {}
    else:
        servers = [s.get("url", "") for s in raw.get("servers", []) if isinstance(s, dict)]
        schemes = (raw.get("components", {}) or {}).get("securitySchemes", {}) or {}

    ops: list[Operation] = []
    for path, item in (raw.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        item = resolve(item)
        shared = item.get("parameters", [])
        for method in HTTP_METHODS:
            op_raw = item.get(method)
            if not isinstance(op_raw, dict):
                continue
            op = Operation(method.upper(), path, deprecated=bool(op_raw.get("deprecated")),
                           tags=list(op_raw.get("tags", [])), operation_id=op_raw.get("operationId", ""))
            if "security" in op_raw:
                op.security = op_raw["security"] or []
            by_key: dict[tuple[str, str], dict] = {}
            for p in list(shared) + list(op_raw.get("parameters", [])):
                if isinstance(p, dict) and "name" in p:
                    by_key[(p["name"], p.get("in", ""))] = p
            for p in by_key.values():
                loc = p.get("in", "")
                if loc == "body":
                    op.request_schema = p.get("schema", {})
                    continue
                schema = p.get("schema") or {k: v for k, v in p.items() if k not in ("name", "in", "description")}
                op.params.append(Param(p["name"], loc, schema, bool(p.get("required"))))
            if not is_v2:
                content = (op_raw.get("requestBody") or {}).get("content", {})
                for media, body in content.items():
                    if "json" in media or "form" in media:
                        op.request_schema = body.get("schema", {})
                        break
            for status, resp in (op_raw.get("responses") or {}).items():
                schema = {}
                if isinstance(resp, dict):
                    if is_v2:
                        schema = resp.get("schema", {}) or {}
                    else:
                        for media, body in (resp.get("content") or {}).items():
                            schema = body.get("schema", {}) or {}
                            break
                op.responses[str(status)] = schema
            ops.append(op)

    return ApiSpec(raw, version, (raw.get("info") or {}).get("title", ""), servers,
                   resolve(schemes), raw.get("security", []) or [], ops, source)


def iter_properties(schema: dict, prefix: str = "", depth: int = 0):
    """스키마의 모든 속성을 (점 표기 경로, 속성 스키마) 로 순회한다."""
    if not isinstance(schema, dict) or depth > 6:
        return
    for key in ("allOf", "oneOf", "anyOf"):
        for sub in schema.get(key, []) or []:
            yield from iter_properties(sub, prefix, depth + 1)
    if schema.get("type") == "array" or "items" in schema:
        yield from iter_properties(schema.get("items", {}), prefix + "[]", depth + 1)
    for name, prop in (schema.get("properties") or {}).items():
        path = f"{prefix}.{name}" if prefix else name
        yield path, prop if isinstance(prop, dict) else {}
        yield from iter_properties(prop, path, depth + 1)


def base_url(spec: ApiSpec, override: str | None = None) -> str | None:
    if override:
        return override.rstrip("/")
    for s in spec.servers:
        if s.startswith(("http://", "https://")):
            return s.rstrip("/")
        if s.startswith("/") and spec.source.startswith(("http://", "https://")):
            return urljoin(spec.source, s).rstrip("/")
    return None
