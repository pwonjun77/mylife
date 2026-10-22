# API Scanner

**OWASP API Security Top 10:2023** 기준으로 REST API의 취약점을 점검하는 도구입니다.
OpenAPI 3.x / Swagger 2.0 **명세 파일만으로** 대부분의 점검이 가능하며, Python 3.10 이상의 표준 라이브러리만 사용합니다
(JSON 명세·핵심 기능은 설치 없이, YAML 명세만 `pip install pyyaml`이 필요합니다).

> 같은 저장소의 `owasp-scanner`가 소스코드(SAST)·의존성·웹페이지(DAST)를 점검한다면,
> 이 `api-scanner`는 **REST API 설계·인증·권한**에 특화되어 있습니다.

## 점검 모드

| 모드 | 설명 | 서버 요청 |
|------|------|-----------|
| `spec` | OpenAPI/Swagger 명세 정적 점검 | ❌ 보내지 않음 |
| `jwt`  | JWT 토큰 오프라인 분석 (약한 서명키·alg=none·만료·민감 클레임) | ❌ 보내지 않음 |
| `live` | 실제 서버 비파괴 점검 (읽기 전용 메서드만, **권한 필요**) | ✅ GET/HEAD/OPTIONS만 |
| `rules`| 점검 분류(OWASP API Top 10:2023) 목록 출력 | - |

## 빠른 시작

```bash
cd api-scanner

# 1) 데모용 취약 명세 점검 (설치 불필요)
python3 -m api_scanner spec examples/vulnerable_api/openapi.json

# 2) HTML 리포트로 저장
python3 -m api_scanner spec examples/vulnerable_api/openapi.json -f html -o report.html

# 3) 내 API 명세 점검 (파일 또는 URL)
python3 -m api_scanner spec ./openapi.yaml           # YAML 은 pip install pyyaml 필요
python3 -m api_scanner spec https://api.example.com/openapi.json

# 4) JWT 토큰 점검 (서버로 전송하지 않음)
python3 -m api_scanner jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."

# 5) CI 연동: 높음 이상 결과가 있으면 종료코드 1
python3 -m api_scanner spec ./openapi.json --fail-on high
```

## OWASP API Security Top 10:2023 대응

| 분류 | 이름 | 주요 점검 항목 |
|------|------|----------------|
| API1 | Broken Object Level Authorization (BOLA) | 인증 없는 객체 조회, 순차 정수형 ID, 두 사용자 토큰 교차 접근(`live`) |
| API2 | Broken Authentication | 인증 요구사항 누락, Basic 인증, 쿼리 API 키, OAuth implicit/ROPC, JWT 약한키·alg=none·만료·민감 클레임 |
| API3 | Broken Object Property Level Authorization | 응답의 민감 필드 노출, 대량 할당(role/is_admin 등), 열린 스키마(additionalProperties) |
| API4 | Unrestricted Resource Consumption | 페이지 크기 상한 없음, 문자열/배열 길이 제한 없음, 업로드 제한 없음, 속도 제한 미문서화 |
| API5 | Broken Function Level Authorization (BFLA) | 관리 기능 API의 인증 누락 |
| API6 | Unrestricted Access to Sensitive Business Flows | 결제·예약·쿠폰·가입 등 남용되기 쉬운 업무 흐름 |
| API7 | Server Side Request Forgery (SSRF) | URL을 입력받는 파라미터(url/callback/webhook/image_url 등) |
| API8 | Security Misconfiguration | 평문 HTTP, 보안 헤더 누락, 와일드카드 CORS+자격증명, 버전 노출, 디버그 엔드포인트 |
| API9 | Improper Inventory Management | 다중 버전 동시 노출, 비운영 서버 노출, 폐기 예정 API, 버전 정보 누락 |
| API10 | Unsafe Consumption of APIs | 외부 콜백·웹훅 정의 |

`python3 -m api_scanner rules` 로 전체 목록을 볼 수 있습니다.

## `live` 모드 (실서버 점검) — 반드시 권한이 있는 대상에만

`live` 모드는 명세의 각 경로에 **읽기 전용 메서드(GET/HEAD/OPTIONS)만** 요청하여,
문서와 실제 구현이 일치하는지 비파괴적으로 확인합니다. 데이터를 생성·수정·삭제하지 않습니다.

```bash
# 명세의 servers 를 대상으로 점검 (권한 확인 프롬프트가 표시됨)
python3 -m api_scanner live ./openapi.json --token "<사용자 A의 JWT>"

# BOLA 교차 점검: 서로 다른 두 사용자 토큰으로 같은 객체 접근이 되는지 확인
python3 -m api_scanner live ./openapi.json \
    --base https://api.example.com \
    --token "<사용자 A JWT>" --token-b "<사용자 B JWT>" --id 1 -y
```

확인하는 항목:
- 인증이 필요한 API가 토큰 없이도 200으로 응답하는지 (API2)
- 두 사용자 토큰이 동일 객체에 모두 접근되는지 (API1 / BOLA)
- HSTS·nosniff 등 보안 헤더, 와일드카드 CORS+자격증명, 서버 버전 노출 (API8)

> ⚠️ 허가 없는 점검은 정보통신망법 등 관련 법률 위반이 될 수 있습니다.
> 반드시 본인이 소유하거나 서면으로 점검 허가를 받은 API에만 사용하세요.

## 출력 형식과 옵션

- `-f text|json|html` : 출력 형식 (기본 text)
- `-o <파일>` : 결과를 파일로 저장
- `--min-severity info|low|medium|high|critical` : 표시 최소 심각도
- `--category API1,API7` : 특정 분류만 표시
- `--fail-on high` : 해당 심각도 이상 결과가 있으면 종료코드 1 (CI 연동)
- `--no-color` : 텍스트 색상 끄기

JSON 출력은 `meta`, `summary`, `findings` 구조로, 각 결과에 `rule_id`, `category`, `severity`,
`location`, `evidence`, `recommendation`, `cwe` 가 포함됩니다.

## 한계

자동화된 명세/비파괴 점검이므로 오탐·미탐이 있을 수 있습니다. 특히 권한·업무 로직(BOLA/BFLA)은
명세만으로 완전히 판단할 수 없으므로 실제 토큰을 이용한 점검(`live`)과 수동 검토·모의해킹을 병행하세요.

## 테스트

```bash
python3 -m unittest discover -s tests -v
```
