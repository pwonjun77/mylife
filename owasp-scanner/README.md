# OWASP Scanner

**OWASP Top 10:2025**(최신판, 기본값)와 **OWASP Top 10:2021** 기준으로 취약점을 점검하는 도구입니다.
Python 3.10 이상의 표준 라이브러리만 사용하므로 따로 설치할 패키지가 없습니다.

> 📘 처음 사용하신다면 설치부터 결과 해석, 문제 해결까지 담은 **[초보자용 사용 설명서(GUIDE.md)](GUIDE.md)** 를 먼저 읽어 보세요.

| 모드 | 설명 | 주요 점검 항목 |
|------|------|----------------|
| `code` | 소스코드 정적 점검 (SAST) | SQL/명령/NoSQL 인젝션, XSS, 경로 조작, SSRF, 역직렬화, 취약한 암호화, 하드코딩된 비밀정보, JWT 검증 누락, 디버그 모드, 예외 처리 미흡(fail-open, 예외 무시), `curl \| sh`·신뢰할 수 없는 패키지 저장소 등 |
| `deps` | 의존성·공급망 점검 | `requirements*.txt`, `package.json`의 버전 미고정, Git/URL 의존성, lock 파일 누락, 설치 스크립트(postinstall 등), OSV.dev 알려진 취약점(CVE) |
| `web`  | 웹 비파괴 점검 (passive DAST) | HTTPS·HSTS·TLS 버전·인증서, 보안 헤더, 쿠키 속성, CORS, HTTP 메서드, 오류 페이지 정보 노출, `.git`/`.env` 등 민감 파일 노출, SRI, 혼합 콘텐츠 |
| `review` | 저장된 JSON 결과를 Claude로 오탐 검토 | `--ai-review`와 같은 판정을 나중에 수행 |

## OWASP Top 10:2025 대응표

기본 기준은 2025년판이며 `--standard 2021`로 2021년판 분류를 쓸 수 있습니다. 2026년판은 따로 없고, 2025년판이 현재 최신판입니다.
모든 결과에는 두 기준의 분류가 함께 기록됩니다(JSON의 `owasp`=2021, `owasp2025`=2025).

| 2025 | 분류 | 2021 대응 | 주요 점검 항목 |
|------|------|-----------|----------------|
| A01 | Broken Access Control | A01 + A10(SSRF) | 경로 조작, CSRF 비활성화, CORS, SSRF, 관리자 페이지 노출 |
| A02 | Security Misconfiguration | A05 | 디버그 모드, 보안 헤더, XXE, 민감 파일 노출, TRACE |
| A03 | Software Supply Chain Failures (신규) | A06 + 일부 A08 | 취약/미고정 의존성, Git/URL 의존성, lock 파일 누락, 설치 스크립트, `curl \| sh`, HTTP 패키지 저장소 |
| A04 | Cryptographic Failures | A02 | 약한 해시·암호, TLS 검증 해제, 하드코딩된 키, HTTPS/HSTS/TLS 버전 |
| A05 | Injection | A03 | SQL/명령/NoSQL/LDAP 인젝션, XSS, eval |
| A06 | Insecure Design | A04 | 자동 점검 불가, 수동 검토 필요 |
| A07 | Authentication Failures | A07 | JWT 검증 누락, 평문 비밀번호 비교, 쿠키 속성 |
| A08 | Software or Data Integrity Failures | A08 | 안전하지 않은 역직렬화, SRI 누락 |
| A09 | Security Logging and Alerting Failures | A09 | 민감 정보 로깅 |
| A10 | Mishandling of Exceptional Conditions (신규) | — | 예외 무시(`except: pass`, 빈 catch), 포괄적 except, 예외 시 허용(fail-open), 오류 페이지 스택 트레이스 노출 |

규칙 ID의 접두어(`A03-SQLI` 등)는 2021 분류 기준의 고정 식별자입니다. 2025 분류는 `python3 -m owasp_scanner rules`에서 확인할 수 있습니다.

## Claude AI 오탐 검토 (선택 기능)

정규식 점검은 오탐이 생길 수밖에 없습니다. `--ai-review`를 붙이면 결과마다 주변 코드(기본 앞뒤 20줄, 비밀값은 `****`로 가림)를 Claude에 보내 **실제 취약점 / 오탐 / 수동 확인 필요** 중 하나로 판정받고, 근거와 수정 제안을 리포트에 함께 표시합니다.

```bash
pip install anthropic                     # 이 기능에만 필요 (나머지는 표준 라이브러리만 사용)
export ANTHROPIC_API_KEY="sk-ant-..."

python3 -m owasp_scanner code ./my-project --ai-review              # 판정 추가
python3 -m owasp_scanner code ./my-project --ai-review --hide-fp    # 오탐 판정은 숨김
python3 -m owasp_scanner review scan.json -f html -o reviewed.html  # 저장한 JSON 결과를 나중에 검토
```

- 기본 모델은 `claude-opus-5-5`(`--ai-model`로 변경 가능)이고, JSON 스키마 구조화 출력으로 판정을 받습니다. 안전 분류기가 거절하면 서버 측 fallback(`fallbacks: "default"`)으로 다른 모델이 자동으로 다시 시도합니다.
- 결과 1건당 API 요청 1회(유료)가 발생합니다. 심각도 높은 순으로 최대 `--ai-max`(기본 30)건까지 검토합니다.
- 코드 일부가 외부로 전송되므로 실행 전에 확인을 받습니다(`--ai-yes`로 생략할 수 있습니다).

### 오탐 테스트: 정답 라벨과 비교 (`--expected`)

`examples/fp_samples/`에는 실제 취약점 3건과 패턴만 비슷한 안전한 코드 5건이 있고, 정답은 `labels.json`에 있습니다.

```bash
# 스캐너 정밀도(오탐 비율) 확인 - AI 없이, 무료
python3 -m owasp_scanner code examples/fp_samples --expected examples/fp_samples/labels.json
# → 라벨 비교: 스캐너 탐지 8건 중 실제 취약점 3건, 오탐 5건 (정밀도 38%)

# Claude 판정 정확도 확인
python3 -m owasp_scanner code examples/fp_samples --ai-review --expected examples/fp_samples/labels.json
# → AI 판정 정확도: N/8, 오탐 5건 중 M건을 오탐으로 판정 (+ 불일치 항목 목록)
```

내 프로젝트의 결과 일부를 직접 판정해 같은 형식의 라벨 파일을 만들면, 내 코드에서 AI 판정을 얼마나 믿을 수 있는지 측정할 수 있습니다. 자세한 내용은 [GUIDE.md 11장](GUIDE.md#11-오탐-알아내고-처리하기-claude-ai-검토-포함)을 참고하세요.

## 사용법

```bash
cd owasp-scanner

# 1) 소스코드 점검 (+ 의존성 점검 함께 수행)
python3 -m owasp_scanner code ./my-project --with-deps

# 2) 의존성 점검 + OSV.dev 취약점 DB 조회 (인터넷 연결 필요)
python3 -m owasp_scanner deps ./my-project --osv

# 3) 웹 점검 (점검 권한이 있는 대상만!)
python3 -m owasp_scanner web https://my-site.example.com

# HTML 리포트 저장
python3 -m owasp_scanner code ./my-project -f html -o report.html

# 규칙 목록
python3 -m owasp_scanner rules
```

### 공통 옵션

| 옵션 | 설명 |
|------|------|
| `-f, --format text\|json\|html` | 출력 형식 |
| `-o, --output FILE` | 결과 파일 저장 |
| `--min-severity LEVEL` | 지정한 심각도 이상만 표시 (`info` < `low` < `medium` < `high` < `critical`) |
| `--standard 2025\|2021` | 분류 기준 (기본: 2025) |
| `--owasp A03,A05` | 선택한 기준의 특정 OWASP 분류만 표시 |
| `--fail-on LEVEL` | 지정한 심각도 이상 결과가 있으면 종료 코드 1 반환 (CI 연동용) |

종료 코드는 `0`이 정상, `1`이 `--fail-on` 기준 초과, `2`가 실행 오류입니다.

### 예외 처리 (오탐 억제)

- 줄 끝에 `# nosec` 또는 `// owasp-ignore` 주석을 달면 그 줄은 건너뜁니다.
- 파일 앞 5줄 안에 `owasp-ignore-file`이 있으면 파일 전체를 건너뜁니다.
- 기본으로 제외하는 디렉터리는 `node_modules`, `.git`, `venv`, `dist`, `build` 등이며, `--exclude DIR`로 더 지정할 수 있습니다(`code`, `deps` 모두 적용).

## 데모

`examples/vulnerable_app/`에는 일부러 취약하게 만든 예제 코드가 들어 있습니다.

```bash
python3 -m owasp_scanner code examples/vulnerable_app --with-deps
```

생성된 HTML 리포트 예시는 `examples/sample-report.html`입니다.

## CI 연동 예시 (GitHub Actions)

```yaml
- name: OWASP 정적 점검
  run: PYTHONPATH=owasp-scanner python3 -m owasp_scanner code . --exclude examples --with-deps --fail-on high
```

## 테스트

```bash
python3 -m unittest discover -s tests -v
```

AI 검토 테스트는 실제 API를 호출하지 않습니다. 가짜 클라이언트를 쓰고, `anthropic`이 설치되어 있으면 진짜 SDK에 가짜 HTTP 응답을 넣어 요청 형식까지 검증합니다.

## 한계 및 주의사항

- 정적 점검은 **한 줄 단위 정규식 패턴 매칭**이라 데이터 흐름(taint)은 추적하지 않습니다. 그래서 오탐과 미탐이 생길 수 있으니 결과는 사람이 직접 검토해야 합니다. 더 깊은 분석이 필요하면 Semgrep, CodeQL, OWASP ZAP 같은 전문 도구를 함께 쓰세요.
- **Insecure Design** (2025 A06 / 2021 A04)은 자동 점검이 어려워 위협 모델링, 설계 검토 같은 수동 점검이 필요합니다.
- 웹 점검은 `GET`/`OPTIONS` 요청만 보내고 공격 페이로드는 보내지 않습니다. 그래도 **본인 소유이거나 서면 허가를 받은 대상에만** 쓰세요. 허가 없는 점검은 정보통신망법 등 관련 법률을 위반할 수 있습니다.
