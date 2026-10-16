# OWASP Scanner

**OWASP Top 10 (2021)** 기준으로 취약점을 점검하는 도구입니다.
Python 3.10 이상의 표준 라이브러리만 사용하므로 따로 설치할 패키지가 없습니다.

| 모드 | 설명 | 주요 점검 항목 |
|------|------|----------------|
| `code` | 소스코드 정적 점검 (SAST) | SQL/명령/NoSQL 인젝션, XSS, 경로 조작, SSRF, 역직렬화, 취약한 암호화, 하드코딩된 비밀정보, JWT 검증 누락, 디버그 모드 등 |
| `deps` | 의존성 점검 (A06) | `requirements*.txt`, `package.json`의 버전 미고정, Git/URL 의존성, OSV.dev 알려진 취약점(CVE) |
| `web`  | 웹 비파괴 점검 (passive DAST) | HTTPS·HSTS·TLS 버전·인증서, 보안 헤더, 쿠키 속성, CORS, HTTP 메서드, 오류 페이지 정보 노출, `.git`/`.env` 등 민감 파일 노출, SRI, 혼합 콘텐츠 |

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
| `--owasp A03,A05` | 특정 OWASP 분류만 표시 |
| `--fail-on LEVEL` | 지정한 심각도 이상 결과가 있으면 종료 코드 1 반환 (CI 연동용) |

종료 코드는 `0`이 정상, `1`이 `--fail-on` 기준 초과, `2`가 실행 오류입니다.

### 예외 처리 (오탐 억제)

- 줄 끝에 `# nosec` 또는 `// owasp-ignore` 주석을 달면 그 줄은 건너뜁니다.
- 파일 앞 5줄 안에 `owasp-ignore-file`이 있으면 파일 전체를 건너뜁니다.
- 기본으로 제외하는 디렉터리는 `node_modules`, `.git`, `venv`, `dist`, `build` 등이며, `--exclude DIR`로 더 지정할 수 있습니다.

## 데모

`examples/vulnerable_app/`에는 일부러 취약하게 만든 예제 코드가 들어 있습니다.

```bash
python3 -m owasp_scanner code examples/vulnerable_app --with-deps
```

생성된 HTML 리포트 예시는 `examples/sample-report.html`입니다.

## CI 연동 예시 (GitHub Actions)

```yaml
- name: OWASP 정적 점검
  run: PYTHONPATH=owasp-scanner python3 -m owasp_scanner code . --with-deps --fail-on high
```

## 테스트

```bash
python3 -m unittest discover -s tests -v
```

## 한계 및 주의사항

- 정적 점검은 **한 줄 단위 정규식 패턴 매칭**이라 데이터 흐름(taint)은 추적하지 않습니다. 그래서 오탐과 미탐이 생길 수 있으니 결과는 사람이 직접 검토해야 합니다. 더 깊은 분석이 필요하면 Semgrep, CodeQL, OWASP ZAP 같은 전문 도구를 함께 쓰세요.
- **A04 (Insecure Design)** 은 자동 점검이 어려워 위협 모델링, 설계 검토 같은 수동 점검이 필요합니다.
- 웹 점검은 `GET`/`OPTIONS` 요청만 보내고 공격 페이로드는 보내지 않습니다. 그래도 **본인 소유이거나 서면 허가를 받은 대상에만** 쓰세요. 허가 없는 점검은 정보통신망법 등 관련 법률을 위반할 수 있습니다.
