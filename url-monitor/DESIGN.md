# URL 모니터링 도구 설계서 (상용 솔루션 검토 · 벤치마킹)

> 목적: 시스템 URL을 등록해 두고 주기적으로 간단히 점검해 **접속 이상 여부**(다운, 지연, 오류 응답, 인증서 만료 등)를 찾아 알려 주는 도구를 만든다.
> 이 문서는 ① 상용·오픈소스 솔루션 검토 ② 벤치마킹 결과 ③ 자체 도구 설계를 담는다.
> 작성일: 2026-10-25 · 가격·요금제는 수시로 바뀌므로 도입 전 각 공식 사이트에서 다시 확인할 것.

---

## 1. 요약 (결론 먼저)

| 질문 | 답 |
|------|----|
| 상용 솔루션이 있는가? | **많다.** 외부 SaaS(UptimeRobot, Better Stack, Pingdom, StatusCake, Site24x7, Datadog Synthetics, Checkly 등), 국내 APM(WhaTap, 제니퍼), 오픈소스(Uptime Kuma, Gatus, Prometheus Blackbox Exporter, Zabbix)가 이미 성숙해 있다. |
| 그대로 쓰면 되는가? | **외부에 공개된 URL만** 본다면 SaaS 무료/저가 요금제로 충분하다. 다만 **사내망(내부 IP·VPN 뒤) 시스템**, **외부 전송 불가 정책**, **점검 결과를 사내 보고 양식으로 일괄 출력**해야 한다면 자체 도구나 설치형 오픈소스가 맞다. |
| 권장안 | **자체 경량 도구(Python 표준 라이브러리)** 를 만들되, 기능 범위와 판정 기준은 Uptime Kuma·Gatus·UptimeRobot을 벤치마킹한다. 기존 `owasp-scanner`와 같은 구조(CLI + JSON/HTML 리포트, 외부 패키지 없음)로 만들어 사내망 서버 한 대에서 cron/스케줄러로 돌린다. |

---

## 2. 솔루션 검토

### 2.1 외부 SaaS (클라우드에서 우리 URL을 호출)

| 제품 | 성격 | 강점 | 약점 / 유의점 |
|------|------|------|---------------|
| **UptimeRobot** | URL 업타임 전문 | 무료 요금제로 다수 모니터, 설정이 매우 단순, 상태 페이지 제공 | 무료는 5분 주기·기능 제한, 사내망 접근 불가 |
| **Better Stack (Uptime)** | 업타임 + 온콜 + 상태페이지 | 다지역 확인 후 장애 판정, 전화/SMS 온콜, 스크린샷 | 온콜·고급 기능은 유료 |
| **Pingdom** (SolarWinds) | 업타임 + 트랜잭션 + RUM | 오래된 레퍼런스, 다지역 프로브, 트랜잭션(로그인 시나리오) 점검 | 상대적으로 비쌈 |
| **StatusCake** | 업타임 + SSL + 도메인 | SSL/도메인 만료 점검, 페이지 속도 점검 | UI가 다소 구식 |
| **Site24x7** (Zoho) | 통합 모니터링 | URL·서버·네트워크·APM 통합, **온프레미스 프로브** 설치로 사내망 점검 가능 | 기능이 많아 학습 비용 |
| **Datadog Synthetics** | 관측성 플랫폼의 일부 | API·브라우저 시나리오 테스트, **Private Location**으로 사내망 점검, APM·로그와 연계 | 호출 건수 과금 → 대량 등록 시 비용 큼 |
| **Checkly** | 코드형(Monitoring as Code) | Playwright 스크립트로 점검 정의, Git으로 관리, CI 연동 | 개발자 중심 |
| **Grafana Cloud Synthetic Monitoring** | Grafana 생태계 | k6·Blackbox 기반, 대시보드 연계, 사설 프로브 지원 | Grafana 스택 이해 필요 |

### 2.2 국내 솔루션

| 제품 | 성격 | 비고 |
|------|------|------|
| **WhaTap (와탭)** | 국내 SaaS 관측성(APM·서버·DB·URL 모니터링) | 한국어 지원·국내 리전, URL 모니터링은 전체 관측성 제품의 일부 |
| **JENNIFER (제니퍼소프트)** | 국내 APM 대표 | 애플리케이션 내부 성능 중심, 단순 URL 생존 점검만을 위해서는 과함 |
| **Scouter** (오픈소스, LG CNS 계열) | APM | URL 업타임보다는 WAS 성능 모니터링용 |

> 공공·금융권처럼 망분리 환경에서는 외부 SaaS가 내부 시스템을 호출할 수 없으므로, 설치형(온프레미스) 제품이나 자체 도구가 일반적이다.

### 2.3 오픈소스 (설치형)

| 제품 | 강점 | 약점 |
|------|------|------|
| **Uptime Kuma** | 웹 UI로 URL 등록, HTTP/키워드/TCP/Ping/DNS 점검, 90여 종 알림 연동, 상태 페이지. Docker 한 줄로 설치 | 단일 노드, 대량 일괄 등록·보고서 출력은 약함 |
| **Gatus** | YAML로 점검 정의, **조건식**(`[STATUS] == 200`, `[RESPONSE_TIME] < 500`, `[CERTIFICATE_EXPIRATION] > 48h`)이 강력, Git 관리 용이 | UI는 조회 전용 |
| **Prometheus + Blackbox Exporter** | 표준 관측성 스택, Alertmanager·Grafana 연계, 대규모 확장 | 구성 요소가 많아 소규모엔 과함 |
| **Zabbix** (Web scenario) | 기존 서버 모니터링에 URL 점검 추가 가능, 엔터프라이즈 사용 많음 | 설정이 복잡 |
| **Statping-ng / Upptime** | 상태 페이지 중심 (Upptime은 GitHub Actions로 동작) | 사내망 점검 불가(Upptime), 유지보수 활발도 낮음 |

---

## 3. 벤치마킹: 공통 기능과 차용할 아이디어

### 3.1 기능 비교 매트릭스

| 기능 | UptimeRobot | Better Stack | Datadog Synth. | Uptime Kuma | Gatus | **자체 도구(목표)** |
|------|:-:|:-:|:-:|:-:|:-:|:-:|
| HTTP(S) 상태코드 점검 | ● | ● | ● | ● | ● | ● |
| 응답시간 임계치 | ● | ● | ● | ● | ● | ● |
| 키워드(본문) 포함/미포함 | ● | ● | ● | ● | ● | ● |
| SSL 인증서 만료 | ● | ● | ● | ● | ● | ● |
| TCP 포트 / DNS | ● | ● | ● | ● | ● | ● (2단계) |
| 재시도 후 장애 판정 | ● | ● | ● | ● | ● | ● |
| 다지역/다지점 교차 확인 | ● | ● | ● | ✕ | ✕ | ✕ (단일 지점) |
| 사내망 점검 | ✕ | ✕ | Private Loc. | ● | ● | **●** |
| 알림(메일/메신저/웹훅) | ● | ● | ● | ● | ● | ● |
| 상태 페이지 | ● | ● | ✕ | ● | ● | HTML 리포트 |
| 설정 파일(코드)로 관리 | API | API/Terraform | Terraform | ✕(UI) | ● | **●** |
| CSV 일괄 등록 | 일부 | 일부 | ✕ | ✕ | ✕ | **●** |
| 1회성 전체 점검 리포트 | ✕ | ✕ | ✕ | ✕ | ✕ | **●** |
| 외부 패키지 없이 실행 | — | — | — | Node+DB | Go 바이너리 | **Python 표준 라이브러리** |

### 3.2 차용할 아이디어

1. **Gatus의 조건식 판정** — "200이면 정상"보다 유연하다. `status`, `response_time_ms`, `body contains`, `cert_days_left` 조건을 URL별로 지정한다.
2. **UptimeRobot의 단순함** — URL 하나만 적으면 기본 규칙(2xx/3xx, 5초 이내, 인증서 14일 이상)으로 바로 점검된다.
3. **Better Stack/Uptime Kuma의 재시도 후 판정** — 1회 실패로 바로 장애 처리하지 않는다(일시적 네트워크 문제로 인한 오탐 방지). 기본 2회 재시도.
4. **상태 전이 기반 알림** — 정상→장애, 장애→복구일 때만 알림. 장애 지속 중에는 주기적 재알림만(알림 폭주 방지).
5. **Datadog의 단계별 시간 측정** — DNS·TCP 연결·TLS 핸드셰이크·첫 바이트(TTFB)를 분리해 기록하면 "어디서 느린지"를 바로 알 수 있다.
6. **상태 페이지** — 정적 HTML 한 장으로 전체 URL의 현재 상태·최근 가용률을 보여 준다.

---

## 4. 자체 도구 설계

### 4.1 요구사항

**기능 요구사항**

| ID | 내용 |
|----|------|
| F1 | URL을 설정 파일(YAML 대신 표준 라이브러리로 읽을 수 있는 **JSON/CSV/TOML**)로 등록·그룹화 |
| F2 | **1회 전체 점검**(`check`): 등록된 모든 URL을 병렬로 점검하고 표/JSON/HTML 리포트 출력 |
| F3 | **주기 점검**(`watch`): 지정 간격으로 반복 점검, 상태 변화 시 알림 |
| F4 | 점검 항목: DNS 해석, TCP 연결, TLS 핸드셰이크·인증서 만료, HTTP 상태코드, 응답시간, 본문 키워드, 리다이렉트 |
| F5 | 판정: 정상(UP) / 경고(WARN: 느림·인증서 임박) / 장애(DOWN), 원인 분류 표시 |
| F6 | 알림: 이메일(SMTP), 웹훅(Slack·Teams·Google Chat), 사내 메신저용 일반 웹훅 |
| F7 | 이력 저장(SQLite)과 가용률(24h/7d/30d)·평균 응답시간 집계 |
| F8 | 상태 페이지(정적 HTML) 생성 |

**비기능 요구사항**

- Python 3.10+, **표준 라이브러리만** 사용(`owasp-scanner`와 동일 원칙) → 망분리 서버에도 그대로 복사해 실행.
- URL 수백 개를 1분 안에 점검(스레드 풀 병렬, 기본 동시 20).
- 비파괴: `GET`/`HEAD`만 사용, 대상 서버에 부담 주지 않도록 URL별 최소 간격 보장.
- 비밀값(헤더의 토큰, SMTP 비밀번호)은 설정 파일이 아니라 환경변수로 참조.

### 4.2 구성도

```
                ┌──────────────────────────────────────────────┐
 targets.json ─▶│  config      : 설정 로드·검증·기본값 병합      │
 targets.csv    │      │                                          │
                │      ▼                                          │
                │  scheduler   : check(1회) / watch(주기)         │
                │      │  ThreadPoolExecutor                      │
                │      ▼                                          │
                │  probe       : DNS → TCP → TLS → HTTP 단계 측정  │
                │      │  ProbeResult                             │
                │      ▼                                          │
                │  evaluator   : 조건식 판정 + 재시도 → UP/WARN/DOWN│
                │      │                                          │
                │      ├─▶ store    : SQLite 이력, 가용률 집계      │
                │      ├─▶ notifier : 상태 전이 시 메일/웹훅        │
                │      └─▶ report   : text / json / html / 상태페이지│
                └──────────────────────────────────────────────┘
```

### 4.3 디렉터리 구조 (예정)

```
url-monitor/
├── DESIGN.md               # 이 문서
├── README.md
├── examples/
│   ├── targets.json        # 예시 설정
│   └── targets.csv         # 일괄 등록 예시
├── url_monitor/
│   ├── __main__.py
│   ├── cli.py              # check / watch / report / validate 명령
│   ├── config.py           # 설정 로드·검증
│   ├── models.py           # Target, ProbeResult, CheckResult, Status
│   ├── probe.py            # 단계별 측정 (socket, ssl, http.client)
│   ├── evaluator.py        # 조건 판정, 재시도
│   ├── scheduler.py        # 병렬 실행, 주기 실행
│   ├── store.py            # SQLite 이력
│   ├── notifier.py         # SMTP, 웹훅
│   └── report.py           # text/json/html, 상태 페이지
└── tests/
```

### 4.4 설정 파일 형식

```json
{
  "defaults": {
    "interval_sec": 60,
    "timeout_sec": 10,
    "retries": 2,
    "expect_status": "200-399",
    "warn_response_ms": 2000,
    "cert_warn_days": 14,
    "verify_tls": true
  },
  "groups": {
    "업무시스템": [
      { "name": "그룹웨어", "url": "https://gw.example.co.kr/login" },
      { "name": "ERP API", "url": "https://erp.example.co.kr/health",
        "expect_status": "200", "body_contains": "\"status\":\"UP\"",
        "headers": { "Authorization": "env:ERP_HEALTH_TOKEN" } }
    ],
    "대외서비스": [
      { "name": "홈페이지", "url": "https://www.example.co.kr", "warn_response_ms": 1000 },
      { "name": "DB 포트", "type": "tcp", "host": "10.0.1.20", "port": 5432 }
    ]
  },
  "notify": {
    "webhooks": [ { "type": "slack", "url": "env:SLACK_WEBHOOK_URL" } ],
    "email": { "smtp": "smtp.example.co.kr:587", "user": "env:SMTP_USER",
               "password": "env:SMTP_PASS", "to": ["ops@example.co.kr"] },
    "repeat_every_min": 30
  }
}
```

CSV 일괄 등록(엑셀에서 관리하던 목록을 그대로 사용):

```csv
group,name,url,expect_status,body_contains,warn_response_ms
업무시스템,그룹웨어,https://gw.example.co.kr/login,200-399,,
대외서비스,홈페이지,https://www.example.co.kr,200,,1000
```

### 4.5 점검 단계 (probe)

각 단계의 소요 시간을 따로 기록해 원인을 좁힌다(Datadog·Pingdom 방식).

| 단계 | 구현 | 실패 시 원인 코드 |
|------|------|------------------|
| 1. DNS 해석 | `socket.getaddrinfo` | `DNS_FAIL` |
| 2. TCP 연결 | `socket.create_connection` | `CONN_REFUSED`, `CONN_TIMEOUT` |
| 3. TLS 핸드셰이크 | `ssl.create_default_context().wrap_socket` → 인증서 `notAfter`, 발급자, 호스트명 일치 | `TLS_ERROR`, `CERT_EXPIRED`, `CERT_HOSTNAME` |
| 4. HTTP 요청 | `http.client` 로 `GET`(본문은 최대 256KB만 읽음), 리다이렉트 최대 5회 추적 | `HTTP_TIMEOUT`, `HTTP_5XX`, `HTTP_4XX`, `UNEXPECTED_STATUS` |
| 5. 본문 검사 | `body_contains` / `body_not_contains` (예: "점검 중", "Error") | `KEYWORD_MISSING`, `KEYWORD_FOUND` |

> 프록시 환경은 `HTTPS_PROXY` 환경변수를 존중한다(이 경우 DNS/TCP 단계는 프록시 기준으로 측정됨을 리포트에 표시).

### 4.6 판정 규칙 (evaluator)

```
DOWN : DNS/TCP/TLS 실패, 인증서 만료, 타임아웃, 기대 상태코드 아님, 키워드 조건 위반
WARN : 응답시간 > warn_response_ms, 인증서 만료까지 cert_warn_days 이하, 리다이렉트 과다
UP   : 위에 해당 없음
```

- **재시도**: DOWN이면 `retries`회(기본 2, 간격 3초) 다시 점검해 모두 실패해야 DOWN 확정 → 일시적 끊김으로 인한 오탐 방지.
- **상태 전이 알림**: 직전 상태와 비교해 `UP→DOWN`(장애), `DOWN→UP`(복구, 장애 지속시간 포함), `UP→WARN`만 알림. 장애 지속 중에는 `repeat_every_min` 마다 재알림.
- **유지보수 시간대**: `maintenance: [{"cron-like": "Sun 02:00-04:00"}]` 동안은 점검은 하되 알림은 보내지 않음(Uptime Kuma 방식).

### 4.7 데이터 모델 (SQLite)

```sql
CREATE TABLE checks (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,          -- group/name
  ts     TEXT NOT NULL,          -- ISO8601
  status TEXT NOT NULL,          -- UP / WARN / DOWN
  reason TEXT,                   -- 원인 코드
  http_status INTEGER,
  dns_ms REAL, connect_ms REAL, tls_ms REAL, ttfb_ms REAL, total_ms REAL,
  cert_days_left INTEGER
);
CREATE INDEX idx_checks_target_ts ON checks(target, ts);

CREATE TABLE incidents (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,                 -- NULL = 진행 중
  reason TEXT
);
```

가용률 = UP+WARN 건수 / 전체 건수 (기간별). 보존 기간 기본 90일, 이후 자동 삭제.

### 4.8 CLI

```bash
# 1회 전체 점검 (가장 많이 쓸 기능) — 콘솔 표 + 종료코드(장애 있으면 2)
python3 -m url_monitor check examples/targets.json
python3 -m url_monitor check targets.csv -f html -o report.html

# URL 하나 빠르게 확인
python3 -m url_monitor check --url https://www.example.co.kr

# 주기 점검 (상주) + 상태 페이지 갱신
python3 -m url_monitor watch targets.json --db monitor.db --status-page /var/www/status/index.html

# 이력 기반 보고서 (일간/주간 가용률)
python3 -m url_monitor report --db monitor.db --since 7d -f html -o weekly.html

# 설정 검증 (URL 형식, 환경변수 존재 여부)
python3 -m url_monitor validate targets.json
```

콘솔 출력 예:

```
[2026-10-25 09:00:03] 전체 12건 · 정상 9 · 경고 2 · 장애 1  (소요 4.2초)

상태  그룹        이름        코드  응답(ms)  인증서  원인
DOWN  업무시스템  ERP API     503     121      85일   HTTP_5XX
WARN  대외서비스  홈페이지    200    2,430     62일   느림 (> 1000ms)
WARN  업무시스템  그룹웨어    200      180      9일   인증서 만료 임박
UP    ...
```

종료코드: `0` 전체 정상, `1` 경고 있음, `2` 장애 있음 → cron, Jenkins, Windows 작업 스케줄러에서 그대로 활용.

### 4.9 운영 방식

| 방식 | 설명 | 추천 상황 |
|------|------|-----------|
| cron + `check` | 5분마다 `check --db` 실행, 장애 시 알림 | 가장 단순, 서버 1대 |
| `watch` 상주 + systemd | 1분 주기, 상태 페이지 자동 갱신 | 상시 모니터링 |
| CI 파이프라인 | 배포 직후 `check` 실행, 장애 시 배포 실패 처리 | 배포 검증(스모크 테스트) |
| 이중화 | 서로 다른 망의 서버 2대에서 실행, 둘 다 DOWN일 때만 장애 확정 | 모니터링 서버 자체 장애·망 경로 오탐 대비 |

### 4.10 보안·운영 유의사항

- **점검 대상은 소유하거나 허가받은 시스템만** 등록한다(무단 반복 호출은 정보통신망법 위반 소지).
- `verify_tls: false`는 내부 사설 인증서 등 예외 대상에만 허용하고, 리포트에 경고 표시.
- 설정 파일에는 비밀값을 직접 쓰지 않고 `env:변수명`으로 참조, 리포트·로그에서는 헤더 값을 마스킹.
- 모니터링 서버 자체가 죽으면 알림도 안 온다 → 하루 1회 "생존 신호(heartbeat)" 알림 또는 외부 무료 SaaS(UptimeRobot 등)로 모니터링 서버의 상태 페이지를 역으로 감시.

---

## 5. 단계별 구현 계획

| 단계 | 범위 | 산출물 |
|------|------|--------|
| **1단계 (MVP)** | 설정 로드(JSON/CSV), HTTP·TLS 점검, 재시도 판정, `check` 명령, text/json/html 리포트, 종료코드 | 1회 전체 점검 도구 |
| **2단계** | SQLite 이력, `watch` 주기 점검, 상태 전이 알림(Slack/Teams 웹훅, SMTP), 유지보수 시간대 | 상시 모니터링 |
| **3단계** | 상태 페이지, 가용률 보고서(`report`), TCP/DNS 점검, 이중화 판정 | 운영 보고·대시보드 |
| (선택) | 장애 원인 요약에 Claude API 활용(`owasp-scanner`의 `--ai-review`처럼 선택 기능) | 장애 보고서 초안 자동 작성 |

---

## 6. 선택 가이드 (자체 개발 vs 도입)

| 상황 | 추천 |
|------|------|
| 대외 공개 URL 몇십 개, 빠르게 시작 | **UptimeRobot / Better Stack 무료 요금제** |
| 사내망 포함, 웹 UI로 관리하고 싶음 | **Uptime Kuma** (Docker) |
| 사내망 포함, 설정을 Git으로 관리 | **Gatus** |
| 이미 Prometheus/Grafana 운영 중 | **Blackbox Exporter** |
| 이미 Datadog/WhaTap 등 관측성 제품 사용 중 | 해당 제품의 Synthetic/URL 모니터링 기능 |
| 망분리·외부 설치 제한, 일괄 점검 보고서 필요, 가볍게 | **이 문서의 자체 도구** |
