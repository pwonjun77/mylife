# URL Monitor

등록한 시스템 URL을 한 번에(또는 주기적으로) 점검해 **접속 이상 여부**를 알려 주는 도구입니다.
Python 3.10 이상의 **표준 라이브러리만** 사용하므로 설치할 패키지가 없습니다. 망분리 서버에도 폴더째 복사해서 바로 실행할 수 있습니다.

> 상용 솔루션 검토·벤치마킹과 설계 배경은 **[DESIGN.md](DESIGN.md)** 에 있습니다.

| 점검 항목 | 장애(DOWN) | 경고(WARN) |
|-----------|------------|------------|
| DNS 조회 | 주소를 찾을 수 없음 | |
| TCP 연결 | 연결 거부, 연결 시간 초과 | |
| TLS·인증서 | 만료, 호스트명 불일치, 신뢰할 수 없는 인증서 | 만료까지 `cert_warn_days`(기본 14일) 이하 |
| HTTP 응답 | 시간 초과, 기대하지 않은 상태코드(기본 200~399 외), 리다이렉트 과다 | 응답시간 `warn_response_ms`(기본 2000ms) 초과 |
| 본문 | `body_contains` 문구 없음, `body_not_contains` 문구 있음 | |

- 장애로 보이면 `retries`(기본 2)번 다시 확인해서 **모두 실패해야 장애로 판정**합니다. 일시적인 끊김 때문에 생기는 오탐을 줄여 줍니다.
- 단계별 소요 시간(DNS·연결·TLS·첫 응답)을 따로 기록하므로 어디서 느린지 알 수 있습니다.
- 대상 서버에 영향을 주지 않도록 `GET`/`HEAD` 요청만 보냅니다.

## 빠른 시작

```bash
cd url-monitor

# URL 하나만 빠르게 확인
python3 -m url_monitor check --url https://www.example.com

# 설정 파일에 등록한 전체 대상을 점검 (콘솔 표)
python3 -m url_monitor check examples/targets.json

# HTML 보고서로 저장
python3 -m url_monitor check examples/targets.json -f html -o report.html
```

콘솔 출력 예:

```
[2026-10-25 09:00:03] 전체 5건 · 정상 2 · 경고 1 · 장애 2  (소요 0.3초)

상태   그룹          이름              코드   응답(ms)   인증서   원인
------------------------------------------------------------------------------------------------
DOWN   업무시스템    ERP API             500          5        -  서버 오류 응답 (5xx) - HTTP 500 (기대값 200-399)
DOWN   대외서비스    DB 포트             TCP          2        -  연결 거부 (포트 닫힘/서비스 중지) - 10.0.1.20:5432 연결 거부
WARN   대외서비스    홈페이지            200      2,306      62일  응답 지연 - 응답 2,306ms (기준 1,000ms 초과)
UP     업무시스템    그룹웨어            200        180      85일
```

**종료코드:** 결과는 종료코드로도 알려 줍니다. cron, Jenkins, Windows 작업 스케줄러에서 그대로 활용할 수 있습니다.

| 코드 | 의미 |
|------|------|
| `0` | 전체 정상 |
| `1` | 경고 있음 |
| `2` | 장애 있음 |
| `3` | 설정 오류 |

## 명령

| 명령 | 설명 |
|------|------|
| `check 설정파일` | 전체 1회 점검. `--url`(여러 번 지정 가능), `--group`, `-f text\|json\|html`, `-o 파일`, `--timeout`, `--no-retry` 옵션 |
| `check 설정파일 --db monitor.db --notify` | 점검 결과를 이력에 저장하고 **상태가 바뀔 때만** 알림을 보냅니다. cron으로 돌릴 때 사용합니다 |
| `watch 설정파일 --db monitor.db --status-page status.html` | 대상마다 `interval_sec` 간격으로 반복 점검합니다(상주 실행). 상태 페이지는 30초마다 자동으로 새로고침됩니다 |
| `report --db monitor.db --since 7d -f html -o weekly.html` | 기간별 가용률, 평균·최대 응답시간, 장애 이력 보고서 |
| `validate 설정파일` | URL 형식, 환경변수, 중복, 오타 항목을 검사합니다 |

## 설정 파일

### JSON (권장)

```json
{
  "defaults": { "timeout_sec": 10, "retries": 2, "warn_response_ms": 2000, "cert_warn_days": 14 },
  "groups": {
    "업무시스템": [
      { "name": "그룹웨어", "url": "https://gw.example.co.kr/login" },
      { "name": "ERP API", "url": "https://erp.example.co.kr/health",
        "expect_status": "200", "body_contains": "\"status\":\"UP\"",
        "headers": { "Authorization": "env:ERP_HEALTH_TOKEN" } }
    ],
    "인프라": [
      { "name": "DB 포트", "type": "tcp", "host": "10.0.1.20", "port": 5432 }
    ]
  },
  "include_csv": ["more-targets.csv"],
  "notify": {
    "webhooks": [ { "type": "slack", "url": "env:SLACK_WEBHOOK_URL" } ],
    "email": { "smtp": "smtp.example.co.kr:587", "user": "env:SMTP_USER", "password": "env:SMTP_PASS",
               "from": "monitor@example.co.kr", "to": ["ops@example.co.kr"] },
    "repeat_every_min": 30
  },
  "settings": { "workers": 20, "retention_days": 90 }
}
```

**비밀값:** `"env:변수명"`으로 쓰면 환경변수에서 값을 읽습니다. 토큰이나 비밀번호를 파일에 직접 쓰지 마세요.

### CSV (엑셀 목록을 그대로 사용)

```csv
group,name,url,expect_status,body_contains,warn_response_ms
업무시스템,그룹웨어,https://gw.example.co.kr/login,200-399,,
대외서비스,홈페이지,https://www.example.co.kr,200,,1000
```

- 엑셀에서 "CSV UTF-8"로 저장한 파일을 그대로 읽습니다.
- 한 칸에 문구를 여러 개 넣을 때는 `|`로 구분합니다.
- CSV만으로는 알림을 설정할 수 없습니다. 알림이 필요하면 JSON의 `include_csv`로 CSV를 불러오세요.

### 대상별 항목

| 항목 | 기본값 | 설명 |
|------|--------|------|
| `url` | | `http://` 또는 `https://` 주소 |
| `type` | `http` | `tcp`이면 `host`, `port`로 포트 연결만 확인 |
| `name` | 호스트명 | 그룹 안에서 고유해야 함 |
| `method` | `GET` | `GET` 또는 `HEAD` |
| `headers` | `{}` | 요청 헤더 (`env:` 사용 가능) |
| `expect_status` | `200-399` | `200`, `200,204`, `2xx`, `200-399` 형식 |
| `body_contains` / `body_not_contains` | | 문자열 또는 목록. 예: `"점검 중"` 문구가 보이면 장애 |
| `warn_response_ms` | `2000` | 응답시간 경고 기준 |
| `timeout_sec` | `10` | 단계별 제한 시간 |
| `retries` / `retry_delay_sec` | `2` / `3` | 장애 판정 전 재시도 횟수 / 간격 |
| `cert_warn_days` | `14` | 인증서 만료 경고 기준(일) |
| `verify_tls` / `ca_file` | `true` / | 사내 인증기관(CA)을 쓰면 `ca_file`에 CA 인증서(PEM) 경로를 지정하세요. `verify_tls: false`는 최후의 수단입니다 |
| `follow_redirects` / `max_redirects` | `true` / `5` | 리다이렉트 따라가기 |
| `interval_sec` | `60` | `watch` 점검 간격(최소 5초) |
| `proxy` | `auto` | `auto`는 `HTTPS_PROXY`/`NO_PROXY`(CIDR 지원)를 따름. `none`은 프록시를 쓰지 않음. 프록시 URL을 직접 지정할 수도 있음 |
| `maintenance` | `[]` | `[{"days": "Sun", "start": "02:00", "end": "04:00"}]` 이 시간대에는 점검만 하고 알림은 보내지 않음. `월-금`처럼 한글 요일도 가능. 자정을 넘는 구간도 지정 가능 |
| `enabled` | `true` | `false`로 두면 점검에서 제외 |

## 알림

- **보내는 시점:** 상태가 바뀔 때만 보냅니다.
  - 🔴 장애: 정상 → 장애
  - 🟢 복구: 장애 → 정상. 장애가 지속된 시간도 함께 알립니다
  - 🟡 경고: 정상 → 경고. `notify_warn: false`로 끌 수 있습니다
  - 장애가 계속되면 `repeat_every_min`(기본 30분)마다 다시 알립니다
- **묶어서 발송:** 한 번 점검할 때 생긴 알림은 메시지 하나로 묶어서 보냅니다.
- **웹훅 `type`:**

  | 값 | 대상 |
  |----|------|
  | `slack` | Slack |
  | `teams` | Microsoft Teams 수신 웹훅 |
  | `googlechat` | Google Chat |
  | `generic` | 결과 전체를 JSON으로 POST. 사내 메신저 연동용 |

- **이메일:** SMTP 587 포트(STARTTLS) 또는 465 포트(SSL)를 사용합니다.
- **이력 DB 유무:**
  - `--db` 없이 `--notify`만 쓰면 이전 상태를 모르므로, 장애·경고인 대상을 매번 알립니다.
  - cron으로 돌릴 때는 `--db`를 함께 지정하세요.

## 운영 예시

```bash
# cron: 5분마다 점검, 상태 바뀔 때만 알림, 이력 저장
*/5 * * * * cd /opt/url-monitor && python3 -m url_monitor check targets.json --db monitor.db --notify -o last.txt

# systemd 등으로 상주 실행 + 웹서버 폴더에 상태 페이지
python3 -m url_monitor watch targets.json --db monitor.db --status-page /var/www/html/status/index.html -q

# 매주 월요일 가용률 보고서
0 9 * * 1 cd /opt/url-monitor && python3 -m url_monitor report --db monitor.db --since 7d -f html -o weekly.html

# 배포 직후 스모크 테스트 (장애면 파이프라인 실패)
python3 -m url_monitor check targets.json --group 대외서비스 --no-retry || exit 1
```

**모니터링 서버 자체 점검:** 모니터링 서버가 멈추면 알림도 오지 않습니다. UptimeRobot 같은 무료 외부 서비스로 상태 페이지 URL을 감시하면 이 문제를 보완할 수 있습니다.

## 주의

- **소유하거나 허가를 받은 시스템만** 등록하세요. 허가 없이 반복 호출하면 관련 법률 위반이 될 수 있습니다.
- **프록시 경유 시:** 프록시를 거쳐 점검하면 연결·TLS 시간이 프록시 기준으로 측정됩니다. 결과에는 `via_proxy`로 표시됩니다.
- **인증서 검증을 끈 경우:** `verify_tls: false`이면 인증서 정보를 읽을 수 없어 만료일 점검도 하지 않습니다.

## 테스트

```bash
cd url-monitor
python3 -m unittest discover -s tests
```

로컬 테스트 서버로 정상, 5xx/4xx, 지연, 시간 초과, 리다이렉트, 문구, 인증서(openssl로 생성), TCP, 알림 상태 전이, CLI를 검증합니다.
