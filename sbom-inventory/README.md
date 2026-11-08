# sbom-inventory — 상용 솔루션 없이 만드는 사내 SBOM·버전 관리

Nmap(오픈소스) + Microsoft 365(Intune / Defender for Endpoint API) + 경량 에이전트 스크립트로
사내망 장비의 **설치 소프트웨어·노출 서비스·OS 버전**을 수집하고, 실행(run)마다 스냅샷을 쌓아
**버전 이력, 변경(diff), 정책 위반, CycloneDX 1.6 SBOM** 을 만듭니다.

- Python 3.10+ 표준 라이브러리만 사용 (설치할 패키지 없음), 저장소는 단일 SQLite 파일
- 모든 수집은 **읽기 전용** (Graph 권한도 `*.Read.All` 만 사용)

---

## 1. 아키텍처

```
          ┌────────────── 수집 계층 (collectors/) ───────────────┐
          │                                                      │
 사내망 ──▶ nmap_scan.py    nmap -sV [-O] -oX → XML 파싱          │  "밖에서 보이는 것"
          │                 (노출 서비스·버전·CPE, OS 추정)       │  ─ 미관리 장비/서버/IoT 발견
          │                                                      │
 M365  ──▶ graph.py        Intune  managedDevices + detectedApps │  "MDM 이 아는 것"
          │                 Defender machines + TVM 인벤토리      │  ─ 등록 PC 설치 앱, 취약점 수
          │                                                      │
 호스트 ──▶ agent_import.py collect-windows.ps1 / collect-linux.sh│  "호스트 안에서 본 것"
          │                 → 공유폴더 JSON(+sha256)              │  ─ 레지스트리/dpkg/rpm 원본
          └──────────────────────────┬───────────────────────────┘
                                     │  list[HostRecord(source, Asset, [Component])]
                                     ▼
          ┌────────────── 정규화 (models.py) ────────────────────┐
          │ hostname short/lower, MAC aa:bb:.., 쓰레기 serial 제거  │
          │ 소프트웨어명 정규화, purl / CPE 2.3 생성, 버전 비교 키     │
          └──────────────────────────┬───────────────────────────┘
                                     ▼
          ┌────────────── 저장/병합 (store.py, SQLite) ───────────┐
          │ assets        : 병합된 자산 (serial > MAC > hostname > IP)│
          │ runs          : 수집 실행 단위                          │
          │ observations  : run × 자산 × 출처 × 컴포넌트 (append-only)│
          │ asset_source_runs : 출처별 최종 관측 run                │
          └──────┬──────────────┬──────────────┬─────────────────┘
                 ▼              ▼              ▼
          policy.py        diff/history    export.py
          최소버전·금지·EOL   설치/삭제/변경    CycloneDX 1.6 / CSV / HTML
```

### 1.1 왜 세 가지 수집원을 함께 쓰나

| 수집원 | 보이는 것 | 못 보는 것 | 자산 식별자 |
|--------|-----------|------------|-------------|
| **Nmap** | 네트워크에 열린 서비스의 제품/버전(-sV), OS 추정(-O), 미등록 장비 | 데스크톱 앱, 로컬 라이브러리 | IP, PTR 이름, MAC(같은 L2 일 때만) |
| **Intune** (Graph) | MDM 등록 PC/모바일의 설치 앱(detectedApps) | 미등록 서버·네트워크 장비 | deviceName, serial, MAC |
| **Defender TVM** | 앱 + 취약점 수 + EOL 상태 + 설치 경로 | 센서 미설치 장비 | DNS명, IP, MAC |
| **에이전트** | 레지스트리/패키지 DB 원본 (사용자별 설치 포함) | 배포 안 된 장비 | hostname, serial, MAC, IP |

Nmap 은 "Intune 에 없는데 망에 붙어 있는 장비"(섀도 IT) 를 찾아내는 역할이 핵심이고,
HTML 보고서에 **"미관리 장비 — Nmap 에서만 발견"** 섹션으로 따로 표시됩니다.

### 1.2 자산 병합(correlation) 로직 — `store.py:_find_asset`

1. **serial** 일치 (Intune ↔ 에이전트). `To be filled by O.E.M.`, `0`, `Default string` 등 가짜 시리얼은 버림 — 그대로 쓰면 다른 PC 들이 한 자산으로 뭉칩니다.
2. **MAC** 일치 (에이전트 ↔ Intune ↔ Defender ↔ 같은 세그먼트의 Nmap). `00:00:..`, `ff:ff:..` 제외.
3. **hostname**(short, 소문자) 일치 (Nmap PTR ↔ 나머지).
4. 위 식별자가 전혀 없을 때만 **IP** 일치 (DHCP 로 IP 가 재사용되므로 가장 약한 근거).

에이전트 JSON 은 serial·MAC·hostname·IP 를 모두 담고 있어 Intune(serial)과 Nmap(IP)을 이어 주는 **브리지** 역할을 합니다.
IP 는 매 관측마다 최신값으로 교체되고, OS 정보는 `agent/intune/defender` 값이 Nmap 추정보다 우선합니다.

### 1.3 버전 이력 모델

- 수집할 때마다 `runs` 에 1행, `observations` 에 관측 전체를 **추가만** 합니다(UPDATE/DELETE 없음).
- 시점 T 의 인벤토리 = 각 (자산, 출처)에 대해 T 이전 **가장 최근 관측 run** 의 결과.
  → Nmap 은 매일, 에이전트는 주 1회처럼 주기가 달라도 '현재 상태'가 올바르게 합쳐집니다.
- `diff` 는 **양쪽 시점 모두에서 관측된 (자산, 출처)** 만 비교 → 이번에 꺼져 있던 PC 가 "전체 삭제"로 보이는 오탐 방지.
- 포렌식 관점: "2026-10-03 시점에 PC-021 에 Chrome 129 가 있었다"를 run ID·수집 시각·원본 증적(`--keep-xml`, 에이전트 JSON + sha256)으로 재현할 수 있는 타임라인이 됩니다.

### 1.4 파일 구조

```
sbom-inventory/
├─ sbom_inventory/
│  ├─ models.py              Asset/Component/HostRecord, 정규화, version_key, purl/CPE
│  ├─ collectors/
│  │  ├─ nmap_scan.py        nmap 실행(대상 검증, shell=False) + XML 파싱(ENTITY 거부)
│  │  ├─ graph.py            OAuth2 client credentials, 페이징, 429 재시도, Intune/Defender
│  │  └─ agent_import.py     에이전트 JSON 검증(스키마/크기/sha256) 및 변환
│  ├─ store.py               SQLite 스키마, 병합, inventory/diff/history
│  ├─ policy.py              최소 버전/최대 버전/금지/EOL 정책
│  ├─ export.py              CycloneDX 1.6, CSV, HTML 보고서
│  ├─ dtrack.py              Dependency-Track 업로드 (장비별 프로젝트, 처리 대기, findings)
│  └─ cli.py
├─ agents/
│  ├─ collect-windows.ps1    Uninstall 레지스트리(HKLM, WOW6432Node, HKU) [+Appx]
│  └─ collect-linux.sh       dpkg / rpm / apk (POSIX sh + awk)
├─ examples/                 config / policy / 에이전트 JSON 샘플
└─ tests/                    unittest (Graph 는 가짜 HTTP 로 테스트)
```

---

## 2. 빠른 시작

```bash
cd sbom-inventory

# (1) 네트워크 스캔 — 승인된 대역만. OS 탐지는 root 필요
sudo python3 -m sbom_inventory nmap 10.10.1.0/24 --os --keep-xml evidence/scan-$(date +%F).xml
#     이미 돌린 nmap 결과를 넣을 수도 있음
python3 -m sbom_inventory nmap --from-xml scan.xml

# (2) Intune / Defender — 비밀값은 환경변수로만
export SBOM_TENANT_ID=... SBOM_CLIENT_ID=... SBOM_CLIENT_SECRET=...
python3 -m sbom_inventory intune                 # 소~중규모 (v1.0 API)
python3 -m sbom_inventory intune --mode export   # 대규모: 보고서 내보내기(AppInvRawData) CSV 한 번에
python3 -m sbom_inventory defender               # MDE P2 / Defender Vulnerability Management 라이선스 필요

# (3) 에이전트 결과 import
python3 -m sbom_inventory import /mnt/sbom-share --verify-hash

# (4) 조회
python3 -m sbom_inventory runs
python3 -m sbom_inventory assets
python3 -m sbom_inventory show PC-021              # 자산 하나의 SBOM
python3 -m sbom_inventory history chrome           # run 별 버전 분포 → 패치 진행률
python3 -m sbom_inventory diff                     # 직전 run 대비 설치/삭제/버전변경
python3 -m sbom_inventory policy examples/policy.example.json --fail-on high

# (5) 내보내기
python3 -m sbom_inventory export cyclonedx -o sbom-org.cdx.json              # 전사(장비별 중첩)
python3 -m sbom_inventory export cyclonedx --asset PC-021 -o PC-021.cdx.json # 장비 단위
python3 -m sbom_inventory export csv -o inventory.csv
python3 -m sbom_inventory export html --policy examples/policy.example.json -o report.html
```

### 정기 실행 (스케줄러)

`run -c config.json` 은 설정의 모든 수집기를 **하나의 run** 으로 실행하고, `reports/` 에
`sbom-run<N>.cdx.json` 과 `report-run<N>.html`(정책 위반 + 직전 run 대비 변경)을 남깁니다.
한 수집기가 실패해도 나머지는 계속 진행하며, 실패가 있으면 종료코드 1.

```cron
# 매일 02:10 수집 (수집 서버의 전용 서비스 계정으로)
10 2 * * *  cd /opt/sbom-inventory && . ./secrets.env && python3 -m sbom_inventory --db /var/lib/sbom/inventory.db run -c config.json
```

---

## 3. Microsoft 365 설정

### 3.1 Entra ID 앱 등록

1. Entra 관리 센터 → 앱 등록 → 새 등록 (리디렉션 URI 불필요)
2. **API 권한 → 애플리케이션 권한** 추가 후 **관리자 동의**
   | 용도 | API | 권한 |
   |------|-----|------|
   | Intune 장비/탐지 앱 | Microsoft Graph | `DeviceManagementManagedDevices.Read.All` |
   | Intune export 모드 | Microsoft Graph | 위 + `DeviceManagementConfiguration.Read.All` (테넌트에 따라 Reports 권한) |
   | Defender | WindowsDefenderATP | `Machine.Read.All`, `Software.Read.All` |
3. 인증서 및 비밀 → 클라이언트 암호 생성(만료 짧게, 예: 6개월) → 수집 서버의 비밀 저장소에 보관
4. 권장: **조건부 액세스(워크로드 ID)** 로 수집 서버 공인 IP 에서만 토큰 발급 허용, 로그인 로그 모니터링

> Graph 호출은 `ApiClient`(graph.py) 하나로 처리: 토큰 캐시(만료 2분 전 갱신), `@odata.nextLink` 페이징,
> 429/5xx 시 `Retry-After` 존중 지수 백오프, 401 시 토큰 재발급 1회. `repr()` 에 비밀값이 나오지 않게 했습니다.

### 3.2 Intune 으로 에이전트 배포 (Windows)

- Intune → 장치 → 스크립트 및 수정 → **플랫폼 스크립트** → `collect-windows.ps1`
  - "로그온한 자격 증명으로 실행" = 아니요(SYSTEM), "64비트 PowerShell" = 예
  - 인자를 줄 수 없으므로 스크립트 상단 `$OutDir` 기본값을 공유 경로로 바꾸거나, 로컬(`ProgramData`)에 쓰고 별도 수거
- 정기 재수집이 필요하면 **Remediations(수정)** 의 감지 스크립트로 등록해 일정 반복 실행
- 공유폴더 권한: `Domain Computers` = **파일 생성만**(목록/읽기 불가), 수집 서버 계정만 읽기.
  Entra 전용 조인 PC 는 SMB 컴퓨터 계정 인증이 안 되므로 Azure Blob(SAS, 쓰기 전용) 같은 경로를 쓰거나 Intune detectedApps 에 의존

> `Win32_Product` 를 쓰지 않는 이유: 조회만으로 모든 MSI 패키지의 일관성 검사·자가복구가 돌고
> 이벤트 로그(MsiInstaller 1035)가 대량 생성됩니다. 시스템 상태를 바꾸므로 운영/포렌식 모두 부적합합니다.

### 3.3 Linux 배포

```bash
ansible all -b -m script -a "agents/collect-linux.sh" -e OUT_DIR=/mnt/sbom-share
# 또는 결과를 stdout 으로 받아 수집 서버에 저장
ssh host 'OUT_DIR=- sh -s' < agents/collect-linux.sh > /srv/sbom/host.json
```

---

## 4. 버전 정책 (`policy.json`)

```json
{"rules": [
  {"match": "google chrome", "min_version": "131.0.6778.85", "severity": "high"},
  {"match": "openssh", "type": "service", "min_version": "9.8", "severity": "critical"},
  {"match": "anydesk|teamviewer|rustdesk", "regex": true, "forbidden": true, "severity": "medium"},
  {"match": "windows 10", "type": "os", "eol": "2025-10-14", "severity": "high"}
]}
```

- `type` 으로 대상 한정 (`application` / `service`(Nmap) / `os`)
- 버전 비교(`models.version_key`): `1.9.9 < 1.10.0`, `2.0 == 2.0.0`, `1.0rc1 < 1.0`, `8.2 < 8.2p1`
- `--fail-on high` 로 CI/스케줄러에서 종료코드 기반 알림

---

## 5. 보안·운영 고려사항

| 위협/이슈 | 대응 |
|-----------|------|
| 스캔 대상 인자 주입 (`--script=…`, `-iL /etc/shadow`) | 대상 문자열 화이트리스트 검증, `-` 시작 거부, `shell=False` 리스트 실행 |
| 실수로 큰 대역 스캔 | /16 보다 넓은 CIDR 거부, 실행 전 확인 질문(`-y` 로 생략) |
| 외부 XML import 시 XXE / billion laughs | `<!ENTITY` 포함 XML 거부 |
| 공유폴더에 위조 JSON 투입 | 스키마·크기(20MB)·패키지 수 제한, `.sha256` 대조(`--verify-hash`). sha256 은 **손상** 탐지용이며 **위조** 방지는 아님 — 필요 시 HMAC 키를 Intune 스크립트에 넣지 말고 장비 인증서 기반 서명 or 쓰기 전용 Blob + 수집 서버 측 Intune 장비 목록 대조 권장 |
| 클라이언트 암호 노출 | 환경변수로만 입력, 명령행/설정 파일 금지, `repr` 마스킹, 짧은 만료 + 조건부 액세스 |
| 인벤토리 DB = 공격자의 "취약 버전 지도" | DB 생성 시 `0600`, 수집 서버 접근 통제, 보고서 배포 범위 제한 |
| Nmap 버전 탐지의 백포트 오탐 | Ubuntu/RHEL 은 보안 패치를 구버전 번호로 백포트(`OpenSSH 8.2p1 Ubuntu 4ubuntu0.5` 가 패치됐을 수 있음). 서비스 정책 위반은 에이전트의 패키지 버전(dpkg/rpm)으로 교차 확인 |
| IDS/EDR 경보 | `--timing` 조절, 수집 서버 IP 를 SOC 에 사전 공유 (예외 등록) |

---

## 6. OWASP Dependency-Track 연동 (`dtrack`)

인벤토리를 **장비 1대 = DT 프로젝트 1개**(classifier `DEVICE`)로 업로드하고 상위 프로젝트 `corporate-network` 아래에 묶습니다.
DT 는 프로젝트 단위로 취약점·정책·메트릭을 계산하므로, 전사 BOM 하나로 올리면 "어느 PC 가 취약한지"가 사라지기 때문입니다.

```
sbom-inventory DB ──(run N, 자산별 CycloneDX 1.6)──▶ PUT /api/v1/bom {projectName=hostname, autoCreate, parentName, projectTags}
                                                    │  token
                                                    ▼
                                           GET /api/v1/event/token/{token}  (처리 완료 폴링)
                                                    ▼
                         DT 분석기: purl → OSV / GitHub Advisories / OSS Index,  CPE → NVD(내부 분석기)
                                                    ▼
                                           GET /api/v1/finding/project/{uuid}  (--findings)
```

```bash
export DTRACK_API_KEY=odt_xxxxx                      # 비밀값은 환경변수로만
python3 -m sbom_inventory dtrack --url https://dtrack.corp.local --dry-run          # 대상 확인
python3 -m sbom_inventory dtrack --url https://dtrack.corp.local --findings --report dt.json
python3 -m sbom_inventory dtrack --url https://dtrack.corp.local --asset PC-021 --ca-bundle corp-ca.pem
python3 -m sbom_inventory dtrack --url ... --version-from-run   # 프로젝트 버전을 run-<N> 으로 → DT 에도 이력 보존
```

**DT 쪽 준비** (Administration → Access Management → Teams)
- 업로드 전용 팀(기본 `Automation`)에 권한: `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`(+ 상위 프로젝트 자동 생성 시 `PORTFOLIO_MANAGEMENT`) → API Key 발급
- Administration → Vulnerability Sources: NVD(CPE 매칭), OSV 생태계(`Ubuntu`, `Debian`, `Red Hat`, `PyPI` …), GitHub Advisories 활성화

**출처별 매칭 품질** — DT 가 무엇을 근거로 취약점을 찾는지 알아야 결과를 해석할 수 있습니다.

| 출처 | 식별자 | DT 매칭 |
|------|--------|---------|
| Linux 에이전트 (dpkg/rpm/apk) | `pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4` | **OSV 배포판 생태계로 정확 매칭** (백포트 패치 버전 반영) |
| Nmap 서비스 | `cpe:2.3:a:openbsd:openssh:8.2p1` | NVD CPE 매칭 — 업스트림 버전 기준이므로 배포판 백포트 오탐 가능 |
| Defender TVM | vendor/product 로 구성한 CPE | NVD CPE 매칭 (Defender 자체 취약점 수는 properties 에 보존) |
| Windows 레지스트리 / Intune | `pkg:generic/...` (CPE 없음) | **매칭 안 됨** — Windows 앱 취약점은 Defender TVM 결과 또는 정책(min_version) 점검으로 보완 |

> ⚠️ **검증 결과 (Dependency-Track 4.13.2 + OSV `Ubuntu` 생태계, 2026-11 실측)**
> Ubuntu 24.04 패키지 847개 업로드 시 25건이 매칭됐으나, 확인한 표본은 모두 **오탐**이었습니다.
> 예: `UBUNTU-CVE-2014-0207` 은 OSV 원본상 *Ubuntu 14.04 의 `file < 1:5.14-2ubuntu3.1`* 만 해당하는데,
> 24.04 의 `file 1:5.45-3build1` 에 매칭됨. 대조 실험:
>
> | 컴포넌트 버전 | 실제 | DT 매칭 |
> |---|---|---|
> | `5.14-2ubuntu3` / `1:5.14-2ubuntu3` | 취약 | **매칭 안 됨 (미탐)** |
> | `1:5.45-3build1` | 안전 | **22건 매칭 (오탐)** |
> | `5.45-3build1` (epoch 제거) | 안전 | 0건 |
>
> `distro=noble` qualifier 로도 다른 릴리스(trusty) 권고가 걸러지지 않았습니다.
> 따라서 **deb 패키지의 DT findings 는 그대로 신뢰하지 말고**, `ubuntu-security-status`/`pro fix`, Debian `debsecan`,
> RHEL `dnf updateinfo` 등 배포판 도구나 OSV.dev API(배포판 릴리스 일치 확인)로 교차 검증하세요.
> epoch 를 제거하는 우회는 진짜 취약점까지 숨기므로 이 도구는 버전을 원본 그대로 보냅니다.

> DT 는 업로드마다 프로젝트 컴포넌트를 **교체**합니다(현재 상태 뷰). 시점별 이력·diff 는 이 도구의 SQLite 가 원본입니다.
> `run -c config.json` 에 `"dependency_track": {"url": "...", "findings": false}` 를 넣으면 정기 수집 직후 자동 업로드합니다.

## 7. 확장 아이디어

- Linux 패키지 purl 은 OSV.dev API 로도 직접 조회 가능
- Defender TVM 의 `numberOfWeaknesses`, `endOfSupportStatus` 는 이미 컴포넌트 properties 에 저장됨
- Entra ID `devices` API 로 Intune 미등록 조인 장비 목록 보강, Nmap `--script smb-os-discovery` 로 Windows 호스트명/도메인 보강

## 8. 테스트

```bash
python3 -m unittest discover -s tests -v
```
테스트는 Nmap XML 픽스처, 가짜 Graph HTTP 응답(페이징 포함), 에이전트 JSON 으로
병합 → 이력 → diff → 정책 → CycloneDX 까지 전체 흐름을 검증합니다.
