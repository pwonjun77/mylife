# OWASP Scanner 사용 설명서 (초보자용)

이 설명서는 **프로그래밍이나 보안을 처음 접하는 분**도 따라 할 수 있도록 설치부터 결과 해석, 문제 해결까지 순서대로 안내합니다.
처음이라면 [1장](#1-이-프로그램은-무엇인가요)부터 [4장](#4-5분-따라-하기-예제로-처음-실행해-보기)까지 차례로 따라 해 보세요.

## 목차

1. [이 프로그램은 무엇인가요?](#1-이-프로그램은-무엇인가요)
2. [준비하기: Python 설치 확인](#2-준비하기-python-설치-확인)
3. [프로그램 내려받기](#3-프로그램-내려받기)
4. [5분 따라 하기: 예제로 처음 실행해 보기](#4-5분-따라-하기-예제로-처음-실행해-보기)
5. [결과 읽는 법](#5-결과-읽는-법)
6. [내 프로젝트 소스코드 점검하기 (`code`)](#6-내-프로젝트-소스코드-점검하기-code)
7. [사용 중인 라이브러리 점검하기 (`deps`)](#7-사용-중인-라이브러리-점검하기-deps)
8. [웹사이트 점검하기 (`web`)](#8-웹사이트-점검하기-web)
9. [결과를 파일로 저장하기 (HTML / JSON)](#9-결과를-파일로-저장하기-html--json)
10. [원하는 결과만 골라 보기](#10-원하는-결과만-골라-보기)
11. [오탐 알아내고 처리하기 (Claude AI 검토 포함)](#11-오탐-알아내고-처리하기-claude-ai-검토-포함)
12. [발견된 문제 고치는 법 (예시)](#12-발견된-문제-고치는-법-예시)
13. [GitHub에서 자동으로 점검하기 (CI)](#13-github에서-자동으로-점검하기-ci)
14. [자주 겪는 문제와 해결 방법](#14-자주-겪는-문제와-해결-방법)
15. [명령어 한눈에 보기](#15-명령어-한눈에-보기)
16. [용어 풀이](#16-용어-풀이)

---

## 1. 이 프로그램은 무엇인가요?

**OWASP**는 웹 보안을 연구하는 국제 비영리 단체입니다. 이 단체가 몇 년마다 발표하는 **OWASP Top 10**은 "웹 애플리케이션에서 가장 흔하고 위험한 보안 문제 10가지" 목록으로, 보안 점검의 사실상 표준으로 쓰입니다.

이 프로그램은 내 코드나 웹사이트에 **OWASP Top 10에 해당하는 문제가 있는지 자동으로 찾아 주는 도구**입니다. 기본 기준은 최신판인 **2025년판**이고, 필요하면 2021년판 기준으로도 볼 수 있습니다.

점검 방법은 세 가지입니다.

| 명령 | 무엇을 점검하나요? | 이럴 때 쓰세요 |
|------|-------------------|----------------|
| `code` | 내 **소스코드 파일** | "내가 짠 코드에 위험한 부분이 있을까?" |
| `deps` | 내가 쓰는 **외부 라이브러리 목록** | "설치한 패키지 중에 취약한 게 있을까?" |
| `web`  | 실제로 동작 중인 **웹사이트** | "내 사이트 보안 설정이 제대로 되어 있을까?" |

> 💡 이 도구는 **문제가 있을 가능성이 높은 곳을 알려 주는 도우미**입니다. 탐지 결과가 100% 정확하지는 않으니, 결과를 보고 사람이 한 번 더 확인해야 합니다.

---

## 2. 준비하기: Python 설치 확인

이 프로그램은 **Python 3.10 이상**만 있으면 동작합니다. 추가로 설치할 패키지는 없습니다.

### 2-1. 터미널(명령 창) 열기

| 운영체제 | 여는 방법 |
|----------|-----------|
| Windows | 시작 메뉴에서 **"PowerShell"** 또는 **"명령 프롬프트"** 검색 후 실행 |
| macOS | `Command + Space` → **"터미널"** 입력 후 실행 |
| Linux | `Ctrl + Alt + T` 또는 앱 목록에서 "터미널" |

### 2-2. Python 버전 확인

터미널에 아래 명령을 입력하고 Enter를 누르세요.

```bash
python3 --version
```

Windows에서는 `python3` 대신 다음 중 하나를 입력합니다.

```powershell
python --version
py --version
```

`Python 3.10.x`, `Python 3.12.x`처럼 **3.10 이상** 숫자가 나오면 준비 완료입니다.

### 2-3. Python이 없거나 버전이 낮다면

1. https://www.python.org/downloads/ 에 접속해 최신 버전을 내려받습니다.
2. **Windows 사용자 주의:** 설치 첫 화면 아래쪽의 **"Add python.exe to PATH"** 에 반드시 체크한 뒤 설치하세요.
3. 설치가 끝나면 **터미널을 닫았다가 다시 열고** 2-2의 명령을 다시 실행합니다.

> 📌 이 설명서의 명령은 `python3`로 적혀 있습니다. Windows에서 `python3`가 안 되면 `python` 또는 `py`로 바꿔서 입력하세요.

---

## 3. 프로그램 내려받기

### 방법 A: ZIP 파일로 받기 (가장 쉬움)

1. 웹 브라우저로 https://github.com/pwonjun77/mylife 에 접속합니다.
2. 초록색 **`<> Code`** 버튼 → **Download ZIP** 을 누릅니다.
3. 받은 ZIP 파일을 원하는 곳(예: 바탕화면)에 압축 해제합니다.
4. 압축을 푼 폴더 안의 **`owasp-scanner`** 폴더가 이 프로그램입니다.

### 방법 B: Git으로 받기

Git을 사용할 줄 안다면 다음과 같이 받습니다.

```bash
git clone https://github.com/pwonjun77/mylife.git
```

### 프로그램 폴더로 이동하기 (중요!)

프로그램을 실행하려면 항상 **`owasp-scanner` 폴더 안에서** 명령을 입력해야 합니다. `cd` 명령으로 폴더를 이동하세요.

```bash
# macOS / Linux 예시 (바탕화면에 받은 경우)
cd ~/Desktop/mylife-main/owasp-scanner

# Windows 예시
cd C:\Users\내이름\Desktop\mylife-main\owasp-scanner
```

> 💡 **경로 입력이 어렵다면:** 터미널에 `cd `(cd 다음에 공백 한 칸)까지 입력한 뒤, 파일 탐색기(Finder)에서 `owasp-scanner` 폴더를 터미널 창으로 **끌어다 놓으면** 경로가 자동으로 입력됩니다.

제대로 이동했는지 확인해 봅시다.

```bash
python3 -m owasp_scanner --version
```

`owasp-scanner 1.2.0` 같은 버전이 나오면 성공입니다.

---

## 4. 5분 따라 하기: 예제로 처음 실행해 보기

프로그램 안에는 **일부러 취약하게 만든 연습용 코드**(`examples/vulnerable_app`)가 들어 있습니다. 내 코드를 점검하기 전에 이 예제로 먼저 연습해 보세요.

### 1단계: 점검 실행

```bash
python3 -m owasp_scanner code examples/vulnerable_app --with-deps
```

- `code` : 소스코드를 점검하겠다는 뜻입니다.
- `examples/vulnerable_app` : 점검할 폴더입니다.
- `--with-deps` : 라이브러리 목록 점검도 함께 하라는 뜻입니다.

### 2단계: 결과 보기

화면에 다음과 같은 결과가 나옵니다. (일부만 옮겼습니다.)

```text
========================================================================
 OWASP Top 10:2025 취약점 점검 결과 - code
========================================================================
 대상     : .../owasp-scanner/examples/vulnerable_app
 점검일시 : 2026-10-16 22:10:32
 점검파일 : 6개
------------------------------------------------------------------------
 총 37건  |  긴급 4  높음 12  중간 12  낮음 8  정보 1

 [OWASP 분류별]
  A01 Broken Access Control (접근 통제 취약점, SSRF 포함)         3 ■■■
  A02 Security Misconfiguration (보안 설정 오류)               3 ■■■
  ...

  1. [긴급] 클라우드/서비스 액세스 키 노출
     분류 : A04:2025 Cryptographic Failures (암호화 실패)  (2021: A02)  /  CWE-798
     위치 : app.py:17
     근거 : AWS_ACCESS_KEY_ID = "AK****"
     설명 : AWS/Google/GitHub/Slack/Stripe 등의 실제 자격 증명 형식이 발견되었습니다.
     조치 : 즉시 키를 폐기(rotate)하고 저장소 이력에서도 제거하세요.
```

### 3단계: 보기 좋은 HTML 리포트 만들기

```bash
python3 -m owasp_scanner code examples/vulnerable_app --with-deps -f html -o my-first-report.html
```

`owasp-scanner` 폴더에 `my-first-report.html` 파일이 생깁니다. 이 파일을 **더블클릭**하면 웹 브라우저에서 그래프와 함께 결과를 볼 수 있습니다. 각 항목을 클릭하면 상세 내용이 펼쳐집니다.

🎉 여기까지 했다면 기본 사용법은 모두 익혔습니다!

---

## 5. 결과 읽는 법

### 5-1. 요약 부분

| 항목 | 의미 |
|------|------|
| 대상 | 점검한 폴더 또는 웹사이트 주소 |
| 점검파일 | 실제로 검사한 파일 수 (그림, 압축 파일 등은 제외) |
| 총 N건 | 발견된 문제의 총 개수 |
| OWASP 분류별 | 10가지 분류마다 몇 건이 나왔는지 막대(■)로 표시 |

### 5-2. 심각도 (얼마나 위험한가?)

| 표시 | 영어 | 의미 | 대응 |
|------|------|------|------|
| **긴급** | critical | 바로 악용되어 큰 피해가 날 수 있음 | **즉시** 수정 |
| **높음** | high | 악용 가능성이 높음 | 빠르게 수정 |
| **중간** | medium | 조건이 맞으면 악용 가능 | 계획을 세워 수정 |
| **낮음** | low | 위험은 작지만 개선 권장 | 여유 있을 때 수정 |
| **정보** | info | 참고용 정보 | 확인만 |

> 💡 결과가 많아서 막막하다면 **긴급 → 높음** 순서로 먼저 처리하세요. [10장](#10-원하는-결과만-골라-보기)에서 심각한 것만 골라 보는 방법을 안내합니다.

### 5-3. 각 항목 읽는 법

```text
  1. [긴급] 클라우드/서비스 액세스 키 노출                          ← ① 심각도와 제목
     분류 : A04:2025 Cryptographic Failures (암호화 실패)  (2021: A02)  /  CWE-798   ← ②
     위치 : app.py:17                                              ← ③
     근거 : AWS_ACCESS_KEY_ID = "AK****"                            ← ④
     설명 : AWS/Google/GitHub/Slack/Stripe 등의 ...                 ← ⑤
     조치 : 즉시 키를 폐기(rotate)하고 ...                           ← ⑥
```

1. **심각도와 제목**: 어떤 종류의 문제인지 보여 줍니다.
2. **분류**: OWASP Top 10 2025년판 기준 번호(A04)와 이름입니다. 괄호 안은 2021년판 번호입니다. `CWE-798`은 국제적으로 쓰이는 약점 분류 번호로, 인터넷에서 검색하면 자세한 설명을 찾을 수 있습니다.
3. **위치**: `파일이름:줄번호` 형식입니다. `app.py:17`은 **app.py 파일의 17번째 줄**이라는 뜻입니다.
4. **근거**: 문제가 발견된 실제 코드입니다. 비밀번호나 키 값은 `****`로 가려서 보여 줍니다.
5. **설명**: 왜 위험한지 알려 줍니다.
6. **조치**: 어떻게 고치면 되는지 알려 줍니다.

### 5-4. OWASP Top 10:2025 분류표

| 번호 | 분류 | 쉽게 말하면 |
|------|------|-------------|
| A01 | 접근 통제 취약점 | 권한 없는 사람이 남의 데이터나 파일에 접근할 수 있음 (SSRF 포함) |
| A02 | 보안 설정 오류 | 디버그 모드, 보안 헤더 누락 등 설정 실수 |
| A03 | 소프트웨어 공급망 실패 | 취약하거나 출처가 불분명한 라이브러리·설치 스크립트 사용 |
| A04 | 암호화 실패 | 약한 암호, 평문 통신, 코드에 적힌 비밀번호 |
| A05 | 인젝션 | 사용자 입력이 SQL·명령어·HTML로 실행됨 (SQL 인젝션, XSS 등) |
| A06 | 안전하지 않은 설계 | 설계 단계의 결함 (**자동 점검 불가**, 사람이 검토해야 함) |
| A07 | 인증 실패 | 로그인·세션·토큰 처리의 허점 |
| A08 | 소프트웨어·데이터 무결성 실패 | 위조된 데이터나 코드를 검증 없이 신뢰 |
| A09 | 보안 로깅·경보 실패 | 로그에 비밀번호를 남기거나 공격을 기록하지 않음 |
| A10 | 예외 상황 처리 미흡 | 오류를 무시하거나, 오류가 나면 오히려 허용해 버림 |

---

## 6. 내 프로젝트 소스코드 점검하기 (`code`)

### 6-1. 기본 사용법

```bash
python3 -m owasp_scanner code <점검할 폴더 경로>
```

내 프로젝트가 다른 곳에 있다면 **전체 경로**를 적어 주세요.

```bash
# macOS / Linux
python3 -m owasp_scanner code ~/projects/my-shop

# Windows (경로에 공백이 있으면 큰따옴표로 감싸기)
python -m owasp_scanner code "C:\Users\내이름\Documents\my shop"
```

파일 하나만 점검할 수도 있습니다.

```bash
python3 -m owasp_scanner code ~/projects/my-shop/app.py
```

### 6-2. 점검하는 파일 종류

- **프로그래밍 언어:** Python(`.py`), JavaScript/TypeScript(`.js` `.ts` `.jsx` `.tsx` `.vue`), Java/Kotlin(`.java` `.kt` `.jsp`), PHP, Ruby, Go, C#
- **웹 템플릿:** `.html` `.ejs` `.hbs` `.j2` 등
- **설정 파일:** `.env` `.yml` `.json` `.ini` `.properties` `.xml` 등
- **스크립트:** `.sh` `.ps1` `Dockerfile` 등

`node_modules`, `.git`, `venv`, `dist`, `build`처럼 외부에서 받아 온 코드나 빌드 결과물이 들어 있는 폴더는 **자동으로 건너뜁니다**.

### 6-3. 자주 쓰는 옵션

```bash
# 라이브러리 점검도 함께
python3 -m owasp_scanner code ./my-project --with-deps

# 특정 폴더 제외 (여러 번 쓸 수 있음)
python3 -m owasp_scanner code ./my-project --exclude tests --exclude docs
```

---

## 7. 사용 중인 라이브러리 점검하기 (`deps`)

요즘 프로그램은 대부분 다른 사람이 만든 라이브러리(패키지)를 가져다 씁니다. 그 라이브러리에 보안 구멍이 있으면 내 프로그램도 위험해집니다. 이 명령은 라이브러리 목록 파일을 읽어서 문제를 찾습니다.

**읽는 파일:** `requirements.txt`(Python), `package.json`(JavaScript/Node.js)

```bash
python3 -m owasp_scanner deps ./my-project
```

### 무엇을 알려 주나요?

| 항목 | 의미 |
|------|------|
| 버전 미고정 | `flask`처럼 버전을 적지 않으면 설치할 때마다 다른 버전이 깔릴 수 있음 |
| 레지스트리 외부 소스 | GitHub 주소 등에서 직접 설치해 검증이 어려움 |
| npm lock 파일 없음 | `package-lock.json`이 없어 하위 라이브러리 버전이 고정되지 않음 |
| 설치 스크립트 | 설치할 때 자동으로 실행되는 스크립트가 있음 (내용 확인 권장) |

### 알려진 취약점(CVE)까지 조회하기

`--osv` 옵션을 붙이면 구글이 운영하는 공개 취약점 데이터베이스 **OSV.dev**에 조회해서, 사용 중인 버전에 **이미 알려진 취약점**이 있는지 알려 줍니다. **인터넷 연결이 필요합니다.**

```bash
python3 -m owasp_scanner deps ./my-project --osv
```

> 📌 OSV 조회는 `requests==2.19.0`처럼 **버전을 정확히 적은 라이브러리**만 대상으로 합니다.

---

## 8. 웹사이트 점검하기 (`web`)

> ⚠️ **반드시 읽어 주세요**
> 웹 점검은 **본인이 운영하는 사이트**이거나 **운영자에게 서면 허가를 받은 사이트**에만 해야 합니다.
> 허가 없이 남의 사이트를 점검하면 「정보통신망법」 등에 따라 **처벌받을 수 있습니다.**
> 이 도구는 공격 코드를 보내지 않는 안전한 방식(조회 요청만 보냄)이지만, 그래도 허가는 꼭 필요합니다.

### 8-1. 기본 사용법

```bash
python3 -m owasp_scanner web https://내사이트주소.com
```

실행하면 점검 권한이 있는지 묻습니다. 권한이 있으면 `y`를 입력하고 Enter를 누르세요.

```text
[주의] 웹 점검은 반드시 소유하거나 서면 허가를 받은 대상에만 수행하세요.
'https://내사이트주소.com'에 대한 점검 권한이 있습니까? [y/N] y
```

### 8-2. 무엇을 점검하나요?

- **HTTPS 사용 여부**, HTTP로 접속했을 때 HTTPS로 넘어가는지
- **TLS 버전과 인증서** 만료일
- **보안 헤더**(HSTS, CSP, X-Frame-Options 등) 설정
- **쿠키** 보안 속성(Secure, HttpOnly, SameSite)
- **CORS** 설정 (다른 사이트가 내 데이터를 읽어 갈 수 있는지)
- 서버 **버전 정보 노출**
- 오류 페이지에 **내부 정보(스택 트레이스)** 가 보이는지
- `.git`, `.env`, 백업 파일처럼 **외부에 공개되면 안 되는 파일**이 열려 있는지
- 외부 스크립트에 무결성 검증(SRI)이 있는지

### 8-3. 상황별 옵션

```bash
# 개발용 서버처럼 인증서가 정식이 아닐 때
python3 -m owasp_scanner web https://localhost:8443 --insecure

# 민감 파일 점검(.git, .env 등)을 생략하고 싶을 때
python3 -m owasp_scanner web https://내사이트주소.com --no-paths

# 응답이 느린 사이트 (기본 10초 → 30초)
python3 -m owasp_scanner web https://내사이트주소.com --timeout 30

# 확인 질문 없이 바로 실행 (자동화할 때)
python3 -m owasp_scanner web https://내사이트주소.com -y
```

---

## 9. 결과를 파일로 저장하기 (HTML / JSON)

`-f`로 형식을 고르고 `-o`로 저장할 파일 이름을 정합니다.

| 형식 | 용도 | 명령 예시 |
|------|------|-----------|
| `text` (기본) | 터미널에서 바로 보기 | `... -o result.txt` |
| `html` | 브라우저로 보기, 다른 사람과 공유 | `... -f html -o report.html` |
| `json` | 다른 프로그램에서 읽기, 자동화 | `... -f json -o report.json` |

```bash
python3 -m owasp_scanner code ./my-project --with-deps -f html -o report.html
```

> 💡 HTML 리포트는 다크 모드도 지원합니다. 팀원에게 공유할 때는 HTML 형식이 가장 편합니다.

---

## 10. 원하는 결과만 골라 보기

### 심각한 것만 보기

```bash
# '높음' 이상만 (높음 + 긴급)
python3 -m owasp_scanner code ./my-project --min-severity high
```

심각도 단계는 `info` < `low` < `medium` < `high` < `critical` 순입니다.

### 특정 분류만 보기

```bash
# 인젝션(A05)과 암호화 실패(A04)만
python3 -m owasp_scanner code ./my-project --owasp A05,A04
```

### 2021년판 기준으로 보기

회사나 고객이 2021년판 기준 보고서를 요구할 때 사용합니다.

```bash
python3 -m owasp_scanner code ./my-project --standard 2021
```

> 📌 `--owasp`에 적는 번호는 **선택한 기준**을 따릅니다. 예를 들어 인젝션은 2025년판에서 `A05`, 2021년판에서 `A03`입니다.

### 점검 규칙 목록 보기

```bash
python3 -m owasp_scanner rules
```

---

## 11. 오탐 알아내고 처리하기 (Claude AI 검토 포함)

이 도구는 코드의 **모양(패턴)** 만 보고 판단하기 때문에, 실제로는 안전한 코드를 문제로 표시할 때가 있습니다. 이를 **오탐**(false positive)이라고 합니다. 반대로 실제 문제를 놓치는 것은 **미탐**이라고 합니다.

오탐인지 알아내는 방법은 세 가지입니다.

| 방법 | 장점 | 단점 |
|------|------|------|
| [11-2. 직접 확인하기](#11-2-직접-확인하기-체크리스트) | 무료, 가장 정확 | 시간이 걸리고 보안 지식이 필요 |
| [11-3. Claude에게 검토 맡기기](#11-3-claude에게-검토-맡기기---ai-review) | 빠르고, 판단 근거와 수정 방법까지 알려 줌 | API 요금 발생, 코드 일부가 외부로 전송됨 |
| [11-4. 정답과 비교해 테스트하기](#11-4-정답과-비교해-테스트하기---expected) | 스캐너와 AI를 얼마나 믿을 수 있는지 숫자로 확인 | 정답(라벨)을 먼저 만들어야 함 |

### 11-1. 오탐은 왜 생기나요?

예를 들어 아래 두 줄은 모두 "명령어 인젝션" 규칙에 걸립니다.

```python
subprocess.run("df -h /", shell=True)          # ① 고정된 명령 → 안전 (오탐)
subprocess.run("convert " + tool, shell=True)  # ② 사용자 입력이 섞임 → 위험 (실제 취약점)
```

스캐너는 `shell=True`라는 **모양**만 보기 때문에 둘을 구분하지 못합니다. 둘을 가르는 것은 **"공격자가 조작할 수 있는 값이 위험한 곳까지 도달하는가?"** 입니다.

### 11-2. 직접 확인하기 (체크리스트)

결과의 **위치**(`파일:줄번호`)를 열어 아래 질문에 차례로 답해 보세요.

1. **값이 어디서 오나요?** 요청 파라미터, 폼, 쿠키, URL, 파일 업로드처럼 **사용자가 보낸 값**인가요, 아니면 코드에 적힌 **고정값**인가요? 고정값이라면 대부분 오탐입니다.
2. **중간에 검증·변환을 거치나요?** `int()` 변환, 허용 목록 검사, 이스케이프나 정제(`DOMPurify.sanitize`, `htmlspecialchars`) 등을 거친다면 오탐일 수 있습니다.
3. **보안 용도인가요?** MD5를 비밀번호 저장에 쓰면 위험하지만, 캐시 파일 이름을 만드는 데만 쓴다면 오탐입니다.
4. **실제로 실행되는 코드인가요?** 테스트 코드, 예제, 사용하지 않는 코드라면 위험도가 낮습니다.
5. **어디에서 돌아가나요?** `DEBUG = True`가 개발용 설정 파일에만 있고 운영에서는 꺼진다면 오탐입니다.

> 💡 위 질문에 하나라도 "모르겠다"는 답이 나오면 **오탐으로 단정하지 마세요.** 동료나 보안 담당자에게 확인을 요청하는 것이 안전합니다.

### 11-3. Claude에게 검토 맡기기 (`--ai-review`)

`--ai-review` 옵션을 붙이면 탐지된 결과마다 **주변 코드(앞뒤 20줄)** 를 Anthropic의 AI인 **Claude**에게 보내, 11-2의 질문을 대신 따져 보게 합니다. Claude는 결과마다 다음 셋 중 하나로 판정합니다.

| 판정 | 의미 | 할 일 |
|------|------|-------|
| **실제 취약점** | 공격자가 악용할 수 있음 | AI 제안을 참고해 수정 |
| **오탐** | 패턴만 비슷하고 안전함 | 근거를 읽고 동의하면 무시 처리(11-5) |
| **수동 확인 필요** | 주어진 코드만으로는 판단 불가 | 11-2 체크리스트로 직접 확인 |

#### 1단계: 준비 (처음 한 번만)

**① anthropic 패키지 설치**

```bash
pip install anthropic
```

Windows에서 `pip`가 안 되면 `python -m pip install anthropic` 또는 `py -m pip install anthropic`을 입력하세요.

**② API 키 발급**

1. https://console.anthropic.com 에 가입하고 로그인합니다.
2. 결제 수단을 등록합니다. AI 검토는 **사용한 만큼 요금이 나가는 유료 기능**입니다.
3. **API Keys** 메뉴에서 **Create Key**를 눌러 키를 만듭니다. `sk-ant-`로 시작하는 키는 다시 볼 수 없으니 바로 복사해 두세요.

**③ API 키 등록** (터미널을 새로 열 때마다 다시 입력해야 합니다)

```bash
# macOS / Linux
export ANTHROPIC_API_KEY="sk-ant-여기에-복사한-키"
```

```powershell
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-여기에-복사한-키"
```

> ⚠️ API 키는 비밀번호와 같습니다. 코드 파일에 적거나 GitHub에 올리지 마세요. (이 프로그램도 코드에 적힌 키를 "긴급"으로 탐지합니다.)

#### 2단계: 실행

```bash
python3 -m owasp_scanner code ./my-project --ai-review
```

실행하면 코드가 외부로 전송된다는 안내와 함께 계속할지 묻습니다. `y`를 입력하면 검토가 시작되고 진행 상황이 `AI 검토 중... 3/8`처럼 표시됩니다.

#### 3단계: 결과 읽기

결과의 각 항목 아래에 AI 판정이 추가됩니다.

```text
  4. [높음] OS 명령 실행 함수 사용 (명령 인젝션)
     분류 : A05:2025 Injection (인젝션)  (2021: A03)  /  CWE-78
     위치 : views.py:14
     근거 : return subprocess.run("df -h /", shell=True, capture_output=True).stdout
     ...
     AI   : 오탐 (확신도 높음) - 실행하는 명령이 "df -h /"라는 고정 문자열이라 사용자 입력이 섞일 수 없습니다.
```

맨 위 **참고** 줄에는 전체 요약(`실제 취약점 3, 오탐 5, 수동 확인 필요 0`)이 나오고, HTML 리포트에는 항목마다 `AI: 오탐` 같은 표시가 붙습니다.

> ⚠️ **AI 판정도 틀릴 수 있습니다.** "오탐" 판정은 **"이 근거를 읽고 사람이 최종 확인할 것"** 이라는 뜻으로 받아들이세요. 특히 **확신도 낮음**인 판정은 반드시 직접 확인하세요.

#### 자주 쓰는 AI 옵션

```bash
# AI가 오탐으로 판정한 항목은 결과에서 숨기기
python3 -m owasp_scanner code ./my-project --ai-review --hide-fp

# 심각한 것만 AI에게 맡기기 (비용 절약)
python3 -m owasp_scanner code ./my-project --ai-review --min-severity high

# 검토할 최대 개수 바꾸기 (기본 30개, 심각도 높은 순)
python3 -m owasp_scanner code ./my-project --ai-review --ai-max 10

# 확인 질문 없이 실행 (자동화할 때)
python3 -m owasp_scanner code ./my-project --ai-review --ai-yes

# 다른 Claude 모델 사용 (기본: claude-opus-5-5)
python3 -m owasp_scanner code ./my-project --ai-review --ai-model claude-sonnet-5-5
```

#### 이미 저장한 결과를 나중에 검토하기 (`review`)

점검은 먼저 해 두고 AI 검토는 나중에 하고 싶다면, 결과를 JSON으로 저장한 뒤 `review` 명령을 쓰세요.

```bash
python3 -m owasp_scanner code ./my-project -f json -o scan.json
python3 -m owasp_scanner review scan.json -f html -o reviewed.html
```

소스코드 위치가 바뀌었다면 `--root ./my-project`로 알려 주세요.

#### 비용과 보안에 대해 꼭 알아 두세요

- **보내는 내용:** 탐지된 줄의 앞뒤 20줄과 규칙 정보만 보냅니다(`--ai-context 10`처럼 줄 수를 줄일 수 있습니다). 코드 속 비밀번호·키 값은 `****`로 가린 뒤 보냅니다. 그래도 **회사 코드라면 외부 AI 서비스로 보내도 되는지 먼저 확인하세요.**
- **비용:** 결과 1건마다 Claude API를 1번 호출합니다. 요금은 코드 길이와 판단 난이도에 따라 달라지며, 대략 1건에 수십 원 수준입니다. 정확한 사용량과 요금은 Anthropic 콘솔에서 확인할 수 있습니다. 처음에는 `--ai-max 5` 정도로 시작해 보세요.
- **AI 거절:** 드물게 Claude가 검토를 거절할 수 있습니다. 그러면 서버가 다른 Claude 모델로 자동으로 다시 시도하고, 그래도 안 되면 그 항목은 "수동 확인 필요"로 표시됩니다.

### 11-4. 정답과 비교해 테스트하기 (`--expected`)

"AI 판정을 얼마나 믿어도 될까?" 하는 생각이 든다면, **정답을 알고 있는 코드**로 시험해 보면 됩니다.

#### 연습용 정답 세트로 시험하기

`examples/fp_samples` 폴더에는 실제 취약점 3개와, 패턴만 비슷하고 안전한 코드 5개가 섞여 있습니다. 정답은 `labels.json`에 들어 있습니다.

```bash
# 1) AI 없이: 스캐너가 낸 결과 중 오탐이 몇 개인지 확인 (무료)
python3 -m owasp_scanner code examples/fp_samples --expected examples/fp_samples/labels.json

# 2) AI 포함: Claude가 오탐을 얼마나 정확히 가려내는지 확인
python3 -m owasp_scanner code examples/fp_samples --ai-review --expected examples/fp_samples/labels.json
```

결과 맨 위 **참고** 줄에 다음과 같은 평가가 나옵니다.

```text
 참고     : 라벨 비교: 스캐너 탐지 8건 중 실제 취약점 3건, 오탐 5건 (정밀도 38%)
 참고     : AI 판정 정확도: 8/8 (100%), 오탐 5건 중 5건을 오탐으로 판정
```

(위의 AI 정확도 숫자는 예시입니다. 실제 결과는 실행할 때마다 조금씩 다를 수 있습니다.)

| 항목 | 뜻 |
|------|-----|
| 정밀도 | 스캐너가 낸 결과 중 실제 취약점의 비율. 낮을수록 오탐이 많다는 뜻 |
| 스캐너 미탐 | 정답에는 실제 취약점인데 스캐너가 찾지 못한 항목 |
| AI 판정 정확도 | AI가 정답과 같게 판정한 비율 |
| AI 판정 불일치 | AI가 틀린 항목. 어떤 경우에 AI를 믿기 어려운지 알 수 있음 |

#### 내 프로젝트용 정답 세트 만들기

1. 내 프로젝트를 점검하고, 11-2 체크리스트로 결과를 몇 개(10~20개 정도) 직접 판정합니다.
2. 판정 결과를 `my-labels.json`으로 저장합니다. `location`, `line`, `rule_id`는 점검 결과에 나온 값을 그대로 적고, `expected`에는 `true_positive`(실제 취약점) 또는 `false_positive`(오탐)를 적습니다.

   ```json
   {
     "labels": [
       {"location": "app/views.py", "line": 42, "rule_id": "A03-SQLI", "expected": "true_positive"},
       {"location": "app/utils.py", "line": 10, "rule_id": "A02-WEAK-HASH", "expected": "false_positive",
        "why": "캐시 키 계산에만 사용"}
     ]
   }
   ```

3. `--expected my-labels.json`을 붙여 실행하면, 내 코드에서 AI 판정이 얼마나 정확한지 확인할 수 있습니다. 정확도가 충분히 높다고 판단되면 그때부터 `--hide-fp`를 써도 좋습니다.

> 📌 `location`은 점검한 폴더를 기준으로 한 경로이고, Windows에서도 `/`로 적습니다. 코드를 고쳐 줄 번호가 바뀌면 라벨도 함께 고쳐야 합니다.

### 11-5. 확인한 오탐 숨기기

직접 확인했거나 AI 판정에 동의해서 오탐이라고 결론 내렸다면, 아래 방법으로 다음 점검부터 표시되지 않게 할 수 있습니다.

**방법 1: 특정 줄만 무시** – 해당 줄 끝에 주석을 붙입니다.

```python
subprocess.run("df -h /", shell=True)  # nosec - 고정 명령
```

```javascript
el.innerHTML = DOMPurify.sanitize(html); // owasp-ignore
```

**방법 2: 파일 전체 무시** – 파일 맨 위 5줄 안에 `owasp-ignore-file`이라는 문구를 넣습니다. 일부러 위험한 코드 예시를 담은 테스트 파일 등에 씁니다.

```python
# owasp-ignore-file: 테스트용 예시 코드
```

**방법 3: 폴더 제외**

```bash
python3 -m owasp_scanner code ./my-project --exclude tests --exclude examples
```

> ⚠️ 무시 처리는 **정말 안전하다고 확인한 경우에만** 하세요. 무시한 이유를 주석에 함께 적어 두면 나중에 다른 사람이 검토하기 쉽습니다.

---

## 12. 발견된 문제 고치는 법 (예시)

자주 나오는 문제를 고치는 예시입니다. 결과의 **조치** 항목에도 고치는 방법이 적혀 있습니다.

### SQL 인젝션 (A05) – 사용자 입력을 쿼리에 직접 붙이지 않기

```python
# ❌ 위험: 사용자가 id에 "1 OR 1=1"을 넣으면 모든 데이터가 조회됨
conn.execute(f"SELECT * FROM users WHERE id = {uid}")

# ✅ 안전: 값을 따로 전달(파라미터 바인딩)
conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
```

### 명령어 인젝션 (A05) – 셸을 거치지 않기

```python
# ❌ 위험: host에 "; rm -rf /"를 넣으면 다른 명령이 실행됨
subprocess.check_output("ping -c 1 " + host, shell=True)

# ✅ 안전: 명령과 인자를 목록으로 분리
subprocess.check_output(["ping", "-c", "1", host])
```

### 코드에 적힌 비밀번호·키 (A04) – 환경 변수로 분리하기

```python
# ❌ 위험: 코드를 보는 누구나 키를 알 수 있음
SECRET_KEY = "s3cr3t-hardcoded-key"

# ✅ 안전: 실행 환경에서 읽어 오기
import os
SECRET_KEY = os.environ["SECRET_KEY"]
```

> ⚠️ 이미 GitHub 등에 올라간 키는 코드에서 지워도 **기록(히스토리)에 남아 있습니다.** 반드시 해당 서비스에서 **키를 새로 발급(폐기 후 재발급)** 하세요.

### 약한 해시 (A04) – 비밀번호는 전용 함수로 저장하기

```python
# ❌ 위험: MD5는 쉽게 풀림
hashlib.md5(pw.encode()).hexdigest()

# ✅ 안전: 비밀번호 전용 해시 (Python 표준 라이브러리)
import hashlib, os
salt = os.urandom(16)
hashed = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)
```

### 예외가 나면 허용해 버리는 코드 (A10)

```python
# ❌ 위험: 토큰 검증 중 오류가 나면 관리자로 인정해 버림
try:
    return verify(token).role == "admin"
except Exception:
    return True

# ✅ 안전: 오류가 나면 거부하고 기록
try:
    return verify(token).role == "admin"
except InvalidTokenError:
    logger.warning("잘못된 토큰으로 관리자 접근 시도")
    return False
```

### 웹 보안 헤더 누락 (A02)

웹 서버 설정에 다음 헤더를 추가합니다. (Nginx 예시)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

> 📌 CSP(`Content-Security-Policy`)는 사이트 동작에 영향을 줄 수 있으니 테스트 환경에서 먼저 확인하세요.

고친 뒤에는 **같은 명령으로 다시 점검**해서 결과가 사라졌는지 확인하세요.

---

## 13. GitHub에서 자동으로 점검하기 (CI)

코드를 GitHub에 올릴 때마다 자동으로 점검하게 만들 수 있습니다. **심각한 문제가 있으면 점검이 실패(빨간 X)로 표시**되어 바로 알 수 있습니다.

저장소에 `.github/workflows/owasp.yml` 파일을 만들고 아래 내용을 넣으세요.

```yaml
name: OWASP 보안 점검

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: 보안 점검 실행
        # 예제 폴더(일부러 취약하게 만든 코드)는 제외하고, '높음' 이상이 있으면 실패 처리
        run: |
          PYTHONPATH=owasp-scanner python3 -m owasp_scanner code . \
            --exclude examples --with-deps --fail-on high
      - name: HTML 리포트 만들기
        if: always()
        run: |
          PYTHONPATH=owasp-scanner python3 -m owasp_scanner code . \
            --exclude examples --with-deps -f html -o owasp-report.html
      - name: 리포트 업로드
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: owasp-report
          path: owasp-report.html
```

- `--fail-on high` : '높음' 이상 문제가 하나라도 있으면 실패로 처리합니다. 처음에는 `critical`로 시작해서 점차 기준을 높이는 것도 방법입니다.
- 점검이 끝나면 GitHub의 **Actions** 탭 → 해당 실행 → **Artifacts**에서 HTML 리포트를 내려받을 수 있습니다.

### 종료 코드 (자동화할 때 참고)

| 종료 코드 | 의미 |
|-----------|------|
| `0` | 정상 종료 (`--fail-on` 기준을 넘는 문제 없음) |
| `1` | `--fail-on` 기준 이상의 문제가 발견됨 |
| `2` | 실행 오류 (경로 없음, 접속 실패, 잘못된 옵션 등) |

---

## 14. 자주 겪는 문제와 해결 방법

### ❓ `python3: command not found` 또는 `'python3'은(는) 내부 또는 외부 명령...이 아닙니다`

- Windows에서는 `python` 또는 `py`로 입력해 보세요.
- 그래도 안 되면 Python이 설치되지 않았거나 PATH 설정이 빠진 것입니다. [2-3](#2-3-python이-없거나-버전이-낮다면)을 참고해 다시 설치하세요. 이때 **"Add python.exe to PATH"** 에 꼭 체크하세요.

### ❓ `No module named owasp_scanner`

`owasp-scanner` 폴더 **안에서** 실행하지 않아서 생기는 오류입니다.

```bash
cd <내려받은 위치>/owasp-scanner
python3 -m owasp_scanner --version
```

다른 폴더에서 실행하고 싶다면 `PYTHONPATH`를 지정하세요.

```bash
# macOS / Linux
PYTHONPATH=/경로/owasp-scanner python3 -m owasp_scanner code .
```

```powershell
# Windows PowerShell
$env:PYTHONPATH = "C:\경로\owasp-scanner"
python -m owasp_scanner code .
```

### ❓ `SyntaxError` 또는 이상한 문법 오류

Python 버전이 3.10보다 낮을 가능성이 큽니다. `python3 --version`으로 확인하고 최신 버전을 설치하세요.

### ❓ Windows에서 한글이 깨져 보여요

명령 프롬프트에서 아래 명령을 먼저 실행한 뒤 다시 시도하세요. **Windows Terminal**을 쓰면 대부분 깨지지 않습니다.

```powershell
chcp 65001
```

또는 결과를 HTML 파일로 저장해서 브라우저로 보세요(`-f html -o report.html`).

### ❓ 화면에 `[1;31m` 같은 이상한 문자가 섞여 나와요

색상 표시를 지원하지 않는 터미널입니다. `--no-color` 옵션을 붙이세요.

### ❓ `오류: 경로를 찾을 수 없습니다`

점검할 폴더 경로가 잘못되었습니다. 경로에 공백이 있으면 **큰따옴표**로 감싸세요.

```bash
python3 -m owasp_scanner code "C:\My Projects\shop"
```

### ❓ 웹 점검에서 `대상에 접속할 수 없습니다`

- 주소가 정확한지, 브라우저에서는 열리는지 확인하세요.
- 회사 네트워크라면 방화벽이나 프록시가 막고 있을 수 있습니다.
- 응답이 느리면 `--timeout 30`을 붙여 보세요.

### ❓ 웹 점검에서 `유효하지 않은 TLS 인증서`

사이트 인증서가 만료되었거나 정식 인증서가 아니라는 뜻으로, **그 자체가 점검 결과**입니다. 개발용 서버라서 일부러 그런 것이라면 `--insecure`를 붙여 나머지 항목을 점검할 수 있습니다.

### ❓ 웹 점검이 `대화형 터미널이 아니므로...`라며 취소돼요

다른 프로그램이나 자동화 스크립트에서 실행하면 권한 확인 질문에 답할 수 없습니다. 점검 권한이 있다면 `-y` 옵션을 붙이세요.

### ❓ `OSV 조회 실패`

인터넷 연결 문제이거나 회사 네트워크에서 `api.osv.dev` 접속이 막혀 있는 경우입니다. `--osv` 없이 실행해도 나머지 점검은 정상적으로 됩니다.

### ❓ `AI 검토에는 anthropic 패키지가 필요합니다`

`pip install anthropic`으로 패키지를 설치하세요([11-3](#11-3-claude에게-검토-맡기기---ai-review)). 컴퓨터에 Python이 여러 개 설치되어 있다면, 프로그램을 실행할 때 쓰는 Python으로 설치해야 합니다(`python3 -m pip install anthropic`).

### ❓ `Claude API 인증에 실패했습니다`

API 키가 등록되지 않았거나 잘못되었습니다. 지금 쓰는 터미널에서 `ANTHROPIC_API_KEY`를 다시 등록하세요. 터미널을 새로 열면 다시 등록해야 합니다.

### ❓ AI 검토 결과가 전부 `AI 검토 실패`예요

요청이 너무 많거나(요금제 한도 초과) 네트워크가 불안정한 경우입니다. 잠시 후 다시 실행하거나 `--ai-max`로 개수를 줄여 보세요. 회사 네트워크라면 `api.anthropic.com` 접속이 막혀 있을 수 있습니다.

### ❓ 결과가 0건이에요. 안전한 건가요?

꼭 그렇지는 않습니다. 이 도구는 **잘 알려진 위험 패턴**만 찾습니다. 프로그램의 동작 흐름 자체에 숨은 문제(예: 다른 사람 주문 번호를 넣으면 주문서가 보이는 문제)는 찾지 못합니다. 중요한 서비스라면 전문가의 점검(모의해킹, 코드 리뷰)을 함께 받으세요.

---

## 15. 명령어 한눈에 보기

```bash
# 도움말
python3 -m owasp_scanner --help
python3 -m owasp_scanner code --help

# 소스코드 점검
python3 -m owasp_scanner code <폴더>
python3 -m owasp_scanner code <폴더> --with-deps          # 라이브러리 점검 포함
python3 -m owasp_scanner code <폴더> --exclude tests      # 폴더 제외

# 라이브러리 점검
python3 -m owasp_scanner deps <폴더>
python3 -m owasp_scanner deps <폴더> --osv                # 알려진 취약점 조회 (인터넷 필요)

# 웹사이트 점검 (허가받은 대상만!)
python3 -m owasp_scanner web https://내사이트.com

# 결과 저장
... -f html -o report.html
... -f json -o report.json

# 결과 거르기
... --min-severity high          # 높음 이상만
... --owasp A05,A04              # 특정 분류만
... --standard 2021              # 2021년판 기준

# Claude AI 오탐 검토 (pip install anthropic, ANTHROPIC_API_KEY 필요)
... --ai-review                  # 결과마다 실제 취약점/오탐 판정
... --ai-review --hide-fp        # 오탐 판정은 숨기기
python3 -m owasp_scanner review scan.json        # 저장한 JSON 결과를 나중에 검토
... --expected labels.json       # 정답과 비교해 정밀도·AI 정확도 계산

# 자동화
... --fail-on high               # 높음 이상이 있으면 종료 코드 1

# 규칙 목록
python3 -m owasp_scanner rules
```

---

## 16. 용어 풀이

| 용어 | 뜻 |
|------|-----|
| **취약점** | 공격자가 악용할 수 있는 보안상의 약점 |
| **OWASP Top 10** | OWASP가 발표하는 웹 보안 위험 상위 10가지 목록 |
| **CWE** | 소프트웨어 약점을 분류한 국제 번호 체계 (예: CWE-89는 SQL 인젝션) |
| **CVE** | 특정 제품에서 실제로 발견된 취약점에 붙는 고유 번호 |
| **인젝션** | 사용자 입력이 데이터가 아닌 명령어로 실행되는 문제 |
| **XSS** | 웹 페이지에 악성 스크립트가 삽입되어 다른 사용자 브라우저에서 실행되는 문제 |
| **SSRF** | 공격자가 서버를 시켜 내부망 등 원래 접근할 수 없는 곳에 요청하게 만드는 문제 |
| **오탐 / 미탐** | 오탐: 안전한데 문제로 표시함 / 미탐: 문제가 있는데 놓침 |
| **정밀도** | 도구가 낸 결과 중 실제로 맞은 결과의 비율 |
| **라벨** | 사람이 미리 정해 둔 정답 (이 결과는 실제 취약점/오탐) |
| **API 키** | 프로그램이 Claude 같은 외부 서비스를 쓸 때 본인임을 증명하는 비밀 문자열 |
| **정적 점검 (SAST)** | 프로그램을 실행하지 않고 소스코드를 읽어서 점검하는 방식 (`code`) |
| **동적 점검 (DAST)** | 실행 중인 서비스에 요청을 보내 점검하는 방식 (`web`) |
| **공급망 공격** | 내가 쓰는 라이브러리나 설치 도구를 오염시켜 나를 공격하는 방식 |
| **CI** | 코드를 올릴 때마다 자동으로 빌드·테스트·점검을 실행하는 것 |
| **HTTPS / TLS** | 웹 통신을 암호화하는 기술 |
| **환경 변수** | 코드 밖에서 프로그램에 값을 전달하는 방법 (비밀번호 보관에 사용) |

---

더 기술적인 내용은 [README.md](README.md)를 참고하세요.
