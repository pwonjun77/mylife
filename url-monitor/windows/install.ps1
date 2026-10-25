<#
.SYNOPSIS
    URL Monitor 를 Windows 작업 스케줄러에 등록해 백그라운드로 실행합니다.

.DESCRIPTION
    - 화면이 잠겨 있어도 계속 점검하고 상태가 바뀌면 Teams 로 알립니다.
      -RunAs System(기본)이면 로그아웃 상태에서도, 재부팅 후 로그인하지 않아도 동작합니다.
    - 창 없이(pythonw.exe) 실행하고, 출력은 로그 파일(5MB 순환)에 남깁니다.
    - 실행 중에는 PC 절전을 막습니다(화면 꺼짐·잠금은 그대로 허용).
    - 실행 시간 제한 없음, 배터리 사용 중에도 실행, 프로세스가 죽으면 5분 안에 다시 시작합니다.
    - Teams 웹훅 주소는 접근 권한을 제한한 파일(url-monitor.env)에 보관합니다.

.EXAMPLE
    # 관리자 PowerShell: PC 부팅 시 자동 시작, 로그아웃 상태에서도 동작 (권장)
    .\windows\install.ps1 -Config .\targets.json -TeamsWebhookUrl "https://..."

.EXAMPLE
    # 관리자 권한 없이: 로그인해 있는 동안(화면 잠금 포함) 동작
    .\windows\install.ps1 -Config .\targets.json -TeamsWebhookUrl "https://..." -RunAs User
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Config,
    [string]$TeamsWebhookUrl,
    [ValidateSet('System', 'User')][string]$RunAs = 'System',
    [string]$DataDir,
    [string]$StatusPage,
    [string]$TaskName = 'URL Monitor',
    [string]$Python,
    [double]$HeartbeatHours = 24,
    [switch]$WakeToRun,
    [switch]$NoTest
)

$ErrorActionPreference = 'Stop'
$AppDir = Split-Path -Parent $PSScriptRoot
$Config = (Resolve-Path -LiteralPath $Config).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($RunAs -eq 'System' -and -not $isAdmin) {
    throw "-RunAs System 은 관리자 권한이 필요합니다. PowerShell 을 '관리자 권한으로 실행'하거나 -RunAs User 를 사용하세요."
}
if (-not $DataDir) {
    if ($RunAs -eq 'System') { $DataDir = Join-Path $env:ProgramData 'url-monitor' }
    else { $DataDir = Join-Path $env:LOCALAPPDATA 'url-monitor' }
}
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# ------------------------------------------------------------ Python 찾기
function Find-Python {
    if ($Python) { return (Resolve-Path -LiteralPath $Python).Path }
    foreach ($candidate in @('py -3', 'python')) {
        $parts = $candidate -split ' '
        $cmd = Get-Command $parts[0] -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $pyArgs = @($parts | Select-Object -Skip 1) + @('-c', 'import sys; print(sys.executable)')
        $out = & $cmd.Source @pyArgs 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return ([string]($out | Select-Object -Last 1)).Trim() }
    }
    throw 'Python 3.10 이상을 찾을 수 없습니다. https://www.python.org 에서 설치하거나 -Python 으로 python.exe 경로를 지정하세요.'
}

$py = Find-Python
if ($py -like '*\WindowsApps\*') {
    throw "Microsoft Store 판 Python($py)은 작업 스케줄러에서 실행되지 않습니다. python.org 설치본을 사용하거나 -Python 으로 지정하세요."
}
& $py -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
if ($LASTEXITCODE -ne 0) { throw "Python 3.10 이상이 필요합니다: $py" }
$pyw = Join-Path (Split-Path -Parent $py) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pyw)) {
    Write-Warning 'pythonw.exe 가 없어 python.exe 로 실행합니다(콘솔 창이 보일 수 있습니다).'
    $pyw = $py
}
Write-Host "Python  : $py"

# ------------------------------------------------------------ Teams 웹훅 (권한 제한 파일)
$envFile = Join-Path $DataDir 'url-monitor.env'
if ($TeamsWebhookUrl) {
    if ($TeamsWebhookUrl -notmatch '^https://') { throw 'Teams 웹훅 주소는 https:// 로 시작해야 합니다.' }
    Set-Content -LiteralPath $envFile -Value "URLMON_TEAMS_WEBHOOK=$TeamsWebhookUrl" -Encoding UTF8
}
elseif (-not (Test-Path -LiteralPath $envFile)) {
    Set-Content -LiteralPath $envFile -Value '# KEY=VALUE 형식. 예) URLMON_TEAMS_WEBHOOK=https://...' -Encoding UTF8
}
# SYSTEM, Administrators, 설치한 사용자만 읽을 수 있게 (SID 로 지정해 한글 Windows 에서도 동작)
& icacls $envFile /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' "*$($identity.User.Value):F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "권한 설정 실패: $envFile" }

$hasTeams = [bool](Select-String -LiteralPath $envFile -Pattern '^\s*URLMON_TEAMS_WEBHOOK=https://' -Quiet)
$teamsArgs = @()
if ($hasTeams) { $teamsArgs = @('--teams-webhook', 'env:URLMON_TEAMS_WEBHOOK') }
else { Write-Warning 'Teams 웹훅이 없습니다. 설정 파일의 notify 에 알림 채널이 없으면 알림이 가지 않습니다. (-TeamsWebhookUrl 지정)' }

# ------------------------------------------------------------ 설정 검사 + 시험 알림
Push-Location $AppDir
try {
    & $py -m url_monitor validate $Config --env-file $envFile @teamsArgs
    if ($LASTEXITCODE -ne 0) { throw '설정 파일 오류를 고친 뒤 다시 실행하세요.' }
    if ($hasTeams -and -not $NoTest) {
        & $py -m url_monitor notify-test $Config --env-file $envFile @teamsArgs
        if ($LASTEXITCODE -ne 0) {
            throw 'Teams 시험 메시지 발송에 실패했습니다. 웹훅 주소와 네트워크(프록시)를 확인하세요. (-NoTest 로 건너뛸 수 있습니다)'
        }
    }
}
finally { Pop-Location }

# ------------------------------------------------------------ 작업 스케줄러 등록
$db = Join-Path $DataDir 'monitor.db'
$log = Join-Path $DataDir 'monitor.log'
if (-not $StatusPage) { $StatusPage = Join-Path $DataDir 'status.html' }

function Quote([string]$s) { return '"' + $s + '"' }
$cliArgs = @('-m', 'url_monitor', 'watch', (Quote $Config), '--db', (Quote $db), '--log-file', (Quote $log),
    '--status-page', (Quote $StatusPage), '--env-file', (Quote $envFile), '--keep-awake', '--notify-start',
    '--heartbeat-hours', $HeartbeatHours.ToString([Globalization.CultureInfo]::InvariantCulture), '-q') + $teamsArgs
$argLine = $cliArgs -join ' '

$action = New-ScheduledTaskAction -Execute $pyw -Argument $argLine -WorkingDirectory $AppDir

# 감시용 반복 트리거: 프로세스가 죽어 있으면 5분 안에 다시 시작 (살아 있으면 IgnoreNew 로 무시)
$watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
if ($RunAs -eq 'System') {
    $boot = New-ScheduledTaskTrigger -AtStartup
    $boot.Delay = 'PT1M'  # 부팅 직후 네트워크 준비 대기
    $triggers = @($boot, $watchdog)
    $account = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18').Translate([Security.Principal.NTAccount]).Value
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType ServiceAccount -RunLevel Highest
}
else {
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $identity.Name), $watchdog)
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
}

$settingsArgs = @{
    AllowStartIfOnBatteries    = $true
    DontStopIfGoingOnBatteries = $true
    StartWhenAvailable         = $true
    DontStopOnIdleEnd          = $true
    ExecutionTimeLimit         = [TimeSpan]::Zero   # 기본 72시간 제한 해제
    RestartCount               = 999
    RestartInterval            = (New-TimeSpan -Minutes 1)
    MultipleInstances          = 'IgnoreNew'
}
if ($WakeToRun) { $settingsArgs.WakeToRun = $true }
$settings = New-ScheduledTaskSettingsSet @settingsArgs

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings `
    -Description 'URL 접속 이상 점검(url-monitor). 화면 잠금 중에도 실행되며 상태가 바뀌면 Teams 로 알립니다.' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
$info = Get-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host "등록 완료: 작업 '$TaskName' ($RunAs 계정, 현재 상태 $($info.State))" -ForegroundColor Green
Write-Host "  설정 파일   : $Config"
Write-Host "  로그        : $log"
Write-Host "  상태 페이지 : $StatusPage"
Write-Host "  이력 DB     : $db"
Write-Host "  비밀값 파일 : $envFile (SYSTEM/관리자/본인만 읽기 가능)"
Write-Host ''
Write-Host "상태 확인 : .\windows\status.ps1 -TaskName '$TaskName'"
Write-Host "제거      : .\windows\uninstall.ps1 -TaskName '$TaskName'"
if ($RunAs -eq 'User') {
    Write-Host '참고: -RunAs User 는 로그아웃하면 멈춥니다(화면 잠금은 괜찮습니다). 로그아웃 상태에서도 돌리려면 관리자 권한으로 -RunAs System 을 쓰세요.' -ForegroundColor Yellow
}
