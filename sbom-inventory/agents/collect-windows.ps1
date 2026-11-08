<#
.SYNOPSIS
  Windows 설치 소프트웨어 인벤토리 수집 (sbom-inventory 에이전트, 읽기 전용).

.DESCRIPTION
  - 설치 프로그램: HKLM / HKLM\WOW6432Node / HKU\<SID> 의 Uninstall 레지스트리 키
    * Win32_Product(WMI) 는 사용하지 않는다: 조회만 해도 모든 MSI 의 일관성 검사/자가복구가 실행돼
      이벤트 로그(MsiInstaller 1035)가 대량 발생하고 시스템 상태가 바뀔 수 있다(포렌식 관점에서도 부적합).
  - 시스템 구성요소(SystemComponent=1), 업데이트(ParentKeyName / ReleaseType=Update) 는 제외
  - (선택) -IncludeAppx : Store/UWP 앱
  - 결과: <OutDir>\<hostname>.json (+ .sha256)

  배포: Intune > 장치 > 스크립트(플랫폼 스크립트, SYSTEM 컨텍스트, 64비트) 또는 GPO 시작 스크립트.
  수집 공유폴더 권한 예: Domain Computers = 쓰기(생성)만, 읽기/목록 없음. 관리자만 읽기.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File collect-windows.ps1 -OutDir \\fileserver\sbom$
#>
[CmdletBinding()]
param(
    [string]$OutDir = "$env:ProgramData\sbom-inventory",
    [switch]$IncludeAppx
)
$ErrorActionPreference = 'Stop'

function Get-UninstallEntries {
    param([string]$Root, [string]$Scope)
    if (-not (Test-Path $Root)) { return }
    Get-ChildItem -Path $Root -ErrorAction SilentlyContinue | ForEach-Object {
        try { $p = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop } catch { return }
        if (-not $p.DisplayName) { return }
        if ($p.SystemComponent -eq 1) { return }
        if ($p.ParentKeyName -or $p.ReleaseType -in @('Update','Hotfix','Security Update')) { return }
        [ordered]@{
            name             = [string]$p.DisplayName
            version          = [string]$p.DisplayVersion
            vendor           = [string]$p.Publisher
            install_date     = [string]$p.InstallDate
            install_location = [string]$p.InstallLocation
            source           = 'registry'
            scope            = $Scope
            arch             = $(if ($Root -match 'WOW6432Node') { 'x86' } else { '' })
        }
    }
}

$pkgs = New-Object System.Collections.Generic.List[object]
$roots = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine' },
    @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine' }
)
# 로그인된(하이브가 로드된) 사용자별 설치 — 사용자 프로필에 설치되는 Chrome/Teams/VSCode 등
Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
    ForEach-Object { $roots += @{ Path = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "user:$($_.PSChildName)" } }

foreach ($r in $roots) { Get-UninstallEntries -Root $r.Path -Scope $r.Scope | ForEach-Object { $pkgs.Add($_) } }

if ($IncludeAppx) {
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { -not $_.IsFramework } | ForEach-Object {
        $pkgs.Add([ordered]@{ name = $_.Name; version = [string]$_.Version; vendor = $_.Publisher; source = 'appx'; arch = [string]$_.Architecture })
    }
}

# 중복 제거 (같은 이름+버전이 32/64비트 키에 모두 있는 경우)
$uniq = $pkgs | Sort-Object { "$($_.name)|$($_.version)|$($_.scope)" } -Unique

$os   = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$cs   = Get-CimInstance Win32_ComputerSystem
$macs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { $_.MACAddress } | Where-Object { $_ })
$ips  = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -notmatch '^fe80' })

$doc = [ordered]@{
    schema       = 'sbom-inventory-agent/1'
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    host = [ordered]@{
        hostname   = $env:COMPUTERNAME
        fqdn       = $(if ($cs.Domain -and $cs.PartOfDomain) { "$($env:COMPUTERNAME).$($cs.Domain)" } else { '' })
        serial     = [string]$bios.SerialNumber
        os         = [string]$os.Caption
        os_version = "$($os.Version).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR)"
        macs       = $macs
        ips        = $ips
        model      = "$($cs.Manufacturer) $($cs.Model)"
    }
    packages = @($uniq)
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$json = $doc | ConvertTo-Json -Depth 5 -Compress
$out  = Join-Path $OutDir "$($env:COMPUTERNAME).json"
$tmp  = "$out.tmp"
[System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -Path $tmp -Destination $out -Force   # 원자적 교체: 수집기가 쓰는 도중의 파일을 읽지 않게
$hash = (Get-FileHash -Path $out -Algorithm SHA256).Hash.ToLower()
Set-Content -Path "$out.sha256" -Value "$hash  $($env:COMPUTERNAME).json" -Encoding ascii
Write-Output "OK $($uniq.Count) packages -> $out"
exit 0
