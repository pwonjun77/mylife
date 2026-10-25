<#
.SYNOPSIS
    작업 스케줄러에서 URL Monitor 작업을 멈추고 제거합니다.
.EXAMPLE
    .\windows\uninstall.ps1                 # 작업만 제거 (로그·이력·비밀값 파일은 남김)
    .\windows\uninstall.ps1 -RemoveData     # 데이터 폴더까지 삭제
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'URL Monitor',
    [string]$DataDir,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "작업 '$TaskName' 을(를) 제거했습니다." -ForegroundColor Green
}
else {
    Write-Host "작업 '$TaskName' 이(가) 없습니다."
}

if ($RemoveData) {
    $dirs = @($DataDir, (Join-Path $env:ProgramData 'url-monitor'), (Join-Path $env:LOCALAPPDATA 'url-monitor')) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($d in $dirs) {
        Remove-Item -LiteralPath $d -Recurse -Force
        Write-Host "삭제했습니다: $d"
    }
}
