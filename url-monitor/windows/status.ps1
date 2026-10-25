<#
.SYNOPSIS
    URL Monitor 작업의 실행 상태와 최근 로그를 보여 줍니다.
.EXAMPLE
    .\windows\status.ps1
    .\windows\status.ps1 -Lines 50
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'URL Monitor',
    [string]$DataDir,
    [int]$Lines = 20
)

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Host "작업 '$TaskName' 이(가) 등록되어 있지 않습니다. .\windows\install.ps1 로 등록하세요." -ForegroundColor Yellow
    exit 1
}
$info = Get-ScheduledTaskInfo -TaskName $TaskName
$color = if ($task.State -eq 'Running') { 'Green' } else { 'Yellow' }
Write-Host "작업        : $TaskName ($($task.Principal.UserId))"
Write-Host "상태        : $($task.State)" -ForegroundColor $color
Write-Host "마지막 실행 : $($info.LastRunTime) (결과 코드 $($info.LastTaskResult))"

if (-not $DataDir) {
    $DataDir = @((Join-Path $env:ProgramData 'url-monitor'), (Join-Path $env:LOCALAPPDATA 'url-monitor')) |
        Where-Object { Test-Path -LiteralPath (Join-Path $_ 'monitor.log') } | Select-Object -First 1
}
if ($DataDir) {
    $log = Join-Path $DataDir 'monitor.log'
    Write-Host "로그        : $log"
    Write-Host ''
    Get-Content -LiteralPath $log -Tail $Lines -Encoding UTF8
}
else {
    Write-Host '로그 파일을 찾지 못했습니다.'
}
Write-Host ''
Write-Host "절전 방지 확인(관리자 권한): powercfg /requests  -> SYSTEM 항목에 pythonw.exe 가 보이면 정상"
