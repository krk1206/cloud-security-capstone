# Windows PowerShell: 단위 + (도구 있으면) 통합 테스트. 현재 폴더에 의존하지 않는다.
$ErrorActionPreference = "Continue"
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$Root = Split-Path -Parent $ScriptDir
$env:PYTHONPATH = "$Root\src;$Root\tests\unit"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# python 찾기 (py 런처 우선). Microsoft Store 가짜 별칭은 --version 이 실패해 걸러진다
$PyExe = $null; $PyPre = @()
foreach ($c in @(@{exe = "py"; pre = @("-3")}, @{exe = "python"; pre = @()}, @{exe = "python3"; pre = @()})) {
    try {
        $out = & $c.exe @($c.pre + @("--version")) 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $out -match "Python 3\.(1[0-9]|[2-9][0-9])") { $PyExe = $c.exe; $PyPre = $c.pre; break }
    } catch {}
}
if (-not $PyExe) { Write-Host "python 3.10+ 이 없다. https://www.python.org/downloads/ 에서 설치 (Add python.exe to PATH 체크)"; exit 1 }
Write-Host ("python   : " + (& $PyExe @($PyPre + @("--version")) 2>&1 | Out-String).Trim())
Write-Host ("repo     : $Root")
& $PyExe @($PyPre + @("-m", "unittest", "discover", "-s", "$Root\tests\unit", "-t", "$Root\tests\unit", "-p", "test_*.py", "-v"))
