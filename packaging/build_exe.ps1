# IaCPatch.exe 만들기 (Windows, 팀 PC 에서 1회). 결과: 저장소 루트의 IaCPatch.exe
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File packaging\build_exe.ps1
#   powershell ... -File packaging\build_exe.ps1 -Console     # 검은 콘솔 창도 같이 뜨는 버전 (주소·오류가 보여서 진단용)
#   GitHub Actions 도 같은 빌드를 한다: .github/workflows/build-exe.yml (Windows 러너) → Actions 아티팩트 / 태그 push 시 Release
#
# exe 는 "실행기" 다 (더블클릭 → 127.0.0.1 로컬 서버 → 기본 브라우저에 화면). 저장소 폴더(policy\, scenarios\, experiments\, tests\, tools\)가 옆에 있어야 하고,
# 실험 스크립트는 exe 가 자기 자신을 `--exec` 로 다시 띄워 돌리므로 PC 에 python 이 없어도 된다.
# trivy.exe / terraform.exe 는 exe 안에 넣지 않는다 (창의 "도구 설치/확인" 버튼 → tools\).
# 하지 않는 것: LLM API, Claude Code 자동 호출, AWS, terraform apply, git push (D-5, D-11).
param([switch]$Console)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$PyExe = $null; $PyPre = @()
foreach ($c in @(@{exe = "py"; pre = @("-3")}, @{exe = "python"; pre = @()}, @{exe = "python3"; pre = @()})) {
  if (Get-Command $c.exe -ErrorAction SilentlyContinue) {
    $v = (& $c.exe @($c.pre + @("--version")) 2>&1 | Out-String)
    if ($v -match "Python 3\.(1[0-9]|[2-9][0-9])") { $PyExe = $c.exe; $PyPre = $c.pre; break }
  }
}
if (-not $PyExe) { Write-Host "python 3.10+ 이 없다. https://www.python.org/downloads/ (Add python.exe to PATH 체크)"; exit 1 }
Write-Host ("python : " + (& $PyExe @($PyPre + @("--version")) 2>&1 | Out-String).Trim())

# tkinter 확인 (python.org 설치본에는 기본 포함. Microsoft Store 판/일부 배포판은 없을 수 있다)
& $PyExe @($PyPre + @("-c", "import tkinter"))
if ($LASTEXITCODE -ne 0) { Write-Host "tkinter 가 없다. python.org 설치본으로 다시 설치 (tcl/tk 옵션 체크)"; exit 1 }

& $PyExe @($PyPre + @("-m", "pip", "install", "--upgrade", "pyinstaller"))
if ($LASTEXITCODE -ne 0) { Write-Host "pyinstaller 설치 실패"; exit 1 }

$mode = if ($Console) { "--console" } else { "--windowed" }
# 경로는 전부 절대경로로 준다. --specpath 를 쓰면 PyInstaller 가 --add-data 의 상대경로를 spec 폴더(packaging\) 기준으로 풀어서
# "packaging\src\iacpatch\generator\prompts 를 찾을 수 없다" 로 실패한다 (팀 PC 첫 빌드에서 실측, 2026-09-22).
$args = @("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", $mode,
          "--name", "IaCPatch",
          "--paths", "$Root\src",
          "--collect-submodules", "iacpatch",
          "--add-data", "$Root\src\iacpatch\generator\prompts;iacpatch\generator\prompts",
          "--add-data", "$Root\src\iacpatch\web\static;iacpatch\web\static",
          "--distpath", "$Root\packaging\dist", "--workpath", "$Root\packaging\build", "--specpath", "$Root\packaging",
          "$Root\src\iacpatch\app.py")
& $PyExe @($PyPre + $args)
if ($LASTEXITCODE -ne 0) { Write-Host "빌드 실패"; exit 1 }

Copy-Item "packaging\dist\IaCPatch.exe" "$Root\IaCPatch.exe" -Force
Write-Host ""
Write-Host "완료: $Root\IaCPatch.exe  (더블클릭 → 브라우저에 화면이 열린다)"
Write-Host "주의: exe 만 다른 폴더로 옮기면 안 된다. 저장소 폴더째로 복사해야 policy\, scenarios\, tests\, tools\ 를 찾는다."
