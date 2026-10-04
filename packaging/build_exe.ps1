# IaCPatch.exe 만들기 (Windows, 팀 PC 에서 1회). 결과: 저장소 루트의 IaCPatch.exe
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File packaging\build_exe.ps1
#   powershell ... -File packaging\build_exe.ps1 -Console     # IaCPatch-console.exe: 검은 콘솔 창에 주소·오류가 보이는 진단용 판
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
$name = if ($Console) { "IaCPatch-console" } else { "IaCPatch" }   # 콘솔판은 검은 창에 로그가 보여서 문제 진단용. 둘 다 만들어 둘 수 있다

# iacpatch 의 모든 모듈을 exe 에 넣는다. 실험 스크립트(scripts/*.py)는 exe 가 자기 자신을 --exec 로 띄워 돌리므로, 진입점(app.py)에서
# 직접 import 하지 않는 모듈(fuzz, verify 일부…)도 전부 들어가야 한다.
#  - --collect-submodules 는 spec 을 만드는 시점에 iacpatch 를 import 할 수 있어야 동작하는데 --paths 는 그 뒤(Analysis)에야 적용된다
#    → PYTHONPATH 로 src\ 를 먼저 보이게 한다 (build-exe #2·#3 실측: 이게 없어서 iacpatch.fuzz 가 빠져 스모크가 죽음, 2026-09-28).
#  - 그래도 빠지는 일이 없게 src\iacpatch\**\*.py 를 전부 --hidden-import 로도 준다. exe 의 --selfcheck 가 빠진 모듈이 없는지 검사한다.
$env:PYTHONPATH = "$Root\src"
& $PyExe @($PyPre + @("-c", "import iacpatch.fuzz.runner, iacpatch.web.server, iacpatch.rubric_demo"))
if ($LASTEXITCODE -ne 0) { Write-Host "src\iacpatch 를 import 할 수 없다 (PYTHONPATH=$env:PYTHONPATH)"; exit 1 }
# 빌드 정보(커밋·시각)를 exe 안에 넣는다 — 화면 '빌드' 칸과 '새 빌드 받기'(GitHub Release dev-latest 와 비교)가 읽는다
$sha = if ($env:IACPATCH_BUILD_SHA) { $env:IACPATCH_BUILD_SHA } else { try { (git rev-parse HEAD 2>$null | Out-String).Trim() } catch { "" } }
$built = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$binfo = Join-Path $Root "src\iacpatch\build_info.json"
@{ sha = $sha; built_at = $built; ref = $env:IACPATCH_BUILD_REF } | ConvertTo-Json -Compress | Out-File -FilePath $binfo -Encoding utf8
Write-Host ("build_info: sha=" + $sha + " built_at=" + $built)
$hidden = @()
Get-ChildItem -Path "$Root\src\iacpatch" -Recurse -Filter *.py | Where-Object { $_.Name -ne "__main__.py" } | ForEach-Object {
  $rel = $_.FullName.Substring("$Root\src\".Length) -replace "\.py$", ""
  $mod = ($rel -replace "\\", ".") -replace "\.__init__$", ""
  $hidden += @("--hidden-import", $mod)
}
Write-Host ("hidden imports: " + ($hidden.Count / 2) + " modules")
# 경로는 전부 절대경로로 준다. --specpath 를 쓰면 PyInstaller 가 --add-data 의 상대경로를 spec 폴더(packaging\) 기준으로 풀어서
# "packaging\src\iacpatch\generator\prompts 를 찾을 수 없다" 로 실패한다 (팀 PC 첫 빌드에서 실측, 2026-09-22).
$args = @("-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", $mode,
          "--name", $name,
          "--paths", "$Root\src",
          "--collect-submodules", "iacpatch") + $hidden + @(
          "--add-data", "$Root\src\iacpatch\generator\prompts;iacpatch\generator\prompts",
          "--add-data", "$Root\src\iacpatch\web\static;iacpatch\web\static",
          "--add-data", "$binfo;iacpatch",
          "--distpath", "$Root\packaging\dist", "--workpath", "$Root\packaging\build", "--specpath", "$Root\packaging",
          "$Root\src\iacpatch\app.py")
& $PyExe @($PyPre + $args)
if ($LASTEXITCODE -ne 0) { Write-Host "빌드 실패"; exit 1 }

Copy-Item "packaging\dist\$name.exe" "$Root\$name.exe" -Force
Write-Host ""
Write-Host "완료: $Root\$name.exe  (더블클릭 → 브라우저에 화면이 열린다. 창 없는 판의 출력은 experiments\exe-console.log)"
Write-Host "주의: exe 만 다른 폴더로 옮기면 안 된다. 저장소 폴더째로 복사해야 policy\, scenarios\, tests\, tools\ 를 찾는다."
