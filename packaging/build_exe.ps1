# IaCPatch.exe 만들기 (Windows, 팀 PC 에서 1회). 결과: 저장소 루트의 IaCPatch.exe
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File packaging\build_exe.ps1
#   powershell ... -File packaging\build_exe.ps1 -Console     # IaCPatch-console.exe: 검은 콘솔 창에 주소·오류가 보이는 진단용 판
#   GitHub Actions 도 같은 빌드를 한다: .github/workflows/build-exe.yml (Windows 러너) → Actions 아티팩트 / 태그 push 시 Release
#
# exe 는 "실행기" 다 (더블클릭 → 127.0.0.1 로컬 서버 → 프로그램 자체 창에 화면. pywebview/WebView2, 없으면 Edge 앱 창). 저장소 폴더(policy\, scenarios\, experiments\, tests\, tools\)가 옆에 있어야 하고,
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

& $PyExe @($PyPre + @("-m", "pip", "install", "--upgrade", "pyinstaller", "pywebview"))
if ($LASTEXITCODE -ne 0) { Write-Host "pyinstaller/pywebview 설치 실패"; exit 1 }
# 자체 창(pywebview) 이 들어가는지 — 못 넣으면 exe 는 Edge 앱 창으로 연다
$collect = @()
& $PyExe @($PyPre + @("-c", "import webview"))
if ($LASTEXITCODE -eq 0) { $collect += @("--collect-all", "webview") } else { Write-Host "pywebview 를 못 불러온다 → Edge 앱 창으로 연다" }
& $PyExe @($PyPre + @("-c", "import clr_loader, pythonnet"))
if ($LASTEXITCODE -eq 0) { $collect += @("--collect-all", "clr_loader", "--collect-all", "pythonnet") }

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
# 빌드 정보(커밋·시각·소스 지문·판 번호)를 exe 안에 넣는다 — 화면 ① 준비 상태 · ⑧ 기록 · '새 빌드 받기' 가 읽는다 (D-37).
#  - 커밋: git 이 PATH 에 없는 PC(GitHub Desktop 만 쓰는 경우)에서도 .git/HEAD 파일을 직접 읽어 채운다 (11-01 빌드는 sha 가 비어 있었다 — 실측).
#  - 소스 지문: src/iacpatch + policy 내용의 sha256 — 커밋하지 않은 수정도 반영. exe 와 옆 폴더 코드가 같은지 화면이 비교한다.
$sha = if ($env:IACPATCH_BUILD_SHA) { $env:IACPATCH_BUILD_SHA } else { try { (git rev-parse HEAD 2>$null | Out-String).Trim() } catch { "" } }
if (-not $sha) {
  try {
    $pv = (& $PyExe @($PyPre + @("-c", "import json,sys;from pathlib import Path;sys.path.insert(0,r'$Root\src');from iacpatch.version import git_head;print(json.dumps(git_head(Path(r'$Root'))))")) 2>$null | Out-String).Trim()
    if ($pv) { $sha = [string](ConvertFrom-Json $pv).sha }
  } catch { $sha = "" }
}
$fp = (& $PyExe @($PyPre + @("-m", "iacpatch.version", "--fingerprint", "--root", $Root)) 2>$null | Out-String).Trim()
$pver = (& $PyExe @($PyPre + @("-c", "import sys;sys.path.insert(0,r'$Root\src');from iacpatch.version import PROGRAM_VERSION;print(PROGRAM_VERSION)")) 2>$null | Out-String).Trim()
$built = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$binfo = Join-Path $Root "src\iacpatch\build_info.json"
@{ sha = $sha; built_at = $built; ref = $env:IACPATCH_BUILD_REF; src_fingerprint = $fp; version = $pver } | ConvertTo-Json -Compress | Out-File -FilePath $binfo -Encoding utf8
Write-Host ("build_info: version=" + $pver + " sha=" + $sha + " src_fingerprint=" + $fp + " built_at=" + $built)
if (-not $sha) { Write-Host "주의: 커밋을 못 읽었다 (.git 없음?) — exe 에 커밋 번호가 비어 들어간다. 소스 지문으로는 구분된다" }
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
          "--icon", "$Root\packaging\iacpatch.ico",
          "--collect-submodules", "iacpatch") + $hidden + $collect + @(
          "--add-data", "$Root\src\iacpatch\generator\prompts;iacpatch\generator\prompts",
          "--add-data", "$Root\src\iacpatch\web\static;iacpatch\web\static",
          "--add-data", "$binfo;iacpatch",
          "--distpath", "$Root\packaging\dist", "--workpath", "$Root\packaging\build", "--specpath", "$Root\packaging",
          "$Root\src\iacpatch\app.py")
& $PyExe @($PyPre + $args)
if ($LASTEXITCODE -ne 0) { Write-Host "빌드 실패"; exit 1 }

Copy-Item "packaging\dist\$name.exe" "$Root\$name.exe" -Force
Write-Host ""
Write-Host "완료: $Root\$name.exe  (더블클릭 → 프로그램 창이 열린다. 창 없는 판의 출력은 experiments\exe-console.log)"
Write-Host "주의: exe 만 다른 폴더로 옮기면 안 된다. 저장소 폴더째로 복사해야 policy\, scenarios\, tests\, tools\ 를 찾는다."
