# 혼자 돌리는 실험 한 방 (Windows PowerShell). 더블클릭은 scripts\run_experiments.bat
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_experiments.ps1 [-NoTools]
#
# 하는 일: tools\ 의 trivy.exe/terraform.exe 를 잡고 → A 결과 재현 확인 → eval-a-probe-rule → eval-seeded-sg
#          → eval-claude-code(후보 있을 때) → experiments\RESULTS_SUMMARY.md
# 하지 않는 일: LLM API 호출, Claude Code 자동 호출, AWS 접속/생성, git push. terraform 은 오프라인 plan 만.
param([switch]$NoTools)
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$env:PYTHONPATH = Join-Path $Root "src"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# python 찾기 (py 런처 우선)
$Py = $null
foreach ($c in @(@("py", "-3"), @("python", ""), @("python3", ""))) {
    try { $v = & $c[0] $c[1] --version 2>$null; if ($LASTEXITCODE -eq 0 -and $v) { $Py = $c; break } } catch {}
}
if (-not $Py) { Write-Host "python 3 이 없다. https://www.python.org/downloads/ 에서 설치 (Add to PATH 체크)"; exit 1 }
function RunPy { param([string[]]$a) if ($Py[1]) { & $Py[0] $Py[1] @a } else { & $Py[0] @a } }

if ($NoTools) {
    $env:TRIVY_BIN = "C:\nonexistent\trivy.exe"; $env:TERRAFORM_BIN = "C:\nonexistent\terraform.exe"
    Write-Host "도구 없이 실행 (검증 계층 NOT_RUN)"
} else {
    $t = Join-Path $Root "tools\trivy.exe";     if (Test-Path $t) { $env:TRIVY_BIN = $t }
    $f = Join-Path $Root "tools\terraform.exe"; if (Test-Path $f) { $env:TERRAFORM_BIN = $f }
    if (-not $env:TRIVY_SKIP_CHECK_UPDATE) { $env:TRIVY_SKIP_CHECK_UPDATE = "1" }
    if (-not $env:TF_PLUGIN_CACHE_DIR) { $env:TF_PLUGIN_CACHE_DIR = Join-Path $Root "tools\plugin-cache" }
    New-Item -ItemType Directory -Force -Path $env:TF_PLUGIN_CACHE_DIR | Out-Null
    $tb = if ($env:TRIVY_BIN) { $env:TRIVY_BIN } else { "trivy" }
    $fb = if ($env:TERRAFORM_BIN) { $env:TERRAFORM_BIN } else { "terraform" }
    try { Write-Host ("trivy    : " + (& $tb --version 2>$null | Select-Object -First 1)) } catch { Write-Host "trivy    : 없음 -> V1/V2 NOT_RUN (scripts\setup_tools.bat)" }
    try { Write-Host ("terraform: " + (& $fb version 2>$null | Select-Object -First 1)) } catch { Write-Host "terraform: 없음 -> V3~V6 NOT_RUN (scripts\setup_tools.bat)" }
}

function Step($t) { Write-Host ""; Write-Host "================ $t" }

Step "1/5 A 의 9 케이스 결과 재현 확인"
RunPy @("experiments\candidate-sets\a-probe-dev\check_a_results.py") | Select-Object -Last 3

Step "2/5 eval-a-probe-rule (규칙 기반 기준선)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-a-probe-rule\manifest.json") | Select-Object -First 12

Step "3/5 eval-seeded-sg (오라클 유무 재료)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-seeded-sg\manifest.json") | Select-Object -First 14

Step "4/5 eval-claude-code (LLM 후보)"
$m = Get-Content (Join-Path $Root "experiments\candidate-sets\eval-claude-code\manifest.json") -Raw -Encoding UTF8 | ConvertFrom-Json
if ($m.candidates -and $m.candidates.Count -gt 0) {
    RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-claude-code\manifest.json") | Select-Object -First 40
} else {
    Write-Host "후보 0건 - scripts\cc_prompt.py 로 프롬프트 뽑아 Claude Code 에서 받고, scripts\cc_add.py 로 등록하면 여기서 돈다"
}

Step "5/5 요약"
RunPy @("scripts\summarize_experiments.py") | Select-Object -Last 25
Write-Host ""
Write-Host "결과 파일:"
Write-Host "  experiments\RESULTS_SUMMARY.md                      <- 한 장 요약"
Write-Host "  experiments\candidate-sets\<세트>\results.md        <- 세트별 표 (+ results-history\ 에 이 실행이 추가됨)"
Write-Host "  data\reviews\<id>\review.md                         <- 후보별 리포트·diff·검증 원문"
