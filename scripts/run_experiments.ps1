# 혼자 돌리는 실험 한 방 (Windows PowerShell). 더블클릭은 scripts\run_experiments.bat
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_experiments.ps1 [-NoTools]
#
# 하는 일: tools\ 의 trivy.exe/terraform.exe 를 잡고 → A 결과 재현 확인 → eval-a-probe-rule → eval-seeded-sg
#          → eval-iam-rule → eval-seeded-iam → eval-claude-code(후보 있을 때) → 오라클 실험 → experiments\RESULTS_SUMMARY.md
# 하지 않는 일: LLM API 호출, Claude Code 자동 호출, AWS 접속/생성, git push. terraform 은 오프라인 plan 만.
param([switch]$NoTools)
$ErrorActionPreference = "Continue"
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$Root = Split-Path -Parent $ScriptDir
Set-Location $Root
$env:PYTHONPATH = Join-Path $Root "src"
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# python 찾기 (py 런처 우선). Microsoft Store 의 가짜 python 별칭은 --version 이 실패하므로 걸러진다
$PyExe = $null; $PyPre = @()
foreach ($c in @(@{exe = "py"; pre = @("-3")}, @{exe = "python"; pre = @()}, @{exe = "python3"; pre = @()})) {
    try {
        $out = & $c.exe @($c.pre + @("--version")) 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $out -match "Python 3\.(1[0-9]|[2-9][0-9])") { $PyExe = $c.exe; $PyPre = $c.pre; break }
    } catch {}
}
if (-not $PyExe) { Write-Host "python 3.10+ 이 없다. https://www.python.org/downloads/ 에서 설치 (Add python.exe to PATH 체크)"; exit 1 }
Write-Host ("python   : " + (& $PyExe @($PyPre + @("--version")) 2>&1 | Out-String).Trim() + "  ($PyExe)")
$Log = Join-Path $Root "experiments\run_experiments.log"
"run_experiments $(Get-Date -Format s)" | Out-File -FilePath $Log -Encoding utf8
# Tee-Object 는 PS 5.1 에서 UTF-16 으로 써서 로그 한글이 깨진다 → 줄마다 화면 출력 + UTF-8 로 append
function RunPy { param([string[]]$a) & $PyExe @($PyPre + $a) 2>&1 | ForEach-Object { $_ | Out-Host; Add-Content -LiteralPath $Log -Value ([string]$_) -Encoding UTF8 } }

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

Step "1/8 A 의 9 케이스 결과 재현 확인"
RunPy @("experiments\candidate-sets\a-probe-dev\check_a_results.py")

Step "2/8 eval-a-probe-rule (규칙 기반 기준선, SG)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-a-probe-rule\manifest.json")

Step "3/8 eval-seeded-sg (오라클 유무 재료, SG)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-seeded-sg\manifest.json")

Step "4/8 eval-iam-rule (규칙 기반 기준선, IAM)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-iam-rule\manifest.json")

Step "5/8 eval-seeded-iam (오라클 유무 재료, IAM)"
RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-seeded-iam\manifest.json")

Step "6/8 eval-claude-code (LLM 후보)"
$m = Get-Content (Join-Path $Root "experiments\candidate-sets\eval-claude-code\manifest.json") -Raw -Encoding UTF8 | ConvertFrom-Json
if ($m.candidates -and $m.candidates.Count -gt 0) {
    RunPy @("scripts\run_candidate_set.py", "experiments\candidate-sets\eval-claude-code\manifest.json")
} else {
    Write-Host "후보 0건 - scripts\cc_prompt.py 로 프롬프트 뽑아 Claude Code 에서 받고, scripts\cc_add.py 로 등록하면 여기서 돈다"
}

Step "7/8 오라클 실험 (스캐너 vs V6, 실제 plan — SG + IAM)"
RunPy @("scripts\oracle_experiment.py")

Step "8/8 요약"
RunPy @("scripts\summarize_experiments.py")
RunPy @("scripts\why_this_gate.py")
Write-Host ""
Write-Host "결과 파일:"
Write-Host "  experiments\ORACLE_RESULTS.md                       <- E2 핵심 (스캐너 vs 오라클, 실제 plan)"
Write-Host "  experiments\RESULTS_SUMMARY.md                      <- 한 장 요약"
Write-Host "  experiments\WHY_THIS_GATE.md                        <- 기업용 한 장 (스캐너 vs 게이트)"
Write-Host "  experiments\candidate-sets\<세트>\results.md        <- 세트별 표 (+ results-history\ 에 이 실행이 추가됨)"
Write-Host "  data\reviews\<id>\review.md                         <- 후보별 리포트·diff·검증 원문"
Write-Host "  experiments\run_experiments.log                     <- 이 실행의 전체 출력 (문제 생기면 이 파일을 보낼 것)"
