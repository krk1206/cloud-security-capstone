# 혼자 실험용 도구 설치 (Windows PowerShell). trivy.exe / terraform.exe 를 저장소 안 tools\ 에만 받는다.
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup_tools.ps1
#   (더블클릭: scripts\setup_tools.bat)
#
# 버전은 팀 기준(A 의 VERIFY.md): Trivy 0.74.0, Terraform 1.16.1. AWS 계정 불필요. 네트워크는 다운로드 때만.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Tools = Join-Path $Root "tools"
$TrivyVer = if ($env:TRIVY_VER) { $env:TRIVY_VER } else { "0.74.0" }
$TfVer = if ($env:TF_VER) { $env:TF_VER } else { "1.16.1" }
New-Item -ItemType Directory -Force -Path $Tools | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Tools "plugin-cache") | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Have($exe, $ver) {
    if (-not (Test-Path $exe)) { return $false }
    try { $out = & $exe --version 2>$null | Out-String; return $out -match [regex]::Escape($ver) } catch { return $false }
}

# ---- trivy
$trivyExe = Join-Path $Tools "trivy.exe"
if (Have $trivyExe $TrivyVer) {
    Write-Host "trivy $TrivyVer 이미 있음: $trivyExe"
} else {
    $url = "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVer/trivy_${TrivyVer}_windows-64bit.zip"
    Write-Host "trivy 다운로드: $url"
    $zip = Join-Path $env:TEMP "trivy_$TrivyVer.zip"
    Invoke-WebRequest -Uri $url -OutFile $zip
    $tmp = Join-Path $env:TEMP "trivy_$TrivyVer"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive -Path $zip -DestinationPath $tmp
    Copy-Item (Join-Path $tmp "trivy.exe") $trivyExe -Force
    Write-Host ("trivy: " + (& $trivyExe --version | Select-Object -First 1))
}

# ---- terraform
$tfExe = Join-Path $Tools "terraform.exe"
if (Test-Path $tfExe) {
    $v = (& $tfExe version | Select-Object -First 1)
    if ($v -match "v$TfVer") { Write-Host "terraform $TfVer 이미 있음: $tfExe" } else { Write-Host "terraform 있음 (다른 버전): $v" }
} else {
    $url = "https://releases.hashicorp.com/terraform/$TfVer/terraform_${TfVer}_windows_amd64.zip"
    Write-Host "terraform 다운로드: $url"
    try {
        $zip = Join-Path $env:TEMP "terraform_$TfVer.zip"
        Invoke-WebRequest -Uri $url -OutFile $zip
        $tmp = Join-Path $env:TEMP "terraform_$TfVer"
        if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
        Expand-Archive -Path $zip -DestinationPath $tmp
        Copy-Item (Join-Path $tmp "terraform.exe") $tfExe -Force
        Write-Host ("terraform: " + (& $tfExe version | Select-Object -First 1))
    } catch {
        Write-Host "terraform 다운로드 실패: $($_.Exception.Message)"
        Write-Host "대안: OpenTofu (https://github.com/opentofu/opentofu/releases) 의 tofu.exe 를 tools\terraform.exe 이름으로 두면 된다"
    }
}

Write-Host ""
Write-Host "완료. 실험 실행: scripts\run_experiments.bat 더블클릭 (tools\ 를 자동으로 잡는다)"
