# Windows PowerShell 버전. 사용법: scripts\predeploy_demo.ps1 [fixture]
param([string]$Fixture = "sg_baseline_ok")
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$env:PYTHONPATH = "$Root\src"
if (-not $env:IACPATCH_TF_VAR_FILE) { $env:IACPATCH_TF_VAR_FILE = "terraform.tfvars.example" }
Set-Location $Root
python -m iacpatch predeploy --target-dir infrastructure/sg-baseline --intent tests/fixtures/intents/sg-baseline.test.json --scenario "demo-$Fixture" --generator llm --llm-provider mock --llm-mock-fixture $Fixture --offline
