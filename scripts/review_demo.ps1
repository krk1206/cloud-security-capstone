# Windows PowerShell: B·C 로컬 검토 흐름 데모. 사용법: scripts\review_demo.ps1 [manual|mock|split]
param([string]$Mode = "manual")
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root; $env:PYTHONPATH = "$Root\src"
switch ($Mode) {
  "manual" { python -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json --candidate manual:examples/bc/manual_candidate_ok --scenario demo-manual }
  "mock"   { python -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json --candidate mock:sg_baseline_ok --scenario demo-mock }
  "split"  { python -m iacpatch review --tf-dir scenarios/dev/case00-baseline --trivy-json scenarios/dev/case00-baseline/trivy-scan.json --candidate manual:examples/bc/case00/candidate_cidr_split --scenario demo-split --verification examples/bc/verification/example_all_pass.json --baseline-plan tests/fixtures/plans/00-baseline/plan.json --candidate-plan examples/bc/case00/plan_candidate_cidr_split.json --intent examples/bc/case00/intent.json }
  default  { Write-Host "usage: review_demo.ps1 [manual|mock|split]"; exit 2 }
}
python -m iacpatch metrics --title "data/reviews 집계"
