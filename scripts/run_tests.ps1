# Windows PowerShell: 단위 테스트 + (도구 있으면) 통합 테스트
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location "$Root\tests\unit"
$env:PYTHONPATH = "$Root\src"
python -m unittest discover -s . -p "test_*.py" -v
