# pr1-two-defects — A 의 PR #1 (krk1206, 2026-09-12 "test: PR 트리거 확인용 RDP 개방 SG 추가") 사본

`git show refs/pull/1/head:infrastructure/sg-baseline/*` 를 그대로 복사한 것. SSH(22) 와 RDP(3389) 가 모두 0.0.0.0/0 에 열려 있어
**같은 룰(AVD-AWS-0107)의 finding 이 2개** 나온다. B 의 대상 선택이 임의로 첫 항목을 고르지 않는지 확인하는 실제 케이스.

`trivy-scan.json` 은 이 디렉터리를 Trivy 0.74.0(내장 체크, 샌드박스, 2026-09-15)으로 스캔한 결과다 — A 의 CI 아티팩트가 아니다.

    python -m iacpatch findings --trivy-json scenarios/dev/pr1-two-defects/trivy-scan.json --rule AVD-AWS-0107
    # → 2건 일치 → review 에서 --resource aws_security_group.vulnerable_ssh 또는 --line 11 로 지정
