# plan-pairs — 라벨(expected_risk)이 있는 후보 22건의 원본/후보 plan JSON 쌍

`data/reviews/<기록>/local_verify/{plan_baseline,plan_candidate}.json` 을 그대로 복사한 것 (2026-09-28). `data/reviews/` 는 git 에 안 올라가므로,
**terraform 없이도** 위험도 기준표(V5 → 점수 → 등급)와 V6 오라클을 같은 입력으로 다시 계산할 수 있게 여기 둔다.

- 생성 도구: `meta.json` 의 `tools` (샌드박스 OpenTofu 1.10.6 + AWS provider 5.100.0, 오프라인 plan). 팀 PC Terraform 1.16.1 실행에서도 판정이 38/38 같았다 (`experiments/candidate-sets/*/results-history/*-DESKTOP-TSH8UUD.md`).
- 원본 .tf = manifest 의 `tf_dir`, 후보 .tf = manifest 의 `candidate` (`experiments/candidate-sets/<set>/candidates/`). plan 쌍은 그 두 개를 plan 한 결과다.
- 라벨 25건 중 3건(`deceptive-prefix-list`, `deceptive-second-policy`, `unapproved-managed-policy`)은 정책 위반(POLICY_BLOCKED)이라 plan 을 만들지 않았고 텍스트 근거 위험도만 있다 → 여기 없음. `iacpatch.rubric_demo.labeled_matrix()` 가 그 3건은 텍스트 근거로 계산한다 (실제 흐름과 같음).
- 쓰는 곳: `src/iacpatch/rubric_demo.py` (웹 화면 4주차 탭), `tests/unit/test_rubric_demo.py` (도구 없는 CI 에서 등급 일치율 재계산).
- 바꾸지 않는다. 후보나 원본이 바뀌면 `scripts/run_candidate_set.py` 로 다시 돌리고 새 기록에서 다시 복사한다.
