# B 가 자기 말로 설명해야 하는 것 — 위험도 기준표 · 상한 · 게이트 (4주차) 와 후보 → PR 흐름 (5주차)

교수 9/28: "AI 가 만들어 준 것은 공격받기 쉬운 포인트다. 본인이 내용을 숙지하고 설명할 수 있어야 한다."
이 문서는 코드를 **읽는 순서**와 **연습 과제**다. 코드는 AI 초안(커밋 메시지에 Co-Authored-By 표기)이고, 아래 과제를 B 가 직접 해서 커밋을 남기면 그때부터 "B 가 설명할 수 있는 코드" 가 된다.

## 1. 한 문장씩

- **위험도(Risk)** 는 "이 변경이 잘못됐을 때 얼마나 크게 터지나" 다. 코드가 plan 의 사실(바뀐 리소스 수, 삭제/교체 여부, IAM 여부, 붙은 인스턴스 수…)로만 정한다. LLM 의 말은 입력이 아니다.
- **자율성 상한(Autonomy cap)** 은 위험도에서 기계적으로 나온다: LOW → HIGH, MEDIUM → MEDIUM, HIGH → LOW. "자율성 HIGH" 는 "안전하다" 가 아니라 "PR 을 자동으로 열어도 되는 범위" 라는 뜻이고, 그래도 apply 는 사람이 한다.
- **LLM 제안(proposed_autonomy)** 은 낮추는 방향으로만 반영된다. 상한보다 높게 제안하면 무시하고 기록에 남긴다.
- **게이트(Gate)** 는 검증 축(V1~V6 PASS/FAIL/미완)과 위험도 축을 합쳐 동작을 정한다. 정책 위반·검증 실패는 등급과 무관하게 차단. 검증이 덜 끝났으면 보류.
- **검토 수준(Review level)** 은 같은 것을 사람 말로 바꾼 것: LIGHT_REVIEW(사람 1인 확인) / FULL_REVIEW(승인 필수) / REPORT_ONLY(반영 금지) / BLOCKED / PENDING.

## 2. 코드 읽는 순서 (30분)

| 순서 | 파일 | 무엇을 보나 |
|---|---|---|
| 1 | `policy/risk_rubric.json` | 점수 항목·임계값(≤2 LOW, ≤5 MEDIUM)·hard HIGH 조건·medium floor. **숫자는 여기가 원본** |
| 2 | `src/iacpatch/policy/risk.py` `score_risk()` | 위 JSON 을 그대로 계산하는 함수. 입력 5개: V5 details(plan 차이), world(SG 부착 지점), diff_stats, V6 details, target_type. 위에서 아래로 한 번 읽으면 된다 (170줄) |
| 3 | `src/iacpatch/models.py` `RISK_TO_AUTONOMY_CAP`, `AUTONOMY_ORDER` | 위험도 → 상한 표. 세 줄 |
| 4 | `src/iacpatch/policy/gate.py` `decide()` | 정책 → 검증 → 상한 vs 제안 순서. 제안이 상한보다 높으면 `ignored (cap enforced)` 문장이 기록에 남는다 |
| 5 | `src/iacpatch/review/level.py` | 게이트를 검토 수준으로. 왜 '자동 반영' 이 없는지 docstring |
| 6 | `src/iacpatch/review/risk_text.py` | plan 이 없을 때(정책 차단 등) HCL 텍스트만으로 잠정 판정. 미확정 항목은 `undetermined` 로 남긴다 — 텍스트로 확정하지 않는다 |
| 7 | `src/iacpatch/rubric_demo.py` | 화면 4주차 탭의 계산. `labeled_matrix()` 가 라벨 25건을 실제 `run_review` 로 다시 돌린다 (도구 없이 plan 쌍만으로) |
| 8 | `src/iacpatch/review/flow.py` `run_review()` | 5주차: 입력 → 후보 → 정책 → 검증 연결 → 위험도 → 검토 수준 → review.md/pr_body.md. 상태 전환 이름을 외우면 화면의 결과가 읽힌다 |
| 9 | `src/iacpatch/tools/github.py` `prepare_pr()` | PR 미리보기: LIGHT/FULL_REVIEW 만 PR 이 되고, BLOCKED/PENDING 은 거부. `--execute` 없이는 명령만 만든다 |

## 3. 연습 과제 (직접 손으로, 커밋 남기기)

1. **라벨 25건 손 검산** — `experiments/candidate-sets/*/manifest.json` 의 `expected_risk` 를 `docs/RISK_RUBRIC_V2.md` 표만 보고 하나씩 다시 매긴다. 맞으면 그 항목에 `"expected_risk_verified_by": "B 2026-10-0X"` 를 적는다. 화면 4주차 탭의 "사람 손 검산 0/25" 가 올라간다. (지금은 B 의 Claude 세션이 적은 값이라 0/25 다 — 이게 정직한 현재 상태다.)
2. **임계값 실험** — `risk_rubric.json` 의 `low_max` 를 2 → 1 로 바꾸고 `python -m unittest tests.unit.test_rubric_demo` 를 돌려 어느 케이스가 뒤집히는지 본다. 결과를 적고 원래대로 되돌린다. (질문: 왜 `05-separate` 가 1점인가?)
3. **강제 하향 재현** — 화면 4주차 ⑤ 에서 위험도 MEDIUM + 제안 HIGH → 최종 MEDIUM 을 확인하고, `gate.py` 의 어느 줄이 그걸 하는지 줄 번호를 적는다.
4. **화이트리스트 결정 8건** — `docs/WHITELIST_VS_POLICY.md` 6절의 결정 항목을 팀 회의에 가져가 하나씩 결정한다. 결정되면 `policy/patch_policy.json` 의 `policy_version` 을 올린다.
5. **후보 하나 끝까지** — 화면 5주차 탭에서 `eval-seeded-sg/correct-approved` 를 돌리고 "PR 미리보기" 까지 만든 뒤, `data/reviews/<id>/pr_commands.sh` 를 읽고 각 줄이 무엇을 하는지 적는다. 실제 push 는 팀 회의 뒤.

## 4. 교수가 물을 것 (답 핵심)

- "왜 이 점수표인가?" → 항목은 TerraProbe 3.11절 방어책 3(고권한·범위 조작은 사람 검토) + 우리 실측(부착 지점·외부 SG 가 있을 때 오라클이 UNKNOWN 이 되던 케이스 13·17)에서 왔다. 임계값 2/5 는 **우리가 정한 값**이고, 라벨 25건에서 세 등급이 다 나오게 조정했다 — 다른 값이 틀렸다는 뜻이 아니다.
- "AI 가 자기 등급을 올릴 수 있나?" → 없다. `gate.decide()` 는 제안이 상한보다 높으면 버린다. 72 조합 전수 검사(`cap_enforcement_check`)가 CI 에서 매번 돈다.
- "High 면 자동 apply 인가?" → 아니다. High 자율성은 "PR 자동 생성 + 병합 전 경량 확인" 까지고 apply 는 항상 사람이다 (D-5).
- "기준표가 맞는지 어떻게 아나?" → (1) 라벨 25건 vs 코드 25/25 — 단, 라벨을 AI 세션이 적었으니 B 의 손 검산이 끝나야 사람 검산이다. (2) 화이트리스트 v0.2(A) 와의 대조표에서 다른 점 8건을 공개해 뒀다.
