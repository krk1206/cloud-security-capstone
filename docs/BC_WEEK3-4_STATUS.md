# B·C 3~4주차 구현 현황 (2026-09-15)

> 구분 규칙: **완료** = 코드 + 테스트 통과 + 이 저장소의 실제 입력(A 의 Trivy JSON·Terraform)으로 실행 확인. **부분** = 코드는 있으나 예제/fixture 로만 확인. **미완료** = 코드 없음 또는 명세만.
> 이번 세션에서 외부 LLM API·Claude Code CLI·AWS·네트워크는 **호출하지 않았다.** mock/manual 후보와 예제 검증 결과는 사람이 만든 것이며 LLM 출력·A 의 실측이 아니다.

## 확인된 입력 (A)

| 항목 | 상태 |
|---|---|
| GitHub `main` | 74a6f38 (2026-09-12). 3~4주차 커밋 없음 |
| PR #1 (krk1206, 09-12) | RDP 개방 SG 추가 — CI 트리거 테스트. `scenarios/dev/pr1-two-defects/` 로 복사 (0107 ×2 = 실제 중복 finding 케이스) |
| A 산출물로 실제 쓴 것 | `infrastructure/sg-baseline/*.tf` + `baseline-scan.json`(Trivy 0.74.0 원문) |
| A 의 V1~V4 검증 결과 파일 | **없음** → 리포트에 NOT_RUN(검증 대기). 형식은 `docs/IO_SPEC_A_B_C.md` 1-3 |
| AGENTS.md / 첨부 자료 | 없음 |

## B — 3주차

| 항목 | 상태 | 위치 / 근거 |
|---|---|---|
| Trivy JSON 로딩·구조 검증 (손상/형식/없음) | 완료 | `review/inputs.py`, `test_review_flow::test_invalid_trivy_json` |
| finding 목록·대상 선택 (룰/파일/리소스/줄), **중복이면 거부** | 완료 | `iacpatch findings`, `test_duplicate_findings_are_not_auto_picked`, `test_pr1_real_duplicate_findings` (A 의 PR #1 실제 케이스) |
| 대상/기타 finding 구분, 필수 정보 누락 처리 | 완료 | `required_fields_missing`, review.md 1절 |
| 스캔-원본 동일 시점 확인 | 부분 | 원인 줄 내용 비교(강) + mtime(참고). 다른 줄 변경은 못 잡음 → A 의 `source_commit` 필요 (기록만) |
| mock/manual 후보 공통 형식 (`PatchCandidate`: 원본·대상·finding·후보·이유·추가정보·출처) | 완료 | `review/candidates.py`, 3 형식(.json/.tf/디렉터리) 테스트 |
| 후보 검사: 빈/동일/읽기불가/형식오류/정보부족 | 완료 | `validate_candidate_shape`, 테스트 |
| LLM 공급자 교체 인터페이스 | 부분 | `PatchCandidate` 를 돌려주는 함수 하나면 됨. API 호출 코드는 지난 세션 것이 남아 있으나 **이번 경로에서 사용·실행되지 않음** |
| 실행 폴더 기록 (원본 사본·후보·diff·finding·출처·상태·오류·검증 여부) | 완료 | `data/reviews/<id>/`, `test_normal_mock_creates_records_and_reports`, `test_repeated_runs_keep_previous_records` |
| 템플릿 설명 리포트 ("AI 분석" 아님) | 완료 | `review/reports.py`, review.md 에 "모델이 분석한 결과가 아니다" 고정 문구 |

## B — 4주차

| 항목 | 상태 | 위치 / 근거 |
|---|---|---|
| 검증 상태 / 위험도 / 검토 수준 분리 | 완료 | `verify/combine.py`, `review/risk_text.py`, `review/level.py` |
| 잠정 위험도 기준표 (항목·조건·이유 문서) | 완료(잠정) | `policy/risk_rubric.json`, `docs/RISK_RUBRIC_DRAFT.md` — 팀 합의 전 |
| 텍스트 근거 위험도 (삭제 의심·타입 변경·교체 유발 속성·리소스 밖 블록) + **미확정 항목 표시** | 완료 | `diff_hcl`, `score_risk_text`, 테스트 3종 |
| plan 근거 위험도 (있을 때 우선) | 부분 | `policy/risk.py` 재사용. fixture plan 으로만 확인 |
| "위험도 LOW ≠ 자동 반영" | 완료 | `ReviewLevel` 에 자동 반영 없음. LOW → LIGHT_REVIEW |
| Intent Oracle 명세 (입력·승인 출처·PASS/FAIL/UNKNOWN·지원 범위·테스트 계획) | 완료(문서) | `docs/INTENT_ORACLE_PLAN.md` |
| Intent Oracle 코드 | 부분 | 지난 세션 구현 + fixture 테스트 22종 통과. **A 의 실제 plan·AWS 로 실측 안 됨** → "fixture 로 구현 확인" 이지 완료 아님 |

## C — 3주차

| 항목 | 상태 | 위치 / 근거 |
|---|---|---|
| 한 명령 로컬 통합 (`iacpatch review`) | 완료 | `review/flow.py`, `scripts/review_demo.*` |
| A 결과 재사용 (Trivy JSON 원문·Terraform 원본) | 완료 | 변환 없이 그대로 읽음 |
| A 검증 결과 연결 (파일) / 없으면 검증 대기 | 완료(형식) | `verification_input.py`. A 의 실제 결과 파일은 아직 없음 → 예제로만 확인 |
| review.md / pr_body.md (대상·이유·diff 위치·출처·검증별 상태·위험도 근거·확인 항목·미확인) | 완료 | `examples/bc/sample_output/` |
| "검증 대기" 눈에 띄게 | 완료 | 배너 + 표 + 미확인 사항 |

## C — 4주차

| 항목 | 상태 | 위치 / 근거 |
|---|---|---|
| 상태 전환 (INPUT_READY→CANDIDATE_READY→VALIDATION_PENDING→REVIEW_REQUIRED + 오류/실패/정보부족) | 완료 | `models.ReviewState`, `state.json.history` |
| 통합 테스트 9종 (정상/없음/중복/JSON 오류/후보 누락·빈 파일/검증 없음/검증 실패/근거 부족/반복 실행) | 완료 | `tests/unit/test_review_flow.py` 21개 |
| fixture PASS 출처 표시 | 완료 | 계층마다 `details.result_source`, 리포트 '결과 출처' 열 |
| 로컬 테스트 명령 | 완료 | `scripts/run_tests.sh` / `.bat` (137 테스트, 도구 없으면 7 skip) |
| 네트워크·키 없는 CI 워크플로 | 부분 | `.github/workflows/bc-unit-tests.yml` 작성. **GitHub 에서 미실행** (push 안 함). A 의 iac-scan.yml 유지 |
| 집계 (`iacpatch metrics --labels`) | 완료 | `metrics.py`: 출처별(E1)·오라클 유무(E2) 수치, 라벨 있을 때만 일치율 |
| 후보 세트 일괄 실행 + 규칙 기반 후보 출처 | 완료 | `scripts/run_candidate_set.py`, `--candidate rule_based`, `experiments/candidate-sets/example-dev/` (개발용 예제), `docs/EXPERIMENT_GUIDE.md` |
| V5·V8 완전 연결 / 비교 실험 | 미완료(명세) | `docs/IO_SPEC_A_B_C.md` 4절 |

## 실제로 실행한 것 / 하지 않은 것

| | |
|---|---|
| 실행 | 단위·통합 테스트 137개 (샌드박스, Python 3.11, 외부 도구 없이 → 7 skip). `iacpatch review` 예제 4건 + PR #1 케이스. `iacpatch metrics`. Trivy 0.74.0 으로 PR #1 사본 스캔(fixture 생성 목적) |
| mock 으로만 확인 | 후보 생성 (mock/manual 전부 사람 작성), V1~V4 값(예제 파일) |
| 외부 연결 없어 확인 못 함 | 실제 LLM 후보, A 의 실제 V1~V4 결과, Terraform 1.16.1 plan, AWS(V7/V8), GitHub Actions 실행, PR 게시 |

## 5주차 이후

1. A: V1~V4 결과를 `verification-v1` JSON 으로 내는 스크립트 (+ `candidate_sha256`, `source_commit`)
2. 팀: `policy/intent/sg-baseline.json` 승인 CIDR 확정 → V6 실측
3. B: 실제 후보 공급자(사람이 Claude Code 등으로 만든 파일을 `manual:` 로 넣는 방식이 지도교수 지시에 맞음) — 20~30건 모아 `metrics` 로 집계
4. C: bc-unit-tests.yml 첫 실행 확인, V5 상태 기준 plan 연결, V8 체크 정의
5. 팀: 위험도 기준표 고정 (`RISK_RUBRIC_DRAFT.md` 4절 결정 사항)
