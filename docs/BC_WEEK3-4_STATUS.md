# B·C 3~4주차 구현 현황 (2026-09-15)

> 구분 규칙: **완료** = 코드 + 테스트 통과 + 이 저장소의 실제 입력(A 의 Trivy JSON·Terraform)으로 실행 확인. **부분** = 코드는 있으나 예제/fixture 로만 확인. **미완료** = 코드 없음 또는 명세만.
> 이번 세션에서 외부 LLM API·Claude Code CLI·AWS·네트워크는 **호출하지 않았다.** mock/manual 후보와 예제 검증 결과는 사람이 만든 것이며 LLM 출력·A 의 실측이 아니다.

## 확인된 입력 (A) — 2026-09-15 재확인

A 의 1~2주차 산출물은 전부 `main` 74a6f38 (2026-09-12) 에 있다. 3~4주차 커밋·브랜치·PR 은 PR #1 외에 없다 (`git ls-remote` 로 확인).

| A 의 파일 | 내용 | B·C 에서 어떻게 썼나 |
|---|---|---|
| `docs/worklog/2026-09-11.md` | 1주차 전체 기록 (TerraProbe 분석, 우회 실험, AWS 구축, CI, 막힌 지점 8건) | 설계 근거로 읽음. 수치 인용은 `docs/DOC_CORRECTIONS.md` 대로 정정 |
| `experiments/trivy-sg-probe/cases/` 9종 + `results/`, `results-verify/` | Trivy 우회 실험 원본과 스캔 JSON (Trivy 0.74.0, 09-08) | `scenarios/eval/a-probe/` 로 byte 동일 복사 → `a-probe-dev` 세트의 원본·입력 스캔. `check_a_results.py` 로 9 케이스 표 **전부 재현** |
| `experiments/trivy-sg-probe/VERIFY.md`, `RESULTS.md` | A/B/C 3단계 검증 기록, 결과 표 | 케이스별 대상 SG 주소를 intent 에 옮김 |
| `infrastructure/sg-baseline/` + `baseline-scan.json` | 의도적 결함 Terraform + 스캔 원문 | 검토 흐름 통합 테스트의 기본 입력 |
| `.github/workflows/iac-scan.yml` | CI (Trivy 스캔) | 손대지 않음. `bc-unit-tests.yml` 은 별도 |
| `README.md`, `한장요약.md`, `criticism and rebuttal.md`, `RoadMap.md` | 계획·요약·예상 질문 | 제목·인용 정정 외 유지 |
| PR #1 (krk1206, 09-12) | RDP 개방 SG 추가 — CI 트리거 테스트 | `scenarios/dev/pr1-two-defects/` (0107 ×2 = 실제 중복 finding 케이스) |
| A 의 후보별 V1~V4 결과 파일 | 없음 (후보가 아직 A 에게 간 적이 없으니 당연) | `--local-tools` 로 대체 가능 — trivy/terraform 이 있는 컴퓨터에서 검토 흐름이 직접 돌림 |
| AGENTS.md / 첨부 자료 | 없음 | — |

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
| 통합 테스트 9종 (정상/없음/중복/JSON 오류/후보 누락·빈 파일/검증 없음/검증 실패/근거 부족/반복 실행) | 완료 | `tests/unit/test_review_flow.py` 26개 |
| fixture PASS 출처 표시 | 완료 | 계층마다 `details.result_source`, 리포트 '결과 출처' 열 |
| 로컬 테스트 명령 | 완료 | `scripts/run_tests.sh` / `.bat` (148 테스트, 도구 없으면 7 skip) |
| 네트워크·키 없는 CI 워크플로 | 부분 | `.github/workflows/bc-unit-tests.yml` 작성. **GitHub 에서 미실행** (push 안 함). A 의 iac-scan.yml 유지 |
| 집계 (`iacpatch metrics --labels`) | 완료 | `metrics.py`: 출처별(E1)·오라클 유무(E2) 수치, 라벨 있을 때만 일치율 |
| 후보 세트 일괄 실행 + 규칙 기반 후보 출처 | 완료 | `scripts/run_candidate_set.py`, `--candidate rule_based`, `experiments/candidate-sets/example-dev/` (개발용 예제), `docs/EXPERIMENT_GUIDE.md` |
| 후보별 오프라인 plan JSON 생성 스크립트 | 부분 | `scripts/make_plan.sh` — 셸 로직만 stub 으로 확인. 샌드박스는 provider 다운로드가 막혀 실제 plan 생성 미확인 |
| `review --local-tools` (V1~V4 로컬 실행 + plan 생성 → V5/V6) | 부분 | `review/local_verify.py`. **Trivy 0.74.0 으로 V1/V2 실측 확인** (A 케이스 4건, 입력 스캔과 키 집합 동일). V3/V4 는 provider 차단으로 ERROR 기록만 확인 — terraform+provider 있는 WSL 에서 확인 필요. 테스트 3종 (도구 없음→NOT_RUN, stub 스캐너→V1/V2, 파일 우선) |
| A 의 9 케이스 세트 (`a-probe-dev`) | 완료(개발용) | `experiments/candidate-sets/a-probe-dev/` — A 결과 표 재현 확인(`A_RESULTS_CHECK.md`), 규칙 기반 후보 4/9 생성, 우회 원본 2건 NO_FINDING, 미지원 3건. 승인 CIDR 예제값 → 발표 수치 아님 |
| 텍스트 단계 리소스 블록 정책 (허용 밖 타입 생성·삭제·허용 밖 타입 변경 차단, plan 없이) | 완료 | `policy/validator.py::_resource_block_checks`. seeded prefix-list 패치·리소스 삭제 패치가 POLICY_BLOCKED. 차단돼도 텍스트 위험도는 기록 |
| 평가용 세트 3종 (expected 고정) | 완료(샌드박스 부분 실행) | `eval-a-probe-rule`(A 9 케이스 × 규칙 기반), `eval-seeded-sg`(00-baseline × seeded 11), `eval-claude-code`(뼈대 + prompt.md, 후보 0건). 결과는 `results-history/` 에 환경별 누적 |
| 결정 기록 | 완료 | `docs/DECISIONS.md` — 제목(D-1), 평가용 승인 출처 10.0.0.0/8(D-2), dev/eval 구분(D-3), 라벨 정정 규칙(D-4) |
| 혼자 실험 키트 | 완료(샌드박스 실행 확인) | `docs/SOLO_RUNBOOK.md`, `scripts/setup_tools.{sh,ps1,bat}`, `scripts/run_experiments.{sh,ps1,bat}`, `scripts/summarize_experiments.py` → `experiments/RESULTS_SUMMARY.md`, `scripts/cc_prompt.py`(프롬프트 7개 생성) / `scripts/cc_add.py`(응답 등록·diff 확인). .sh 경로는 샌드박스에서 끝까지 실행(50초). **.ps1/.bat 는 Windows 가 없어 미실행** |
| V5·V8 완전 연결 / 비교 실험 | 미완료(명세) | `docs/IO_SPEC_A_B_C.md` 4절 |

## 실제로 실행한 것 / 하지 않은 것

| | |
|---|---|
| 실행 | 단위·통합 테스트 148개 (샌드박스, Python 3.11, 외부 도구 없이 → 7 skip). `iacpatch review` 예제 4건 + PR #1 케이스. `iacpatch metrics`. Trivy 0.74.0 으로 PR #1 사본 스캔(fixture 생성 목적). **Trivy 0.74.0 으로 A 의 9 케이스 재스캔(전부 A 결과와 동일) + eval-a-probe-rule·eval-seeded-sg 세트 V1/V2 실측** (seeded: CIDR 2분할·4분할·승인 밖 대역·규칙 삭제·포트 변경이 Trivy 를 통과함을 실측, ipv6 ::/0 은 Trivy 가 잡음) |
| mock 으로만 확인 | 후보 생성 (mock/manual 전부 사람 작성), V1~V4 값(예제 파일) |
| 외부 연결 없어 확인 못 함 | 실제 LLM 후보, terraform plan (OpenTofu 1.10.6 은 있으나 provider 레지스트리가 차단됨 → V3/V4 ERROR, V5/V6 NOT_RUN), AWS(V7/V8), GitHub Actions 실행, PR 게시 |

## 5주차 이후

1. A: WSL(Terraform 1.16.1 + trivy) 에서 `eval-a-probe-rule` 과 `eval-seeded-sg` 두 세트를 실행 → V3~V6 가 채워지는지, expected 대비 일치 건수 (샌드박스에서는 V6 미실행이라 correct/deceptive/breaks_required 가 전부 '확인 못 함'). 따로 결과 JSON 스크립트를 만들 필요 없음 (`--local-tools` 가 그 역할)
2. 팀: D-1(제목)·D-2(승인 출처 10.0.0.0/8) 확인. 이의가 있으면 `docs/DECISIONS.md` 에 새 항목으로
3. B: 실제 후보 공급자(사람이 Claude Code 등으로 만든 파일을 `manual:` 로 넣는 방식이 지도교수 지시에 맞음) — 20~30건 모아 `metrics` 로 집계
4. C: bc-unit-tests.yml 첫 실행 확인, V5 상태 기준 plan 연결, V8 체크 정의
5. 팀: 위험도 기준표 고정 (`RISK_RUBRIC_DRAFT.md` 4절 결정 사항)
