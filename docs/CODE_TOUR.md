# 코드 투어 — 파일별 설명과 실행 흐름 (공부용)

처음 보는 팀원이 `iacpatch review` 한 번의 실행을 따라갈 수 있게 쓴 문서다. 프레임워크 없음, 표준 라이브러리만.

## 0. 한 번의 `review` 실행이 지나가는 파일 순서

```
cli.py (review 명령 파싱)
 └─ review/flow.py run_review()
     ├─ review/inputs.py      load_trivy_report → list_findings → select_findings → check_source_consistency
     ├─ evidence.py           read_tf_files (원본 *.tf 읽기 — 수정 안 함)
     ├─ review/candidates.py  CandidateSpec.parse → load_candidate(mock|manual) → validate_candidate_shape
     ├─ policy/validator.py   validate_candidate (경로·보호 파일·금지 토큰·provider 블록)
     ├─ report.py             unified_diff
     ├─ review/verification_input.py  link_verification (A 결과 파일 → LayerResult, 없으면 NOT_RUN; plan 있으면 V5/V6 로컬 계산)
     │     ├─ verify/layers.py v5_plan_diff
     │     └─ verify/v6.py → verify/plan_model.py → verify/sg_oracle.py → verify/netset.py
     ├─ verify/combine.py     combine (PASS / FAIL / INCOMPLETE)
     ├─ review/risk_text.py   diff_hcl → score_risk_text  (+ policy/risk.py score_risk when plan given)
     ├─ review/level.py       decide_review_level
     └─ review/reports.py     render_review → review.md, render_pr_body → pr_body.md
```

## 1. 파일별 설명

### src/iacpatch/ (공통)

| 파일 | 한 줄 설명 | 이번(3~4주차) 역할 |
|---|---|---|
| `cli.py` | 명령 진입점. `findings`, `review`, `metrics` 가 이번에 추가됨 | C |
| `config.py` | 설정(환경변수 > iacpatch.config.json > 기본값). 비밀값은 파일에 못 넣게 막음 | 공통 |
| `models.py` | 모든 데이터 구조. `Verdict.NOT_RUN`, `ReviewState`, `ReviewLevel`, `PatchCandidate.provenance/needs_info` 추가 | B·C |
| `evidence.py` | 원본 *.tf 읽기, Evidence Bundle | B |
| `intent.py` | Intent JSON 로딩·검증 (플레이스홀더·draft·인터넷 전체 승인 거부) | B |
| `report.py` | diff 텍스트, (predeploy 용) PR 본문 | C |
| `metrics.py` | 기록 집계 → 표 | C |
| `pipeline.py` | (지난 세션) 도구를 직접 실행하는 predeploy 흐름. 이번엔 `select_target` 이 중복 finding 을 거부하도록 고침 | 참고 |
| `postdeploy.py` | V7/V8/복구 (코드만, 미실측) | 이후 |

### src/iacpatch/review/ (이번 세션 신설 — B·C 로컬 흐름)

| 파일 | 설명 | 담당 |
|---|---|---|
| `inputs.py` | Trivy JSON 로딩·검증, finding 목록, 엄격 선택(중복이면 거부), 스캔-원본 정합(원인 줄 내용 비교) | B |
| `candidates.py` | mock/manual 후보를 `PatchCandidate` 로. 빈/동일/읽기불가/형식오류/정보부족 판정 | B |
| `verification_input.py` | A 의 검증 결과 파일 → 계층 결과. 없으면 NOT_RUN. 후보 해시 대조. plan 있으면 V5/V6 로컬 계산 | B |
| `risk_text.py` | HCL 텍스트 근거 위험도(잠정). 미확정 항목 표시 | B |
| `level.py` | 검토 수준 판정 (자동 반영 없음) | B |
| `reports.py` | review.md / pr_body.md 템플릿 (한국어) | C |
| `flow.py` | 상태 전환·실행 폴더·전체 연결 | C |

### src/iacpatch/verify/ (검증 계층 — 지난 세션 구현, 이번엔 파일 입력으로 재사용)

| 파일 | 설명 |
|---|---|
| `netset.py` | CIDR 집합 (collapse, 차집합, 포함). 0.0.0.0/1+128.0.0.0/1 = 0.0.0.0/0 |
| `sgmodel.py` | SG 규칙 공통 모델 (plan 과 AWS 실측을 같은 모양으로) |
| `plan_model.py` | plan JSON → 모델. 미확정 값·참조 해석·부착 지점 |
| `sg_oracle.py` | V6 판정 (EXCESS / MISSING / UNKNOWN) |
| `v6.py` | V6 래퍼 | 
| `layers.py` | V1(대상 제거), V2(finding 집합 비교), V3/V4(도구 결과 → 계층), V5(plan 구조 비교) |
| `combine.py` | 종합 (NOT_RUN 은 INCOMPLETE) |

### src/iacpatch/policy/

| 파일 | 설명 |
|---|---|
| `validator.py` | 후보 파일 정책 검사 + HCL 최상위 블록 추출(`extract_top_level_blocks`) |
| `risk.py` | plan 근거 위험도 |
| `gate.py` | (predeploy 용) 게이트 |

### src/iacpatch/generator/ (지난 세션. 이번엔 `base.py` 의 응답 파싱만 재사용)

| 파일 | 설명 |
|---|---|
| `base.py` | 후보 응답 계약·파싱 (잘림/비JSON/스키마 위반) — mock/manual JSON 도 이걸로 읽는다 |
| `llm_providers.py` | mock 과 (미사용) API 제공자. **이번 세션에서 API 호출 코드는 실행되지 않으며 기본 경로가 아니다** |
| `llm_generator.py`, `rule_based.py`, `prompts/` | predeploy 용 |

### 데이터·설정

| 경로 | 설명 |
|---|---|
| `policy/patch_policy.json` | 편집 가능 파일, 보호 경로, 금지 토큰, 허용 리소스 타입, V2 차단 심각도 |
| `policy/risk_rubric.json` | 잠정 위험도 기준표 값 |
| `policy/intent/*.json` | 승인 출처 (예제는 플레이스홀더) |
| `examples/bc/` | 이번 흐름 예제 입력·출력 |
| `scenarios/dev/case00-baseline/` | 예제용 원본 + Trivy JSON |
| `tests/fixtures/` | plan/Trivy/mock/intent fixture |
| `data/reviews/` | review 실행 기록 (git 제외) |

## 2. 상태와 판정을 읽는 법

- `state.json.state`: 마지막 상태. `history` 에 전환 순서. `errors` 에 무엇이 막았는지.
- `state.json.verification_status`: `NOT_LINKED`(결과 파일 없음) / `PENDING`(일부 NOT_RUN·UNKNOWN) / `COMPLETE`(전부 PASS·WARN) / `FAILED`.
- `review.md` 4절 표의 "결과 출처" 열: `example-fixture` 면 예제 값, `A: ...` 면 A 가 돌린 값, `local:v5_plan_diff`/`local:v6_intent_oracle` 면 이 코드가 plan JSON 으로 계산한 값.
- `review_level`: PENDING 이면 검증 결과부터 받아야 한다. LIGHT/FULL 이면 사람 검토, REPORT_ONLY/BLOCKED 면 반영 금지.

## 3. 테스트 읽는 법

- `tests/unit/test_review_flow.py`: 이번 흐름의 통합 테스트 20개 (정상·오류·검증 연결·위험도·반복 실행·집계). 도구 불필요.
- `tests/unit/test_oracle_fixtures.py`: V6 케이스 22개 (fixture plan).
- `tests/unit/test_layers.py`, `test_policy_risk_gate.py`, `test_generators.py`, `test_postdeploy.py`, `test_intent.py`, `test_netset.py`: 모듈 단위.
- `tests/unit/test_pipeline_integration.py`: terraform/trivy 가 있을 때만 (없으면 skip 7).

## 4. 자주 헷갈리는 것

- "review 가 REVIEW_REQUIRED 로 끝났다" ≠ "패치 검증 통과". 검증은 `verification_status` 와 계층 표를 본다.
- mock/manual 후보는 LLM 출력이 아니다. 리포트 3절 '후보 출처' 와 metrics 의 출처 분포가 항상 같이 나온다.
- 위험도 LOW 는 "경량 검토" 이지 "자동 반영" 이 아니다. 이 버전엔 자동 반영 경로가 없다.
- `NOT_RUN` 과 `SKIPPED` 의 차이: NOT_RUN 은 결과 파일이 없는 것, SKIPPED 는 실행 시점에 도구가 없어 못 돌린 것. 둘 다 PASS 가 아니다.
