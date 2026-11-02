# examples/bc — B·C 로컬 검토 흐름 예제 입력·출력

**전부 개발 중 작성한 예제다.** LLM 이 생성한 것도, A 가 실제로 실행한 검증 결과도 아니다.
성능 실험·자연 발생률 자료로 쓰지 않는다. 파이프라인이 입력을 받아 기록·판정·리포트를 만드는지 확인하는 용도다.

| 경로 | 내용 | 출처 표기 |
|---|---|---|
| `manual_candidate_ok/` | 수동 후보 (디렉터리 형식: `main.tf` + `candidate.json`(수정 이유·출처)) — sg-baseline 의 SSH 를 예제 CIDR 203.0.113.0/24 로 제한 | candidate.json 의 provenance |
| `manual_candidate_ok.json` | 같은 후보를 JSON 응답 계약 형식으로 | provenance 필드 |
| `manual_candidate_ok_main.tf` | 같은 후보를 단일 .tf 파일로 (대상 파일 전체 대체). 수정 이유가 없어 needs_info 에 남는다 | `--candidate-note` 로 적는다 |
| `manual_candidate_empty.tf` / `manual_candidate_identical.tf` | 오류 케이스: 빈 후보 / 원본과 동일한 후보 → CANDIDATE_INVALID | — |
| `case00/` | `scenarios/dev/case00-baseline` 용 예제: 정상 수정본(`candidate_fixed/`), 기만적 CIDR 분할(`candidate_cidr_split/`, SEEDED), intent, 파생 plan(`plan_candidate_cidr_split.json` — 01-cidr-split 실제 plan 의 리소스 이름만 바꾼 것) | 각 candidate.json / plan 의 `_iacpatch_note` |
| `verification/example_all_pass.json` | A 검증 결과 **예제** (V1~V4 PASS). 값은 예제이며 실제 실행 결과가 아니다. 리포트의 '결과 출처' 열에 example-fixture 로 표시된다 | source 필드 |
| `verification/example_v1_fail.json` | V1 FAIL 예제 → VALIDATION_FAILED / BLOCKED | source 필드 |
| `verification/broken.json` | 손상 파일 → 오류 기록 후 NOT_RUN 으로 진행 | — |
| `sample_output/01~04` | `iacpatch review` 가 실제로 만든 review.md / pr_body.md / state.json (이 저장소의 코드로 생성) | 각 파일 머리말 |
| `sample_output/metrics.md` | `iacpatch metrics` 집계 표 | — |

## 재현 명령 (WSL / Windows 공통, 도구·API 불필요)

```bash
export PYTHONPATH=src      # PowerShell: $env:PYTHONPATH="$PWD\src"
# 01 검증 대기
python -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \
  --candidate manual:examples/bc/manual_candidate_ok --scenario ex01
# 02 검증 결과 예제 + plan 으로 V5/V6 로컬 계산 → LIGHT_REVIEW
python -m iacpatch review --tf-dir scenarios/dev/case00-baseline --trivy-json scenarios/dev/case00-baseline/trivy-scan.json \
  --candidate manual:examples/bc/case00/candidate_fixed --scenario ex02 --verification examples/bc/verification/example_all_pass.json \
  --baseline-plan tests/fixtures/plans/00-baseline/plan.json --candidate-plan tests/fixtures/plans/00b-baseline-fixed/plan.json --intent examples/bc/case00/intent.json
# 03 기만적 CIDR 분할 → V6 FAIL → BLOCKED
python -m iacpatch review --tf-dir scenarios/dev/case00-baseline --trivy-json scenarios/dev/case00-baseline/trivy-scan.json \
  --candidate manual:examples/bc/case00/candidate_cidr_split --scenario ex03 --verification examples/bc/verification/example_all_pass.json \
  --baseline-plan tests/fixtures/plans/00-baseline/plan.json --candidate-plan examples/bc/case00/plan_candidate_cidr_split.json --intent examples/bc/case00/intent.json
# 04 검증 실패 결과 입력
python -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \
  --candidate mock:sg_baseline_ok --scenario ex04 --verification examples/bc/verification/example_v1_fail.json
python -m iacpatch metrics --title "집계"
```
