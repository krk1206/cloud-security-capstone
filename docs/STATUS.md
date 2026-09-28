# 구현 현황 (2026-09-13 기준)

> 2026-09-15 B·C 3~4주차 작업(도구·API 없이 파일 입력만으로 동작하는 `iacpatch review` 흐름)은 [`BC_WEEK3-4_STATUS.md`](BC_WEEK3-4_STATUS.md) 에 따로 정리했다.

"실제로 실행한 것" 과 "코드는 있으나 실행하지 못한 것" 을 구분한다. mock 성공은 API 연동 성공이 아니고, 스캐너 통과는 보안 검증 성공이 아니다.

## 완료 (코드 + 테스트 + 샌드박스 실행 확인)

| 항목 | 위치 | 실행 근거 |
|---|---|---|
| Trivy 스캔 어댑터 + finding 파싱 | `tools/trivy.py` | Trivy 0.74.0 실제 실행 (`data/runs-sample/*/run.json`) |
| Terraform 어댑터 (init/fmt/validate/plan/show -json, 오프라인 override) | `tools/terraform.py` | 샌드박스는 **OpenTofu 1.10.6 + AWS provider 5.100.0** (릴리스 서버 차단). 팀 PC 에서 **Terraform 1.16.1** 로 4세트 38건 재실행(2026-09-22 16:12, `results-history/*-DESKTOP-TSH8UUD.md`) → 상태·검토 수준·위험도·V1~V6 판정이 샌드박스 기록과 38/38 동일 |
| Intent Spec 로딩/검증 (플레이스홀더·draft·인터넷 전체 승인 거부) | `intent.py` | `test_intent.py` |
| Evidence Bundle | `evidence.py` | 통합 테스트 |
| LLM 응답 계약·파싱 (잘림/비JSON/스키마 위반 → GENERATION_FAILED) | `generator/base.py` | `test_generators.py`, matrix |
| Mock 제공자 (키 없이 실행) | `generator/llm_providers.py` | matrix 17종 |
| Rule-based baseline 생성기 | `generator/rule_based.py` | `test_generators.py`, matrix |
| Policy Validator (경로/보호 파일/금지 토큰/provider 블록/파일 수) | `policy/validator.py` | `test_policy_risk_gate.py`, matrix(edits_provider) |
| V1 대상 finding 제거 / V2 finding 집합 비교 | `verify/layers.py` | `test_layers.py` (실제 Trivy JSON fixture) |
| V3 validate / V4 plan | `verify/layers.py` | 통합 테스트 (tofu) |
| V5 plan 구조 비교 (삭제/교체/허용 밖 타입·속성/개수/provider) | `verify/layers.py` | `test_layers.py`, matrix |
| **V6 Intent Oracle** (집합 계산, v4/v6 분리, 방향·프로토콜·포트, prefix list 전개, 참조 SG 비상속, ENI 합산, UNKNOWN) | `verify/netset.py`, `plan_model.py`, `sg_oracle.py` | `test_oracle_fixtures.py` 22 케이스 (실제 plan JSON), matrix |
| Risk Rubric Scorer (결정론적, hard condition) | `policy/risk.py`, `policy/risk_rubric.json` | `test_policy_risk_gate.py` |
| Gate (검증/위험도 별도 축, LLM 하향만) | `policy/gate.py` | `test_policy_risk_gate.py`, matrix(ok_propose_low) |
| 오케스트레이터 + 재시도 루프 + 실행 기록 + PR 본문 | `pipeline.py`, `runrecord.py`, `report.py` | 통합 테스트 7종, matrix 17종 |
| CLI (selfcheck/scan/predeploy/oracle/pr/postdeploy/recover) | `cli.py` | predeploy/oracle/selfcheck 실행 확인 |
| 테스트 fixture (plan 23종 + Trivy 23종 + mock 응답 16종 + intent 2종) | `tests/fixtures/` | `scripts/generate_fixtures.sh` 로 재생성 가능 |
| 문서 정정 (TerraProbe 분모, validate, S3, 00-baseline 오해) | `docs/DOC_CORRECTIONS.md` + README/한장요약/criticism 최소 수정 | arXiv 원문 대조 |

## 부분 구현 (코드는 있으나 이 환경에서 실행하지 못함)

| 항목 | 위치 | 상태 | 필요한 것 |
|---|---|---|---|
| 실제 LLM API 제공자 (anthropic / openai / openai_compatible) | `generator/llm_providers.py` | 코드 작성, **미실행**. 키 없음·제공업체 미정. 키 없이 호출하면 error 로 끝나는 것만 확인 | 제공업체 결정 + 키(환경변수) + 첫 실행 기록 |
| V7 AWS 실측 (describe-security-groups / network-interfaces / prefix-list 전개 → 오라클) | `postdeploy.py`, `tools/awscli.py` | 코드 + FakeCli 단위 테스트. **실제 AWS 미호출** | 샌드박스 apply 후 `postdeploy --execute` (사람 승인) |
| V8 통신 확인 (허용 성공 + 승인 밖 vantage 에서 실패) | `postdeploy.py` | 로컬 소켓 단위 테스트만. 실제 인스턴스 없음. 체크 정의 예시 `policy/intent/sg-baseline.v8.example.json` (09-22) | EC2 인스턴스 + 승인 밖 관측 지점(예: 별도 SG 의 임시 EC2, 핫스팟) + 체크 JSON |
| 복구 절차 (파일 복원 → plan → apply → 수렴 확인 + describe 기록) | `postdeploy.run_recover` | 미리보기 모드만 실행. 09-22: `--review <id>` 로 실험 기록의 `original/` 에서 복원 가능(단위 테스트) | 샌드박스에서 `--execute` (사람 승인) |
| 배포 후 결과를 실험 기록에 연결 (`postdeploy --review`) | `postdeploy.py` | 09-22 구현. FakeCli 로 VERIFIED / DEPLOY_FAILED / UNVERIFIED 경로 단위 테스트. metrics 표에 V7/V8/배포후 열. **실제 AWS 실행 0회** | A 가 sandbox apply 후 `--execute` |
| 위험도 기준표 | `policy/risk_rubric.json` risk-v2, `docs/RISK_RUBRIC_V2.md` | 2026-09-22 확정안. 등급 일치율(손 적용 vs 코드) 25/25 (샌드박스 4세트). 팀 OK 후 고정 | 팀 확인 |
| PR 생성 (브랜치/커밋/push/REST) | `tools/github.py` | 미리보기 모드(명령 출력)만 실행. push 미실행. 2026-09-22: `--review <id>` 로 실험 기록(data/reviews)도 받음 — LIGHT/FULL_REVIEW 만 허용, 단위 테스트 4건 | 저장소 권한 + `--execute` (사람) |
| GitHub Actions `iacpatch-verify.yml`(단위 테스트 + 후보 세트 4개 실측 + PR 댓글) / `build-exe.yml`(Windows exe) | `.github/workflows/` | 2026-09-28 작성 (`bc-unit-tests.yml`·`patch-verify.yml` 을 대체). **Actions 첫 실행은 push 뒤** | 첫 실행 결과를 `docs/CI_FIRST_RUN.md` 에 기록 |
| 온라인 plan (상태 기준, `plan_actions_delete/replace` 실측) | `tools/terraform.py --online` | 오프라인만 실행 | AWS 프로필 |

## 미완료

| 항목 | 이유 / 계획 |
|---|---|
| IAM 과다 권한 시나리오 | **Tier 1 배포 전 슬라이스 구현·실측 (2026-09-22)**: 대상 룰 AVD-AWS-0345, IAM intent(D-7), IAM Intent Oracle(V6), 규칙 기반 IAM 분기, seeded 13 + 규칙 기반 5 (`docs/IAM_SCOPE.md` 머리). 배포 후 V7(IAM 실측)은 미구현 |
| S3 / 컨테이너 CVE / EKS / 대시보드 | 계획대로 핵심 흐름 완성 전 착수하지 않음 |
| Rule-based vs LLM 생성 비교 실험, Oracle 유무 검증 효과 비교 | 실험 경로는 갖춰짐(`--generator rule_based`, `scripts/run_fixture_matrix.py`). 실제 LLM 출력이 있어야 시작 가능. 개발용(`scenarios/dev`)·평가용(`scenarios/eval`) 분리 폴더만 마련 |
| MTTR(사람 승인 대기 제외 자동 처리 시간) 측정 | `timings.json` 에 단계별 시간이 기록되지만(예: 샌드박스에서 predeploy 약 36초, 그중 plan 2회 34초) 실제 LLM/AWS 단계가 없어 수치로 쓸 수 없음 |
| Terraform 1.16.1 로 fixture 재생성 및 결과 비교 | 팀 WSL 에서 `scripts/generate_fixtures.sh` 실행 후 diff |
| CIS 매핑 원문 확인 | `policy/cis_mapping.json` verified=false |

## 안전 기준 (README 14.2) 준수 여부 — 이 환경

- 승인 없는 `terraform apply` 자동 실행: 0건 (코드 경로 없음; recover --execute 만 사람 명령)
- 프로덕션 계정 실행: 0건 (AWS 미접속)
- 정책 위반 패치 병합: 0건 (병합 기능 없음)
- 무인 apply 가 샌드박스 밖에서 실행: 0건

## 이 문서를 읽고 바로 할 일 (팀)

1. WSL 에서 `scripts/run_tests.sh` → 116 테스트 통과 확인 (Terraform 1.16.1 로 통합 테스트 7종 포함)
2. `policy/intent/sg-baseline.json` 작성 (승인 CIDR 은 팀 결정)
3. (2026-09-15 지도교수 지시) 유료 LLM API 대신 **Claude Code** 로 패치 후보를 만든다 → 렌더링된 프롬프트(bundle)를 Claude Code 에 주고 응답 JSON 을 파일로 받는 `file` 제공자 + `prompt` 덤프 명령 추가가 다음 구현 항목. API 제공자 코드(anthropic/openai)는 유지하되 기본 경로가 아니다
4. 샌드박스 apply(사람) → `postdeploy --execute` 로 V7 첫 실측 → 06-prefix-list 배포 후 확인(부록 A 항목)
