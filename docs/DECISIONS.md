# 결정 기록 (누가·언제·무엇을·왜)

실험 결과를 보고 기준을 바꾸지 않기 위해, 실행 전에 정한 것을 여기에 남긴다. 바꾸면 새 항목을 추가하고 이전 항목은 지우지 않는다.

| ID | 날짜 | 결정 | 근거 / 비고 | 결정자 |
|---|---|---|---|---|
| D-1 | 2026-09-15 | 제목: **LLM이 생성한 AWS IaC 보안 수정의 실효성 검증 시스템 구현** (영문: Implementation of an Effectiveness Verification System for LLM-Generated AWS IaC Security Fixes) | 지도교수 지시(하는 일이 드러나고 동사로 끝날 것) + 팀 의견(짧게, '파이프라인' 빼고, 핵심은 검증). 대안 "…실효성 검증 및 위험도 기반 승인 구현"(38자) 은 보류. 이전 긴 제목은 README 주석에 이력으로 남김 | B (팀 확인 필요) |
| D-2 | 2026-09-15 | 평가용 승인 출처 = `10.0.0.0/8` (SSH 22). RDP 3389 는 승인 출처 없음(규칙이 남아 있으면 안 됨). 필수 접근 = 10.0.0.0/8 → 22 | 승인 출처가 없으면 "규칙 삭제" 패치가 만점으로 통과해 V6 가 Trivy 재탕이 된다. 값 자체는 실제 조직 IP 일 필요가 없고 **실행 전에 고정**되는 것이 중요. 배포 후 접속 검증(V8) 때만 실제 공인 IP /32 가 필요 → 그때 `sg-baseline.sandbox.json` 별도 | B (위임받아 확정) |
| D-3 | 2026-09-15 | 개발용 세트(`example-dev`, `a-probe-dev`) 숫자는 발표에 쓰지 않는다. 평가용 세트는 `eval-*` 이름으로 manifest·expected 를 먼저 고정하고 돌린다. 실행 결과는 `results-history/` 에 환경별로 누적한다 | 결과 보고 기준 바꾸기 금지 (docs/EXPERIMENT_GUIDE.md 2절) | B |
| D-4 | 2026-09-15 | `expected` 라벨 정정은 manifest 의 `expected_history` 에 이유와 함께 남긴다 (첫 사례: a-probe-dev 07-ipv6-only unsupported→correct) | 라벨을 조용히 바꾸지 않기 위해 | B |
| D-5 | 2026-09-21 | **유료 LLM API 를 쓰지 않는다.** LLM 후보는 사람이 Claude Code 를 새 세션으로 열어 고정 프롬프트(`scripts/cc_prompt.py`)를 붙여 넣고, 응답 파일을 `scripts/cc_add.py` 로 등록한다 (출처 `claude-code`). 실험 경로(`scripts/run_experiments.*` → `run_candidate_set.py` → `iacpatch.review`)는 `mock:` / `manual:` / `rule_based` 후보만 읽고 LLM 생성기를 import 하지 않는다. 1주차에 만든 API 호출 코드(`generator/llm_generator.py`, `generator/llm_providers.py`, `iacpatch run --generator llm`)는 기본값 `LLM_PROVIDER=mock` 이라 키 없이는 아무 곳에도 접속하지 않으며, 실험 결과에 쓰지 않는다 | 지도교수 지시(09-15, 유료 API 대신 Claude Code) + B 지시(API 키·결제·로컬 모델·CLI 자동 호출 금지). 자동 호출이 아니라 사람이 세션을 여는 것이므로 "생성 시각·모델·세션" 은 `responses/` 원문과 manifest 의 `note` 로 남긴다 | B |
| D-6 | 2026-09-22 | 위험도 기준표 **risk-v2-draft**: `iam_resource_touched` 를 hard HIGH 에서 **medium floor**(최소 MEDIUM = FULL_REVIEW, 사람 승인 필수)로. `iam_trust_policy_changed`(assume_role_policy 변경)·삭제·교체·provider 변경은 hard HIGH 유지 | v1 대로면 IAM 패치는 전부 REPORT_ONLY 라 PR 이 될 수 없어 IAM 시나리오가 성립하지 않는다. 사용자 원칙("IAM 변경 = Medium, 사람 승인 필수 / 복잡한 권한 변경 = High")과 일치. 아직 초안이므로 실행 전 변경 허용 — 팀 합의 후 고정 | B (팀 확인 필요) |
| D-7 | 2026-09-22 | IAM 평가용 intent 고정값: 대상 `aws_iam_policy.worker` + `aws_iam_role.worker`, 승인 = `s3:GetObject`/`s3:ListBucket` on `arn:aws:s3:::report-archive`(+`/*`), 필수 = 같은 두 권한, 승인 관리형 정책 없음 (`experiments/candidate-sets/eval-seeded-iam/intent.json`) | D-2 와 같은 원칙: 값은 실제 계정의 버킷일 필요가 없고 **실행 전에 고정**되는 것이 중요. seeded 13 + 규칙 기반 5 케이스의 expected 는 이 값 기준으로 실행 전에 적음 | B |
| D-8 | 2026-09-22 | IAM 시나리오의 대상 룰은 **AVD-AWS-0345(무제한 S3 정책 `s3:*`)**. `Action:"*"` 시나리오는 쓰지 않는다 | Trivy 0.74.0 내장 체크(`--skip-check-update`)에서 AVD-AWS-0057(일반 와일드카드)이 **deprecated, 빈 규칙**이라 `"*"` 를 잡지 않는다 (샌드박스 실측 7종, `docs/worklog/2026-09-22.md`). finding 이 없으면 파이프라인이 시작되지 않는다(NO_FINDING). 대신 "s3:* → *" 가 스캐너를 통과하는 기만 패치의 대표 사례가 된다 | B |
| D-9 | 2026-09-22 | 위험도 기준표 **v2 확정안** (`docs/RISK_RUBRIC_V2.md`, `policy/risk_rubric.json` risk-v2): `outside_target_family_touched`(대상 가족 기준), `non_core_attribute_changed`(타입별 핵심 속성), plan/텍스트 병합 max, IAM floor·신뢰 정책 hard(D-6). 등급 일치율 실험(`expected_risk`) 추가 | v1 은 SG 전용 표현이라 IAM 정책 변경에 부당한 점수(+2, +1)가 붙고 병합 합산으로 점수가 경계와 안 맞았다. 팀 OK 전까지 '확정안'. 실행 결과를 보고 값을 바꾸지 않기 위해 지금 고정 후보를 낸다 | B (팀 확인 필요) |
| D-10 | 2026-09-22 | **범위 확정(4주차 재검토, `docs/PROJECT_REVIEW_WEEK4.md` 5절)**: SG(됨)·IAM Tier 1(배포 전 됨)·Public S3(6~7주차) 세 유형만. Container CVE·EKS/Kubernetes·LangChain/LangGraph·대시보드·유료 LLM API = **하지 않음**. PR→승인→apply→V7/V8 1회 실측이 이번 달 최우선. 사람이 만든 ground truth(`ground-truth/`)를 분리하고 AI 작성 세트는 작성 주체를 명시 | 지도교수 9/22(남는 것·직접 쓰기·교차검증·제약)와 9/8 대화(피벗 금지·V6·seeded)를 병합. 기능 추가보다 제거 우선 | B (팀 확인 필요) |
| D-11 | 2026-09-22 | Claude Code 사용 제약을 저장소에 고정: `CLAUDE.md` + `.claude/settings.json`(apply/destroy/aws/sudo/push/자격증명 거부), 후보 생성은 `scripts/cc_batch.sh`(사람 시작, 도구 금지, 빈 디렉터리) 또는 수동 붙여넣기 | 지도교수 9/22 "AI 제약을 잘 걸어라". D-5 의 연장 | B |


## 아직 안 정한 것

- 위험도 기준표 고정 — 확정안 `docs/RISK_RUBRIC_V2.md` (2026-09-22) 에 팀 OK 만 남음. 평가용 LLM 후보 세트 돌리기 전에
- 제목 확정: 운영계획서 "AI 생성 IaC 보안 패치의 실효성 검증 자동화 파이프라인 설계 및 구현" vs D-1 vs 9/22 교수 언급 "AI 가 생성한 Terraform 보안 패치의 실효성 검증 자동화 구현" — 하나로
- TerraProbe 인용 출처(원문 링크·수치) 확보 전 인용 금지
- Claude Code 후보 프롬프트 고정본 승인 (`experiments/candidate-sets/eval-claude-code/prompt.md` 초안) 과 케이스당 반복 횟수
- V8 체크 정의와 sandbox 용 intent (실제 공인 IP)
