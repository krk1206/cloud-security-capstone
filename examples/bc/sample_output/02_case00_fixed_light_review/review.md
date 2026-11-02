# 로컬 검토 리포트 — ex02-case00-fixed (20260915-063845-106eac)

_이 문서는 입력(Trivy 결과·원본·수정 후보)과 확인된 검증 결과를 템플릿으로 정리한 것이다. 모델이 분석한 결과가 아니다._

> ✅ 필수 검증 계층 결과가 모두 있다 (결과 출처는 아래 표 참조). 최종 판단은 사람이 한다.

- 상태: **REVIEW_REQUIRED**  |  검토 수준: **LIGHT_REVIEW** — 경량 검토 — 사람 1인 확인 후 진행 (자동 반영 아님)
  - 위험도 LOW (점수 1, risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [plan basis + text basis])
  - 경량 검토: 사람 1인이 diff 와 검증 표를 확인한 뒤 진행 (자동 반영 아님)

## 1. 수정 대상과 이유

- 대상 finding: `AVD-AWS-0107` (HIGH) — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.
- 위치: `main.tf:14` 리소스 `aws_security_group.baseline`
- Trivy 메시지: Security group rule allows unrestricted ingress from any IP address.
- Trivy 권고: Set a more restrictive CIDR range
- 수정 이유(후보 작성자 기재): SSH ingress 를 승인 출처(예제 값 10.0.0.0/8)로 제한

## 2. 변경 요약과 diff 위치

- 변경 파일: `main.tf`
- diff: `candidate.diff`  (원본 사본 `original/`, 후보 `candidate/`)
- 리소스 블록 변경(텍스트 근거): 변경 {'aws_security_group.baseline': ['ingress', 'description', 'cidr_blocks']} / 추가 [] / 삭제 의심 [] / 타입 변경 [] / 리소스 밖 블록 []

## 3. 후보 출처

- origin: **manual** — 수동 입력 (사람이 준비한 파일 — 프로그램이 생성하지 않음)
- generator: `manual:candidate_fixed`  |  후보 ID: `cand-849b719e`
- 출처 설명(사람 기재): 개발 중 작성한 예제 (tests/fixtures/src/00b-baseline-fixed 와 동일 내용) — LLM 출력 아님

## 4. 검증별 상태

| 계층 | 내용 | 상태 | 요약 | 결과 출처 |
|---|---|---|---|---|
| V1 | 대상 finding 제거 (Trivy 재스캔) | ✅ 통과 | AVD-AWS-0107 이 재스캔에서 사라짐 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V2 | 새 finding 발생 여부 (Trivy 전후 비교) | ✅ 통과 | 새 finding 없음 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V3 | terraform validate | ✅ 통과 | validate 통과 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V4 | terraform plan | ✅ 통과 | plan 생성 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V5 | plan diff within policy | ✅ 통과 | changes within policy: changed=['aws_security_group.baseline'] added=[] removed=[] | local:v5_plan_diff |
| V6 | intent oracle | ✅ 통과 | PASS: all guarded services within approved sources and all required access preserved | local:v6_intent_oracle |

- 종합: **PASS** — all required layers passed
- 검증 결과 파일에 candidate_sha256 이 없어 이 후보에 대한 결과인지 대조하지 못했다 (A 가 해시를 넣어 주면 자동 대조됨)

## 5. 위험도와 판정 근거 (잠정 기준표)

- 위험도: **LOW** (점수 1) — 기준표: risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [plan basis + text basis]
- 위험도는 '틀렸을 때 얼마나 터지나' 이며, 검증 통과 여부와 별개다. 위험도 LOW 가 자동 반영을 뜻하지 않는다.

| 항목 | 값 | 점수 | 근거 종류 | 비고 |
|---|---|---|---|---|
| non_network_resource_touched | [] | 0 | plan |  |
| resources_touched | 1 | 0 | plan |  |
| new_resources_created | 0 | 0 | plan |  |
| attachment_points | 0 | 0 | plan | no attachment in plan (standalone SG) |
| attachment_has_external_or_unknown_sg | False | 0 | plan |  |
| egress_changed | False | 0 | plan |  |
| non_rule_attribute_changed | True | 1 | plan |  |
| oracle_partial_rules_or_caveats | False | 0 | plan |  |
| patch_lines | 5 | 0 | plan |  |
| files_changed | 1 | 0 | plan |  |
| non_network_resource_touched | [] | 0 | text |  |
| resources_touched | 1 | 0 | text |  |
| new_resource_blocks | [] | 0 | text |  |
| egress_changed | False | 0 | text |  |
| replace_forcing_attribute_changed | [] | 0 | text |  |
| non_rule_attribute_changed | False | 0 | text |  |
| non_resource_block_changed | [] | 0 | text |  |
| patch_lines | 5 | 0 | text |  |
| files_changed | 1 | 0 | text |  |

## 6. 사람이 확인할 항목

1. [ ] diff 가 대상 finding(AVD-AWS-0107 @ aws_security_group.baseline)만 다루는지 확인
2. [ ] 승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)
3. [ ] 검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행
4. [ ] 이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록

## 7. 미확인 사항

- V7(실제 AWS 상태)·V8(통신 확인)은 배포 후에만 가능하며 이번 로컬 흐름에 없다

## 부록. 입력 정합 확인

- 방법: cause-line content match (Trivy CauseMetadata.Code.Lines ↔ 원본 파일 줄)  |  결과: 일치  |  확인한 원인 줄 수: 1
- 일부 파일의 수정 시각이 스캔 시각보다 늦다 (git checkout 만으로도 생기는 현상이라 참고용). 줄 내용 비교 결과를 우선한다
- 지목된 원인 줄이 원본에 그대로 있다. 다른 줄의 변경은 이 방법으로 잡지 못한다 (A 가 source_commit 을 넘기면 완전 확인 가능)
- 도구: iacpatch 0.2.0 (review flow)
