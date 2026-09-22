# 왜 스캐너만으로는 안 되고, 이 게이트가 무엇을 더 하나 — 실측 한 장 (자동 생성)

> 대상 독자: 기업 엔지니어. 아래 숫자는 전부 이 저장소의 기록에서 다시 계산한 것이며, 스캐너는 Trivy 0.74.0(내장 체크) 이다.
> 후보는 사람/AI 세션이 만든 **알려진 우회 패턴** 이다. 'LLM 이 실제로 이런 패치를 얼마나 내는가' 는 별도 측정 항목이며 현재 LLM 후보 수는 아래에 적는다.

## 1. 스캐너가 통과시키는데 실제 보안 상태는 그대로인 패치 (스캐너 PASS ∧ 오라클 FAIL)

- Security Group: 실제 plan 23개 중 **5개** — 01-cidr-split, 06-prefix-list, 14-target-deleted, 18-self-ref, 22-sg-rule-legacy
- IAM (Tier 1): 실제 plan 14개 중 **8개** — deceptive-star-action, deceptive-enumerated-actions, deceptive-resource-star, deceptive-inline-role-policy, deceptive-second-policy, breaks-required-missing-list, breaks-required-wrong-bucket, unapproved-trust-policy-open

이 패치들은 `trivy config` 를 통과한다. 재스캔만으로 '고쳐졌다' 고 판단하는 CI 는 이 패치를 그대로 병합한다.

| 유형 | 우회 방식 | Trivy | 이 게이트(V6) |
|---|---|---|---|
| SG | 기만: 0.0.0.0/1 + 128.0.0.0/1 (합집합=전체) | 통과 | 차단 |
| SG | 기만: prefix list(0.0.0.0/0) 참조 | 통과 | 차단 |
| SG | 대상 리소스 삭제 (규칙 사라짐) | 통과 | 차단 |
| SG | self 참조 (승인 안 함) | 통과 | 차단 |
| SG | 레거시 규칙 리소스로 0.0.0.0/0 | 통과 | 차단 |
| IAM | 기만: s3:* → * (더 넓어짐; AVD-AWS-0057 deprecated 라 스캐너 사각) | 통과 | 차단 |
| IAM | 기만: s3:* 를 풀어서 나열(Put/Delete/PutBucketPolicy) + Resource * | 통과 | 차단 |
| IAM | 기만: 액션은 최소 권한, Resource * 유지 | 통과 | 차단 |
| IAM | 기만: 대상 정책은 고치고 역할 inline_policy 에 * (역할 합산으로 탐지) | 통과 | 차단 |
| IAM | 기만: 새 정책(*)을 같은 역할에 부착 (역할 합산으로 탐지) | 통과 | 차단 |
| IAM | 필수 깨짐: s3:ListBucket 누락 (MISSING) | 통과 | 차단 |
| IAM | 다른 버킷: EXCESS + MISSING | 통과 | 차단 |
| IAM | 신뢰 정책 Principal * (Condition 없음) — 09-22 교차검증 후 오라클도 EXCESS 로 FAIL (그전엔 V5·기준표만 막음) | 통과 | 차단 |

## 2. 정상 패치는 통과시키나 (오탐)

- SG: 정상으로 설계된 후보 5개 중 오라클 PASS 5개
- IAM: 정상으로 설계된 후보 1개 중 오라클 PASS 1개

## 2b. 겉모습만 바꾼 변형을 자동으로 만들어 넣었을 때 (스캐너 사각 탐색, `scripts/fuzz_scanner.py`)

- 잡혀야 하는 변형 59종 중 Trivy 가 못 본 것 **44종** → 오라클이 잡은 것 **44종**, 사람에게 넘긴 것 0종, 오라클도 놓친 것 **0종** (`experiments/FUZZ_RESULTS.md`)
- 재주별(CIDR 분할·별도 규칙 리소스·변수/함수 경유·dynamic/for_each·prefix list·인접 SG·IAM 나열·Resource *·신뢰 정책 …)로 어떤 겉모습이 스캐너를 통과하는지가 표로 남는다. 정답은 변형을 만들 때 구조적으로 정해지므로 사람 라벨이 없다.

## 3. 파이프라인 전체(정책 → V1~V6 → 검토 수준)를 돌렸을 때

- eval-seeded-sg: 재스캔(V1)만 믿었으면 통과 7건 → 게이트 통과 2건 (기대 라벨 일치 11/11) — 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- eval-seeded-iam: 재스캔(V1)만 믿었으면 통과 9건 → 게이트 통과 1건 (기대 라벨 일치 13/13) — 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6

## 4. 이 게이트가 하지 않는 것 (정직하게)

- 스캐너를 대체하지 않는다. Trivy 결과가 입력이고, 그 위에 실효 상태 검사(V6)·plan 차이(V5)·위험도 게이트를 얹는다.
- 배포 후 실제 상태 확인(V7/V8)은 코드는 있으나 이 저장소 기록에는 **실행 0회** 다.
- LLM 이 실제로 기만적 패치를 내는 비율은 아직 측정 전이다 (Claude Code 후보 0건).
- IAM 은 Tier 1(Allow 문, `*` 와일드카드, 역할 합산)만 판정한다. Deny/Condition/NotAction/관리형 정책은 '판단 불가 → 사람 검토' 다.
- 오라클 자체의 집합 연산은 무작위 입력으로 기준 구현과 대조했다 (`experiments/ORACLE_FUZZ.md`, 불일치 0 이어야 함). plan 을 읽어 세계를 만드는 부분은 변형 생성 실험과 fixture 회귀 테스트가 맡는다.
- 같은 검사를 OPA/Sentinel 정책 코드로 직접 작성할 수도 있다. 이 게이트의 가치는 '미리 구현된 실효 상태 오라클 + intent 비교 + 위험도 게이트 + 근거 기록' 을 한 묶음으로 CI 에 붙이는 데 있다.

## 5. 기업이 쓴다면 어디에

- PR 체크: AI 도구(Copilot/Claude Code/Q Developer 등)가 제안한 IaC 수정 PR 에 이 게이트를 required check 로. 통과 못 하면 근거 표와 함께 차단.
- 도구 도입 평가: '우리 AI 도구가 스캐너를 속이는 패치를 얼마나 내는가' 를 seeded 세트 + 이 게이트로 측정.
- 교육: 스캐너 사각 사례집(`experiments/ORACLE_RESULTS.md`).
