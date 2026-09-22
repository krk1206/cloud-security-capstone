# 검증 8계층(V1~V8)은 어디서 나왔나 — 근거와 대응 논리 (2026-09-22)

지도교수 9/22: "8개 계층이 어디서 나온 건지 근거와 대응 논리를 준비할 것. 이게 없으면 주먹구구로 만든 건지 알 수 없다. AI 가 만들어 준 것은 공격받기 쉬운 포인트이므로 본인이 숙지하고 설명할 수 있어야 한다."

이 문서는 그 질문에 대한 답이다. 한 줄 요약: **8이라는 숫자가 목표였던 게 아니라, 선행 연구의 5계층 + 우리가 실측으로 필요성을 확인한 1계층(실효 상태) + 우리 환경(샌드박스 apply 가능)이라 추가한 2계층(배포 후)의 합이 8이다.** 아래는 계층마다 (a) 출처, (b) 무엇을 잡는지, (c) 우리 저장소의 실측 근거, (d) 못 잡는 것을 적는다. 숫자는 전부 저장소 기록에서 나온 것이고, 확인 안 된 것은 [확인 필요] 로 표시했다.

## 1. 계보 — 어디서 왔나

| 우리 | 선행 연구 TerraProbe (arXiv:2606.26590) 의 오라클 계층 | 같은가 |
|---|---|---|
| V1 대상 finding 제거 (Trivy 재스캔) | **L1 Targeted Finding Removal** — 스캐너 재실행으로 지목된 finding 이 사라졌는지 | 같음. 스캐너만 Checkov → Trivy |
| V2 새 finding 없음 (Trivy 전체 스캔 전/후 비교) | **L2 Full Scanner Rerun** — 수정된 파일 전체를 전체 정책으로 재스캔 | **의미를 바꿈**: 논문은 "전체 통과", 우리는 "새로 생긴 CRITICAL/HIGH 만 차단, 나머지는 WARN" (이유는 3절 V2) |
| V3 `terraform fmt`/`validate` | **L3 Structural Validation** — `terraform validate` 로 스키마 정합성 | 같음 (+fmt 은 경고만) |
| V4 `terraform plan` 성공 | **L4 Planning** — 가짜 자격증명으로 `plan`, 클라우드 접속 없음 | 같음 (provider override 로 오프라인 plan) |
| V5 plan JSON 차이 | **L5 Plan Comparison** — `terraform show -json` 으로 수정 전 baseline 과 비교 | 같음 + 우리는 허용 속성·리소스 타입·delete/replace 를 정책으로 판정 |
| **V6 Intent Oracle (실효 상태 검사)** | 논문에는 계층으로 없음. 논문의 권고: "IAM 정책 시뮬레이터로 수정 전후 실효 권한 비교", "고권한 리소스는 사람 리뷰", "L4 이상에서 게이트" | **우리 추가** (근거는 2절) |
| V7 apply 후 실제 AWS 상태 실측 | 논문은 "`terraform apply` 는 수행하지 않음" 을 한계로 명시, plan 이 최강 증거 | **우리 추가** — 샌드박스가 있으므로 가능 |
| V8 기능 검증 (허용돼야 할 접근이 되는가) | 논문에 없음. 운영계획서 요구사항 "정상 기능 보존율" 에서 옴 | **우리 추가** |

- 논문 원문 대조 기록: `docs/DOC_CORRECTIONS.md` 1절 (2026-09-13, arxiv.org/html/2606.26590). 계층 이름은 원문 표기 그대로다. 권고가 나오는 절 번호(3.11, 6.2 로 읽힘)는 발표 전에 원문에서 한 번 더 확인할 것 [확인 필요].
- 그러니까 "왜 8개냐" 의 정직한 답: **5(논문) + 1(V6) + 2(V7/V8)**. 7개나 9개가 아닌 이유는 "이 만큼이 각각 다른 실패 유형을 잡기 때문" 이고(3절 표), 합칠 수 있는 것도 있다(V3+V4 를 "terraform 정합성" 하나로 봐도 논리는 안 깨진다). S3 오라클을 넣어도 V6 안의 종류가 늘 뿐 계층 수는 안 는다.

## 2. V6 를 왜 추가했나 — 스캐너 사각을 우리가 직접 쟀다

논문의 정의: **기만적 패치(deceptive fix)** = (i) 검사는 통과하는데 (ii) 보안 의도는 충족하지 않는 패치 (finding 은 사라졌지만 위험한 속성은 그대로). 이걸 잡으려면 "finding 이 사라졌나" 가 아니라 "**실제로 허용되는 상태가 무엇인가**" 를 스캐너와 독립적으로 계산해야 한다. 그게 V6 다.

우리가 직접 확인한 것 (전부 저장소 기록):

| 무엇 | 결과 | 기록 |
|---|---|---|
| Trivy 0.74.0 을 통과하는 SG 우회 패턴 (A 의 실험 9종) | `01-cidr-split`(0.0.0.0/1 + 128.0.0.0/1), `06-prefix-list`(prefix list 로 0.0.0.0/0) 는 **Trivy 통과, 실제로는 전 인터넷 개방**. 다른 컴퓨터·내장 체크 번들로 9/9 재현 | `experiments/trivy-sg-probe/`, `experiments/candidate-sets/a-probe-dev/A_RESULTS_CHECK.md` |
| 실제 plan 23개에서 스캐너 vs V6 (SG) | 스캐너 PASS ∧ V6 FAIL **5건** (01, 06, 14 대상 삭제, 18 self 참조, 22 레거시 규칙). 기대 FAIL 16/16 탐지, 정상 5/5 통과, 판정 불가 2건은 UNKNOWN | `experiments/ORACLE_RESULTS.md` |
| 실제 plan 14개에서 스캐너 vs V6 (IAM Tier 1) | 스캐너 PASS ∧ V6 FAIL **8건** (기만 5 + 필수 권한 깨짐 2 + 신뢰 정책 전체 개방 1). UNKNOWN 3건(NotAction/Condition/관리형)은 사람 검토 | `experiments/ORACLE_RESULTS.md` IAM 절 |
| 파이프라인 전체(정책→V1~V6→검토 수준) | SG seeded 11: 재스캔(V1)만 믿었으면 통과 **7건 → V6 까지 통과 2건**. IAM seeded 13: **9건 → 1건** (교차검증 전 기록은 2건 — 신뢰 정책 전체 개방을 통과시키던 false PASS 를 고친 뒤 1건). 라벨 일치 11/11, 13/13 | `experiments/candidate-sets/eval-seeded-{sg,iam}/results-history/` (2026-09-22 03:38/03:43 vm) |
| V6 자체의 오류 | 교차검증 1회차에서 IAM 오라클의 **false PASS 7종**(참조 세탁, 모듈 prefix, exclusive attachment 등)을 찾아 고침 | `docs/CROSS_VERIFICATION_2026-09-22.md` |
| 겉모습만 바꾼 변형을 자동 생성해 넣었을 때 (SG 42 + IAM 32 종) | 잡혀야 하는 변형 중 **Trivy 사각 종수 / 그중 오라클 탐지 / 오라클도 놓침** — 숫자는 `experiments/FUZZ_RESULTS.md` 머리의 "합계" 줄 (실행 때마다 갱신) | `scripts/fuzz_scanner.py`, `src/iacpatch/fuzz/` |
| 오라클의 집합 연산이 맞는가 | 무작위 CIDR 목록 20,000건 + 글롭 쌍 2,014건을 따로 짠 기준 구현과 대조 → **불일치 0** (seed 고정, 재실행 가능) | `experiments/ORACLE_FUZZ.md`, `scripts/oracle_fuzz.py` |

즉 V6 는 "논문이 권고했으니까" 가 아니라 **우리 스캐너·우리 케이스에서 사각이 실제로 있었고, 그 사각을 메우는 계층이 V6 하나뿐** 이라서 넣었다. 마지막 줄은 V6 도 틀릴 수 있다는 근거이고, 그래서 적대적 교차검증을 계속한다.

## 3. 계층별 "무엇을 잡나 / 못 잡나" — 실패 유형 대응표

패치가 잘못되는 방식은 한 가지가 아니다. 각 계층은 서로 다른 실패 유형 하나씩을 맡는다. 한 계층이 다른 계층을 대신 못 하는 것이 8개가 각각 필요한 이유다.

| 계층 | 잡는 실패 유형 | 저장소의 실제 사례 | 못 잡는 것 (그래서 다음 계층이 필요) |
|---|---|---|---|
| (정책 검증, V1 앞) | 패치가 허용 파일·리소스 범위를 벗어남 (다른 파일 수정, 리소스 타입 추가) | `deceptive-prefix-list`(prefix list 리소스 추가) → POLICY_BLOCKED, `unapproved-managed-policy`, `deceptive-second-policy` | 범위 안에서 잘못 고친 것 |
| V1 | **지목된 finding 이 그대로** (안 고침) | `unapproved-ipv6-open`(V1 FAIL), `deceptive-condition-s3star`(V1 FAIL) | finding 만 사라지고 상태는 그대로인 것(기만) — 01, 06 이 V1 PASS |
| V2 | 고치면서 **다른 심각한 문제를 새로 만듦** (새 CRITICAL/HIGH) | 05/08 케이스에서 새 finding 이 보안 의도와 무관한 것(설명 누락 0124, IMDSv2 0028, EBS 암호화 0131)이라 **WARN 만** 하도록 바꿈. 논문: 기만 패치의 90.0% vs 정상 패치의 43.5% 가 새 finding 을 만듦 → 신호로는 유용, 차단 조건으로는 오탐 | 새 finding 없이 기만하는 것(01, 06 은 V2 도 PASS) |
| V3 | **문법·스키마·참조가 깨짐** (적용 자체가 불가능) | `sg_baseline_deletes_sg`: SG 를 지우자 outputs.tf 의 참조가 깨져 validate 실패 (`docs/DOC_CORRECTIONS.md` 2절) | 문법은 맞는데 뜻이 틀린 것 |
| V4 | **plan 이 안 나옴** (provider 제약, 값 미확정, 순환) | 저장소에 실제 V4 FAIL 사례는 **아직 없다** (단위 테스트는 합성 입력). 논문: 실제 GitHub 코드의 약 79% 가 스캐폴딩 없이는 plan 불가 [원문 재확인]. → 케이스 추가 필요 | plan 은 나오는데 변경 범위가 엉뚱한 것 |
| V5 | **허용 안 된 변경**: 대상 밖 리소스 변경, 삭제/교체, 허용 안 된 속성 | `deceptive-inline-role-policy`(V5 FAIL: 정책 문서 밖 속성 변경), `14-target-deleted`(delete → hard HIGH) | 허용된 속성 안에서 값만 나쁘게 바꾼 것 (CIDR 분할은 `cidr_blocks` 안의 값 변경이라 V5 는 PASS) |
| V6 | **실효 상태가 의도를 안 지킴**: 승인 밖 출처/권한이 남음(기만·미승인), 필수 접근/권한이 사라짐(기능 파괴) | SG: `deceptive-cidr-split/quad`, `unapproved-other-range`, `breaks-required-delete-rule/wrong-port`. IAM: `deceptive-star-action`, `deceptive-resource-star`, `breaks-required-missing-list`, 신뢰 정책 Principal `*` | plan 에 없는 것: 계정에 이미 있는 다른 리소스, 실제 라우팅/NACL, 서비스 동작. Tier 1 밖(Deny/NotAction/Condition/관리형)은 **UNKNOWN → 사람** |
| V7 | **plan 과 실제가 다름**: apply 실패, drift, 콘솔 수정, provider 가 plan 과 다르게 적용 | 코드 있음(`postdeploy`), **실행 0회** (샌드박스 apply 는 사람 승인 뒤) | 상태는 맞는데 서비스가 안 되는 것 |
| V8 | **기능이 깨짐**: 허용돼야 할 접근이 실제로 안 됨 / 막혀야 할 접근이 됨 | 체크 정의 예시(`policy/intent/sg-baseline.v8.example.json`), **실행 0회** | — (마지막 계층) |

읽는 법: 위에서 아래로 갈수록 비싸고(시간·계정·권한) 정보량이 크다. 배포 전 계층(V1~V6)은 **전부 돌리고 전부 기록한다** — 한 계층이 FAIL 이어도 멈추지 않는다. 표가 완성돼야 "어느 계층이 잡았나" 를 셀 수 있기 때문이다 (V4 가 실패해 plan 이 없으면 V5/V6 는 자연히 SKIPPED). **판정은** 하나라도 FAIL 이면 BLOCKED, UNKNOWN/NOT_RUN 이 남으면 PENDING(사람) 이다 (`src/iacpatch/verify/combine.py`, `review/level.py`). V7/V8 은 사람 승인·apply 뒤에만 돈다. 이 순서는 논문의 L1→L5 순서와 같고, 논문의 권고 "L4 이상에서 게이트" 를 우리는 "V6 까지 PASS 여야 PR" 로 더 세게 잡았다.

## 4. 계층 ↔ 게이트 — 검증(Validity)과 위험도(Risk)는 섞지 않는다

- V1~V6 판정 = **Validity**. 하나라도 FAIL 이면 BLOCKED, UNKNOWN 이 남으면 PENDING(사람). 등급이 아무리 낮아도 여기서 막히면 자동화 안 한다.
- 위험도 기준표(`policy/risk_rubric.json` risk-v2) = **Risk**. plan/텍스트에서 변경 종류·범위·IAM·신뢰 정책·삭제/교체를 점수화. 검증 통과 여부를 점수에 안 넣는다.
- 검토 수준 = 두 축의 조합 (`src/iacpatch/review/level.py`): 정책 위반·검증 FAIL → BLOCKED / 검증 미완 → PENDING / 위험도 HIGH 또는 근거 부족 → REPORT_ONLY / MEDIUM(IAM floor 포함) → FULL_REVIEW / LOW → LIGHT_REVIEW (후보에 필수 정보 누락이 있으면 FULL_REVIEW 로 올림). 어느 수준이든 apply 는 사람이 한다.
- 근거: 논문 권고 "고권한 리소스·finding 증가는 사람 리뷰" 를 등급표로 고정한 것 + 운영계획서 3등급 정의. `docs/RISK_RUBRIC_V2.md`.

## 5. 표준·가이드와의 대응 (어느 계층이 어느 통제 항목을 확인하나)

`docs/STANDARDS_MAPPING.md` 가 원본이다. 요약:

| 통제 항목 (확인된 것만) | 확인하는 계층 |
|---|---|
| SK쉴더스 2024 클라우드 보안 가이드(AWS) 3.1 보안 그룹 ANY 설정 [항목명 2차 출처 확인, 원문 PDF 재확인 필요] | V1(AVD-AWS-0107) + **V6 SG**(분할·prefix list·인접 SG 합산까지) |
| AWS Security Hub EC2.13/EC2.14 (SSH/RDP 0.0.0.0/0) — Trivy 룰 references | V1 + V6 SG |
| Trivy AVD-AWS-0345 (`s3:*` 무제한 정책), AVD-AWS-0342 (PassRole) | V1 + **V6 IAM**(Action×Resource ⊆ 승인, 역할 합산, 신뢰 정책) |
| CIS AWS Foundations Benchmark 5.2/5.3(원격 관리 포트), 1.16(`*:*` 정책) | **번호·버전 원문 확인 전** (`policy/cis_mapping.json` verified=false). 차주 과제: Trivy↔CIS 매핑표 (`docs/TRIVY_CIS_MAPPING.md`) |

핵심 대응 논리: 표준은 "무엇이 양호/취약인가" 를 정하고, 스캐너(Trivy)는 그 중 **코드 문자열로 보이는 형태** 만 잡는다. V6 는 표준이 실제로 요구하는 **상태**(관리 포트가 인터넷 전체에 안 열림, 권한이 최소)를 계산한다. 그래서 표준 ↔ Trivy 룰 ↔ V6 를 한 줄에 놓는 매핑표가 필요하고, Trivy 룰이 CIS 항목과 1:1 이라고 가정하지 않는다 (AVD-AWS-0057 처럼 CIS 1.16 을 표기해 놓고 deprecated 인 룰도 있다).

## 6. 교수·심사위원 예상 질문과 답 (우리 말로)

1. **"8개는 어디서 나왔나?"** — 5개는 TerraProbe 의 L1~L5 를 그대로 가져왔다. V6 는 우리 Trivy 실험(01/06 통과)에서 필요성을 확인하고 논문의 "실효 권한 비교" 권고를 구현한 것. V7/V8 은 논문이 못 한 apply 를 샌드박스에서 하기 위해 나눈 것(상태 / 기능). 문서: 이 파일 1~2절.
2. **"V2 는 왜 차단이 아니라 경고인가?"** — 실측에서 새 finding 의 대부분이 보안 의도와 무관(설명 누락 등)했고, 논문도 정상 패치의 43.5% 가 새 finding 을 만든다고 보고. 차단으로 쓰면 오탐이 크다. 새 CRITICAL/HIGH 만 차단.
3. **"V6 없이 V5 로 안 되나?"** — V5 는 "어디가 바뀌었나" 만 본다. CIDR 분할은 허용된 속성 안의 값 변경이라 V5 PASS 다. "바뀐 값이 무엇을 허용하나" 는 집합 계산이 필요하고 그게 V6.
4. **"V6 가 틀리면?"** — 틀린다. 교차검증에서 false PASS 7종을 찾았다. 그래서 (a) UNKNOWN 을 PASS 로 안 만들고 사람에게 보내고, (b) 적대적 fixture 를 회귀 테스트로 쌓고, (c) 변형 자동 생성기(`fuzz_scanner.py`)가 오라클을 계속 공격하고, (d) 집합 연산은 무작위 2만 건으로 기준 구현과 대조했고(`ORACLE_FUZZ.md`), (e) V7 로 실제 상태를 다시 본다.
5. **"V7/V8 은 돌려봤나?"** — 아직 0회. 코드·기록 형식은 있고, 샌드박스 apply 는 사람 승인 뒤 이번 달 안에 1회 실측이 목표 (D-10).
6. **"이 정도면 규칙 몇 줄로 되지 않나?"** — SG 하나면 그렇다. 규칙 기반 생성기(`rule_based.py`)가 그 기준선이고, 비교 실험(E1)에 넣었다. 우리 주장은 "AI 가 낫다" 가 아니라 "AI 든 규칙이든 **만든 패치를 믿지 말고 실효 상태로 검증하라**" 다.
7. **"AI 가 만든 코드를 네가 설명할 수 있나?"** — 이 문서와 `docs/walkthroughs/`(작성 중) 로 답한다. 계층마다 "잡는 것/못 잡는 것" 한 줄과 실제 케이스 하나씩은 외워서 말할 수 있어야 한다.

## 7. 팀이 직접 채울 것

- [ ] 각자 자기 담당 계층을 예제 하나로 손 추적해서 `docs/walkthroughs/{A,B,C}.md` 에 적기 (A: V1~V4·V7, B: V6, C: V5·V8·게이트).
- [ ] TerraProbe 권고 절 번호 원문 재확인 → 이 문서 1절의 [확인 필요] 제거.
- [ ] 차주: `docs/TRIVY_CIS_MAPPING.md` (Trivy 룰 메타데이터 ↔ CIS 원문 대조, 담당 B) — 5절 표 갱신.
- [ ] V7 1회 실측 후 3절 표의 "실행 0회" 갱신 (A).
