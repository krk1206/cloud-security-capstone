# 졸업작품 통합 개발 계획

## 확신도 기반 클라우드 인프라 자율 보안 패치 파이프라인
### Confidence-Gated AWS IaC Auto-Remediation

> Terraform으로 작성한 AWS 인프라 코드의 설정 오류(misconfiguration)를 Trivy로 탐지하고, AI Agent가 패치 후보를 생성하면, 결정론적 검증 스택과 Risk Rubric이 자동화 수준을 결정하는 클라우드 네이티브 DevSecOps 파이프라인. **스캐너 통과만으로 성공을 판정하지 않고, 실효 보안 상태를 독립적으로 재검증한다.**
>
> **점검 대상은 AWS 자체가 아니라 우리가 작성한 인프라 코드다.** 공동 책임 모델(Shared Responsibility Model)상 AWS 플랫폼의 보안은 AWS가 책임지고, 그 위에 올리는 설정은 사용자 책임이다. 따라서 이 프로젝트는 "AWS 취약점 점검"이 아니라 "Terraform 설정이 CIS AWS Benchmark를 준수하는지 점검"하는 프로젝트다.

- **사전 학습:** 2026년 9월 2일(수) ~ 9월 7일(월)
- **본 개발:** 2026년 9월 8일(화) ~ 11월 16일(월) — 10주
- **기능 동결:** 11월 16일. 이후 신규 기능 추가 금지
- **실험·안정화:** 11월 17일(화) ~ 11월 23일(월)
- **발표 준비:** 11월 24일(화) ~ 12월 2일(수) — 문서화, 데모 녹화, 리허설
- **최종 발표:** 2026년 12월 3일(목) ~ 4일(금)
- **인원:** 3명
- **개발 원칙:** Depth-first, Vertical Slice 우선, 재현성과 평가 가능성 우선
- **최종 완성 기준:** 설정 오류 2개 유형(과다 개방 보안그룹, IAM 과다권한) 필수 + 검증 스택 8계층 + confidence 3단계 동작, Rule-based baseline 대비 정량 비교까지 테스트 완료된 상태. 퍼블릭 S3와 컨테이너 CVE는 여유가 있을 때만 추가한다.

---

## 0. 이 프로젝트가 필요한 이유

### 0.1 선행 연구

2026년 6월 발표된 TerraProbe 연구(arXiv:2606.26590)는 LLM이 생성한 Terraform 보안 패치를 5단계 오라클로 검증했다.

- 지목된 스캐너 finding 제거율 **83.3%**, 그러나 전체 스캔 통과율은 **10.4%**
- 실제 GitHub 코드에서 plan 비교까지 도달한 패치의 **57.1~71.4%가 "기만적 패치"** — 스캐너·`validate`·`plan`을 모두 통과하면서 실제 권한은 그대로 유지
- 모델 3종(Gemini / GPT-4o / Claude) 간 통계적으로 유의한 차이 없음 → 특정 모델의 결함이 아니라 구조적 문제
- 논문의 실무 권고: **plan 기준으로 게이팅하고, IAM 정책 시뮬레이션을 추가하고, 신규 finding 증가를 보조 신호로 쓸 것**

즉 "재스캔에서 오류가 사라졌다"는 것은 성공 판정 기준으로 부적절하다. 이 프로젝트가 검증 계층을 별도로 두는 이유다.

### 0.2 본 프로젝트의 자체 실측

논문은 Checkov 기준이므로, 본 프로젝트가 사용하는 Trivy에서도 같은 격차가 있는지 직접 측정했다.
전체 기록: [`experiments/trivy-sg-probe/`](experiments/trivy-sg-probe/)

**환경:** Trivy 0.74.0 / Terraform 1.16.1

Security Group 우회 후보 9종을 스캔한 뒤, 0 FAIL이 나온 케이스가 실제 우회인지 3단계로 재검증했다.

| 검증 | 방법 | 결과 |
|---|---|---|
| A. 룰이 실제로 실행됐는가 | `--include-non-failures`로 PASS 기록까지 확보 | 전 케이스에서 룰 71개 실행. 01·06에서 AWS-0107이 `Status=PASS` |
| B. 판정을 가른 원인이 무엇인가 | CIDR 값 한 곳만 바꾼 대조군(01b) 생성 | 01b는 FAIL, 01은 0 FAIL |
| C. 배포 가능한 코드인가 | `terraform validate` | 전부 통과 |

**확인된 우회 패턴 2종**

| 케이스 | 내용 | 실효 상태 |
|---|---|---|
| **01-cidr-split** | `0.0.0.0/0` → `0.0.0.0/1` + `128.0.0.0/1` | 두 CIDR의 합집합이 `0.0.0.0/0`과 **수학적으로 동일**. 보안 상태 변화 0 |
| **06-prefix-list** | CIDR 대신 `0.0.0.0/0`을 담은 managed prefix list를 참조 | 전면 개방 (배포 후 확인 필요) |

**부수 확인** — `08-second-sg`는 대상 SG를 조여도 인접 SG가 열려 있어 실효 접근이 유지된다. "대상 finding 제거"만으로 성공을 판정하면 놓치는 사례다.

**검증 방법론** — 0 FAIL을 우회로 판정하기 전에 반드시 대조군을 둔다. 스캔이 실패해서 0 FAIL이 나온 경우와, 룰이 실행됐으나 통과시킨 경우는 다르다. 이 원칙을 이후 모든 실험에 적용한다.

### 0.3 아직 확인하지 않은 것

과장하지 않기 위해 명시한다.

- `terraform validate`는 문법만 검증한다. **배포 후 실제 포트 개방 여부는 미확인**
- 06의 prefix list 참조가 실제 SG에 반영되는지 — sandbox `apply` + `describe-security-groups` 필요
- **LLM이 이 패턴을 실제로 생성하는지는 측정하지 않았다.** 본 실험은 탐지기 능력 측정이며, 자연 발생률 측정이 아니다. 논문과 주장의 층위가 다르므로 혼동하지 않는다

---

## 1. 프로젝트 정의와 핵심 축

이 프로젝트는 모든 클라우드 보안 문제를 다루지 않는다. Terraform으로 관리되는 AWS 인프라의 설정 오류를 연구 대상으로 삼는다.

**확신도 판정의 주체:** AI Agent(LLM)는 패치안과 함께 자신의 확신도 등급과 근거를 *제안*하고, Confidence Scorer가 사전 정의된 Risk Rubric(변경 리소스 종류, 영향 범위, IAM 관련 여부, 되돌리기 난이도)으로 **등급 상한을 강제한다.** 즉 AI는 등급을 낮출 수는 있어도 Scorer가 허용한 상한 위로 올릴 수는 없다. LLM의 제안은 **하향 방향으로만** 작동하므로 구조적으로 안전하다.

**검증과 등급은 별개다.** 등급은 "잘못됐을 때 파급이 얼마나 큰가"를 재고, 검증은 "이 패치가 실제로 고쳤는가"를 재는 별도 축이다. **검증을 통과하지 못한 패치는 등급이 아무리 높아도 PR을 만들지 않는다.**

### 1.1 핵심 2축

| 축 | 역할 | 필수 산출물 |
|---|---|---|
| **클라우드 인프라 (1차)** | Terraform/AWS 설정 오류 탐지 및 패치의 중심 무대 | Trivy(IaC 모드) 연동, CIS 직접 대응 항목 매핑, 설정 오류 2개 이상 유형 |
| **검증·게이팅** | 패치가 실제로 고쳤는지 판정하고, 위험도에 따라 자율성 부여 | 검증 스택 8계층, Intent Oracle, Confidence Scorer, Policy Validator |

**AI Agent의 역할** — Trivy 결과와 Terraform 코드 컨텍스트 분석, 패치 후보 생성, 근거 설명, 확신도 등급 제안(하향 전용). 등급 상한을 결정할 권한은 없다.

**선택 확장 (후순위)** — 컨테이너 이미지 CVE(`trivy image`), 퍼블릭 S3. 핵심 Vertical Slice가 안정된 뒤에만 착수하며, 시간이 부족하면 제거한다.

```
Terraform 코드 변경
  ↓
Trivy IaC 스캔 (trivy config)
  ↓
CIS 직접 대응 항목 매핑 + 코드 컨텍스트 수집 (Evidence Bundle)
  ↓
AI Analyzer: 패치 방향 분석 + Terraform 패치 후보 생성 + 근거·제안 등급
  ↓
검증 스택 V1~V6 (2.2절)
  ├─ 전부 통과 ────────→ Confidence Scorer 판정 → 등급별 PR 생성
  ├─ V6 실패 (기만 의심) → PR 생성 안 함. 재생성 1회 또는 리뷰 요청 리포트
  └─ V1/V3/V4 실패 ────→ PR 생성 안 함. 실패 사유 기록
  ↓
사람 승인 → 병합 → terraform apply (수동 확인)
  ↓
V7 실제 AWS 상태 실측 → V8 정상 기능 확인
```

### 1.2 최종 연구 질문

1. Trivy IaC 스캔을 통과하면서 실효 보안 상태를 개선하지 않는 Terraform 패치가 존재하는가? 이를 결정론적 오라클로 탐지할 수 있는가?
2. 패치별로 Agent와 Human에게 서로 다른 수준의 자율성을 부여했을 때, 안전성(부작용·오탐)과 처리 효율(MTTR) 사이의 균형을 개선할 수 있는가?
3. Rule-based baseline(고정 규칙 자동 수정)과 비교했을 때, AI Agent가 더 다양한 설정 오류 변형에 적응적인 패치를 생성하는가?

> 1번은 0.2절에서 부분적으로 답했다. 2·3번은 10~11주차 비교 실험으로 검증한다.
>
> **Rule-based가 더 안정적이라는 결과, 또는 특정 유형에서 AI 사용의 이점이 없다는 결과도 유효한 연구 결과로 인정한다.** AI가 항상 우수하다고 가정하지 않는다.

### 1.3 핵심 차별점

1. 컨테이너 CVE가 아닌 **AWS IaC 설정 오류를 1차 연구 대상**으로 삼는 자율 패치 파이프라인
2. **패치 생성 주체와 등급 상한 결정 주체를 분리.** LLM의 확신도 제안은 하향 전용이며, 자신의 자율성 수준을 올릴 수 없다
3. **스캐너와 독립적인 Intent Oracle.** Trivy가 통과시킨 패치도 실효 상태로 재검증한다 (0.2절 실측 근거)
4. **정적 검사에 그치지 않고 실제 AWS Sandbox 상태를 실측.** TerraProbe는 `apply`를 수행하지 않아 plan JSON이 최강 증거였으나, 본 프로젝트는 배포 후 상태를 직접 확인한다
5. 패치 근거를 **CIS AWS Benchmark 조항 중 직접 대응 가능한 항목에 매핑**해 설명 가능하게 함
6. Rule-based baseline과의 정량 비교(성공률, MTTR, 부작용률)로 게이팅의 효과를 실험적으로 검증

> 상용 도구(Dependabot / Snyk Fix 등)의 내부 동작을 확인하지 않았으므로, "기존 도구에는 위험도 기반 처리가 없다"는 식의 단정은 하지 않는다. 비교는 우리가 직접 구현한 Rule-based baseline과 수행한다.

### 1.4 신뢰 경계

| 구성요소 | 신뢰 수준 | 원칙 |
|---|---|---|
| Trivy(IaC 모드) | 관측 데이터 신뢰 | 원본 스캔 결과를 변경 없이 보존 |
| AI Analyzer (LLM) | 비신뢰(untrusted) 판단기 | 패치안·근거·제안 등급만 출력. 직접 실행 권한 없음 |
| **Intent Oracle** | **신뢰 경계** | **Trivy 결과를 입력으로 사용하지 않고 실효 상태를 독립 계산.** 판정이 엇갈리면 Intent Oracle을 따른다 |
| Confidence Scorer | 신뢰 경계 | Risk Rubric으로 등급 상한 산정. AI가 제안한 등급이 상한을 넘으면 강제 하향 |
| Policy Validator | 신뢰 경계 | 패치 diff가 화이트리스트를 벗어나면 등급과 무관하게 거부 |
| Executor (GitHub Actions bot) | 최소 권한 신뢰 | 승인된 PR만 생성, `terraform apply`는 별도 승인 없이 자동 실행 금지 |
| 사람 승인자 | 최종 결정권 | Medium/Low 등급의 최종 승인자, High 등급도 병합 전 최소 확인 필요 |

**명시적 제외 범위**

- 실제 운영 중인 프로덕션 AWS 계정 대상 실험 (격리된 샌드박스 계정만 사용)
- `cluster-admin`/`AdministratorAccess` 등 관리자급 IAM 정책의 완전 자동 재작성
- 사람 확인 없는 `terraform apply` 자동 실행
- High confidence를 포함한 모든 등급에서 완전 무인 자동 병합

---

## 2. 검증과 등급 설계

### 2.1 두 축을 분리한다

| 축 | 무엇을 재는가 | 결과 |
|---|---|---|
| **Validity** | 이 패치가 실제로 고쳤는가 | 통과 / 기만 의심 / Invalid → **게이트** |
| **Confidence** | 잘못됐을 때 파급이 얼마나 큰가 (Risk Rubric 기반) | High / Medium / Low → **자율성 수준** |

Validity를 통과하지 못하면 Confidence가 High여도 자동화하지 않는다.

### 2.2 검증 스택 (Validity)

| 계층 | 내용 | 담당 | 상태 |
|---|---|---|---|
| V1 | Trivy 재스캔 — 대상 룰 제거 확인 | A | 기존 |
| V2 | Trivy 전체 스캔 — 신규 finding 증가 확인 | A | **신설** |
| V3 | `terraform fmt` / `validate` | A | 기존 |
| V4 | `terraform plan` 성공 | A | 기존 |
| V5 | plan JSON diff — 허용된 변경 범위인지 | C | **신설** |
| **V6** | **Intent Oracle — 실효 상태 독립 검사** | **B** | **신설 (핵심)** |
| V7 | `apply` 후 실제 AWS 상태 실측 | A | **신설** |
| V8 | 기능 검증 — 허용돼야 할 트래픽 통과 확인 | C | 기존 |

**V6 Intent Oracle 스펙 (Security Group 기준)**

0.2절 실측 결과가 이 설계를 결정했다. 문자열 검사(`"0.0.0.0/0" in cidr_blocks`)로 구현했다면 01과 06을 **둘 다 통과시켰을 것이다.**

```
① 해당 포트로 들어오는 모든 출처를 수집한다
   cidr_blocks + ipv6_cidr_blocks + prefix_list_ids(내용 전개) + security_groups
② CIDR 합집합을 계산한다 — 문자열 매칭 금지
   Python ipaddress.collapse_addresses()
③ 공인 인터넷을 덮으면 FAIL — Trivy 판정과 무관하게
④ 인스턴스/ENI에 붙은 모든 SG를 합산해 판정한다
```

- **Trivy 출력을 입력으로 사용하지 않는다.** 독립성이 이 계층의 존재 이유다
- Python 표준 라이브러리(`ipaddress`)만 사용. 외부 의존성 없음
- V7도 같은 계산을 적용한다. `describe-security-groups` 결과에서 06 케이스는 `IpRanges`가 비고 `PrefixListIds`만 나오므로, `describe-managed-prefix-lists`로 한 번 더 전개해야 한다
- 회귀 테스트: `experiments/trivy-sg-probe/cases/`의 01·06·08을 탐지하고, 00-baseline 정상 패치에서는 오탐이 없어야 한다
- IAM 확장 시에는 실효 권한 계산이 필요하다. 6주차 시점에 구현 난이도를 재평가하고, 어려우면 **"IAM은 무조건 사람 승인"** 정책으로 대체한다

**V2에 대한 주의** — 실측에서 05번이 FAIL 4개, 08번이 3개였으나 description 누락(AWS-0124), IMDSv2(AWS-0028), EBS 암호화(AWS-0131) 등 보안 의도와 무관한 항목이 섞여 있었다. TerraProbe도 정상 패치의 43.5%가 새 finding을 만든다고 보고했다. **V2는 차단 조건이 아니라 값싼 보조 신호로만 사용하고, 룰 카테고리별 가중치를 둔다.**

### 2.3 Confidence 등급

| 등급 | Risk Rubric 조건 예시 | 동작 |
|---|---|---|
| **High** | 단일 리소스의 포트/CIDR 범위 축소, 명백한 오탈자성 설정 | 패치 브랜치 + PR 자동 생성, 경량 승인(1인 확인)으로 병합 가능 |
| **Medium** | 보안그룹 규칙 재구성, 여러 리소스에 영향 | PR 생성 + `plan` diff·검증 결과 첨부, 승인 필수 |
| **Low** | IAM 권한 변경, 근거 evidence 부족, 광범위 변경, 롤백 난이도 높음 | 패치 시도하지 않고 `request_review` 리포트만 생성, 미패치 사유 기록 |

등급 산정 기준(변경 리소스 종류, 영향받는 리소스 수, IAM 관련 여부, blast radius, 되돌리기 난이도)은 개발 4주차에 사전 고정하고, 이후 결과를 보고 등급 기준을 바꾸지 않는다.

**"High = 안전하다"고 주장하지 않는다.** 사전 정의된 위험 기준상 상대적으로 자동화 가능한 범위라는 의미로만 사용한다.

---

## 3. 시스템 구조

```
┌──────────────────── Dev ────────────────────┐
│ GitHub Actions: Terraform 변경 감지            │
└─────────────────────┬───────────────────────┘
                      ▼
┌──────────────────── Sec ────────────────────┐
│ Trivy(IaC 모드, trivy config) 스캔             │
│ 기준 미달 시 배포 차단, Evidence Bundle 생성    │
└─────────────────────┬───────────────────────┘
                      ▼
┌───────────────── AI Analyzer ───────────────┐
│ 위반 조항·코드 컨텍스트 분석                    │
│ Terraform 패치 후보 생성 + 근거 + 제안 등급     │
│ (등급 상한 결정 권한 없음)                      │
└─────────────────────┬───────────────────────┘
                      ▼
┌─────────────── 검증 스택 ───────────────────┐
│ V1 대상룰   V2 전체스캔   V3 validate         │
│ V4 plan     V5 plan diff  V6 Intent Oracle   │
│ → 기만 의심 시 여기서 차단                     │
└─────────────────────┬───────────────────────┘
                      ▼
┌────────── Confidence Scorer + Policy ───────┐
│ Risk Rubric → 등급 상한 → 등급별 PR 생성       │
│ 화이트리스트 위반 시 등급 무관 거부             │
└─────────────────────┬───────────────────────┘
                      ▼
┌──────────────── 승인·반영 ──────────────────┐
│ 등급별 승인 → 병합 → terraform apply(수동 확인) │
│ → V7 AWS 상태 실측 → V8 기능 확인              │
└─────────────────────┬───────────────────────┘
                      ▼
┌──────────────────── Ops ────────────────────┐
│ AWS 샌드박스 계정 반영                         │
│ (컨테이너 축 진행 시: EC2+K3s 또는 로컬)        │
└─────────────────────────────────────────────┘
```

---

## 4. 환경 구성

```
GitHub Repository
├─ .github/workflows/       # CI/CD 파이프라인
├─ infra/                   # Terraform (의도적 설정 오류 포함, AWS 샌드박스 대상)
├─ ai-agent/                # Analyzer · Patch Generator
├─ oracle/                  # Intent Oracle(V6), Confidence Scorer, Policy Validator
├─ policy/                  # 패치 화이트리스트, CIS 매핑 테이블
├─ tests/deceptive/         # Seeded Deceptive Patch 세트 (V6 회귀 테스트)
├─ experiments/             # 실험 기록 (trivy-sg-probe 등)
├─ app/                     # 샘플 애플리케이션 (컨테이너 축 진행 시)
└─ data/sessions/           # 세션별 스캔 리포트, 등급 판정, PR 기록
```

- **AWS 샌드박스 계정**: 실습·평가 전용으로 별도 분리, 프로덕션 자원과 격리. AWS 무료 플랜(6개월, 크레딧 기반) 사용을 전제로 하며, EKS·NAT Gateway 등 상시 과금 자원은 사용하지 않는다. 테스트 후 `terraform destroy`를 원칙으로 하고, Budgets 알림·루트 MFA·작업용 IAM 사용자 분리를 1주차에 완료한다. GitHub Actions의 AWS 접근은 액세스 키 대신 **OIDC 연동**을 사용한다.
- **Trivy(IaC 모드, `trivy config`)**: IAM, 보안그룹, S3 등 CIS AWS Benchmark 매핑 대상 룰 우선 사용 (Kubernetes 매니페스트 스캔은 선택). *(tfsec은 2023년 Aqua Security가 개발을 중단하고 Trivy로 룰셋을 통합했으므로, 별도 도구 대신 Trivy의 IaC 스캔 모드를 사용한다. 룰 ID는 `AVD-AWS-*` 체계.)*
  - **CIS AWS Benchmark는 직접 대응 가능한 항목만 매핑한다.** 모든 Trivy 룰이 CIS 항목과 1:1 대응한다고 가정하지 않는다
  - **버전을 기록한다.** 룰셋은 버전마다 다르므로 재현성을 위해 필수 (현재 실험 기준: Trivy 0.74.0)
- **Trivy(컨테이너 모드, `trivy image`)**: 컨테이너 이미지 OS·라이브러리 취약점 보조 스캔 (선택 확장)
- **Intent Oracle**: Python 표준 라이브러리만 사용. 외부 의존성 없음
- **AI Agent 구조**: 일반 Python 상태 머신을 우선한다. 반복 루프가 복잡해질 경우에만 LangGraph 도입을 검토한다. 프레임워크 사용 자체는 연구 목표가 아니다

---

## 5. 3인 역할 분담

| 역할 | 담당 | 주요 산출물 |
|---|---|---|
| **A — 클라우드 인프라** | Terraform 샘플 인프라, Trivy 연동, CIS 매핑, AWS 샌드박스 관리, V1·V2·V3·V4·V7 | 설정 오류 시나리오, Seeded Deceptive 세트, CIS 매핑 테이블, AWS 실측 스크립트 |
| **B — AI Agent + Oracle** | LLM 연동, 패치 생성, **Intent Oracle(V6)**, Confidence Scorer | 패치 생성기, Intent Oracle, Risk Rubric 구현 |
| **C — 파이프라인·평가** | GitHub Actions 통합, PR/승인 흐름, V5·V8, Rule-based baseline, 실험·문서화 | 통합 파이프라인, baseline 스크립트, 실험 리포트 |

---

## 6. 사전 학습 기간 (9월 2일 수 ~ 9월 7일 월) — 완료

이 기간에는 코드를 짜지 않는다. 3인 모두 기초 개념 숙지가 목표.

| 날짜 | 내용 |
|---|---|
| 9/2 (수) | 공통 — CI/CD 기본 구조, Shift-Left 보안, Git 기초(커밋·브랜치·PR) |
| 9/3 (목) | 공통 — Docker 기본 개념, GitHub Actions 워크플로우 문법 |
| 9/4 (금) | A: AWS 기초(IAM/EC2/S3/SG/VPC) / B: Python·LLM API·JSON 구조화 출력 / C: Actions 심화(secrets, PR 트리거), REST API |
| 9/5 (토) | A: Terraform 기초, `plan`과 `apply`의 차이 / B: Agent·Tool·Chain 개념 / C: GitHub API PR 생성, Trivy 설치 |
| 9/6 (일) | A: CIS AWS Benchmark 대표 항목, `trivy config` 사용법 / B: Function Calling, Prompt Engineering, Reasoning-Action / C: `trivy image`, 평가지표 기초 |
| 9/7 (월) | 공통 — 아키텍처 리뷰, Evidence Bundle 스키마 초안, 착수 계획 점검 |

**완료 기준:** 3인 모두 자기 역할에 필요한 도구를 한 번씩 손으로 만져봤고, 전체 파이프라인 흐름을 서로에게 설명할 수 있다.

---

## 7. 개발 일정 개요 (9월 8일 ~ 11월 23일)

| 주차 | 기간 | 핵심 목표 |
|---|---|---|
| 1주차 | 9/8~9/14 | 3인 개별 환경 구축 (저장소, AWS 샌드박스, LLM 연동) |
| 2주차 | 9/15~9/21 | Trivy IaC 스캐너 파이프라인 연동 |
| 3주차 | 9/22~9/28 | CIS 매핑 + AI 분석 리포팅 + **V2 신규 finding 카운트** |
| 4주차 | 9/29~10/5 | **Confidence Scorer(Risk Rubric) 설계** + Validity/Confidence 축 분리 |
| 5주차 | 10/6~10/12 | High-confidence 첫 폐루프 (탐지→패치→PR) |
| 6주차 | 10/13~10/19 | **V6 Intent Oracle + Seeded Deceptive 세트** + Medium 처리 |
| 7주차 | 10/20~10/26 | Low 처리 + IAM 유형 추가 + baseline 착수 |
| 8주차 | 10/27~11/2 | **V5 plan diff + V7 AWS 실측** + 통합 점검 |
| 9주차 | 11/3~11/9 | V8 기능 보존 검증 + MTTR 측정 체계 + 실험 프로토콜 확정 |
| 10주차 | 11/10~11/16 | Rule-based baseline vs AI Agent 반복 실험. **11/16 기능 동결** |
| 11주차 | 11/17~11/23 | 실험 마무리 + end-to-end 테스트 + 버그 수정 (**신규 기능 금지**) |

**11/16 기능 동결.** 이후 신규 기능을 추가하지 않는다. 발표(12/3~4) 전에 문서화·데모 녹화·리허설 시간을 확보하기 위한 조치다.

### 주요 게이트

| 게이트 | 시점 | 통과 조건 |
|---|---|---|
| **게이트 A** | 5주차 말 | High-confidence 설정 오류 1개 시나리오가 탐지→패치→PR까지 자동 동작하며 3회 재현 |
| **게이트 B** | 6주차 말 | **V6가 01·06·08 케이스를 탐지하고, 00-baseline 정상 패치에서는 오탐 없음** |
| **게이트 C** | 8주차 말 | 검증 스택 V1~V7이 모두 동작하고 Rule-based baseline 준비 완료 |

---

## 8. 9월 개발 일정 (1~4주차)

### 1주차 (9/8~9/14) — 환경 구축
- **A**: AWS 샌드박스 계정 준비(무료 플랜 가입, Budgets 알림, 루트 MFA, 작업용 IAM 사용자, GitHub OIDC 연동), 의도적 설정 오류를 포함한 Terraform 인프라 작성
- **B**: 개발환경 세팅, LLM API 연동 테스트 (프롬프트-응답 확인)
- **C**: GitHub 저장소 정비, 기본 GitHub Actions 빌드 워크플로우 구현
- **완료 기준:** 3인 각자 기본 환경이 개별적으로 동작한다

### 2주차 (9/15~9/21) — 스캐너 연동
- **A**: Trivy(IaC 모드)를 파이프라인에 연동, Critical/High 발견 시 배포 차단
- **B**: Evidence Bundle 스키마 설계
- **C**: 스캔 결과 아티팩트 저장·조회 흐름 구현
- **완료 기준:** Trivy 스캔 결과가 파이프라인에서 자동 생성되고 3회 재현된다

### 3주차 (9/22~9/28) — CIS 매핑, AI 분석, V2
- **A**: Trivy 룰 중 **CIS AWS Benchmark와 직접 대응 가능한 항목**을 매핑하는 테이블 작성
- **A**: **V2 구현** — 패치 전후 Trivy 전체 스캔 결과를 비교해 신규 finding 수 산출 (JSON 두 개 비교)
- **B**: LLM이 Evidence Bundle을 읽고 CIS 근거를 포함한 분석 리포트를 JSON으로 출력하도록 구현
- **C**: 분석 리포트를 PR 댓글로 자동 게시
- **완료 기준:** 탐지 → CIS 근거 포함 AI 분석 → PR 댓글까지 폐루프가 완성된다. 여기까지가 발표 가능한 최소 결과물이다.

### 4주차 (9/29~10/5) — Confidence Scorer 설계
- **B**: Risk Rubric(변경 리소스 종류, 영향 리소스 수, IAM 관련 여부, blast radius, 롤백 난이도) 설계 및 등급 상한 로직 구현
- **B**: LLM 제안 등급이 상한을 넘을 때 강제 하향되는지 확인
- **A**: 패치 화이트리스트(허용된 Terraform 변경 유형) 정의
- **C**: Policy Validator 스켈레톤 구현
- **완료 기준:** 목업 데이터로 High/Medium/Low 등급이 올바르게 분류되고, 상한 강제가 동작한다

### 9월 말 산출물
- Trivy 연동이 완료된 CI/CD 파이프라인
- CIS 직접 대응 매핑 테이블
- V2 신규 finding 카운터
- Confidence Scorer 모듈 (동작 검증 완료)
- 10월 확장 backlog

---

## 9. 10월 개발 일정 (5~7주차)

### 5주차 (10/6~10/12) — High-confidence 첫 폐루프
- **B**: High-confidence 시나리오에 대해 실제 Terraform 코드 수정 + 브랜치 생성 구현
- **A**: `terraform plan` 자동 실행으로 변경 사항 사전 확인
- **C**: GitHub API PR 생성 연동
- **완료 기준(게이트 A):** High-confidence 설정 오류 1개 시나리오가 탐지→패치→PR까지 자동 동작하며 3회 재현된다

### 6주차 (10/13~10/19) — Intent Oracle + Seeded 세트 + Medium 처리
- **B**: **V6 Intent Oracle 구현.** 2.2절 스펙에 따라 CIDR 합집합 계산, prefix list 전개, 다중 SG 합산
- **A**: **Seeded Deceptive Patch 세트를 `tests/deceptive/`로 승격.** `experiments/trivy-sg-probe/cases/`의 01·06·08 사용
- **B**: Medium-confidence 케이스 — 검증 결과 첨부, 승인 필수 표시 로직
- **여유 시**: LLM에게 00-baseline 패치를 20~30회 시켜 01 같은 패턴이 자연 발생하는지 관찰. **0건이어도 정직하게 보고한다**
- **완료 기준(게이트 B):** V6가 01·06·08을 탐지하고 00-baseline에서 오탐이 없다. Medium 등급 패치가 승인 필수 상태로 생성된다

### 7주차 (10/20~10/26) — Low 처리 + IAM 확장 + baseline 착수
- **B**: Low-confidence 케이스 — 패치 시도 없이 리포트만 생성, 미패치 사유 기록
- **A**: 두 번째 설정 오류 유형 추가 (IAM 과다권한)
- **B**: IAM에 대한 Intent Oracle 구현 난이도 재평가. 어려우면 **"IAM은 무조건 사람 승인"** 정책으로 대체하고 그 사실을 기록
- **C**: Rule-based baseline 스크립트 구현 착수 (비교용, 10월 말 동결 예정)
- **완료 기준:** 3개 confidence 등급이 모두 목적대로 동작한다

---

## 10. 11월 개발 일정 (8~11주차)

### 8주차 (10/27~11/2) — 검증 스택 완성 + 통합 점검
- **C**: **V5 구현** — plan JSON diff로 변경 범위가 화이트리스트 안인지 확인
- **A**: **V7 구현** — `apply` 후 `describe-security-groups`로 실제 상태 실측. prefix list는 `describe-managed-prefix-lists`로 전개
- **A**: 패치 병합 후 Trivy 재스캔 자동화
- **3인 공동:** 설정 오류 2개 유형 × confidence 3단계 × 검증 스택 8계층 통합 테스트
- **완료 기준(게이트 C):** 검증 스택 V1~V7이 모두 동작하고 Rule-based baseline이 준비된다

### 9주차 (11/3~11/9) — 기능 보존 검증 + 실험 프로토콜 확정
- **C**: **V8 구현** — 정상 인프라 기능 보존 검증 자동화 (허용돼야 할 트래픽이 통하는지)
- **B**: 등급별 자동 처리 시간과 사람 승인 대기 시간을 분리 측정하는 MTTR 로깅 구현
- **3인 공동:** 실험 프로토콜 확정 (반복 횟수, 평가 지표, held-out 시나리오 분리) — **이후 변경하지 않음**

### 10주차 (11/10~11/16) — 반복 실험 + 기능 동결
- **3인 공동:** Rule-based baseline vs Confidence-Gated AI Agent 비교 실험 반복 수행
- 실패·오탐 사례를 삭제하지 않고 원인과 함께 보존
- **11/16 기능 동결.** 이후 신규 기능 추가 금지

### 11주차 (11/17~11/23) — 마무리 및 완전 동작 검증
- 반복 실험 마무리, 통계 요약
- **전체 파이프라인 end-to-end 테스트**: 탐지 → 검증 → 등급 판정 → 패치 → PR → 승인 → apply → 재검증 전 과정을 여러 번 실행
- 발견된 버그·엣지 케이스 수정 (**신규 기능은 추가하지 않는다**)
- **완료 기준 (11/23):** 전체 시스템이 테스트를 통과하고 처음부터 끝까지 완전하게 동작한다

---

## 11. 발표 준비 (11월 24일 ~ 12월 2일)

| 기간 | 내용 |
|---|---|
| 11/24~11/27 | 결과 정리, 통계 요약, 아키텍처·신뢰 경계·검증 스택 문서화 |
| 11/28~11/30 | 발표자료 완성, **데모 녹화** |
| 12/1~12/2 | 리허설 2회 |
| **12/3~12/4** | **최종 발표** |

발표는 5~10분 컨셉 발표를 기준으로 준비한다. 심사위원이 라이브 데모를 요구하는지는 **확인 필요 항목**이다.

**최종 결과는 "스캐너 통과가 곧 보안 개선이 아니라는 점을 실측으로 보이고, 실효 상태 검증과 자율성 게이팅이 안전성과 속도를 동시에 개선했는가"를 중심으로 제시한다.**

---

## 12. 참고: 심화 이론

- **IaC와 Terraform**: resource/variable/provider 구조, `plan`과 `apply`의 차이
- **CIS AWS Benchmark**: 클라우드 설정 보안 모범사례가 무엇이고 왜 표준으로 쓰이는가
- **클라우드 IAM 최소 권한 원칙**: 과다 권한이 왜 위험한가
- **APR의 오라클 문제**: 테스트를 통과한 수정이 명세를 만족한다는 보장은 없다 (Monperrus, 2018). IaC 보안에서는 "체크를 통과한 패치가 보안 의도를 만족한다는 보장이 없다"로 대응된다
- **AI Agent의 Reasoning-Action 구조**: 판단과 실행을 분리하는 이유
- **AI 입력 보안**: 리소스명·태그 등은 공격자가 조작 가능한 불신 데이터로 취급, 근거 부족 시 `abstain` 허용
- **실험 타당성**: 평가 지표와 반복 횟수를 결과 확인 전에 고정, 개발용/평가용 시나리오 분리

---

## 13. 새 기능 추가 조건

```
현재 vertical slice 성공 기준 충족
AND 연구 질문 중 하나에 직접 필요
AND 기존 재현성 테스트를 깨지 않음
AND 11/16 이전
```

---

## 14. 데이터·평가 원칙

### 14.1 필수 지표

"정확도"라는 단어는 무엇에 대한 정확도인지 반드시 정의한다.

| 지표 | 정의 |
|---|---|
| 설정 오류 탐지 성공률 | 의도적으로 삽입한 오류 중 Trivy가 탐지한 비율 |
| CIS 매핑 일치율 | **직접 대응 가능한** Trivy 룰 중 CIS 항목과 올바르게 매핑된 비율 |
| Confidence 등급 일치율 | Scorer 판정과 사전 정의된 Risk Rubric의 일치율 |
| 패치 성공률 | V1~V6를 전부 통과한 패치의 비율 |
| **기만적 패치 탐지율** | **Trivy는 통과했으나 V6가 잡아낸 패치의 비율 (Seeded 세트 기준)** |
| 정상 기능 보존율 | 패치 후 허용돼야 할 트래픽이 정상 동작한 비율 |
| Policy 위반률 | 화이트리스트를 벗어난 패치의 비율 |
| MTTR | 자동 처리 시간과 사람 승인 대기 시간을 **분리** 측정 |
| baseline 비교 | Rule-based 대비 성공률·커버리지·패치 수정 횟수 |
| 실패·오탐 유형 | 유형별로 분류해 보존 |

### 14.2 안전 기준 (성능과 무관하게 반드시 만족)

- 승인 없는 `terraform apply` 자동 실행: **0건**
- 프로덕션 계정 대상 실행: **0건**
- Policy 화이트리스트 위반 패치 병합: **0건**

> "패치 후 정상 기능 손상 0건"은 안전 기준이 아니라 **측정 지표**다(14.1의 정상 기능 보존율). 0건을 안전 기준으로 걸면 손상 사례를 보고하기 어려워진다.

### 14.3 실험 타당성

- 평가 지표와 반복 횟수를 결과 확인 전에 고정한다. **결과를 보고 기준을 바꾸지 않는다**
- 개발용 시나리오와 평가용 시나리오를 분리한다
- **실패 사례와 오탐을 삭제하거나 숨기지 않는다.** 원인과 함께 보존한다
- **0 FAIL을 우회로 판정하기 전에 반드시 대조군을 둔다** (0.2절 검증 A·B 방식)
- 도구 버전을 기록한다 (현재: Trivy 0.74.0 / Terraform 1.16.1)

---

## 15. 종료 조건

```
if scanner_clean              # V1 + V2
and plan_diff_within_policy   # V4 + V5
and intent_satisfied          # V6  ← 실효 상태 검증
and aws_state_verified        # V7  ← 실제 배포 확인
and service_healthy           # V8
and approval_satisfied(confidence_level):
    SUCCESS

elif deceptive_suspected:     # V6 실패
    BLOCK_AND_REPORT          # PR 생성하지 않음

elif revision_count < 2:
    REVISE_PATCH

else:
    FAIL_AND_REPORT
```

기만적 패치가 감지되면 **낮은 등급으로 통과시키는 것이 아니라 차단한다.**

---

## 16. 축소·대체 경로

| 실패 지점 | 축소·대체 경로 |
|---|---|
| V6 Intent Oracle 구현 난항 | SG 단일 유형으로 범위를 좁히고, IAM은 "무조건 사람 승인" 정책으로 대체 |
| 06-prefix-list 케이스 탈락 | 01·08만으로 Seeded 세트 구성. 핵심 주장에 영향 없음 |
| Confidence Scorer 판정 불안정 | 등급을 2단계(자동 가능 / 승인 필요)로 단순화 |
| 설정 오류 다중 유형 확장 실패 | 보안그룹 1개 유형의 완전한 폐루프를 보존하고 확장 실패를 정직하게 보고 |
| Terraform 자동 패치 불안정 | 패치는 `plan` 미리보기까지만 자동화, 실제 코드 수정은 반자동으로 축소 |
| AWS 샌드박스 자원 제약 | V7을 LocalStack 등으로 일부 대체하고 한계를 명시 |
| 컨테이너 축(선택 확장) 실패 | 핵심 vertical slice에 영향 없음. 제거하고 보고 |
| 10주차까지 전체 통합이 불안정 | High-confidence 1개 유형의 완전한 폐루프만이라도 안정 동작하도록 범위 최소화 |

---

## 17. 최종 완료 정의

1. 설정 오류 2개 유형(보안그룹, IAM 과다권한)을 반복 가능하게 탐지한다
2. Trivy 결과를 CIS 직접 대응 근거와 함께 Evidence Bundle로 구조화한다
3. **Confidence Scorer가 Risk Rubric으로 등급 상한을 결정하고,** LLM 제안 등급이 상한을 넘으면 강제 하향한다
4. **Intent Oracle이 Trivy를 통과한 기만적 패치를 탐지하고 차단한다**
5. 승인 절차를 거쳐 패치가 병합되고, **실제 AWS 상태 실측으로** 효과를 검증한다
6. Rule-based baseline과 같은 기준으로 비교한다
7. 결과는 성공률뿐 아니라 실패·오탐 사례 분석과 함께 제시한다
8. 11월 16일까지 전체 파이프라인이 동작하고, 11월 23일까지 실험이 마무리된다

더 많은 스캐너를 나열하는 프로젝트가 아니다. **스캐너 통과가 곧 보안 개선이 아니라는 실측 근거 위에서**, 패치의 실효 상태를 독립적으로 검증하고 위험도에 따라 자율성을 다르게 부여하는 시스템을 만들고, 그 판단이 실제로 안전하고 효과적인지 정량적으로 검증하는 프로젝트다.

---

## 부록 A. 확인 필요 항목

추측으로 채우지 않고 확인해야 하는 것들.

- [ ] 06-prefix-list가 배포 후 실제로 포트를 개방하는지 (sandbox `apply` + `describe-security-groups`)
- [ ] Trivy `AVD-AWS-*` 룰 중 CIS AWS Benchmark와 직접 대응 가능한 항목 목록
- [ ] LLM이 01 같은 우회 패턴을 자연 발생시키는지 (6주차 여유 시)
- [ ] IAM 시나리오에서 Intent Oracle을 어디까지 구현할 수 있는지 (실효 권한 계산 난이도)
- [ ] 심사위원이 라이브 데모를 요구하는지

## 부록 B. 참고 문헌

- Alsaid, M., Nebolisa, C., Abbas, F. — *TerraProbe: A Layered-Oracle Framework for Detecting Deceptive Fixes in LLM-Assisted Terraform Security Repair*, arXiv:2606.26590, 2026
- Monperrus, M. — *Automatic Software Repair: A Bibliography*, ACM Computing Surveys, 2018 (오라클 문제)
- Pearce, H. et al. — *Asleep at the Keyboard?*, IEEE S&P, 2022 (LLM 생성 코드의 보안 결함)
- CIS Amazon Web Services Foundations Benchmark
