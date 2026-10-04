# 프로젝트 전면 재검토 — 4주차 (2026-09-22)

> 역할: Cloud Security / DevSecOps 아키텍트 + 기술 검증자 + 심사위원 + 개발 보조. 칭찬 없이, 확인된 것과 아닌 것을 나눠 쓴다.
> 입력: 9/8 A 의 Claude 대화(TerraProbe → V1~V8·Validity/Risk 분리·seeded 세트 결정), 운영계획서, 9/22 지도교수 피드백, 저장소 실측(`docs/PLAN_CHECK_2026-09-21.md`, `docs/CROSS_VERIFICATION_2026-09-22.md`).
> 표기: **[확인됨]** = 이 저장소에서 실측/재현됨, **[확인 필요]** = 출처나 실측이 아직 없음, **[NO]** = 하지 않기로 판단.

---

## 1. 프로젝트 한 줄 정의

**"AI 가 고쳐 준 Terraform 보안 패치가 진짜 고친 건지, 스캐너만 속인 건지를 사람 대신 여러 겹으로 검증하고, 위험도에 따라 PR 까지만 자동으로 만들어 주는 CI 검증 게이트."**

기업 관계자용 한 줄: *"Copilot·Claude 같은 도구가 제안한 IaC 보안 수정을 배포 전에 '실효성(effective state)' 기준으로 자동 심사해, 통과한 것만 PR 로 올리고 나머지는 근거와 함께 차단합니다."*

제목(안): **AI 가 생성한 Terraform 보안 패치의 실효성 검증 자동화 구현** — 9/22 교수 언급 문구. 운영계획서 과제명과 다르므로 팀이 하나로 확정해야 한다 (DECISIONS D-1 갱신 필요).

## 2. 실제 기업 수요 — 있는가

**있다고 볼 근거 (검증된 것만):**
- 스캐너를 통과하는 기만적 패치가 실제로 만들어진다는 것은 우리가 **직접 재현**했다 [확인됨]: Trivy 0.74.0 은 `0.0.0.0/1+128.0.0.0/1` 분할, prefix list 우회, IAM `Action:"*"`(AVD-AWS-0057 deprecated), `s3:*` 나열, `Resource:"*"` 유지, 역할에 다른 정책으로 권한 이동 등을 잡지 못한다 (`experiments/ORACLE_RESULTS.md`, `docs/worklog/2026-09-22.md`). 이런 패치가 CI 를 통과하면 "고쳤다" 는 기록만 남고 실제 권한은 그대로다.
- 선행 연구(TerraProbe, A 의 9/8 대화 요약)는 LLM 패치의 상당수가 스캐너·validate·plan 을 다 통과하면서 보안 의도는 안 지켰다고 보고했다 [확인 필요 — 원문 링크·수치를 `docs/` 에 남겨야 인용 가능].
- AI 코딩 도구가 IaC 수정을 제안하는 흐름 자체는 이미 일반화됐다(Copilot, Claude Code, Amazon Q Developer 등). "제안을 어떻게 믿나" 는 도구가 늘수록 커지는 문제다.

**없을 가능성 (정직하게):**
- 정책 코드(OPA/Conftest, HCP Terraform 의 Sentinel/OPA run task)를 이미 plan JSON 에 대해 운영하는 조직은 우리 V5/V6 에 해당하는 검사를 **직접 써서** 갖고 있을 수 있다. 그런 조직에게 우리 것의 증분 가치는 "미리 만들어진 실효 상태 오라클 + 위험도 게이트 + 기만 패치 테스트 세트" 정도다.
- 규모가 큰 조직은 CSPM(Wiz, Prisma Cloud 등)이 배포 후 상태를 잡아 준다. 우리 것은 **배포 전** 게이트라 역할이 다르지만, "배포 후에 잡으면 되지 않나" 는 반박에는 "잡히기 전까지 열려 있는 시간 + 되돌리는 비용" 으로만 답할 수 있다.
- 우리 오라클이 다루는 범위(SG, IAM Tier 1, 예정된 S3)는 좁다. 범용 제품이 아니라 **특정 오류 유형에 대한 검증 게이트**다.

**결론:** 수요는 "AI 패치 생성" 이 아니라 **"AI 패치 검증·통제"** 에 있다. 우리 프로젝트의 정체성도 그쪽이다 (제목·계획서·코드 모두 이미 그렇게 돼 있다). "AI 를 썼다" 는 가치가 아니고, "AI 를 못 믿는다는 전제로 무엇을 자동으로 확인할 수 있나" 가 가치다.

## 3. 기존 솔루션과의 역할 차이

| 도구 | 하는 것 | 우리와의 관계 | 근거 상태 |
|---|---|---|---|
| Trivy (`trivy config`) | HCL/plan JSON 을 룰(Rego)로 정적 스캔. 커스텀 Rego 체크 가능 | **입력이자 V1/V2**. 대체가 아니라 그 위에 얹는다. 룰 사각을 우리가 실측했다 | 실측 [확인됨] |
| Checkov / (구)tfsec | 같은 부류의 정적 스캐너 | 스캐너를 바꿔도 우리 V5~V6 는 그대로 쓸 수 있어야 한다 (아직 Trivy 만 연동) | tfsec→Trivy 통합은 공지된 사실 [확인 필요: 출처 링크] |
| OPA / Conftest, HCP Terraform Sentinel·OPA run task | plan JSON 에 대한 정책 코드. 원하는 검사를 직접 작성 | 가장 가까운 대체재. 차이: 우리는 (a) SG CIDR 합집합·prefix list 전개·ENI/역할 합산 같은 **실효 상태 계산을 미리 구현**, (b) intent(승인 출처/권한)와 비교, (c) 위험도 게이트·근거 기록까지 한 묶음. **정책 코드를 이미 잘 쓰는 조직엔 증분 가치가 작다** | 기능 존재는 일반 지식, 세부는 [확인 필요] |
| Snyk IaC, Prisma Cloud(Bridgecrew) 의 자동 수정 PR, Copilot Autofix, Amazon Q Developer | 스캔 + 수정 제안/PR 생성 | **우리가 검증하려는 대상 쪽**이다. 이들이 낸 패치를 우리 게이트에 넣는 그림. 이들에 우리 V6 같은 실효 검증이 있는지는 확인 안 됐다 — "없다" 고 말하지 않는다 | [확인 필요] |
| CSPM (Wiz, Prisma, AWS Security Hub) | 배포 후 실제 상태 점검·자동 교정 | 우리 V7/V8 과 겹치지만 우리는 배포 전 게이트가 본체. 보완 관계 | [확인 필요] |
| AWS IAM Access Analyzer 정책 검증 / `simulate-custom-policy` | IAM 정책 검증·시뮬레이션 | V7-IAM 에서 **써야 할 것**(직접 만들지 말 것). 배포 전 정적 검사는 우리 Tier 1 | 서비스 존재 [확인 필요: 문서 링크] |

"그냥 Trivy 쓰면 되지 않나?" 에 대한 답 (한 문장): *Trivy 는 "코드가 룰 패턴에 걸리나" 를 보고, 우리는 "패치 후 실제로 어디까지 열려 있나/어떤 권한이 남나" 를 계산한다. Trivy 0.74.0 이 놓치는 우회 8종을 우리 오라클이 잡은 표가 `ORACLE_RESULTS.md` 다.* 그리고 정직한 덧붙임: *같은 검사를 Trivy 커스텀 Rego 로 짤 수도 있다(OPA 에 `net.cidr_merge` 가 있다 [확인 필요]). 우리는 그것을 intent 와 연결하고 게이트로 묶은 것이며, 결과를 커스텀 Rego 로 내보내는 것이 자연스러운 후속이다.*

## 4. 차별점 ("AI 썼다" 제외)

1. **실효 상태 오라클(V6)** — 스캐너 출력과 독립. SG: CIDR 합집합·prefix list 전개·같은 ENI 의 SG 합산·참조 SG. IAM: Allow 문 Action×Resource ⊆ 승인 집합, 필수 권한 유지, 역할 단위 합산, 신뢰 정책 전체 개방. **실측: SG 16/16·오탐 0, IAM 스캐너 사각 8건 탐지** [확인됨].
2. **Validity 와 Risk 를 분리한 게이트** — 검증 FAIL 이면 위험도와 무관하게 차단, 검증 통과 후에만 위험도로 검토 수준 결정. 무인 apply 없음. LLM 확신도는 입력이 아님(있어도 낮추는 용도만) [확인됨: `review/level.py`, `policy/gate.py`].
3. **기만 패치 테스트 세트 + 스캐너 사각 실측** — 논문이 사람 판정으로 한 것을 우리는 plan 기반 자동 판정으로, Trivy 에 대해 측정했다 [확인됨]. 이 데이터 자체가 산출물이다.
4. **근거 기록** — 후보마다 입력 원문·diff·계층별 판정·위험도 요인·검토 수준이 `data/reviews/<id>/` 에 남는다 (Audit Log) [확인됨].
5. **배포 후 실측 연결(V7/V8)** — 코드·연결은 됐지만 **실행 0회** [확인됨: 미실행]. 실행 전까지 차별점으로 말하지 않는다.

## 5. 최종 Scope (YES / OPTIONAL / NO)

| 항목 | 판정 | 이유 |
|---|---|---|
| 과다 개방 Security Group (탐지→후보→V1~V6→등급) | **YES (됨)** | 완료·실측 |
| IAM 과다 권한 (Tier 1: `s3:*`/`*`/`Resource:*`/역할 합산/신뢰 정책) | **YES (배포 전 됨)** | 완료·실측. V7-IAM 은 배포 후 |
| Public S3 (public access block, ACL, 버킷 정책 Principal *) | **YES — 6~7주차** | 계획서 3종 중 마지막. A 가 fixture 를 손으로 먼저 쓴 뒤 B 가 오라클. SG/IAM 배포 후 검증이 먼저 |
| PR 자동 생성 → 사람 승인 → apply → V7/V8 | **YES — 이번 달 안 1회 실측** | 코드 있음, 실행 0회. 이게 없으면 "파이프라인" 이 아니다 |
| 규칙 기반 baseline 비교 | YES (됨) | E1 축 |
| Claude Code 후보 수집 (SG 7 + IAM 5 케이스 × 3) | **YES — B, 이번 주 시작** | LLM 축이 0 |
| 프롬프트 요인 실험(의도 있음/없음) | OPTIONAL | 9/8 대화가 지목한 싼 후속. 36개 더 받아야 함 → 10월 말 여유 시 |
| Container CVE (`trivy image`) | **NO** | 연구 질문(IaC 패치 실효성)과 무관. 발표 메시지 흐림. 3인·8주 |
| Kubernetes / EKS | **NO** | 동일 |
| LangChain / LangGraph | **NO** | 후보 생성은 사람이 새 세션으로 요청(D-5). 상태 머신은 Python 함수로 충분(이미 그렇게 됨) |
| 대시보드 / UI | **NO** | results.md + review.md 로 충분 |
| WSL 자동 실행기 | OPTIONAL (1시간, 됐음) | `scripts/run_experiments_wsl.cmd`. 편의 기능이지 핵심 아님 |
| Trivy 커스텀 Rego 로 오라클 일부 내보내기 | OPTIONAL (11월) | "기존 도구로 쓰게 하는" 제품 방향. 시간 남으면 |
| 유료 LLM API 연동 | **NO** | D-5. 1주차 코드는 휴면 |

## 6. 최종 Architecture (구현된 것 기준)

```
[A] Terraform 원본 (취약)            [사람] intent (승인 출처 / 승인 권한 — 실행 전 고정)
        │                                        │
        ▼                                        │
  trivy config ──► finding 선택 ──► Evidence(원문·finding·intent) ──► 후보 생성
                                                      │            ├─ rule_based (baseline, 코드)
                                                      │            └─ Claude Code 새 세션 (사람이 프롬프트 붙여넣기, D-5)
                                                      ▼
   Stage1 텍스트 정책 ─ 파일 범위·금지 토큰·리소스 생성/삭제/타입 (policy/patch_policy.json)  → 위반 = POLICY_BLOCKED
   V1  Trivy 재스캔: 대상 finding 사라짐?      V2  전체 스캔: 신규 CRITICAL/HIGH 없음?
   V3  fmt(경고) / validate(차단)              V4  plan (오프라인, provider override)
   V5  plan JSON diff: 허용 속성·타입·delete/replace 만?
   V6  Intent Oracle: SG 실효 허용 대역 / IAM Action×Resource ⊆ 승인 집합  (Trivy 와 독립)
        │  FAIL → BLOCKED   UNKNOWN/NOT_RUN → PENDING(사람)   전부 PASS → ↓
   Risk (결정론적 기준표 v2, plan+텍스트 max) → LOW: LIGHT_REVIEW / MEDIUM: FULL_REVIEW / HIGH: REPORT_ONLY
        │
   iacpatch pr --review <id>  → 브랜치·커밋·PR 본문(검증 표 첨부)  [사람이 --execute]
        │
   [사람] 리뷰·승인·병합 → [사람] terraform apply (샌드박스)
        │
   V7 describe-security-groups / (IAM 은 미구현) → 같은 오라클 재판정     V8 승인 출처에서 열림·승인 밖에서 막힘
   postdeploy --review <id> → VERIFIED / DEPLOY_FAILED(→ recover) / UNVERIFIED
   기록: data/reviews/<id>/ (입력 원문, diff, 계층별 판정, 위험도 요인, 검토 수준, 배포 후 결과)
```

구성 요소 ↔ 코드: `src/iacpatch/review/flow.py`(오케스트레이션), `review/local_verify.py`(V1~V4 실행), `verify/layers.py`(V5), `verify/sg_oracle.py`·`verify/iam_oracle.py`(V6), `policy/validator.py`(Stage 1), `policy/risk.py`·`review/risk_text.py`(위험도), `review/level.py`(게이트), `tools/github.py`(PR), `postdeploy.py`(V7/V8/복구).

## 7. AI Security Guardrail (구체)

**파이프라인 안의 LLM 출력에 대해** (구현됨):
- LLM 은 후보 파일만 낸다. 판정 권한 없음. 후보의 `proposed_autonomy` 는 기록만, 등급을 올릴 수 없다 [확인됨].
- 텍스트 정책: 편집 가능 파일 `*.tf` 만, 보호 경로(`policy/`, `tests/`, `src/`, `.github/`, `scripts/`, `docs/`, `experiments/`, `data/`) 수정 불가, `provider.tf`/`versions.tf`/`backend.tf` 수정 불가, 금지 토큰(`provisioner`, `local-exec`, `null_resource`, `data "external"`, `backend "` …), 허용 목록 밖 리소스 타입 생성/변경 금지, 삭제·교체 금지, 파일 2개·64KB 상한 [확인됨: `policy/patch_policy.json`].
- 검증 FAIL 이면 위험도와 무관하게 BLOCKED. UNKNOWN 은 PASS 가 아니다 [확인됨].
- 무인 apply/merge 는 코드 경로 자체가 없다. `pr --execute`, `postdeploy --execute`, `recover --execute` 는 전부 사람이 친다 [확인됨].

**Claude Code 를 개발 도구로 쓸 때** (2026-09-22 추가, `CLAUDE.md` + `.claude/settings.json`):
- 허용: `terraform fmt/validate/init -backend=false/plan/show`, `trivy config`, `git status/diff/log`, 단위 테스트, `scripts/*`.
- 거부: `terraform apply/destroy`, `aws` CLI 전부, `sudo`, `rm -rf`, `git push`/main 수정/merge, `curl|wget`, 환경변수 출력, `.env`/`~/.aws`/`*.tfstate`/`terraform.tfvars` 읽기, `policy/`·`tests/fixtures/`·`results-history/`·`.github/` 쓰기.
- 후보 생성용 세션(`scripts/cc_batch.sh`, 사람이 시작): 빈 임시 디렉터리 + 도구 전부 금지 + 1턴 + 고정 프롬프트. 저장소·자격증명에 닿을 수 없다. **[확인 필요: 플래그 이름은 팀 PC 에서 `claude --help` 로 확인, 첫 실행은 `--dry-run`]**
- Claude Code 에 AWS 권한을 주지 않는다. AWS 프로필은 사람 터미널에만.

**개발 과정에서의 AI 사용 원칙** (교수 지적 반영, `docs/AI_CONSTRAINTS.md` 4절):
- 핵심 Terraform(취약 원본·정답)은 사람이 먼저 쓴다. AI 는 검토·오류 수정·테스트 확장.
- AI 가 쓴 핵심 로직은 팀원 1명 이상이 walkthrough 문서로 설명한다. 못 하면 핵심 코드로 인정하지 않는다.
- AI 산출물은 다른 세션·다른 방법으로 교차검증하고 사람이 재현·서명한다 (`docs/CROSS_VERIFICATION_2026-09-22.md` — 1회차에서 false PASS 7종이 나왔다. 이 원칙이 왜 필요한지의 증거다).

## 8. Validator 설계 (무엇을 검사하고 언제 실패시키나)

| 단계 | 검사 | 실패 조건 | 구현 | 실측 |
|---|---|---|---|---|
| Stage 1 변경 범위 (텍스트) | 파일 수·크기, 보호 경로, 금지 토큰, 리소스 블록 생성/삭제/타입, provider·terraform 블록 | 하나라도 위반 → POLICY_BLOCKED (검증 안 함) | `policy/validator.py` | seeded prefix-list·second-policy·managed-policy 차단 |
| V1 | 대상 finding 제거 | 재스캔에 같은 (룰, 파일, 리소스) 있음 → FAIL | `verify/layers.py` | |
| V2 | 신규 finding | CRITICAL/HIGH 신규 → FAIL, 그 외 경고 | 〃 | 9/8 실측대로 노이즈 많아 차단은 상위 심각도만 |
| V3 | `fmt -check`(경고) / `validate` | validate 실패 → FAIL | 〃 | |
| V4 | `plan` (오프라인 override) | plan 실패 → FAIL | 〃 | |
| V5 | plan JSON diff | 허용 속성 밖 변경, 허용 타입 밖 생성, delete/replace, provider diff → FAIL | 〃 | inline_policy·assume_role_policy 변경 차단 |
| V6 | Intent Oracle | SG: 승인 밖 출처 허용(EXCESS)/필수 접근 사라짐(MISSING) → FAIL. IAM: 승인 밖 (action,resource)/필수 권한 누락/신뢰 정책 전체 개방 → FAIL. 판단 불가 → UNKNOWN | `verify/sg_oracle.py`, `iam_oracle.py` | SG 16/16, IAM 8 사각 탐지 |
| V7 | 배포 후 실측 | describe 결과를 같은 오라클로 → FAIL | `postdeploy.py` | **0회** |
| V8 | 통신 | 승인 출처에서 막힘 or 승인 밖에서 뚫림 → FAIL; 승인 밖 관측 없음 → UNKNOWN | 〃 | **0회** |

"Semantic Guardrail"(요구 8-Stage 6) 은 V5(destroy/replace/예상 밖 생성)+V6(공개 노출·와일드카드·포트) 로 이미 나뉘어 있다. 별도 단계를 더 만들지 않는다.

## 9. Confidence Gate (LLM 자기확신 의존 금지)

- 입력은 전부 Validator 결과와 결정론적 요인이다: V1~V6 판정, 텍스트 정책, 변경 리소스 수·타입, 새 리소스 수, 부착 지점, egress·핵심 밖 속성, 교체 유발 속성, 삭제/교체, provider 변경, diff 크기, 파일 수, 오라클 caveat, IAM 여부, 신뢰 정책 변경 (`docs/RISK_RUBRIC_V2.md`).
- 계산: hard HIGH 조건 → HIGH. 아니면 점수 ≤2 LOW / 3~5 MEDIUM / ≥6 HIGH. IAM 변경은 최소 MEDIUM(floor). plan 기반·텍스트 기반 둘 다 있으면 max.
- 행동: **HIGH = REPORT_ONLY**(패치 반영 금지, 리포트만) / **MEDIUM = FULL_REVIEW**(PR + 검증표 첨부 + 승인 필수) / **LOW = LIGHT_REVIEW**(PR 자동 생성, 1인 확인 후 병합). 검증 FAIL 은 등급과 무관하게 BLOCKED, UNKNOWN/NOT_RUN 은 PENDING. 어느 등급에도 자동 merge/apply 없음.
- 요구서의 HIGH/MEDIUM/LOW 명칭은 "자동화 수준" 이고 우리 코드의 LOW/MEDIUM/HIGH 는 "위험도" 다. **대응: 요구서 HIGH = 위험도 LOW(LIGHT_REVIEW), 요구서 MEDIUM = 위험도 MEDIUM(FULL_REVIEW), 요구서 LOW = 검증 실패/HIGH(BLOCKED·REPORT_ONLY)**. 발표에서 용어를 하나로 통일해야 한다 — 위험도 이름을 그대로 쓰고 "자동화 수준" 은 검토 수준 이름(LIGHT/FULL/REPORT_ONLY/BLOCKED)으로 부르는 것을 권한다.
- **Confidence calibration** (요구 16): 검토 수준별로 "실제로 맞는 패치였던 비율" 을 낸다 — LIGHT_REVIEW 로 판정된 후보 중 ground-truth 라벨이 correct 인 비율, FULL_REVIEW 중 correct 비율, BLOCKED 중 deceptive/breaks/unapproved 비율. `metrics.py` 에 이 표를 추가하는 것이 C 의 다음 작업이다 (지금은 라벨 일치·등급 일치만 있다).

## 10. 표준 보안 가이드 매핑

원칙: **"준수" 가 아니라 "관련 통제 항목에 매핑"**. SK쉴더스 자료는 Terraform 전용 표준이 아니라 AWS 클라우드 보안 점검 가이드이며, 그 항목을 Terraform 설정과 Trivy 룰, 우리 Validator 에 연결한다. 표의 뼈대와 확인된 항목은 `docs/STANDARDS_MAPPING.md`.

확인된 것 [확인됨]: SK쉴더스 『2024 클라우드 보안 가이드』(AWS/Azure/GCP 3종, 2024-04 발간, 자가 점검 체크리스트·ISMS-P 연계) — AWS 편 **3.1 보안 그룹 인/아웃바운드 ANY 설정 관리** (양호: 포트가 Any 로 허용돼 있지 않음 / 취약: Any 허용) ← 우리 SG 시나리오와 직접 대응. 나머지 항목(권한 관리 2.x 의 IAM 정책 항목, S3 항목)은 PDF 를 받아 **팀이 원문 번호·문구를 채운다** — 내가 추측으로 채우지 않는다.
[확인 필요]: CIS AWS Foundations Benchmark 의 정확한 버전·항목 번호(5.2/5.3 SG, 1.16 IAM `*:*` 정책), KISA 2024 클라우드 취약점 점검 가이드 항목, AWS Well-Architected Security Pillar(SEC03 권한 관리, SEC05 네트워크 보호) 문항 번호, AWS Prescriptive Guidance(Terraform AWS Provider best practices) — 각자 원문 링크를 붙여 채운다.

## 11. 이번 주(4주차, 9/22~9/28) 작업 — A/B/C

**이번 주에 반드시 끝낼 것 (사람이 직접 하는 것 위주):**

**A — AWS / Terraform**
1. 샌드박스 네트워크 구성도를 **손으로** 그린다(draw.io 등): VPC, public/private subnet, IGW, route table, SG(sg-baseline), EC2, IAM role, S3. → `docs/ARCHITECTURE_AWS.md` + 이미지. 각 구성 요소가 왜 있는지 한 줄씩.
2. 같은 구성을 Terraform 으로 **직접** 작성: `infrastructure/sandbox-net/` (provider, variables, outputs, VPC/subnet/IGW/route/SG/EC2). `fmt` → `validate` → `plan` 까지. apply 는 계정·예산 알림·MFA·작업용 IAM 사용자가 준비된 뒤(README 1주차 항목) 사람 승인으로.
3. **사람이 만든 ground truth**: `ground-truth/{sg,iam,s3}/vulnerable/main.tf` 와 `expected_safe/main.tf` 3쌍. 각각 `trivy config` 전/후 표를 손으로 정리 (`ground-truth/README.md`). 이게 18절의 답이다.
4. 계정 증거: 예산 알림·MFA·IAM 사용자 설정 화면 캡처 → `docs/AWS_SANDBOX_SETUP.md`.

**B — AI / Oracle / 위험도**
1. `docs/walkthroughs/B.md`: `sg_oracle.py`, `iam_oracle.py`, `level.py` 를 **자기 말로** 설명 + 예제 하나를 손으로 추적(입력 plan → 집합 계산 → 판정). 교수 질문 대비.
2. Claude Code 후보 수집 시작: `cc_prompt.py --all` → SG 00-baseline, IAM iam-00-literal-list 두 케이스 × 3회를 새 세션에 직접 붙여넣어 받는다. `cc_batch.sh` 는 `--dry-run` 으로 플래그 확인만.
3. LLM 후보의 `expected`·`expected_risk` 를 **실행 전에** 적는다(블라인드). 실행 후 바꾸지 않는다.
4. 교차검증 1회차 항목 5개 재현·서명 (`docs/CROSS_VERIFICATION_2026-09-22.md`).

**C — CI / Validator / 평가**
1. 브랜치 push(B 가 번들 전달) → `bc-unit-tests.yml` Actions 첫 실행 기록 → `docs/CI_FIRST_RUN.md`.
2. **직접 작성** 미니 검증기: `student/v1v2_compare.py` — Trivy JSON 두 개를 읽어 대상 finding 제거 여부와 신규 finding 을 세는 30~50줄. 저장소의 V1/V2 결과와 같은지 비교(독립 검산 + 학습).
3. `docs/EVALUATION_PLAN.md`: 16절 지표를 results.md 열과 대응시키고, 검토 수준별 calibration 표 형식을 정한다. 표본: seeded 24 + 규칙 14 + LLM 36(목표).
4. V8 체크 정의 초안: `policy/intent/sg-baseline.v8.example.json` 을 샌드박스 값으로 채울 계획(승인 밖 관측 지점 = 별도 SG 의 임시 EC2).

**팀 공통 (30분 회의)**: 제목 확정(D-1 갱신), 위험도 기준표 v2 OK, SK쉴더스 PDF 나눠 읽고 매핑표 채우기(A: SG, B: IAM, C: S3), 다음 주 배포 후 실측 일정(A 의 apply → `postdeploy --execute`).

**이번 주에 하면 안 되는 것:** S3 오라클 코드, Container/EKS, LangGraph, 대시보드, 자동 PR 실행, IAM Tier 2, 새 스캐너 추가.

### 11.1 지도교수 9/22 메모 반영 — 이번 주 추가 + 차주(5주차, 9/29~10/5)

메모 원문 항목 → 우리 대응:

| 교수 메모 | 대응 | 담당 |
|---|---|---|
| "제목 확정 빨리할 것" — 메모 문구 "AI가 생성한 테라폼 보안패치의 실효성 검증 자동화 검증 구현" | `docs/DECISIONS.md` D-12 후보(**'검증' 한 번**으로 정리). 팀 회의에서 OK → 교수께 원문 그대로가 맞는지 확인 → README·운영계획서 통일 | B, 이번 주 |
| "의도적 결함 Terraform → Trivy 스캔 → 등급 → 높은 등급이면 실패 → 실 코드 반영 방지" | 배포 전 게이트(V1/V2 → BLOCKED → PR 거부)는 있음. **CI required check(trivy 등급 게이트) 는 Actions 실행 0회** → C-1 에 포함. 정리: `docs/TRIVY_CIS_MAPPING.md` 2절 | C |
| "AI 에이전트로 실험 자동화 → harness 활용 제약사항 만들 것" | `CLAUDE.md` + `.claude/settings.json` + `scripts/cc_batch.sh`(미검증) — `docs/AI_CONSTRAINTS.md`. 차주까지 cc_batch 첫 실행 기록 | B |
| "보안패치 어떻게 구현?" | `docs/PATCH_GENERATION.md` (생성 경로 3개 + 같은 검증) | B (각자 읽고 설명 연습) |
| "기본 기술 스택 공부가 되도록 AI 활용 조정 / 요구사항 주면 Terraform 만들 수준" | `docs/LEARNING_OUTCOMES.md` 체크리스트 + A 의 `infrastructure/sandbox-net/` 직접 작성 (11절 A-1·A-2) | A·B·C |
| "Terraform 으로 만들 수 있는 취약점의 한계? → 권한·접근 허용 범위 오류로 범위 / 이 정도에 자동화 도구까지 필요한가? 표준 가이드 있는가?" | 범위 = SG·IAM·S3 (D-10). "왜 자동화" 의 답은 `experiments/WHY_THIS_GATE.md`(스캐너 통과 ∧ 실제 개방 5+8건) + 표준 근거 `docs/STANDARDS_MAPPING.md`(SK쉴더스·CIS·Security Hub) | 발표 준비 |
| "SK쉴더스 테라폼 보안가이드 참고" | `docs/STANDARDS_MAPPING.md` 2절 담당표(A SG / B IAM / C S3) — **원문 PDF 로 채움** | A·B·C, 이번 주 |
| **차주 1: "Trivy ↔ CIS AWS 벤치마크 매핑테이블 작성"** | 뼈대 + Trivy 자체 선언 태그(실측) `docs/TRIVY_CIS_MAPPING.md` (`scripts/trivy_check_meta.py`). CIS 원문 열은 **사람이** 채움(판 확정 → 번호·제목 원문 그대로 → 확인자) | B, 차주 |
| **차주 2: "실효성 검증(v2계층) 구현"** | 교수의 '2계층' = (1층) Trivy 스캔·등급 게이트, (2층) 실효성 검증 — 우리 V6(+V5) 에 해당하며 SG·IAM Tier 1 은 **이미 구현·실측**. 차주 할 일: ① 사람이 만든 `ground-truth/` 3쌍에 그대로 돌려 표 만들기, ② 계층 근거 설명 연습(`docs/WHY_8_LAYERS.md`), ③ CI 등급 게이트 첫 실행. **확인 필요:** 메모의 "v2" 가 우리 V2(새 finding 검사)를 뜻하는지 '두 번째 계층' 인지 교수께 확인 | B·C, 차주 |
| "8개 계층이 어디서 나온 건지 근거와 대응 논리" | `docs/WHY_8_LAYERS.md` — 5(TerraProbe L1~L5) + 1(V6, 실측 근거) + 2(V7/V8). 각자 담당 계층을 자기 말로 설명할 수 있어야 함 (`docs/walkthroughs/`) | A·B·C |

한 번 클릭 실행기(`IaCPatch.bat`, D-13)는 발표·시연용 껍데기이고 판정 코드는 그대로다. 기능 추가로 세지 않는다.

## 12. Windows → WSL 실행 구조 (최소)

```
scripts\run_experiments_wsl.cmd  (더블클릭)
  └─ wsl.exe --cd "<이 저장소의 Windows 경로>" -e bash -lc "bash scripts/run_experiments.sh"
        └─ WSL Ubuntu: python3 + tools/ (trivy, terraform — bash scripts/setup_tools.sh 로 WSL 안에 설치)
              └─ 8단계 실험 → experiments/RESULTS_SUMMARY.md, ORACLE_RESULTS.md, data/reviews/<id>/
```
- 이미 있는 Windows 네이티브 경로(`run_experiments.bat` → PowerShell → Python)도 그대로 유효하다. 둘 중 하나만 쓰면 된다.
- 주의: `/mnt/c` 아래에서 `terraform init` 은 느리다(9/8 대화에서 2.5GB 경험). 저장소를 WSL 홈(`~/`)에 클론해 두고 .cmd 는 그 경로를 가리키게 바꾸는 게 낫다 — `.cmd` 의 `--cd` 값을 `~/cloud-security-capstone` 로 바꾸면 된다.
- 이 실행기는 편의 기능이다. 1시간 이상 쓰지 않는다. **[확인 필요: 팀 PC 에서 첫 실행]**

## 13. 최종 평가 방법

- **데이터셋**: (1) 사람이 만든 ground truth 3쌍(vulnerable/expected_safe, 이번 주 A), (2) seeded 우회 패턴 세트 SG 11 + IAM 13 (AI 세션 작성, 사람 검수 — 명시), (3) A 의 Trivy 우회 케이스 9, IAM probe 5, (4) LLM 후보 36 (Claude Code, 고정 프롬프트, 케이스당 3회). 개발용/평가용 분리(D-3), expected 는 실행 전 고정(D-4).
- **비교 실험**: E1 후보 출처별(규칙 기반 vs Claude Code) 성공률·기대 일치, E2 오라클 유무(V1 만 vs V1+V6)가 막는 건수, (선택) 프롬프트 의도 유무.
- **지표 ↔ results.md 열**: Patch Generation Success = 후보 생성됨/케이스; Terraform Validation Success = V3·V4 PASS 비율; Original Finding Removal = V1 PASS; New Finding Introduction = V2 FAIL 비율; Security Regression = V2 심각도 상승; Unsafe Change Detection = 기만/필수깨짐/승인밖 라벨 중 BLOCKED 비율; Destroy/Replace 발생률 = V5 plan_actions; 처리 시간 = 소요(s) (승인 대기 제외); Human Acceptance = 실제 PR 승인/거절 (배포 후 축 시작 후); **Calibration = 검토 수준별 실제 정답 비율** (9절); 규칙 기반 vs LLM = E1.
- 표본 수는 위 정도면 검토 수준별 30개 근처가 나온다. 더 늘리지 않는다.

## 14. 팀원에게 남는 기술 (프로젝트 후 "할 수 있어야 하는 것")

`docs/LEARNING_OUTCOMES.md` 에 체크리스트로. 요약:
- **A**: 손으로 그린 AWS 네트워크 구성도와 그것을 만든 Terraform(VPC~EC2~IAM~S3), `plan` 결과를 읽고 설명, 세 가지 취약 설정을 만들고 고치기, Trivy 결과 원문 읽기, 배포 후 `describe-*` 로 실제 상태 확인.
- **B**: IAM 정책 평가 논리(Allow/Deny/NotAction/Condition 이 왜 다른가), CIDR 집합 계산, 오라클 설계 원칙(스캐너와 독립·UNKNOWN 은 PASS 아님), 위험도 기준표 설계와 게이트, LLM 을 신뢰하지 않는 구조(권한 분리), 프롬프트 고정·재현성.
- **C**: GitHub Actions 파이프라인(unit test → scan → artifact), PR 흐름·브랜치 보호, Trivy JSON 구조·심각도·룰 ID·전후 비교, plan JSON diff, 평가 지표 설계와 CSV/표 생성, 실패 사례를 남기는 실험 기록.
- 공통: Terraform init/fmt/validate/plan/show -json, `trivy config` 동작 원리(내장 Rego 체크, `--skip-check-update`, deprecated 체크가 있다는 것), Git 브랜치/PR.

## 15. 취업 포트폴리오 관점

면접에서 말할 수 있는 것(과장 없이): "IaC 보안 스캐너(Trivy)의 룰 사각을 직접 실측했고, AI 가 만든 Terraform 패치를 plan JSON 기반 실효 상태 오라클과 위험도 게이트로 검증하는 CI 게이트를 구현했다. SG·IAM 두 유형에서 seeded 우회 패턴 24종에 대해 검출률을 측정했고, Claude Code 후보 N 개에 대해 검토 수준별 정답 비율을 냈다. 무인 apply 없이 PR 까지만 자동화했고 배포 후 실측(V7/V8)을 샌드박스에서 M 회 돌렸다."  — N, M 은 실제 숫자가 생기면 채운다. 지금 N=0, M=0 이다.
사업화: 작은 GitHub Action / CI 도구(“AI IaC fix verifier”)로 발전할 여지는 있으나, 정책 코드 도구와 CSPM 이 이미 있는 시장이라 **돈이 된다고 말하지 않는다**. 현실적 자산은 포트폴리오 + 재사용 가능한 오라클 라이브러리 + 기만 패치 데이터셋 + 측정 결과다.

## 16. 치명적인 문제점 (질문받으면 지금은 답이 약한 것)

1. **"실제 AWS 에서 돌려봤나?"** — 아니오. V7/V8·apply·PR 실행 0회. 이번 달 안 1회가 최우선.
2. **"LLM 패치가 실제로 몇 % 기만적이었나?"** — 측정 전(후보 0). seeded 숫자는 탐지력이지 발생률이 아니다.
3. **"AI 가 다 만든 것 아닌가?"** — 현재 코드 대부분이 B 의 AI 세션에서 나왔다. 이번 주부터 사람이 쓰는 ground truth·구성도·미니 검증기·walkthrough 로 답을 만든다. 숨기지 않는다.
4. **"seeded 우회 패턴도 AI 가 만든 거면 AI 가 자기 답을 채점한 것 아닌가?"** — 맞는 지적. 그래서 사람이 만든 ground truth 세트를 분리하고(18절), 교차검증 세션에서 실제로 false PASS 7종이 나왔음을 공개한다.
5. **"OPA/Sentinel 로 같은 걸 하면 되지 않나?"** — 가능하다. 우리 답은 3절. 커스텀 Rego 로 내보내는 후속을 열어 둔다.
6. **"IAM 은 Tier 1 만 되는데 그게 IAM 검증인가?"** — Deny/Condition/NotAction/관리형 정책은 UNKNOWN(사람 검토)이다. "IAM 전체" 라고 말하지 않는다. V7-IAM(시뮬레이션) 미구현.
7. **"TerraProbe 수치 출처?"** — 원문 링크 없음. 확보 전까지 인용 금지.
8. **"제목이 두 개다"** — 운영계획서 vs 저장소. 이번 주 확정.
9. **"Trivy 룰이 업데이트되면 결과가 바뀌지 않나?"** — 맞다. 내장 번들·`--skip-check-update`·버전 0.74.0 고정을 기록했고, 룰이 바뀌면 사각 표도 다시 재야 한다.
10. **"등급 일치율 25/25 가 뭘 증명하나?"** — 코드가 표를 그대로 구현했다는 것뿐. 블라인드가 아니었다고 문서에 적었다.

## 17. 즉시 수정·착수 (우선순위)

1. 배포 후 축 1회 실측 (A: 계정 준비 → apply → `postdeploy --execute`; C: 실제 PR 1건) — 프로젝트 정체성.
2. 사람이 만든 ground truth 3쌍 + 네트워크 구성도 (A) — 교수 지적의 직접 답.
3. Claude Code 후보 수집 시작 (B) — LLM 축 0 해소.
4. 제목·기준표 v2·TerraProbe 출처 확정 (팀).
5. walkthrough 문서 + 교차검증 재현 서명 (전원) — "설명 가능한 코드".
6. 표준 매핑표 채우기 (SK쉴더스 PDF 원문 번호) (전원).
7. Container/EKS/LangGraph 를 README·계획서에서 "제외/선택" 으로 명시 (문서 정리).

## 18. Ground truth 를 사람이 만든다 — 구조

```
ground-truth/
  sg/  vulnerable/main.tf   expected_safe/main.tf   README.md (왜 취약한가, 무엇을 고쳤나, trivy 전/후 표 — A 가 손으로)
  iam/ vulnerable/main.tf   expected_safe/main.tf   README.md
  s3/  vulnerable/main.tf   expected_safe/main.tf   README.md
```
- `expected_safe` 는 정답 후보이자 오라클의 "PASS 여야 하는 것" 대조군이다. LLM 후보(`candidate_patch`)는 이것과 diff 하고, 오라클 판정과 사람 판정을 나란히 기록한다.
- 기존 seeded 세트(AI 세션 작성)는 "알려진 우회 패턴 탐지력" 용으로 유지하되 작성 주체를 명시했다 (manifest `_authorship_note`).

## 19. 9/8 대화와의 병합 결과 (충돌 없음 확인)

| 9/8 대화의 결정 | 현재 상태 |
|---|---|
| V1~V8 8계층, Validity/Risk 분리 | 구현·실측(V1~V6), V7/V8 코드 |
| seeded 기만 패치 세트, 01·06·08 회귀 테스트 | 구현(23 plan + IAM 14), 오라클 실험 |
| V2 는 차단이 아니라 보조(심각도 가중) | CRITICAL/HIGH 만 차단 |
| "기만 = 스캐너·plan 통과 + 의도 위반", Low 로 통과시키지 말고 차단 | 검증 FAIL → BLOCKED |
| IAM 은 Tier 1 후순위, "무조건 사람 승인" 대체안 | Tier 1 구현, 최소 FULL_REVIEW(floor) — 대화보다 앞섰지만 원칙 유지 |
| 프롬프트 요인 실험(선택) | OPTIONAL 로 유지 |
| 기능 동결 11/16, 리허설 12/1~2 | README 반영됨 |
| 과장 금지 문장들 | 이 문서·ORACLE_RESULTS 에 그대로 |
