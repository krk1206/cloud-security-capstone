# 운영계획서([붙임2] 캡스톤 디자인 계획안) 대비 구현 점검 — 2026-09-21

- 대상: 운영계획서 `과제명: AI 생성 IaC 보안 패치의 실효성 검증 자동화 파이프라인 설계 및 구현` (운영기간 2026-09-08 ~ 12-04)
- 저장소 상태: 브랜치 `claude/iacpatch-sg-slice` @ 5624b61, 단위 테스트 150 OK
- 실측 근거: B 의 PC (Windows, Python 3.14.7, Trivy 0.74.0, Terraform 1.16.1) 2026-09-21 실행 — `experiments/candidate-sets/*/results-history/20260921-*-DESKTOP-TSH8UUD.md`, `experiments/ORACLE_RESULTS.md`
- 판정 기준: **실제로 실행돼서 기록이 남은 것만 "됨"**. 코드만 있고 실행 안 된 건 "코드만". 숫자를 지어내지 않는다.

## 1. 계획서 "목표 및 세부내용" 7항목

| # | 계획서 항목 | 판정 | 근거 (저장소) | 남은 것 / 담당 |
|---|---|---|---|---|
| 1 | 보안 설정 오류 탐지 — SG **필수**, IAM **필수**, S3 선택. `trivy config` 정적 탐지 + Evidence Bundle | **SG 됨 / IAM 배포 전 됨(09-22) / S3 안 됨** | SG: A 의 우회 케이스 9종(`scenarios/eval/a-probe/`), `trivy config` 실측 9/9 재현(`A_RESULTS_CHECK.md`). IAM: 시나리오·지원 룰·오라클 전부 없음. `docs/IAM_SCOPE.md` 명세만 있고 코드는 IAM 리소스가 바뀌면 무조건 HIGH → REPORT_ONLY. Evidence Bundle: `evidence.py`(evidence-v1) 는 1주차 `predeploy` 흐름용. Claude Code 프롬프트(`scripts/cc_prompt.py`) 는 별도 형식으로 같은 역할 | IAM Tier-1 (A: 시나리오 Terraform + Trivy 룰 확인, B: IAM 오라클). S3 는 선택이므로 보류 |
| 2 | AI 패치 후보 생성 — Claude Code, **요청마다 신규 세션**, AI 는 후보만 | **흐름 됨 / 후보 0건** | `cc_prompt.py`(케이스별 고정 프롬프트 7개) → 사람이 새 세션에 붙여 넣기 → `cc_add.py` 등록. 유료 API 미사용(D-5). `eval-claude-code` manifest 후보 0 | B: 7 케이스 × 3회 = 21개 받아서 등록 |
| 3 | 검증 8계층 V1~V8, 한 계층이라도 실패하면 PR 차단 | **V1~V6 됨(실측) / V7·V8 코드만** | V1~V6: `review/local_verify.py` + `verify/*`, B PC 실측 NOT_RUN 0. 차단: `review/level.py` — FAIL → BLOCKED(위험도 무관), NOT_RUN/UNKNOWN → PENDING(PR 불가). V7/V8: `postdeploy.py` 코드 + FakeCli 단위 테스트, **실제 AWS 호출 0회**(`docs/STATUS.md`). 참고: V3 의 `fmt` 는 비차단(포맷 차이는 실패가 아님), `validate` 만 차단 | A: 샌드박스 apply 후 `postdeploy --execute` 1건. C: V8 체크 JSON 정의 |
| 4 | Intent Oracle(V6) — CIDR·IPv6·Prefix List·참조 SG 합산, IAM 은 Action·Resource 범위로 확장 | **SG 됨 / IAM Tier 1 됨(09-22, 샌드박스 실측)** | `verify/sg_oracle.py`: IPv4/IPv6 집합 계산, prefix list 는 같은 plan 안에서만 전개(아니면 UNKNOWN), 참조 SG·self 처리. 실측: 기만 16/16 탐지, 정상 5/5 통과, 스캐너 PASS∧오라클 FAIL 5 (`ORACLE_RESULTS.md`); seeded 11건 V1만 통과 7 → V1+V6 통과 2 | B: IAM Action·Resource 집합 계산(`IAM_SCOPE.md` Tier 1 범위) |
| 5 | 위험도 3등급 — 사전 기준표(리소스 종류·수, IAM 여부, 영향 범위, 롤백 난이도) → 등급별 자동화 차등. AI 확신도는 **낮추는 용도로만** | **구조 됨 / 기준표 미확정** | `policy/risk_rubric.json` + `policy/risk.py`(plan 기반) + `review/risk_text.py`(HCL 기반) → `review/level.py` LIGHT_REVIEW / FULL_REVIEW / REPORT_ONLY / BLOCKED. AI 확신도: `policy/gate.py` 는 낮추는 방향만 반영, review 흐름은 아예 입력받지 않음 → 계획과 일치. 그러나 기준표는 `RISK_RUBRIC_DRAFT.md`(초안), "등급 vs 기준표 일치율" 실험 없음 | B: 기준표 확정(LLM 세트 돌리기 전), 등급 일치율 표 |
| 6 | PR·승인·배포 후 재검증 — GitHub Actions 로 검증 결과 첨부 PR 자동 생성, 사람 승인, 샌드박스 apply, 재확인 | **안 됨 (가장 큰 구멍)** | (a) `tools/github.py` 는 미리보기만 실행, push/PR 생성 0회. (b) **`iacpatch pr` / `postdeploy` 는 1주차 `predeploy` 기록(`data/runs`, `gate.action`)만 읽었다. 실험·실측은 전부 `review` 기록(`data/reviews`, `review_level`)이라 측정한 흐름과 PR 단계가 연결돼 있지 않았다.** → 09-22 `pr --review <id>` 추가(LIGHT/FULL_REVIEW 만 허용, 미리보기 테스트 통과). `postdeploy --review` / `recover --review` 도 09-22 연결(FakeCli 단위 테스트, 실제 AWS 0회). (c) 워크플로 3개(`bc-unit-tests`, `iac-scan`, `patch-verify`) 작성됐으나 Actions 실행 0회이고, PR 을 "자동 생성"하는 워크플로는 없다(검증만). (d) apply·V7·V8 실행 0회 | B: `pr --review <id>` 어댑터(LIGHT/FULL_REVIEW 만 허용, `candidate/` + `pr_body.md` 사용). C: 브랜치 push 후 Actions 첫 실행, PR 생성 1건. A: apply + V7 |
| 7 | 규칙 기반 baseline 비교 — 겉보기 수정 탐지율·패치 성공률·정상 기능 보존율·처리 시간, 개발/평가 세트 분리 | **절반** | 있음: 규칙 기반 생성기 실측(9 케이스 중 후보 4, 4건 모두 V1~V6 PASS), 개발/평가 분리(D-3), 겉보기 수정 탐지(오라클 5건 차단·오탐 0). 없음: AI 축(0건), **정상 기능 보존율(V8 필요 — V6 의 MISSING 은 "필수 접근 규칙이 남아 있나"의 배포 전 대용이지 같은 지표가 아님)**, 처리 시간(`state.json` 에 started_at/finished_at 은 있으나 집계 안 함) | B: metrics 에 소요 시간 열. C: 평가 표 설계. A: V8 로 보존율 |

## 2. "수행방법" 1~6 과 일정

| 수행방법 | 상태 |
|---|---|
| 1 환경 구축 — AWS Sandbox(최소 권한 IAM, 예산 알림), Terraform, Trivy, Actions CI | Terraform·Trivy: 됨(팀 버전 고정, `setup_tools`). AWS 계정·예산 알림: **저장소에 증거 없음 → A 확인**. Actions: 실행 0회 |
| 2 설계 — 검증 8계층, 위험도 기준표, Evidence Bundle 형식, 신뢰 경계 | 됨(문서: `ARCHITECTURE.md`, `INTENT_ORACLE_PLAN.md`, `RISK_RUBRIC_DRAFT.md`, `IO_SPEC_A_B_C.md`). 기준표만 초안 |
| 3 개발 — Trivy 연동, AI 패치 생성, Intent Oracle, 위험도 산정, PR 자동 생성, 배포 후 검증 | Trivy·오라클·위험도: 됨. AI 패치: 흐름만. PR·배포 후: 코드만 |
| 4 테스트 — SG 단일 시나리오 전 과정 → IAM 확장 | 배포 전(탐지→패치→검증→등급)까지 실측. **PR→승인→apply→재검증은 0회.** IAM 미착수 |
| 5 실험 및 평가 | E2(오라클 유무)·규칙 기반 축 실측. LLM 축·보존율·시간 없음 |
| 6 정리 | 미착수(정상) |

일정 대비: 9/21 현재 계획 2·3번은 앞서 있고, 4번(전 과정 통합)의 뒷부분(PR·apply·V7/V8)과 IAM 확장이 남았다. 기능 동결 11/16 까지 8주. IAM 을 계획서대로 "필수"로 가려면 10월 첫 주에 착수해야 한다.

## 3. 계획서 문장 중 확인이 필요한 것

- "2026년 6월 발표된 선행 연구(TerraProbe) … 83.3% / 10.4% / 71.4%" — 이 저장소 어디에도 출처(논문 링크·저자)가 없다. 발표·보고서에 쓰기 전에 원문을 찾아 `docs/` 에 인용 정보를 남길 것. **확인 전까지 숫자를 인용하지 말 것.**
- "우회 후보 9종 중 2종이 탐지를 우회" — 저장소 재현과 일치(01-cidr-split, 06-prefix-list 가 NO_FINDING). 그대로 써도 된다.
- 과제명이 저장소·D-1 의 제목("LLM이 생성한 AWS IaC 보안 수정의 실효성 검증 시스템 구현")과 다르다. 어느 쪽이 최종인지 정해서 README·DECISIONS·발표 자료를 한 제목으로 맞출 것(교수 지시 "동사로 끝날 것"은 둘 다 만족).
- "V3 terraform fmt/validate" — 구현은 `validate` 만 차단, `fmt` 는 경고. 발표 때 그렇게 말하면 된다.
- "정상 기능 보존율" — V8 이 돌기 전까지는 측정값이 없다. 배포 전 실험에서 나온 건 "필수 접근 규칙 유지 여부(V6 MISSING)"로 이름을 구분해서 쓸 것.

## 4. 계획서의 역할 분담 vs 실제

계획서: A = AWS·Terraform·Trivy 연동·V1·V2·V3·V4·V7 / B = Claude Code 연동·V6·위험도 / C = Actions·PR·승인·V5·V8·baseline·평가.
실제: V1~V6 로컬 실행, V5 plan diff, 규칙 기반 baseline, 평가 스크립트가 전부 B 의 브랜치에서 구현됐다. 제품엔 문제가 없지만 "각자 뭘 했나"를 물으면 답이 있어야 하므로, 남은 일을 계획서의 분담에 맞춰 나눈다:

- A: AWS 샌드박스 증거(계정·예산 알림·IAM 사용자), SG 시나리오 apply, `postdeploy --execute` 로 V7 첫 실측, IAM 과다 권한 시나리오 Terraform + Trivy 룰 확인
- B: Claude Code 후보 21개, 위험도 기준표 확정, `pr --review` 어댑터, IAM 오라클(Tier 1), 소요 시간 집계
- C: 브랜치 push 후 Actions 첫 실행 기록, 실제 PR 1건(어댑터 후), V8 체크 JSON + 승인 밖 관측 지점, 평가 표(보존율·시간) 설계

## 5. 한 줄 결론

배포 전 반쪽(탐지 → 후보 → V1~V6 → 위험도 등급)은 계획서대로 구현됐고 실측도 있다. 배포 후 반쪽(PR 생성 → 사람 승인 → apply → V7/V8)은 코드는 있지만 한 번도 실행되지 않았고, 특히 PR 단계는 실험에 쓴 `review` 기록과 연결조차 안 돼 있다. IAM 은 계획서에 "필수"로 적혀 있는데 아직 시작하지 않았다. LLM 축 숫자는 0이다.
