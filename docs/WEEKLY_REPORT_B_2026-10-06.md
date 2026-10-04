# B 주간업무보고 초안 — 6주차 (10/6) 보고용 (2026-10-02 작성, 실측 기준)

말로 할 문장은 `docs/ARCH_WEBAPP_2TIER.md` 6절. 아래는 보고판에 적는 형식. **[ ] 는 10/6 전에 B 가 PC 에서 하고 숫자를 채우는 칸** — 못 하면 "0회" 그대로 적는다.

## 지난주(9/29) 지도교수 피드백 → 대응

| 피드백 | 대응 | 상태 |
|---|---|---|
| Terraform 이 너무 부족함, 많이 만들 것 | 아키텍처 Terraform 9 파일 / 17 리소스 (`scenarios/arch/webapp-2tier/`), 후보 변형 12 파일 추가 | 됨 |
| 본인이 한 작업을 설명할 수 있어야 함 | `docs/TERRAFORM_STUDY_B.md` (파일 줄 단위 문법 + 10문제), `docs/ARCH_WEBAPP_2TIER.md` 6절 문장 | 됨 (외우는 건 B) |
| Terraform → Trivy → 결과 플로우 테스트 | `scripts/arch_scan.py` 1회 실행으로 fmt/validate/plan + Trivy → findings.md (`experiments/arch-webapp-2tier/RESULTS.md`) | 됨 (개발 환경), [ ] 팀 PC 재실행 |
| 아키텍처 선정 → Terraform 구성 → 실행 시연 | VPC 2계층 웹 선정 (이유 문서화). **실제 apply 는 0회** — 계정 접근이 먼저 | [ ] 계정·키 (A), [ ] apply 1회 |
| Trivy 결과물 | 85 검사 / 18 finding (의도적 7 + 부수 11), Trivy 가 못 잡는 공개 읽기 버킷 정책 1건 확인 | 됨 |
| AI 에이전트가 해석 | 프롬프트 생성 + 응답 등록·기계 대조(지어냄/누락/CIS 불일치) 구현·테스트. **모델 응답 등록 0건** | [ ] Claude Code 1회 |
| 다음 단계(패치→검증)도 제작 | 아키텍처 후보 세트 2개: SG 7건 7/7 기대 일치, IAM 6건 5/6 (규칙 기반 거부 1건 기록) | 됨 |
| Terraform 문법 공부 | 위 문법 문서 + 실습 | [ ] 10문제 자답 |

## 이번 주 한 일 (10/2 기준, 숫자는 전부 실측)

1. **아키텍처 Terraform**: VPC·서브넷 2·IGW·라우트·SG 2·EC2 2·S3(버킷·차단 설정·정책)·IAM(역할·정책·연결·프로필) = 17 리소스. `fmt`/`validate`/오프라인 `plan` 통과(17 create, 삭제·교체 0). provider 5.100.0 고정.
2. **Trivy 점검 자동화**: `scripts/arch_scan.py` (exe 에서 `--exec` 로 실행 가능) → 검사 85개 중 finding 18 (CRITICAL 2·HIGH 13·MEDIUM 2·LOW 1). CIS 대응은 팀 매핑표에 있는 3룰만 표시, 나머지 "매핑표에 없음".
3. **AI 해석 단계**: 프롬프트(스캔 원문 + Terraform 전체 + JSON 스키마) 자동 생성, 응답 등록 시 실제 finding 과 대조. 단위 테스트 13개.
4. **패치 → 검증**: SG 세트 7건(규칙 기반 1 + seeded 6) — V1 만으로는 7건 통과, V1+V6 는 2건만 통과, 기대 라벨 7/7, 위험도 7/7. IAM 세트 6건 — 5/6, 규칙 기반이 `name` 의 변수 때문에 후보 생성 거부(한계로 기록).
5. **V6 개선 1건(실측에서 나옴)**: SG 두 개짜리 아키텍처에서 "80 공개" 요구가 앱 SG 에도 적용돼 정상 패치까지 FAIL → intent 의 `required_access` 에 대상 SG 지정(`targets`) 추가. 기존 단일 SG 세트·무작위 20,000건 결과 불변.
6. **Claude Code 케이스 추가**: `cc_prompt.py arch-sg / arch-iam` (다중 파일 아키텍처용).
7. 문서: 계정 접근·시연 순서(`AWS_ACCESS_SETUP_B.md`), 문법 공부, 아키텍처 선정·답안지, D-16.

## 안 된 것 (먼저 말할 것)

- AWS 실제 apply 0회 → V7·V8 0회 (계정 접근 준비 중).
- AI 해석 모델 응답 0건, Claude Code 패치 후보 0건 (아키텍처 케이스 포함).
- 팀 PC(Terraform 1.16.1) 재실행 0회.
- 라벨 손 검산 0/25 (지난주 과제, 아직).

## 다음 주 계획 (10/6~10/12) — B

1. [ ] AWS 계정 접근(A 의 샌드박스 IAM 사용자 또는 본인 프리 플랜 계정) → `init/validate/plan/apply/output` 1회, 캡처 5장 (`docs/SOLO_ABC_RUNBOOK.md` 1·3단계).
2. [ ] 전/후 측정: 취약 상태에서 V7·V8(FAIL 이 정답) → PR(`sandbox` 브랜치) → 패치 apply → V7·V8(PASS) → destroy. A·C 역할을 B 가 혼자 수행(10-04 결정).
3. [ ] `interpret_prompt.md` 를 Claude Code 에 넣어 해석 1회 등록 (`arch_interpret_add.py`) — 지어냄/누락/CIS 불일치 수 보고.
4. [ ] `cc_prompt.py arch-sg`, `arch-iam` 로 Claude Code 후보 각 3회 → 등록 → 검증 (규칙 기반이 거부한 IAM 케이스와 비교).
5. [ ] 25건 라벨 손 검산 (`expected_risk_verified_by`).
6. 팀 결정 요청: 규칙 기반 IAM 생성기 검사 범위(블록 전체 vs policy 속성) — D-16.
