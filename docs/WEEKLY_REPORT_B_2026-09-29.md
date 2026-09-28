# B 주간업무보고 초안 — 4주차 (9/29~10/5) 착수 시점 (2026-09-28 작성)

> 게시판에 올릴 때는 아래 【 】 세 칸을 그대로 복사한다. 숫자는 전부 저장소에서 다시 계산되는 것만 적었다 (출처 괄호). "완료" 는 실제로 돌아간 것만.
> 작성 방식: AI 초안(B 의 Claude 세션) → B 가 읽고 고친 뒤 게시. 코드 커밋은 Co-Authored-By 로 AI 초안임을 표기했다 (부록 C 원칙).

【이번 주 한 일】

1. Risk Rubric(위험도 기준표) v2 — 변경 리소스 종류·수, IAM 여부, blast radius(부착 지점 수·외부 SG), 삭제/교체, provider 변경을 점수·hard 조건으로 정의(`policy/risk_rubric.json`, `docs/RISK_RUBRIC_V2.md`). 등급 상한 로직: 위험도 LOW/MEDIUM/HIGH → 자율성 상한 HIGH/MEDIUM/LOW, LLM 제안은 낮추는 방향만 반영(`policy/gate.py`).
2. 완료 기준 확인 — (a) 목업 데이터로 분류: 후보 세트 라벨 25건을 실제 검토 흐름으로 다시 돌려 기대 등급 = 코드 등급 25/25, 세 등급 모두 출현(LOW 12·MEDIUM 12·HIGH 1) — terraform 없이 커밋된 plan 쌍으로 재계산되며 CI 단위 테스트에 포함. (b) 상한 강제: 위험도 3 × LLM 제안 4 × 검증 3 × 정책 2 = 72 조합 전수 검사 위반 0(`tests/unit/test_rubric_demo.py`).
   - 정직 표기: 라벨 25건은 B 의 Claude 세션이 기준표를 읽고 적은 값이라 **사람 손 검산은 아직 0/25**. 이번 주에 B 가 직접 검산해 `expected_risk_verified_by` 를 채운다.
3. 실행 방식 교체 — bat/tkinter 창 대신 **IaCPatch.exe → 브라우저 화면**(로컬 127.0.0.1 서버, 외부 접속·외부 스크립트 없음). 탭: 4주차 기준표(표시·라벨 재계산·상한 전수 검사·계산기·게이트 데모), 5주차 후보→검증(V1~V6)→위험도→검토 수준→PR 미리보기, 실험 8단계, 리포트, 도구. Chromium 자동 시험(5탭) 통과. exe 는 GitHub Actions(Windows 러너)가 자동 빌드(`.github/workflows/build-exe.yml`) — **첫 빌드는 push 뒤 확인**.
4. main 합치기 — A 의 CI 게이트·V2 초안·화이트리스트 v0.2·CIS 매핑 v0.2·피드백 문서를 B 브랜치에 병합. A 의 V2 스크립트와 파이프라인 V2 가 fixture 9쌍에서 같은 결과를 내는 테스트 추가. 화이트리스트 v0.2 ↔ 정책 파일 대조표(`docs/WHITELIST_VS_POLICY.md`, 다른 점 8건 → 팀 결정 항목). CIS 매핑 v0.2 값을 기계용 사본(`policy/cis_mapping.json`)에 반영(원문 대조는 미완 그대로).
5. C 몫 선반영(C 확인 필요) — PR 마다 단위 테스트 + 후보 세트 4개 실측 + 검증 표를 PR 댓글로 다는 워크플로(`.github/workflows/iacpatch-verify.yml`). 자동 병합·apply 없음. **Actions 첫 실행은 push 뒤**.
6. 팀 PC 실측(9/22) — Terraform 1.16.1 로 4세트 38건 판정이 샌드박스(OpenTofu 1.10.6)와 38/38 동일, 후보당 6~12초.

【다음 주 계획】

- B: 라벨 25건 손 검산(연습 과제 1) → 사람 검산 25/25. 화이트리스트 결정 8건 팀 회의. `docs/walkthroughs/B.md` 4절을 안 보고 말할 수 있게.
- B: Claude Code 후보 36개(SG 7 + IAM 5 케이스 × 3회, 새 세션·고정 프롬프트 `scripts/cc_prompt.py --all` → `scripts/cc_add.py`). 지금 "LLM 후보 0(미측정)" 인 칸을 채운다.
- A: PR 첫 실행 확인(iac-scan + iacpatch-verify + build-exe), V8 테스트베드 Terraform(손으로), CIS 원문 대조.
- C: `docs/WHITELIST_VS_POLICY.md` 5절의 V5 보강 3건(규칙 블록 짝짓기·CIDR 부분집합·prefix_list/참조/self 신규 차단) — 기존 `verify/layers.py v5_plan_diff` 위에.
- 5주차 목표(High 등급 첫 폐루프): 화면 5주차 탭의 PR 미리보기 → 팀 회의 뒤 실제 PR 1건 → 승인 → A 의 샌드박스 apply → V7/V8 첫 기록.

【이슈/건의사항】

- 제목은 09-28 확정본으로 통일했다(README·한장요약·앱·리포트). 운영계획서·발표자료도 같은지 A 확인.
- 룰 ID 표기: A 의 매핑표는 Trivy 출력 그대로 `AWS-0107`, B 코드는 `AVD-AWS-0107` 로 정규화. 같은 룰이며 코드는 두 표기를 다 읽지만 문서 표기를 하나로 정할 필요.
- AI 활용 원칙(부록 C)에 따라 "Risk Rubric 표는 직접 작성" 인데 현재 표·라벨은 AI 초안이다. B 가 손 검산과 연습 과제로 소유권을 가져오는 중이며, 그 전까지 발표에서 "사람이 검산했다" 고 말하지 않는다.
- V8 테스트베드 Terraform 은 부록 C 대로 AI 초안 없이 팀이 직접 쓴다(이번 작업에서 만들지 않음).
