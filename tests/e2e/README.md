# 화면 E2E 시험 (Playwright) — 2026-11-07 17차 기준 기록

이 폴더는 **클라우드 작업 환경에서 실제로 돌린** 화면 자동 시험의 스크립트와 시험용 대역이다. 결과(검사 번호 ↔ 시나리오)는 `docs/SCENARIOS_E2E.md` 에 있다.
단위 시험(`tests/unit`)과 달리 **그 환경의 절대 경로(`SP = /tmp/claude-0/.../scratchpad`)와 준비물에 묶여 있다** — 다른 PC 에서 그대로 돌아가지 않는다. 옮겨 돌리려면 아래 준비물을 갖추고 경로 상수만 바꾼다.

| 파일 | 하는 일 |
|---|---|
| `team_e2e.js` (40 검사) | 팀 3계층 예제 (D-49 — 깃허브 main 의 팀장 three-tier 사본 + 시나리오 1): ① 고객 요청함의 요청 1 줄 (16차) → ② 상자 5개 · 리소스 54 · 위험 1(왼쪽 메뉴 ② 밑 — 17차) · 틀 없음 · web (ALB)/(ASG) · 맨 위 가상 고객 요청 칸 · [요청서 보기] (D-50) → ③ 팀 설계 문서 + 초안 확정 → ④ 같은 문제 한 줄 · 'Trivy 는 못 봄' 0 → ⑤ 수정안 1~4 마다 그림 · [고객 설계도] · 규칙 기반 통과 · 수정안마다 고객 요청 조건 5칸 → ⑥ good → ⑧ 승인 · 조건 모두 지킴 · PR 준비 확인 · PR 미리보기 본문의 고객 요청 칸 |
| `main_e2e.js` (87 검사) | 예제 프로젝트(3계층 · 2계층)로 ①~⑧: 준비 상태 · 흐름 그림(틀 · S3 · IAM 없음 · 전체 보기 없음) · 설계도 편집 · 수정안 번호마다 바뀌는 그림 · 승인 · PR 준비 확인 · 미리보기(실행 안 함) · AI 수정(대역) · IAM 요구사항 파일 버전 |
| `proj_e2e.js` (52 검사) | 내 Terraform 폴더 연결(주문 서비스 예제) → 자동 초안 → 수정 · 저장 → 초안 기준 AI 수정 = 검증 불가 → 확정 → 재검사 통과 → 미검증 확인 승인 → PR 준비 · 미리보기 → 연결 끊기 · 지원 범위 밖 폴더 |
| `scen_e2e.js` (16 검사) | 실패 갈래: GAVE_UP → 직접 제출 통과 · REPEATED · AI_ERROR · TOOL_ERROR(TF_FAIL) · UNDECIDABLE(외부 prefix list) · ⑧ 끝맺음 세 줄 · PR 본문 끝맺음 |
| `tb_e2e.js` (46 검사) | ⑦ AWS 시험 환경 5단계를 흐름 화면에서 (9차, D-43): 원본 반영 → 확인 창 → apply → 수정 전 측정(자동) → 수정안 반영(plan 확인 → 확인 창 → apply) → 수정 후 측정 → 삭제(닫으면 취소 → 다시 destroy). 교체가 나오는 수정안은 차단. apply 수 = 사람이 [실행] 누른 수, `terraform destroy` 명령 없음, '후보 · 배포' 라는 말 없음. 대기 시간은 파일 수정 시각으로 흉내(`age()`). 가짜 aws 는 자격증명 오류 → 측정 결과 '판정 불가' |
| `rb_try.js` (18 검사) | ⑤ 설계도대로 자동 수정 (규칙 기반, D-45): 연습 저장소(`board_repo`) 연결 → v1 자동 초안에서 누르면 '수정안 없음 + 이유' → ③ 이 IP만 허용 → v2 확정 → 통과 → ⑥ · ⑧ |
| `proposal_e2e.js` (29 검사) | 고객 제안서 예제 (D-46, 13차부터 화면에서 숨김 — 주소로 연다): ② 점검 → ③ 제안서 원문 + 설계도 v1 초안 → 담당자 확정 → ④ → ⑤ 번호 1~4 마다 그림 바뀜 · [고객 설계도] 단추 (D-48) · 규칙 기반 통과 → ⑥ → ⑧ 승인 · PR 준비 확인(시연용 줄) |
| `req_e2e.js` (31 검사) | 팀 3계층 요청 2 · 3 (D-51): ① 요청함 줄 2개 (16차) → 요청 3(IAM) ② 권한 그림 · 조건 4개 → ③ 팀 설계 문서에서 옮긴 IAM 요구사항 v1 · [지금 코드와 비교] · 확정 → ④ `s3:*` 한 줄 · 그림 강조 → ⑤ 수정안 1~4 권한 그림(요구사항 밖 ✕ · 꼭 필요한데 없음) · 조건 4칸 → ⑥ '고객이 허용한 권한만 남았나요?' → ⑧ 승인 · PR 미리보기 본문(실행 안 함) / 요청 2(S3) ② '사람에게 넘김' 칸 → ③ ④ ⑤ 고치기 없음 |
| `inbox_e2e.js` (39 검사) | 고객 요청함 (D-52 · 17차 D-53): ① 받은 요청 3줄(최근 것 위) · 타이머 · [지금 받기] · [처음부터] · 방식 고르기 · 숫자 칸 없음 · 한글 낱말 중간 줄바꿈 없음 → ② 에 있는 동안 요청 4 도착(API = 다른 사람이 넣음 · 알림 · 왼쪽 숫자 · 창 제목) · ② 숫자 네 칸 없음 → [고객 역할로 요청 넣기] (안 온 요청만 · 이름 필수) · `/api/inbox/control` 404 → 요청 5 · 11 의 '사람에게 넘김'(두 칸 · 이유 접힘 · 지금 값 / 요청한 값) · 넣은 사람 · 메모 → 요청 4 ②~⑧ 승인(④ 한 줄 · Trivy 못 본 것 0 · ⑤ 포트 글자와 ✕ 안 겹침 · ⑥ 아래 그림 없음 · ⑦ 할 것 없음 · ⑧ 반복 칸 없음) → ① '승인됨' → 요청 6 ② 넓은 권한 · ⑥ 질문 4. 시작 상태는 `reset.sh` 가 쓴 요청함(요청 1 ~ 3 도착 · 읽음), 서버의 '지금' = `start.sh` 의 `IACPATCH_INBOX_NOW` |
| `walk_e2e.js` (120 검사) | 모든 화면 × 1366×768 · 1280×720 · 1920×1080 (× 큰 글씨 `big`) — 가로 넘침 · 버튼 글자 잘림 · 형제 칸 겹침 · 메뉴 잠김(기록 없이 ⑥) · 머리말 '다음 ▶' 로 ②→⑧. 팀 3계층 요청 1 · 2 · 3 · 4 · 6 의 ② ~ ⑤ · 넘김 요청 6건의 ② 포함 (아직 안 온 요청도 주소로 연다). 바꾸는 동작 없음 |
| `fakeclaude/claude` | Claude Code 대역 — 미리 적어 둔 답만 돌려준다 (`answers.json` 3계층 · `answers_orders.json` 주문 서비스 · `answer_unknown.txt`). `mode.txt` 로 갈래(bad · repeat · error · unknown) 선택. 실제 AI 아님 |
| `faketf.py` | 시험 환경 폴더(webapp-3tier-testbed)의 plan · apply 만 흉내 내는 terraform 대역 (실제 AWS 에 닿지 않음). 그 밖은 진짜 tofu 로 넘김. `bin/TF_FAIL` 파일이 있으면 init · plan · validate 실패(실행 오류 시나리오) |
| `reset.sh` · `start.sh` · `e2e_restart.sh` · `mk_userproj.sh` · `serve8897.py` | 시험 사본(`e2e/cap`) 초기화 · 8897 포트 서버 · 사용자 폴더 예제(git 저장소, push 안 됨) |

준비물: Playwright(chromium) · Trivy 0.74.0 · OpenTofu/Terraform + 오프라인 provider 캐시(`TF_PLUGIN_CACHE_DIR`) · 저장소 사본(`e2e/cap`) 에 10-23 기록 3건(`pristine/`) · 위 대역들. AWS 계정 · 실제 AI · PR 실행은 필요 없고 쓰지도 않는다.

돌리는 순서 (작업 환경):
```
bash e2e_restart.sh && node main_e2e.js <스크린샷 폴더>
bash mk_userproj.sh && bash e2e_restart.sh && node proj_e2e.js <스크린샷 폴더>
bash e2e_restart.sh && node scen_e2e.js <스크린샷 폴더>
bash e2e_restart.sh && node tb_e2e.js
node walk_e2e.js <연결한 프로젝트 id> [big]
bash e2e_restart.sh && node rb_try.js
bash e2e_restart.sh && node proposal_e2e.js
bash e2e_restart.sh && node team_e2e.js
bash e2e_restart.sh && node req_e2e.js
bash e2e_restart.sh && node inbox_e2e.js
```
`e2e_restart.sh` 는 `src` 와 함께 고객 제안서 예제 폴더(`scenarios/arch/board-saas` · `experiments/arch-board-saas` · `experiments/candidate-sets/board-saas-sg`)와 팀 3계층 예제 폴더(`scenarios/arch/three-tier-team` · `experiments/arch-three-tier-team` · `experiments/candidate-sets/three-tier-team-sg`) · 요청 2 · 3 폴더(`scenarios/arch/three-tier-team-s3` · `-iam`, `experiments/arch-three-tier-team-s3` · `-iam`, `experiments/candidate-sets/three-tier-team-iam`) · 가상 고객 요청서(`scenarios/requests`) · 요청 4 ~ 11 폴더(`scenarios/arch/three-tier-team-<dbsg · dbpublic · upload · imds · dbenc · deletion · flowlog · backup>`, `experiments/arch-…`, `experiments/candidate-sets/three-tier-team-dbsg` · `-upload`)도 시험 사본에 맞춘다. `reset.sh` 는 요청함 상태(`data/inbox/state.json`)를 늘 같은 값(요청 1 ~ 3 도착 · 읽음)으로 쓰고, `start.sh` 는 서버의 '지금' 을 `IACPATCH_INBOX_NOW=2026-11-06T21:00:00+09:00`(+ 켜진 뒤 지난 시간)으로 고정한다 — 실제 날짜를 쓰면 날이 바뀔 때 ① 의 줄 수가 달라진다.
main 의 PR 준비 확인(G7)은 시험 저장소에만 있는 `origin/e2e-base`(= 로컬 커밋 5aadd26, 3계층 원본)를 쓴다 — `git fetch --prune` 을 하면 지워지므로 `git update-ref refs/remotes/origin/e2e-base 5aadd26` 으로 되돌린다.
`bin/aws` 대역(자격증명 오류를 내는 셸 스크립트)은 `AWS_BIN` 으로 넘긴다 — 측정이 실제 AWS 에 닿지 않게.
