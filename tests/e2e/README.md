# 화면 E2E 시험 (Playwright) — 2026-11-02 기준 기록

이 폴더는 **클라우드 작업 환경에서 실제로 돌린** 화면 자동 시험의 스크립트와 시험용 대역이다. 결과(검사 번호 ↔ 시나리오)는 `docs/SCENARIOS_E2E.md` 에 있다.
단위 시험(`tests/unit`)과 달리 **그 환경의 절대 경로(`SP = /tmp/claude-0/.../scratchpad`)와 준비물에 묶여 있다** — 다른 PC 에서 그대로 돌아가지 않는다. 옮겨 돌리려면 아래 준비물을 갖추고 경로 상수만 바꾼다.

| 파일 | 하는 일 |
|---|---|
| `main_e2e.js` (80 검사) | 예제 프로젝트(3계층 · 2계층)로 ①~⑧: 준비 상태 · 화면 안내 · 설계도 편집 · 수정안 · 비교 그림 · 승인 · PR 준비 확인 · 미리보기(실행 안 함) · AI 수정(대역) · IAM 요구사항 파일 버전 |
| `proj_e2e.js` (51 검사) | 내 Terraform 폴더 연결(주문 서비스 예제) → 자동 초안 → 수정 · 저장 → 초안 기준 AI 수정 = 검증 불가 → 확정 → 재검사 통과 → 미검증 확인 승인 → PR 준비 · 미리보기 → 연결 끊기 · 지원 범위 밖 폴더 |
| `scen_e2e.js` (16 검사) | 실패 갈래: GAVE_UP → 직접 제출 통과 · REPEATED · AI_ERROR · TOOL_ERROR(TF_FAIL) · UNDECIDABLE(외부 prefix list) · ⑧ 끝맺음 세 줄 · PR 본문 끝맺음 |
| `tb_e2e.js` (46 검사) | ⑦ AWS 시험 환경 5단계를 흐름 화면에서 (9차, D-43): 원본 반영 → 확인 창 → apply → 수정 전 측정(자동) → 수정안 반영(plan 확인 → 확인 창 → apply) → 수정 후 측정 → 삭제(닫으면 취소 → 다시 destroy). 교체가 나오는 수정안은 차단. apply 수 = 사람이 [실행] 누른 수, `terraform destroy` 명령 없음, '후보 · 배포' 라는 말 없음. 대기 시간은 파일 수정 시각으로 흉내(`age()`). 가짜 aws 는 자격증명 오류 → 측정 결과 '판정 불가' |
| `walk_e2e.js` (54 검사) | 모든 화면 × 1366×768 · 1280×720 · 1920×1080 (× 큰 글씨 `big`) — 가로 넘침 · 버튼 글자 잘림 · 형제 칸 겹침 · 메뉴 잠김(기록 없이 ⑥) · 머리말 '다음 ▶' 로 ②→⑧. 바꾸는 동작 없음 |
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
```
`bin/aws` 대역(자격증명 오류를 내는 셸 스크립트)은 `AWS_BIN` 으로 넘긴다 — 측정이 실제 AWS 에 닿지 않게.
