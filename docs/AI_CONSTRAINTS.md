# AI 제약 — 파이프라인 안의 LLM, 개발 도구로서의 Claude Code, 개발 과정의 AI 사용 (2026-09-22)

지도교수 9/22: "AI 가 제멋대로 돌 수 있으니 제약을 잘 걸어라", "AI 가 만든 걸 교차검증해라", "직접 쓰고 교정만 시켜라".
이 문서는 그 세 가지를 코드·설정·운영 규칙으로 옮긴 것이다. 파이프라인 구조는 `docs/PROJECT_REVIEW_WEEK4.md` 6~9절.

## 1. 파이프라인 안의 LLM 출력 (구현됨)

| 제약 | 어디에 | 확인 방법 |
|---|---|---|
| LLM 은 후보 파일만 낸다. 등급·통과 판정 권한 없음. 후보가 제안한 자율성은 낮추는 방향만 | `policy/gate.py`, `review/level.py` | `tests/unit/test_policy_risk_gate.py` |
| 편집 가능: `*.tf` 만. 보호 경로·보호 파일·금지 토큰·허용 타입 밖 생성/변경·삭제·교체 금지, 파일 2개·64KB | `policy/patch_policy.json`, `policy/validator.py` | seeded 세트에서 POLICY_BLOCKED 3건 |
| 검증 FAIL → BLOCKED(등급 무관). UNKNOWN/NOT_RUN → PENDING. PASS 는 배포 전 판정 | `review/level.py` | `test_review_flow.py` |
| 무인 apply/merge/destroy 없음. `--execute` 는 전부 사람 | `tools/github.py`, `postdeploy.py` | 코드에 자동 경로 없음 |
| LLM API 를 호출하지 않는다 (D-5). 후보는 사람이 새 세션에서 받아 파일로 등록 | `scripts/cc_prompt.py`, `cc_add.py` | 교차검증 1회차: 실험 경로 import 그래프에 LLM 모듈 없음 |

## 2. 개발 도구로서의 Claude Code (2026-09-22 추가)

- `CLAUDE.md`(저장소 루트): 절대 금지 목록·허용 목록·보고 방식. Claude Code 가 세션마다 읽는다.
- `.claude/settings.json`: 명령 allow/deny (apply·destroy·aws·sudo·rm -rf·push·main·curl·환경변수 출력 거부, 자격증명·상태 파일 읽기 거부, `policy/`·`tests/fixtures/`·`results-history/`·`.github/` 쓰기 거부). **팀 PC 에서 실제로 적용되는지 첫 사용 때 확인** — 형식은 Claude Code 문서의 permissions 규칙을 따랐지만 이 세션에서 실행 확인은 못 했다.
- AWS 프로필·토큰은 Claude Code 세션에 주지 않는다. AWS 작업은 사람 터미널.
- 작업은 브랜치(또는 `git worktree`)에서만. main 은 PR 로만.
- 실험 재료(취약 Terraform)를 "고쳐 주려는" 행동을 막는다 (9/8 대화에서 실제로 일어났던 일). 지시 없이 손대면 되돌린다.

## 3. 후보 생성 세션 (`scripts/cc_batch.sh`, 사람이 시작)

빈 임시 디렉터리 + 도구 전부 금지 + 최대 1턴 + 고정 프롬프트 + 텍스트 출력만. 저장소·자격증명에 닿을 수 없고, 응답은 파일로 저장돼 sha256 이 기록에 남는다. 라벨(expected)은 사람이 파일을 읽고 적는다. 플래그 이름은 팀 PC 에서 `claude --help` 로 확인(`--dry-run` 먼저).

## 4. 개발 과정에서의 AI 사용 (운영 규칙)

1. **사람이 먼저 쓰는 것**: 취약 원본·정답 Terraform(`ground-truth/`), AWS 네트워크 구성도, 아키텍처·테스트 기준, intent 값, expected 라벨·expected_risk.
2. **AI 가 하는 것**: 코드 검토, 오류 수정, 테스트 확장, 자동화 스크립트 보조, 문서 교정.
3. **설명 책임**: AI 가 쓴 핵심 로직(오라클, 게이트, 위험도, 검증 계층)은 팀원 1명 이상이 `docs/walkthroughs/<A|B|C>.md` 에 자기 말로 설명하고 예제 하나를 손으로 추적한다. 못 하면 핵심 코드로 인정하지 않는다.
4. **교차검증**: AI 산출물은 다른 세션(다른 컨텍스트)에 "깨라" 고 시키고, 그 결과를 사람이 재현·서명한다 (`docs/CROSS_VERIFICATION_2026-09-22.md`). 1회차에서 false PASS 7종이 나왔다 — 이 규칙이 형식이 아니라는 증거.
5. **기록**: AI 가 만든 파일은 그렇게 표시한다 (seeded manifest `_authorship_note`). "완성" 은 실행·테스트 결과가 있을 때만. 실환경(AWS) 에서 안 돌린 것은 "실환경 검증 완료" 라고 쓰지 않는다.
6. **한 번에 수천 줄 금지**: 설계 → 사람이 할 부분 → 작은 코드 단위 → 테스트 → 결과 → 다음.
