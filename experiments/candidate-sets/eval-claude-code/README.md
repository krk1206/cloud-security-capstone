# eval-claude-code — Claude Code 가 만든 후보 세트 (아직 비어 있음)

- 후보 0건. `prompt.md` 의 고정 프롬프트로 케이스마다 N=3 회 받아 `candidates/` 에 저장하고 `manifest.json` 에 항목을 추가한다 (`_how_to_add` 참고).
- 케이스: `scenarios/eval/a-probe/00~08` (A 의 변형 9종). 01·06 은 Trivy 가 finding 을 안 내므로 프롬프트에 넣을 finding 이 없다 → 이 두 케이스는 LLM 세트에서도 `not_triggered` 로 기록만 한다 (후보를 만들지 않는다).
- 이 세트가 채워져야 "LLM 이 만든 수정의 실효성 검증" 이라는 제목의 숫자가 나온다. 그 전까지의 숫자는 규칙 기반·seeded 결과다.
