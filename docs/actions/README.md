# GitHub Actions 로 AI 수정 돌리기 (D-27)

앱의 **AI 에게 고치게 하기**와 같은 코드(`src/iacpatch/llmfix.py`)를 GitHub 러너에서 돌린다.
Claude Code(구독)에게 수정안을 받고 → 배포 전 검사(V1~V6) → 막히면 이유를 붙여 다시 요청(최대 3번) → 결과 표를 작업 요약에, 기록은 아티팩트로.

하지 않는 것: `terraform apply`, AWS 접속, PR 자동 생성 · 병합, API 키(종량 과금) 사용. AI 는 도구 없이 글만 만든다.

`.github/` 는 사람만 고친다 (CLAUDE.md). 그래서 워크플로 파일은 여기(`docs/actions/iacpatch-ai-fix.yml`)에 두고, 사람이 웹에서 올린다.

## 1. 구독 토큰 만들기 (PC, 한 번)

PowerShell:

```powershell
claude setup-token
```

- 브라우저에서 Claude 계정으로 승인하면 토큰이 화면에 나온다 (Pro · Max 구독 필요).
- 이 값은 비밀번호와 같다. 채팅 · 문서 · 코드에 붙여 넣지 말고 2번에만 넣는다.

## 2. 저장소 Secret 등록 (웹)

저장소 → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

- Name: `CLAUDE_CODE_OAUTH_TOKEN`
- Secret: 1번 토큰

## 3. 워크플로 파일 올리기 (웹)

저장소 → **Add file** → **Create new file**

- 파일 이름: `.github/workflows/iacpatch-ai-fix.yml`
- 내용: 이 폴더의 `iacpatch-ai-fix.yml` 전체를 복사해 붙여 넣기
- **Commit changes** (팀 규칙대로 브랜치 → PR → 병합). `Run workflow` 버튼은 기본 브랜치(main)에 파일이 있어야 보인다.

## 4. 실행

저장소 → **Actions** → **IaCPatch AI fix (Claude Code, 구독 토큰)** → **Run workflow**

- set: `arch-3tier-sg` (기본)
- context: `trivy` (Trivy 결과만) 또는 `design` (+ 고객 설계도)
- max_attempts: `3`
- claude_version: 처음에는 `latest`. 로그의 `claude --version` 값으로 고정해 두면 같은 조건으로 다시 돌릴 수 있다.

## 5. 결과 보기

- 실행 화면 **Summary**: 시도별 V1~V6 표 (통과 · 막힘 · AI 오류)
- **Artifacts** → `iacpatch-ai-fix-<번호>`: `data/llm_runs/<실행 id>/` (시도별 요청문 · 응답 원문 · 후보 파일 · run.json), `data/reviews/` (검사 기록)
- 작업의 성공 · 실패 = 마지막 **판정** 단계. **검증 통과(PASSED)만 성공**이다. 2026-11-02 전에는 GAVE_UP 도 종료 코드 0 이라 성공으로 보였다 — 고침 (D-36).

| 결과 상태 | 뜻 | 종료 코드 | 다음 |
|---|---|---|---|
| PASSED | 배포 전 검사(V1~V6) 통과 | 0 | 사람이 검토 → PR (앱 ⑧) |
| GAVE_UP | 수정안 부적합 — 최대 시도까지 미통과 | 1 | 원본 그대로. 사람이 고친 파일을 ⑤ '고친 파일 올리기' 로 제출 (같은 검사) |
| REPEATED | 수정안 부적합 — AI 가 같은 파일을 되풀이해 중단 | 1 | 위와 같음 |
| AI_ERROR | AI 응답 실패 (설치 · 토큰 · 시간 초과 · 형식) | 2 | 환경 확인 후 다시 실행 |
| TOOL_ERROR | 실행 오류 — 도구 · provider · 입력 문제로 검사가 안 돎 | 3 | 환경을 고친 뒤 다시 실행. **AI 에게 다시 묻지 않는다** (코드 문제가 아님) |
| UNDECIDABLE | 검증 불가 — 미확정 값 · 미지원 구성 | 4 | 사람 검토. **AI 에게 다시 묻지 않는다** |

세 갈래로 나눈 이유: 모든 실패를 AI 에게 보내면 provider 를 못 받은 것 같은 환경 문제까지 코드를 고쳐서 풀려고 한다 (검토 문서 2026-11-02).

## 결과를 읽을 때 주의

- 시도 1 통과율과 3번 안 통과율을 따로 적는다. 2번째부터는 검증기의 실패 이유를 받은 결과라서 섞으면 안 된다.
- 러너는 같은 코드라도 AI 응답이 매번 다를 수 있다. 몇 번 돌렸고 몇 번 통과했는지를 같이 적는다.
- 배포 전 검사 통과 = 배포해도 된다는 뜻이 아니다. 실제 AWS 검사(V7 · V8)와 사람 승인은 앱에서 따로 한다.

## 6. main 의 기존 워크플로 고친 사본 (2026-11-02, D-41)

GitHub main(759b3be) 에 있는 `.github/workflows/iac-scan.yml` · `terraform-plan.yml` 을 검토 문서 지적대로 고친 사본이 이 폴더에 있다.
`.github/` 는 사람만 고치므로(CLAUDE.md) **사람이 웹에서 같은 경로에 덮어쓴다** (브랜치 → PR → 병합). 적용 전까지 main 은 옛 파일 그대로다.

| 파일 | 고친 것 | 사람이 할 일 |
|---|---|---|
| `iac-scan.yml` | Trivy 0.74.0 고정(설치 판 검사) · `trivy --version`(버전 + 체크 번들)을 `versions.txt` 로 기록 · 보고(JSON)와 게이트가 **같은 대상** · 대상은 Terraform 루트 목록(`ROOTS`) 기준 + modules/ 변경 시 그 모듈을 쓰는 루트 · 체크 번들 자동 갱신 끔 | 새 루트 폴더를 만들면 `ROOTS` 에 추가 |
| `terraform-plan.yml` | 역할 ARN(계정 번호)을 파일에서 빼고 저장소 변수 `AWS_ROLE_ARN` 로 · 계정 번호 로그 안 찍음 · 포크 PR 은 역할 사용 안 함 · 공개 저장소에서는 `plan.json` 을 올리지 않고 주소 · 동작만 담은 `summary.json` + 계정 번호를 가린 `plan.txt` · 같은 루트 규칙 | Settings → Secrets and variables → Actions → **Variables** 에 `AWS_ROLE_ARN` 만들기 (값 = 기존 파일의 ARN). 옛 파일의 ARN 줄은 지운다 |

검토 문서가 지적한 것과 코드로 확인한 사실: 옛 `iac-scan.yml` 은 보고는 `sg-baseline` 만, 게이트는 '바뀐 폴더' 였고 Trivy 는 apt 최신판(= 날마다 다를 수 있음)이었다. 옛 `terraform-plan.yml` 은 계정 번호가 든 ARN 이 파일에 있고 `plan.json` 전체를 아티팩트로 올렸다. 둘 다 '바뀐 파일의 상위 폴더' 를 루트로 써서 modules/ 변경을 놓친다 (main 에는 아직 modules/ 가 없어 지금은 드러나지 않음).

확인한 것: 세 파일 모두 YAML 로 읽힘 · 루트 결정 셸 로직을 main 사본과 모듈 예제에서 돌려 봄 (`infrastructure/three-tier/rds.tf` → three-tier, 두 루트 변경 → 둘 다, `modules/vpc` 변경 → 그 모듈을 참조하는 루트). 실제 러너에서 돌린 결과는 아직 없다 — 사람이 올린 뒤 첫 실행 로그를 `docs/CI_FIRST_RUN.md` 에 적는다.
