# A → B → C 입출력 명세 (3~4주차 기준)

이 문서는 팀원이 서로 넘기는 **파일**의 형식을 정한다. 모든 단계는 파일로 주고받으며, B·C 단계는 외부 도구·API·AWS 없이 동작한다.

```
A: Terraform 원본 디렉터리 + Trivy JSON (+ 선택: 검증 결과 JSON, plan JSON)
        ↓ (파일)
B: iacpatch review  → data/reviews/<id>/ (원본 사본·후보·diff·기록·판정)
        ↓ (같은 폴더)
C: review.md, pr_body.md, state.json, metrics
```

## 1. A → B

### 1-1. Terraform 원본 디렉터리 (필수)

- 예: `infrastructure/sg-baseline/`. B 는 이 디렉터리의 `*.tf` 만 읽는다 (하위 디렉터리·`.terraform/`·tfvars 는 읽지 않음).
- B 는 원본을 **절대 수정하지 않는다.** 실행 폴더에 사본을 뜬다.
- 정책상 편집 가능 파일: `*.tf` 중 `provider.tf`, `versions.tf`, `backend.tf` 제외 (`policy/patch_policy.json`).

### 1-2. Trivy JSON (필수)

`trivy config <dir> --format json [--include-non-failures]` 의 출력 그대로. B 가 쓰는 필드:

| 필드 | 용도 |
|---|---|
| `Results[].Target` | finding 의 파일명 (예: `main.tf`) |
| `Results[].Misconfigurations[].ID` / `AVDID` | 룰 ID. `AWS-0107` 이면 `AVD-AWS-0107` 로 정규화 |
| `.Severity`, `.Title`, `.Message`, `.Resolution`, `.Status` | 리포트 표시. `Status != FAIL` 은 대상에서 제외 |
| `.CauseMetadata.Resource` | 리소스 주소 (예: `aws_security_group.vulnerable_ssh`) |
| `.CauseMetadata.StartLine` / `EndLine` | 위치. 같은 리소스에 같은 룰이 여러 개일 때 `--line` 으로 구분 |
| `.CauseMetadata.Code.Lines[].{Number,Content,IsCause}` | **스캔-원본 정합 확인**: IsCause 줄의 Content 가 원본의 그 줄과 같아야 한다 |
| `CreatedAt`, `Trivy.Version` | 기록용 |

대상 선택 키 = (룰 ID, 파일, 리소스, 시작 줄). 조건에 맞는 finding 이 0개면 `NO_FINDING`, 2개 이상이면 `AMBIGUOUS_FINDING` 으로 멈춘다 (첫 항목을 임의로 고르지 않는다).

**정합 한계**: 줄 내용 비교는 "지목된 줄이 그대로 있다" 까지만 보장한다. A 가 스캔 시점의 커밋 해시를 같이 주면(아래 1-3 의 `source_commit`) 완전 확인이 가능하다 — 현재는 기록만 하고 검사에 쓰지 않는다.

### 1-3. 검증 결과 JSON (선택) — `iacpatch-verification-v1`

A 가 V1~V4(·V7) 를 실행한 결과를 이 형식으로 넘기면 B 가 리포트에 연결한다. 없으면 해당 계층은 `NOT_RUN`(검증 대기).

```json
{
  "schema": "iacpatch-verification-v1",
  "source": "A: trivy 0.74.0 재스캔 + terraform 1.16.1 validate/plan (2026-09-xx, WSL)",
  "candidate_sha256": "<선택> B 가 state.json 에 적어 둔 candidate_sha256 을 그대로 복사",
  "source_commit": "<선택> 스캔·검증에 쓴 커밋 해시",
  "layers": [
    {"layer": "V1", "verdict": "PASS", "summary": "AVD-AWS-0107 이 재스캔에서 사라짐", "tool": "trivy 0.74.0", "executed": true,
     "details": {"before_count": 2, "after_count": 1}},
    {"layer": "V2", "verdict": "PASS", "summary": "새 finding 없음", "tool": "trivy 0.74.0", "executed": true},
    {"layer": "V3", "verdict": "PASS", "summary": "validate 통과", "tool": "terraform 1.16.1", "executed": true},
    {"layer": "V4", "verdict": "PASS", "summary": "plan 생성", "tool": "terraform 1.16.1", "executed": true}
  ]
}
```

- `verdict` ∈ PASS / WARN / FAIL / UNKNOWN / SKIPPED / ERROR / NOT_RUN. 모르면 UNKNOWN, 안 돌렸으면 빼거나 NOT_RUN.
- `candidate_sha256` 이 있고 현재 후보와 다르면 B 는 그 파일을 **쓰지 않는다** (다른 후보의 결과이므로). 값은 `state.json` 의 `candidate_sha256` 을 복사하면 된다.
- A 의 기존 스크립트(`experiments/trivy-sg-probe/verify.sh` 류)가 이 형식을 바로 내지 않으면, 결과를 이 JSON 으로 옮겨 적는 변환 스크립트를 A 가 만든다 (B 코드는 `src/iacpatch/review/verification_input.py`).

### 1-4. plan JSON (선택)

`terraform show -json plan.bin` 출력. 원본 plan 과 후보 plan 을 같이 주면 B 가 **로컬에서** V5(구조 비교)를 계산하고, 후보 plan + intent 가 있으면 V6(Intent Oracle)도 계산한다 (terraform 실행 없음).
오프라인 plan(자격증명 없이 provider override)은 "전부 create" 라서 V5 의 삭제/교체 액션은 구조 비교로만 잡힌다 — 상태 기준 plan 이면 실제 액션이 반영된다.

### 1-5. intent JSON (사람이 작성, 선택)

`policy/intent/*.json`. 승인 출처(CIDR/SG 참조/prefix list)와 필수 접근. 플레이스홀더가 남아 있으면 사용 불가. 형식은 `src/iacpatch/intent.py` 머리말과 `docs/INTENT_ORACLE_PLAN.md`.

## 2. B 내부 형식

### 2-1. 후보 (mock / manual → `PatchCandidate`)

| 필드 | 뜻 |
|---|---|
| `origin` | `mock`(고정 fixture) / `manual`(사람이 준비한 파일). 이후 `llm` 이 추가될 자리 |
| `generator` | `mock:<fixture>` / `manual:<파일명>` |
| `provenance` | 사람이 적은 출처 설명 (`--candidate-note`, candidate.json 의 provenance). 리포트에 그대로 실린다 |
| `status` | `PATCH` / `INSUFFICIENT_INFO` / `ABSTAIN` / `GENERATION_FAILED` |
| `files` | `{파일명: 전체 내용}` — 원본에 있는 파일만 허용 |
| `rationale` | 수정 이유. 없으면 `needs_info` 에 "수정 이유 미기재" |
| `needs_info` | 검토 전에 사람이 채워야 하는 정보 |

수동 파일 형식: `.json`(응답 계약), `.tf`(대상 파일 전체 대체), 디렉터리(`*.tf` + `candidate.json{rationale, provenance}`).

### 2-2. B → C 실행 폴더 `data/reviews/<id>/`

| 파일 | 내용 |
|---|---|
| `state.json` | 상태·전환 이력(history)·오류·`verification_status`(NOT_LINKED/PENDING/COMPLETE/FAILED)·`review_level`·`candidate_sha256` |
| `input/trivy.json`, `input/findings.json`, `input/selected_finding.json`, `input/ambiguous.json`, `input/source_check.json` | 입력 사본과 선택 결과, 정합 확인 |
| `original/*.tf`, `original/sha256.json` | 원본 사본 |
| `candidate/*.tf`, `candidate.json`, `candidate.diff` | 후보와 diff |
| `policy.json` | Policy Validator 결과 |
| `verification.json` | 연결된 검증 결과(`report.layers[]`, 계층마다 `details.result_source`), 출처, 노트 |
| `risk.json` | 위험도 판정(`decision`)과 텍스트 근거(`hcl_change`), plan 기반 판정(있을 때) |
| `review.md`, `pr_body.md` | C 산출물 |

상태 전환: `INPUT_READY → CANDIDATE_READY → VALIDATION_PENDING → REVIEW_REQUIRED`(또는 `VALIDATION_FAILED`). 오류: `INPUT_ERROR`, `NO_FINDING`, `AMBIGUOUS_FINDING`, `CANDIDATE_INVALID`, `INFO_INSUFFICIENT`, `POLICY_BLOCKED`.
`REVIEW_REQUIRED` 는 "사람이 볼 자료가 준비됨" 이지 "패치 검증 통과" 가 아니다. 통과 여부는 `verification_status == COMPLETE` 와 각 계층 상태로 본다.

## 3. C 산출물

- `review.md`: 수정 대상과 이유 / 변경 요약과 diff 위치 / 후보 출처 / 검증별 상태(결과 출처 포함) / 위험도와 근거 / 사람이 확인할 항목 / 미확인 사항 / 입력 정합.
- `pr_body.md`: PR 본문 초안 (게시하지 않음). 검증 대기·실패는 머리에 배너로.
- `iacpatch metrics`: 기록 집계 표 (후보 출처 분포를 항상 같이 표시).

## 4. 이후 단계에 넘기는 것 (연결 명세만)

| 항목 | 필요한 입력 | 담당 |
|---|---|---|
| V5 상태 기준 plan | AWS 프로필로 만든 원본/후보 plan JSON | A(plan 생성) → B(계산은 이미 구현) |
| V6 실제 plan | 팀 승인 CIDR 이 들어간 intent + 후보 plan | B |
| V7 | `describe-security-groups` 등 결과 (`postdeploy` 명령이 읽는 형식) | A |
| V8 | 체크 정의 JSON + 승인 밖 vantage 결과 | C |
| PR 게시 | 사람 승인 후 `pr_body.md` 사용 | C |
| 실제 LLM 후보 | 같은 `PatchCandidate` 를 돌려주는 공급자 (origin=`llm`, 프롬프트 버전·모델 기록) | B (이번 범위 아님) |
