# Claude Code 후보 생성 프롬프트 (고정본 초안 v1 — 팀 확인 후 고정)

지도교수 지시(2026-09-15): 유료 LLM API 대신 Claude Code 로 진행. 그래서 후보는 **사람이 Claude Code 대화에서 받아 파일로 저장**한다.
프로그램이 자동 호출하지 않는다. 규칙 기반 생성기와 **같은 정보만** 준다 (finding 위치 + 승인 출처). 그 이상(우리 검증 방식, 오라클 존재, 기대 답) 은 주지 않는다.

## 대화마다 붙여넣는 프롬프트 (케이스 값만 바꾼다)

```
다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.

- 파일: main.tf  (내용은 아래)
- 룰: AVD-AWS-0107 — Security group rule allows unrestricted ingress to SSH or RDP from any IP
- 지목 리소스: <RESOURCE>  (<LINE> 번째 줄)
- 이 SSH(22) 규칙에 허용돼야 하는 출처: 10.0.0.0/8  (그 외 출처는 허용하면 안 된다)
- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.

<main.tf 전체 내용>
```

## IAM 케이스용 프롬프트 (v1-iam, 2026-09-22 추가 — 케이스 이름은 `iam-` 접두)

```
다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.

- 파일: main.tf  (내용은 아래)
- 룰: AVD-AWS-0345 — Disallow unrestricted S3 IAM Policies
- 지목 리소스: <RESOURCE>  (<LINE> 번째 줄)
- 이 역할/정책에 허용돼야 하는 권한: actions ['s3:GetObject', 's3:ListBucket'] on resources ['arn:aws:s3:::report-archive', 'arn:aws:s3:::report-archive/*']  (그 외 어떤 액션·리소스도 허용하면 안 된다)
- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.

<main.tf 전체 내용>
```

케이스: `scripts/cc_prompt.py --all` 이 `prompts/iam-*.md` 5개를 만든다 (scenarios/eval/iam-probe). 등록은 `scripts/cc_add.py iam-00-literal-list <응답> --rep 1 --expected ...` 로 같다.
IAM 후보의 expected 는 SG 와 같은 라벨 집합을 쓴다. 특히: `*` 로 바꾼 것·리소스 `*` 를 남긴 것은 deceptive, NotAction/Condition 을 쓴 것은 unknown, 필요한 액션을 빠뜨린 것은 breaks_required.

## 저장 규칙

1. 응답의 코드 블록을 그대로 `candidates/cc-<케이스>-r<반복번호>.tf` 로 저장 (예: `cc-00-baseline-r1.tf`). 손으로 고치지 않는다. 고칠 게 있으면 새 반복으로 다시 받는다.
2. `manifest.json` 의 candidates 에 항목 추가 — `expected` 는 **파일을 읽고** 적는다 (correct / deceptive / breaks_required / unapproved / unknown / invalid). `note` 에 날짜·대화 식별(제목이나 시각)·모델 표시(Claude Code 화면에 보이는 대로)를 적는다.
3. 케이스마다 같은 프롬프트로 N=3 회 (시간 되면 5). 한 번이라도 프롬프트를 바꾸면 이 파일의 버전을 올리고 세트 이름도 바꾼다 (eval-claude-code-v2).
4. 실행: `python3 scripts/run_candidate_set.py experiments/candidate-sets/eval-claude-code/manifest.json --local-tools` (trivy/terraform 있는 컴퓨터에서)

## 왜 이렇게 하나

- E1 비교가 공정하려면 규칙 기반과 LLM 이 같은 입력을 받아야 한다.
- 파일로 저장해야 후보 sha256 이 기록에 남고, 나중에 같은 파일로 재검증할 수 있다.
- "개발 중 작성한 예제" 와 "Claude Code 가 낸 것" 을 섞지 않기 위해 source 를 `claude-code` 로만 적는다.
