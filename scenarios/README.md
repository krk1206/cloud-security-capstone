# scenarios/ — 파이프라인 입력 시나리오

| 폴더 | 용도 |
|---|---|
| `dev/`  | 개발 중 반복 실행하는 시나리오 (게이트 로직을 맞추는 데 사용). 평가 수치에 포함하지 않는다 |
| `eval/` | 평가 전용. **개발 중 게이트/정책을 이 케이스에 맞춰 고치지 않는다.** 실험 프로토콜 확정 후에만 실행한다 |
| `arch/` | 지도교수 9/29 지시의 **아키텍처 단위 시나리오** (`webapp-2tier`: VPC 2계층 웹 17 리소스, 의도적 설정 오류 7줄). 샌드박스 apply 시연·Trivy 점검·AI 해석·패치 세트(`experiments/candidate-sets/arch-webapp-*`)의 원본. `infrastructure/` 가 아니라 여기에 두는 이유: 일부러 취약한 실험 재료라서 — `iac-scan.yml` 의 PR 게이트(HIGH/CRITICAL 이면 실패)는 `infrastructure/**` 만 본다. 실제 샌드박스에 올리는 패치는 `sandbox` 브랜치로 (docs/SOLO_ABC_RUNBOOK.md) |
| `requests/` | 예제마다 **가상** 고객 요청서 (D-50, 14차 · D-51, 15차) — 화면 ② 맨 위 · ⑤ ⑥ ⑧ 의 '고객 요청 조건' · PR 본문. Terraform 폴더 밖에 둔다 (PR 의 `git add` · 원본 plan 캐시에 섞이지 않게). 조건과 검사의 연결은 `src/iacpatch/web/request.py`. 팀 3계층은 같은 가상 운영팀의 요청 11건 (16차, D-52 — 받은 시각은 요청서에 없고 ① 고객 요청함이 정한다: 정해 둔 한국 시각 11-05 ~ 11-14 · 고객 역할로 넣기 — 발표용 타이머는 17차 D-53 에서 뺌, `src/iacpatch/web/inbox.py`): `three-tier-team.md`(요청 1 · Bastion SSH) · `three-tier-team-s3.md`(요청 2 · S3 공개 차단 — 정책 범위 밖이라 사람에게 넘김) · `three-tier-team-iam.md`(요청 3 · 웹 서버 역할 권한) · `-dbsg`(요청 4 · DB 보안 그룹 전체 개방 — 수정) · `-dbpublic`(5 · DB 공개 접속 — 넘김) · `-upload`(6 · 업로드 권한 `s3:*` — 수정) · `-imds`(7 · IMDSv2 — 넘김) · `-dbenc`(8 · DB 암호화 — 넘김) · `-deletion`(9 · 삭제 보호 — 넘김) · `-flowlog`(10 · 흐름 로그 — 넘김) · `-backup`(11 · 백업 1일 — 넘김) |
| `arch/three-tier-team*` | 팀 저장소 main 의 `infrastructure/three-tier` 사본 11개 — 팀 README 의 시나리오 1 · 2 · 3 을 하나씩 넣은 3개 (D-49 · D-51) + 요청 1 · 3 을 고친 코드에 설정 오류를 하나씩 넣은 8개 (D-52 — 요청 9 · 10 은 원래 있던 지적이라 넣지 않음). 원본과 다른 곳은 각 폴더 README 표에 전부 (단위 `test_requests16.py` 가 글자 그대로 비교). 원본 폴더는 건드리지 않는다 |

`infrastructure/sg-baseline/` 은 실제 AWS 샌드박스에 배포하는 기준 시나리오(운영 경로)다.
`tests/fixtures/src/` 는 오라클 단위 테스트용 plan fixture 원본이며, 생성기가 수정하는 대상이 아니다 (policy 의 protected_paths 로 보호됨).
