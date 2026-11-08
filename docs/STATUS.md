# 구현 현황 (2026-09-13 기준)

> **2026-11-07 17차 — 화면 정리 (D-53 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 요청함의 발표용 타이머 · [다음 요청 지금 받기] · [처음부터] · 방식 고르기를 빼고 [고객 역할로 요청 넣기]만 남김(도착은 실제 날짜 기준 하나 — 11-14 뒤에는 11건 모두 와 있음). 같은 말을 되풀이하던 칸을 뺌(② 숫자 네 칸 · ③ ⑤ '다음 할 일' 칸 · ⑤ '고른 수정안' · '기준' 칸 · ⑥ 아래 그림 · ⑦ ⑧ 세 단계 띠 · ⑧ 결론 칸 · '검증하지 못한 부분' 칸)과 긴 설명을 접음(넘김 이유 · 지킨 조건의 근거 · 확정 뒤 원문). 버그: 요청 4 ④ 에서 같은 규칙이 세 줄 · 'Trivy 못 본 것 2' 로 잘못 세던 것 → 한 줄 · 0, 포트 글자와 ✕ 겹침 · 상자 이름 잘림 · 한글 낱말 중간 줄바꿈 · ⑧ 긴 이름 잘림 · 알림이 머리말을 가림 · ⑦ 할 일 문장 · 머리말 '할 일' 칩만 홀로 남던 줄바꿈 등 11개. 판정 · 정책은 그대로. 확인: 단위 613 · ESLint 0 · E2E inbox 39 · main 87 · team 40 · req 31 · prop 29 · proj 52 · scen 16 · tb 46 · rb 18 · walk 120 + 120. **PC 할 일**: exe 다시 만들기 → v0.15.0 확인.

> **2026-11-06 16차 — 고객 요청함 (D-52 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 같은 가상 운영팀의 요청이 11건으로 늘고, 시간이 지나면 하나씩 '도착' 한다 — ① 맨 위 고객 요청함(실제 날짜 기준 11-05 ~ 11-14 · 발표용 타이머 · [다음 요청 지금 받기] · [고객 역할로 요청 넣기] · [처음부터]) · 어느 화면에서든 새 요청 알림. 요청 4 (DB 보안 그룹 전체 개방) · 6 (업로드 권한 `s3:*`) = ② ~ ⑧ 끝까지 (수정안 12개 결과 = 예상과 같음), 요청 5 · 7 ~ 11 = 정책 밖이라 사람에게 넘김(지금 값 / 요청한 값 표). 새 예제가 드러낸 표시 버그 2개 고침(⑥ V5 '바뀐 리소스 없음' 이 '범위 밖 변경' 으로 보이던 것 · 버킷 하나에 `s3:*` 가 넓은 권한 빨강이 아니던 것) · ⑥ 설명 글의 조사('김담당 가 확정한' → '확정한 사람 김담당') 다듬음. 확인: 단위 613 · ESLint 0 · E2E inbox 32(새) · main 87 · team 40 · req 31 · prop 29 · proj 52 · scen 16 · tb 46 · rb 18 · walk 120+120. **PC 할 일**: exe 다시 만들기 → v0.14.0 확인. (발표용 타이머 · [처음부터] 는 17차 D-53 에서 뺐다.)

> **2026-11-06 15차 — 팀 3계층 고객 요청 3건 (D-51 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 같은 가상 운영팀의 요청 1(Bastion SSH) · 요청 2(S3 공개 차단 꺼짐) · 요청 3(웹 서버 역할 `s3:*`). 요청 2 = 찾기만 하고 고치지 않음 — 팀 정책의 자동 수정 범위 밖이라 ② 맨 위 '사람에게 넘김' 칸(할 일 · 확인 방법). 요청 3 = ② ~ ⑧ 끝까지: V6 가 plan 에 정책 값이 없으면 코드의 `data.aws_iam_policy_document` 를 읽어 참조끼리 비교(`verify/iam_hcl.py`, 모르는 모양은 판정 불가), 요구사항 v1 = 팀 설계 문서에서 옮긴 초안, 수정안 7개 결과 = 예상과 같음(틀린 5개 모두 Trivy 통과 · V6 차단), 그림 = 권한 그림(역할 → 리소스, 요구사항 밖 빨강 · 없어진 필수 권한 빨간 점선). 위험도 버그 1개(data 소스 대상이 '네트워크 가족' 으로 가던 것) 고침. 확인: 단위 586 · ESLint 0 · E2E req 31(새) · team 40 · main 87 · prop 29 · proj 52 · scen 16 · tb 46 · rb 18 · walk 78+78. **PC 할 일**: exe 다시 만들기 → v0.13.0 확인. 팀이 정할 것: 요청 2 를 정책에 넣을지(정책 3줄 + S3 용 V6 필요).
> **2026-11-06 14차 — 예제마다 가상 고객 요청서 + 조건마다 지켰는지 (D-50 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 두 예제에 '(가상) 3계층 웹 서비스 운영팀' 의 요청서 (`scenarios/requests/`, 조건 5개). ② 맨 위에 요청 · [요청서 보기], ⑤ 수정안마다 조건 5칸(✓ · ✕ · … 아직), ⑥ 조건마다 근거, ⑧ 짧은 칸 · 끝맺음 · PR 본문에도. 조건 결과는 기록 값(V1 · V6 · V5 · V2 · 결정 · 시험 환경)을 모은 것 — 새 판정 없음. ① 카드와 ② 의 리소스 수가 달랐던 것(54 · 55, data 소스) 고침. 확인: 단위(새 test_request 14) · ESLint 0 · E2E team 40 · main 87 · proj 52 · scen 16 · tb 46 · prop 29 · rb 18 · walk 66+66. **PC 할 일**: (13차 할 일과 같이) exe 다시 만들기 → v0.12.0 확인.
> **2026-11-04 13차 — 팀 저장소 3계층이 기본 예제 · [전체 보기] 제거 · 버그 4개 · main 과 합칠 준비 (D-49 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① 첫 예제 = 깃허브 main 의 팀장 `infrastructure/three-tier` 사본 + 시나리오 1(Bastion SSH 전체 공개), ③ 설계도 v1 = 팀 설계 문서의 허용 통신 5개(담당자 확정), ⑤ 수정안 1~4 마다 그림이 바뀜(정답 3번). 두 번째 예제 = 3계층(AWS 시험 환경 실측 — ⑦ 용). 게시판은 숨김. [전체 보기] 없음. 규칙을 따로 쓴 코드에서 나던 버그(④ 같은 문제 두 줄 · 'Trivy 는 못 봄' 잘못 · 그림 위치 못 찾음 · 'web → web') 와 ② 숫자 '그림의 상자' 가 출발지를 빼고 세어 그림과 다르던 것(5개인데 4) 수정. main 과는 충돌 없이 합쳐짐(확인용 합친 트리에서 단위 545 OK). 확인: 단위 545(둘 다) · ESLint 0 · E2E team 29 · main 86 · proj 52 · scen 16 · tb 46 · prop 29 · rb 18 · walk 66+66 (팀 3계층 · 큰 글씨). **PC 할 일**: exe 다시 만들기 · GitHub Desktop 에서 exe 4개 · 안 쓰는 파일 2개 지우고 커밋 → 'Update from main' → push → 새 PR.
> **2026-11-04 12차 — 그림은 통신만 · ⑤ 번호마다 그림이 바뀜 (D-48 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ②③④⑤⑥ 의 기본 그림 = 흐름 그림 (상자 = 출발지 · 보안 그룹 묶음, 화살표 = 허용 포트). VPC · 서브넷 틀 · 게이트웨이 · IAM · S3 는 [전체 보기] 에서만. ⑤ 는 나란히 그림 대신 그림 하나 — 수정안 1~4 를 누를 때마다 그 그림이 '수정안 N 적용 후' 로 바뀌고 설계도와 다른 곳만 빨강, [고객 설계도] 단추로 같은 자리에서 설계도. 수정안 번호 → 그림 → 결과 → 다른 방법(AI · 설계도대로 자동 수정 · 내 파일) 순서. 기록 이름은 지금 목록 이름(3계층의 '후보 14' → '수정안 1'). 검사 · 판정 · 승인 · PR 규칙은 그대로. 확인: 단위 536 OK(둘 다) · ESLint 0 · E2E main 85 · proj 52 · scen 16 · tb 46 · rb 18 · prop 29 · walk 66+66. **PC exe · 팀 저장소 반영은 아직** — exe 다시 만들고 ② 그림에 상자 · 화살표만 있는지, ⑤ 번호 1~4 를 누를 때마다 그림이 바뀌는지 본다.
> **2026-11-03 11차 — 화면 줄이기 (D-47 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① 예제 = 고객 제안서 · 3계층 둘만 (2계층 IAM 예제는 화면에서 숨김 — 실험 · 시험은 그대로), 시작 화면은 준비 상태 + 예제 카드만. ⑤ 수정안 = 4개 큰 버튼 + **미리 분석**(프로젝트를 열 때 · 설계도 확정 뒤 배경에서 미리 검사) → 번호를 누르면 기다림 없이 오른쪽 그림이 그 수정안으로 바뀐다. 화면 안내 · 검사 범위 표 · 전문가 화면 링크 · 리소스 목록 · 거름 버튼 · '자세히' 접힘 칸 · 버전 카드 제거. 검사 · 판정 · 승인 · PR 규칙은 그대로. 확인: 단위 536 OK(둘 다) · E2E main 82 · proj 51 · scen 16 · tb 46 · rb 18 · prop 26 · walk 66+66. **PC exe · 팀 저장소 반영은 아직** — exe 다시 만들고 ① 고객 제안서 → ③ 확정 → (미리 분석 끝날 때까지 1~2분) → ⑤ 번호 1~4 눌러 그림이 바뀌는지 본다.
> **2026-11-03 10차 — ⑤ 설계도대로 자동 수정(규칙 기반) · 고객 제안서 예제 (D-45 · D-46 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① ⑤ 에 '설계도대로 자동 수정 (규칙 기반 · AI 아님)' — 연결한 프로젝트 · 예제 모두 ③ 설계도의 '밖에서 → 이 계층' 화살표의 IP 대역을 허용 목록으로 써서 지목된 규칙의 IP 목록만 바꾸고 바로 8개 관문. 못 하는 것(규칙 삭제 · 보안 그룹 참조 · 설계도에 없는 보안 그룹 · 설계도가 이미 공개 허용)은 '수정안 없음' + 이유 + ③ 으로 안내. 규칙 기반 기준선이 예제 세트 밖에서도 AI 수정과 나란히 비교된다. ② 예제 '고객 제안서 — 모두의 게시판' (`scenarios/arch/board-saas` + `PROPOSAL.md`): ③ 설계도 v1 = 제안서 조건을 옮긴 **초안** → 담당자 확정 → ⑤ 규칙 기반 · AI · 직접 → ⑧ 승인 → PR(시연용). ① 시작하기 카드 4개. 확인: 단위 535 OK(도구 있음 · 없음 둘 다) · ESLint 0 · E2E main 80 · proj 51 · scen 16 · tb 46 · walk 66(+66 큰 글씨) · rb 18 · prop 22. **PC exe · 팀 저장소 반영은 아직** — exe 다시 만들고 ① 에서 '고객 제안서로 해 보기' 를 눌러 ②~⑧ 을 한 번 따라가야 한다.
> **2026-11-03 PR 실측 (팀 PC, D-44)**: 예제 기록으로 GitHub 에 첫 PR 을 만들었다 (`[approval required] [iacpatch] arch-3tier-sg: AVD-AWS-0107 …`, base = 저장소 기본 브랜치 `claude/iacpatch-sg-slice`). GitHub 검사: Trivy 스캔 통과 · **단위 시험 실패 6건 — 예제 원본을 기준으로 읽는 시험이라 '예제를 고치는 PR' 에서는 실패가 정상** → 예제 PR 은 시연용으로 두고 병합하지 않는다 (프로그램이 PR 준비 확인 · PR 본문에 그렇게 적음). PATH 에 git 없이 GitHub Desktop 내장 git 으로 PR 준비 확인 · push 가 됐다 (9차 대체 경로 실측).
> **2026-11-02 9차 — ⑦ 시험 환경을 흐름 화면 안에서 · '다음 할 일' · 버그 (D-43 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① ⑦ AWS 시험 환경 = 원본 반영 → 수정 전 측정 → 수정안 반영 → 수정 후 측정 → 시험 환경 삭제를 흐름 화면 안에서 끝까지 (전문가 화면과 같은 API · 같은 판단 함수, 반영 · 삭제는 '실행 전 확인 (아직 반영 안 됨)' 창에서 사람이 체크 + [실행], 측정은 읽기만 · 반영 성공 뒤 자동 1회). 전문가 화면 링크는 '원본 증거' 용으로만. ② 머리말 '할 일' = 지금 상태의 할 일 하나, ③ ⑤ ⑧ 맨 위 '다음 할 일' 칸(③ 예제는 '바꿀 것 없음', 초안은 확정 버튼 / ⑤ AI · 팀 · 내 파일 중 지금 누를 것 / ⑧ 5칸 띠 + 승인 뒤 PR 준비 확인 자동), 시작 화면 '가장 짧은 길'. ③ 버그: ⑧ 이유 · 이름 지워짐, PR 준비 확인 겹침, 색 없는 알림 안 보임, NOT_RUN 영문. ④ Windows 에서 PATH 에 git 이 없어도 GitHub Desktop 내장 git · Git for Windows 기본 위치를 찾아 씀. 확인: 단위 516 · E2E main 80/80 · proj 51/51 · scen 16/16 · tb 46/46(새 ⑦, 가짜 terraform · aws) · walk 54/54(1366×768 · 1280×720 · 1920×1080 × 큰 글씨) · ESLint 0. 남은 일(사람): PC 에 반영 뒤 exe 빌드(`packaging\build_exe.ps1`) · 실제 AWS 로 ⑦ 1바퀴 · GitHub Desktop 커밋
> **2026-11-02 8차 — 검토 문서(ZIP · GitHub 검토) 대응 1~3단계 (D-36 · D-37 · D-38 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① AI 수정 결과 = 검증 통과만 성공 — 실패를 수정안 부적합(재요청) · 실행 오류 · 검증 불가(AI 에게 다시 묻지 않음) · 같은 수정안 반복으로 나누고 종료 코드 0/1/2/3/4 (전에는 GAVE_UP 도 0). ② 버전 묶음(프로그램 판 0.7.0 · 커밋 · 소스 지문 · 정책 · 위험도 기준표 · 요청문 · 도구)을 ① 준비 상태 · 검사 기록 · AI 실행 · PR 요약 · ⑧ '이 판정의 버전' 에 기록, exe 가 옆 폴더 코드와 다르면 경고. ③ 설계도 초안 ↔ 확정 — 담당자가 이름을 적고 확정하기 전의 설계도(자동 기준 · 저장만 한 판)로 한 검사는 통과해도 '고객 요구 충족' 이 아니고 승인 불가, 검사 기록에 검사 당시 확정 상태를 고정, 실험 세트 설계도는 '팀 작성 평가 기준' 으로 표시. ④ 낱말 규칙(D-39): '후보' → '수정안', '실제 AWS 검사' → 'AWS 시험 환경 검사', 통과 문장에 '운영 반영 후 확인 아님', ⑥⑦⑧ 세 단계 띠(배포 전 → 시험 환경 → 운영), 그림 선 = 보안 그룹 허용(실제 연결 아님). ⑤ IAM 요구사항 파일 버전(D-40): ③ 에서 고친 JSON 올리기 → 초안 → 확정, 검사 입력이 따라감. ⑥ CI 사본 고침 · 검증 범위 표 · 범위 밖 표(D-41: docs/actions/iac-scan.yml · terraform-plan.yml, docs/VERIFICATION_SCOPE.md, docs/OUT_OF_SCOPE.md). ⑦ 끝맺음 세 줄(⑧ · PR 본문) · 실패 갈래 시나리오 E2E(scen 16) · docs/SCENARIOS_E2E.md · docs/EVAL_PROTOCOL.md (D-42). 확인: 단위 513 · E2E main 80/80 · proj 51/51 · scen 16/16 · ESLint 0. PC 저장소에 소스 59개 파일 반영(sha256 일치, 덮어쓴 36개는 `_백업_2026-11-02_검토대응_전\`). **exe 는 아직 7차 판** — PC 에서 `packaging\build_exe.ps1` 로 다시 빌드해야 ① 준비 상태에 판 번호 · 커밋 · 소스 지문이 나온다. 남은 일(사람): exe 빌드 · GitHub Desktop 커밋 · .github 사본 올리기 · held-out 평가 묶음
> **2026-11-02 7차 (B: "청중 · 사용자가 쓰기 쉽게 — 전체적으로 · 다양한 거 추가 · PR 링크도 바로 넘어가게", D-35 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ① 준비 상태 + [준비하기](검사 도구 설치) · 처음 여는 예제는 바로 점검 · 머리말 할 일 한 줄 · 화면 안내(하이라이트 + 바로 가기) · 메뉴 네 묶음 + ⑧ 밑 PR 만들기 바로 가기 · 용어 풀이 · 크게 보기 · ④ 한 줄 요약 + 'Trivy 가 못 본 문제' 강조 · ⑤ AI 버튼 맨 위 · 팀 후보 접기 + 후보마다 바꾼 곳 한 줄 · ⑦ 실제 AWS 검사 순서. 확인: 단위 497 · E2E main 75/75 · proj 40/40 · 새 설치 시나리오(도구 없음 → 준비 실패 기록 표시 / 준비 성공 → 예제 자동 점검 → 그림 51초) · ESLint 0. PC exe 에서는 아직 확인 안 함
> **2026-11-01 6차 (B: "너무 어려움 · 설계도랑 토폴로지를 합치지 말고 따로 · 후보는 각각", D-34 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ③ = 왼쪽 설계도만 그린 그림 + 오른쪽 통신 목록([허용]/[막기] · 이 IP만 허용 · 이 서버만 허용 · 통신 추가 → 미리보기 → 저장). ⑤ = 후보 하나씩 버튼(AI 는 시도마다) → 왼쪽 설계도 · 오른쪽 그 후보 적용 후 나란히, 설계도와 다른 선만 빨강 + 다른 곳 목록. ③⑤⑥ 그림 기본 = 통신 관련만, [전체 보기]. 확인: 단위 497 · E2E main 63/63 · proj 39/39 · 11/11 · 17/17 · 43/43 · 45/45 · 스모크 HTTP 오류 0 · ESLint 0
> **2026-11-01 갈아엎기 5차 (B: "토폴로지를 저것만 해 · 사용하기 어렵게 · 설계도 굳이 꼭 완전히 넣을 필요 없잖아", D-33 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: ②~⑥ 그림 = 코드의 리소스 전부를 AWS 구성도처럼(VPC · 공개/비공개 서브넷(코드의 라우팅) · 게이트웨이 · LB → 서비스 · DB · 캐시 · IAM 역할 · S3 · CloudFront 등, 공식 아이콘). 보안 그룹 허용은 포트 단위 색(위험한 포트만 빨강), 상자 숫자 = 문제 수. ③ 원하는 구조 = 자동 기준 v1(지금 코드 − 위험한 통신) + 그림에서 바꾼 것(선: 그대로 · 막기 · 출발지 좁히기 · 포트 바꾸기 / 상자: 들어오는 통신 모두 빼기 · 통신 추가) → 미리보기 → 저장 = 새 버전. 폼 편집기 삭제. ⑤⑥ = 적용 후 구성도 + 원하는 구조 겹쳐 보기 + 새로 생긴 · 없어진 통신. ③ 'AI 에게 이대로 고치게 하기' (설계 위반을 고칠 대상으로 ⑤ AI 수정 시작). 자동 기준으로 검사한 결과에는 '고객이 확인한 구조 아님' 을 확인하지 않은 것에 적음. 확인: 단위 491(새 test_archmap 8 · test_structure 8 · test_archlayout_js 2 · 서버 1) · E2E main 59/59 · proj 38/38 · ③ AI 버튼 5/5 · 11/11 · 17/17 · 43/43 · 45/45 · 스모크 HTTP 오류 0. 발표 흐름은 프로그램 순서 유지(화이트보드를 고침)

> **2026-11-01 갈아엎기 4차 (B: "3계층 아니어도 됨 · 갈아엎어라 · 스토리대로 탄탄하게", D-32 — 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 시작 화면 맨 위 = '새 프로젝트 — 내 Terraform 폴더 연결'(경로로 연결 · 읽기만 · 바로 점검). 아무 Terraform 폴더로 ②~⑧: 코드 그림 → 설계도 초안 확정 → 문제 → (④ 에서 고른 문제 = ⑤ 고칠 대상) → AI · 직접 수정 → 판정 → 시험 환경이 없으면 '실제 AWS 미검증' 확인 표시 승인 → 그 폴더의 git 저장소로 PR 준비. 지원 범위 밖(AWS 를 조회하는 data 소스 · 모듈)은 plan 을 돌리지 않고 이유와 함께 '그리지 못함 · 탐지만'. 새 예제 `scenarios/arch/orders-ecs`(ALB → ECS Fargate → PostgreSQL + 운영 EC2, 3계층 아님). 확인: 단위 472(새 test_projects 16) · 새 E2E `proj_e2e.js` 36/36(주문 서비스 폴더를 프로그램 밖 git 저장소로 두고 연결 → 설계도 v1 → DB 설계 위반 고르기 → AI(대역) 시도 1 막힘 · 2 통과 → ⑧ 확인 표시 없이 거절 · 표시 후 승인 → PR 준비 통과 · 미리보기 → 확인 창에서 취소 → 연결 끊기 뒤 폴더 · git 그대로 + data 소스 폴더 = 분석 못 함) · 기존 E2E 54/54 · 11/11 · 17/17 · 43/43 · 45/45. PR 실제 실행 · 실제 Claude 는 안 함 (사람)

> **2026-11-01 갈아엎기 3차 (B: 전면 재설계 요구사항 — 새 프로그램 8단계, 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 첫 화면 `/` = 사용자 질문 8단계(프로젝트 → 현재 인프라(코드에서 그림 · 분석 못 한 리소스 표시) → 고객 설계(없으면 초안 → 사람이 확정) → 보안 문제(Trivy 전체 + 자체 보안 그룹 검사 + 설계 위반, 같은 문제 합침) → 수정 후보(설계도 vs 적용 후 구조 나란히) → 적용 판단 → 실제 AWS → 최종 결정 · PR 준비 확인 · PR 버튼). 검사 범위 표. 결정 D-31. 확인: 단위 455 (도구 포함), 새 화면 E2E 53/53 (AI 는 시험용 대역 claude, PR 은 준비 확인 · 미리보기 · 확인 창까지 — 실행 안 함), 이전 화면 E2E 11/11 · 17/17 · 43/43 · 45/45, 스모크 HTTP 오류 0, ESLint 0. 다음: PC 반영 · exe 빌드 확인 · 진짜 Claude 로 AI 수정 · PR 은 사람이 PC 에서 · 내 Terraform 폴더 넣기 · 독립 표본 평가

> **2026-11-01 갈아엎기 2차 (B: 설계도 따라 토폴로지가 바뀌게 · AI 연결 둘 다, 클라우드 작업 환경에서 확인 · PC exe 확인 전)**: 설계도 편집 · 버전(v1 = 실험 기준, 저장하면 새 버전이 지금 기준) · 편집 중 '설계도 + 지금 코드' 겹쳐 그리기(코드에 없는 구성요소 점선 · 설계도에 없는 리소스 빨간 상자) · V6 2판(설계도에 없는 리소스로 들어오는 통신도 위반, 기존 plan 41개 판정 변화 0) · AI 수정(Claude Code 구독, 도구 끔 · 빈 폴더 · 키 제거, 막히면 이유 붙여 최대 3번, 요청문 화면 공개) · Actions 워크플로 파일(`docs/actions/`, 사람이 웹으로 올림). 결정 D-27 · D-30. 확인: 단위 425 (도구 포함), 화면 E2E 4종 17/17 · 11/11 · 43/43 · 45/45 (AI 는 시험용 대역 claude — 진짜 AI 품질은 PC 에서), 스모크 HTTP 오류 0, ESLint 0. 다음: PC 에서 진짜 Claude 로 AI 수정 · 내 Terraform 폴더 넣기(프로젝트) · 변형 실험실 · 도전 화면

> **2026-10-31 갈아엎기 1차 (교수 피드백 2차 · B 결정)**: 첫 화면을 흐름 화면으로(① 설계도 → ② 지금 코드: Trivy 가 찾은 것 / 설계도로만 보이는 것 → ③ 수정 코드 → ④ 8개 관문 → ⑤ 결과), 기존 6단계는 '자세히'(/work). 설계도 그림 고정 좌표 제거 — 설계도 · 후보 검사 결과로 자동 배치. 후보 목록에서 사람이 적은 설명 · 이전 결과 묶음 제거. 결정 D-27~D-29. 다음: LLM 연동(앱 + Actions, 최대 3회 재요청), 설계도 편집 · 버전, 변형 실험실, 도전 화면 · 검사 범위 지도
>
> **2026-10-31 교수 UX 피드백 반영 (클라우드 작업 환경에서 단위 · 화면 E2E 3종 · 스모크 통과, PC exe 확인 전)**: 목적 문장 · 사용자 관점 단계 이름(배포 전 검사 · 실제 AWS 검사 · 승인 결정) · 질문형 검사 이름(V1~V8) · 4단계 결과 화면(결론 · 발견된 문제의 무엇/왜/어떻게 · 다음 할 일 · 확인하지 않은 것, `web/problems.py`) · 3단계 그림을 고른 후보의 구조로. 실행 전 안전 점검 v2(허용 목록 + 원본 검사, D-25). 결정: D-25 · D-26. 남은 것은 아래 1단계 줄과 같음
>
> **2026-10-31 중간발표 피드백 반영 1단계 (클라우드 작업 환경에서 단위 377 · 화면 E2E 3종 통과, PC exe 확인 전)**: 후보 화면 중립화('후보 NN', 기대 결과·메모 화면 자료에서 제외) · 수정 코드 제출(.tf 여러 개 · 폴더, `web/submission.py`) · 설계도 버전 기록(기록마다 sha256 + 사본) · 실행 전 안전 점검(D-23) · V6 문구 범위 제한(D-22 ⑤). 결정: D-22~D-24. 남은 것: 설계도 표 편집·버전 저장, 실패 → 재생성 요청 흐름(최대 3회), 지원 범위 표, 블라인드 평가 모드
>
> **2026-10-27 3계층 시험 환경 실제 AWS 1바퀴 (B, 화면 버튼 — 확인 창에서 사람이 [실행])**: 원본 배포 생성 39 → 수정 전 측정 V7 FAIL·V8 25건 중 4건 불일치(DEPLOY_FAILED, 원본의 기대 결과) → sg-desc-replace plan 확인에서 Bastion 보안 그룹 교체 → 차단(PLAN_BLOCKED, apply 안 함) → pass-rule-desc 반영(제자리 수정 2) 후 V7·V8 PASS(VERIFIED) → pass-two-blocks 반영(제자리 수정 1, pass-rule-desc 반영 상태 기준) 후 V7·V8 PASS(VERIFIED) → destroy 39 — [`scenarios/arch/webapp-3tier-testbed/README.md`](../scenarios/arch/webapp-3tier-testbed/README.md) '실제 AWS 실행 기록'. 그날 고친 화면 동작은 D-21.
>
> **2026-10-04 실제 AWS 1바퀴(B 본인 프리 플랜 계정, 서울)**: 아키텍처 apply 17 → 전 측정 V7 FAIL·V8 FAIL(DEPLOY_FAILED) → 패치 기록 LOW·LIGHT_REVIEW → PR #5 사람 승인·병합 → apply 1 changed → 후 측정 V7 PASS·V8 PASS(VERIFIED) → destroy 17 — [`experiments/arch-webapp-2tier/RESULTS.md`](../experiments/arch-webapp-2tier/RESULTS.md) 5절. V7·V8 실측 2회. 요금·크레딧 확인은 아직.
>
> 2026-10-02 아키텍처 과제(지도교수 9/29): `scenarios/arch/webapp-2tier/` 17 리소스 → Trivy 18 finding → AI 해석 등록(모델 응답 0건) → 패치·검증 세트 SG 7/7·IAM 5/6.
>
> 2026-09-15 B·C 3~4주차 작업(도구·API 없이 파일 입력만으로 동작하는 `iacpatch review` 흐름)은 [`BC_WEEK3-4_STATUS.md`](BC_WEEK3-4_STATUS.md) 에 따로 정리했다.

"실제로 실행한 것" 과 "코드는 있으나 실행하지 못한 것" 을 구분한다. mock 성공은 API 연동 성공이 아니고, 스캐너 통과는 보안 검증 성공이 아니다.

## 완료 (코드 + 테스트 + 샌드박스 실행 확인)

| 항목 | 위치 | 실행 근거 |
|---|---|---|
| Trivy 스캔 어댑터 + finding 파싱 | `tools/trivy.py` | Trivy 0.74.0 실제 실행 (`data/runs-sample/*/run.json`) |
| Terraform 어댑터 (init/fmt/validate/plan/show -json, 오프라인 override) | `tools/terraform.py` | 샌드박스는 **OpenTofu 1.10.6 + AWS provider 5.100.0** (릴리스 서버 차단). 팀 PC 에서 **Terraform 1.16.1** 로 4세트 38건 재실행(2026-09-22 16:12, `results-history/*-DESKTOP-TSH8UUD.md`) → 상태·검토 수준·위험도·V1~V6 판정이 샌드박스 기록과 38/38 동일 |
| Intent Spec 로딩/검증 (플레이스홀더·draft·인터넷 전체 승인 거부) | `intent.py` | `test_intent.py` |
| Evidence Bundle | `evidence.py` | 통합 테스트 |
| LLM 응답 계약·파싱 (잘림/비JSON/스키마 위반 → GENERATION_FAILED) | `generator/base.py` | `test_generators.py`, matrix |
| Mock 제공자 (키 없이 실행) | `generator/llm_providers.py` | matrix 17종 |
| Rule-based baseline 생성기 | `generator/rule_based.py` | `test_generators.py`, matrix |
| Policy Validator (경로/보호 파일/금지 토큰/provider 블록/파일 수) | `policy/validator.py` | `test_policy_risk_gate.py`, matrix(edits_provider) |
| V1 대상 finding 제거 / V2 finding 집합 비교 | `verify/layers.py` | `test_layers.py` (실제 Trivy JSON fixture) |
| V3 validate / V4 plan | `verify/layers.py` | 통합 테스트 (tofu) |
| V5 plan 구조 비교 (삭제/교체/허용 밖 타입·속성/개수/provider) | `verify/layers.py` | `test_layers.py`, matrix |
| **V6 Intent Oracle** (집합 계산, v4/v6 분리, 방향·프로토콜·포트, prefix list 전개, 참조 SG 비상속, ENI 합산, UNKNOWN) | `verify/netset.py`, `plan_model.py`, `sg_oracle.py` | `test_oracle_fixtures.py` 22 케이스 (실제 plan JSON), matrix |
| Risk Rubric Scorer (결정론적, hard condition) | `policy/risk.py`, `policy/risk_rubric.json` | `test_policy_risk_gate.py` |
| Gate (검증/위험도 별도 축, LLM 하향만) | `policy/gate.py` | `test_policy_risk_gate.py`, matrix(ok_propose_low) |
| 오케스트레이터 + 재시도 루프 + 실행 기록 + PR 본문 | `pipeline.py`, `runrecord.py`, `report.py` | 통합 테스트 7종, matrix 17종 |
| CLI (selfcheck/scan/predeploy/oracle/pr/postdeploy/recover) | `cli.py` | predeploy/oracle/selfcheck 실행 확인 |
| 테스트 fixture (plan 23종 + Trivy 23종 + mock 응답 16종 + intent 2종) | `tests/fixtures/` | `scripts/generate_fixtures.sh` 로 재생성 가능 |
| 문서 정정 (TerraProbe 분모, validate, S3, 00-baseline 오해) | `docs/DOC_CORRECTIONS.md` + README/한장요약/criticism 최소 수정 | arXiv 원문 대조 |

## 부분 구현 (코드는 있으나 이 환경에서 실행하지 못함)

| 항목 | 위치 | 상태 | 필요한 것 |
|---|---|---|---|
| 실제 LLM API 제공자 (anthropic / openai / openai_compatible) | `generator/llm_providers.py` | 코드 작성, **미실행**. 키 없음·제공업체 미정. 키 없이 호출하면 error 로 끝나는 것만 확인 | 제공업체 결정 + 키(환경변수) + 첫 실행 기록 |
| V7 AWS 실측 (describe-security-groups / network-interfaces / prefix-list 전개 → 오라클) | `postdeploy.py`, `tools/awscli.py` | 코드 + FakeCli 단위 테스트. **10-04 실제 AWS 2회**: 전 FAIL(22 ← 0.0.0.0/0 EXCESS) / 후 PASS (`RESULTS.md` 5.3·5.5) | IAM 세트·prefix-list 케이스는 아직 |
| V8 통신 확인 (허용 성공 + 승인 밖 vantage 에서 실패) | `postdeploy.py`, `scripts/arch_v8_checks.py` | **10-04 실제 인스턴스 2회**: 승인 밖인 B 의 PC 에서 전 FAIL(22 열림) / 후 PASS(80 열림, 22·3389·8080 닫힘) | 핫스팟 관측 지점은 선택(미실행) |
| 복구 절차 (파일 복원 → plan → apply → 수렴 확인 + describe 기록) | `postdeploy.run_recover` | 미리보기 모드만 실행. 09-22: `--review <id>` 로 실험 기록의 `original/` 에서 복원 가능(단위 테스트) | 샌드박스에서 `--execute` (사람 승인) |
| 배포 후 결과를 실험 기록에 연결 (`postdeploy --review`) | `postdeploy.py` | 09-22 구현. FakeCli 단위 테스트 + **10-04 실제 1회** (`20261004-154935-dc5b50` ← `20261004-235735-b463c7` VERIFIED) | — |
| 위험도 기준표 | `policy/risk_rubric.json` risk-v2, `docs/RISK_RUBRIC_V2.md` | 2026-09-22 확정안. 등급 일치율(손 적용 vs 코드) 25/25 (샌드박스 4세트). 팀 OK 후 고정 | 팀 확인 |
| PR 생성 (브랜치/커밋/push/REST) | `tools/github.py` | 미리보기 모드(명령 출력)만 실행. push 미실행. 2026-09-22: `--review <id>` 로 실험 기록(data/reviews)도 받음 — LIGHT/FULL_REVIEW 만 허용, 단위 테스트 4건 | 저장소 권한 + `--execute` (사람) |
| GitHub Actions `iacpatch-verify.yml`(단위 테스트 + 후보 세트 4개 실측 + PR 댓글) / `build-exe.yml`(Windows exe) | `.github/workflows/` | 2026-09-28 작성 (`bc-unit-tests.yml`·`patch-verify.yml` 을 대체). PR #4 첫 실행: **verify 2회 성공**(5m13s, 4m25s — 러너의 Terraform 1.16.1 + Trivy 0.74.0), build-exe #1~#3 실패(원인 셋: exe 에 `iacpatch.fuzz` 누락, 스크립트 모드 상대 import, onefile 임시 폴더 루트) → **#4 성공**(Windows 러너: 단위 테스트 206 OK, exe 스모크·창 없는 exe·exe 안 테스트 206 OK, 아티팩트 `IaCPatch-portable` 45.4 MB). 로그는 브랜치 `ci-logs`. `docs/CI_FIRST_RUN.md` | **팀 PC 실측 완료(09-29)**: exe 더블클릭 → 도구 받기 → 8단계 전체 실행 → 리포트. 38/38 라벨 일치, 사각 탐색 44/44/0, 차등 검증 0 — 샌드박스와 동일 (`docs/worklog/2026-09-28.md`) |
| 온라인 plan (상태 기준, `plan_actions_delete/replace` 실측) | `tools/terraform.py --online` | 오프라인만 실행 | AWS 프로필 |

## 미완료

| 항목 | 이유 / 계획 |
|---|---|
| IAM 과다 권한 시나리오 | **Tier 1 배포 전 슬라이스 구현·실측 (2026-09-22)**: 대상 룰 AVD-AWS-0345, IAM intent(D-7), IAM Intent Oracle(V6), 규칙 기반 IAM 분기, seeded 13 + 규칙 기반 5 (`docs/IAM_SCOPE.md` 머리). 배포 후 V7(IAM 실측)은 미구현 |
| S3 / 컨테이너 CVE / EKS / 대시보드 | 계획대로 핵심 흐름 완성 전 착수하지 않음 |
| Rule-based vs LLM 생성 비교 실험, Oracle 유무 검증 효과 비교 | 실험 경로는 갖춰짐(`--generator rule_based`, `scripts/run_fixture_matrix.py`). 실제 LLM 출력이 있어야 시작 가능. 개발용(`scenarios/dev`)·평가용(`scenarios/eval`) 분리 폴더만 마련 |
| MTTR(사람 승인 대기 제외 자동 처리 시간) 측정 | `timings.json` 에 단계별 시간이 기록되지만(예: 샌드박스에서 predeploy 약 36초, 그중 plan 2회 34초) 실제 LLM/AWS 단계가 없어 수치로 쓸 수 없음 |
| Terraform 1.16.1 로 fixture 재생성 및 결과 비교 | 팀 WSL 에서 `scripts/generate_fixtures.sh` 실행 후 diff |
| CIS 매핑 원문 확인 | `policy/cis_mapping.json` verified=false |

## 안전 기준 (README 14.2) 준수 여부 — 이 환경

- 승인 없는 `terraform apply` 자동 실행: 0건 (코드 경로 없음; recover --execute 만 사람 명령)
- 프로덕션 계정 실행: 0건 (AWS 미접속)
- 정책 위반 패치 병합: 0건 (병합 기능 없음)
- 무인 apply 가 샌드박스 밖에서 실행: 0건

## 이 문서를 읽고 바로 할 일 (팀)

1. WSL 에서 `scripts/run_tests.sh` → 116 테스트 통과 확인 (Terraform 1.16.1 로 통합 테스트 7종 포함)
2. `policy/intent/sg-baseline.json` 작성 (승인 CIDR 은 팀 결정)
3. (2026-09-15 지도교수 지시) 유료 LLM API 대신 **Claude Code** 로 패치 후보를 만든다 → 렌더링된 프롬프트(bundle)를 Claude Code 에 주고 응답 JSON 을 파일로 받는 `file` 제공자 + `prompt` 덤프 명령 추가가 다음 구현 항목. API 제공자 코드(anthropic/openai)는 유지하되 기본 경로가 아니다
4. 샌드박스 apply(사람) → `postdeploy --execute` 로 V7 첫 실측 → 06-prefix-list 배포 후 확인(부록 A 항목)
