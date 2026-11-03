# arch-3tier-sg 후보 25개 — 팀 노트북 실행 결과 (2026-10-23)

## 실행 조건
- 실행한 곳: 팀 노트북. IaCPatch.exe (2026-10-23 13:27 빌드 — V3 도구 오류 판정·창 두 개 잠금 포함) 에서 [이 영역 후보 전부 검사] 1회
- 도구: Trivy 0.74.0, Terraform 1.16.1
- 기록: `data/reviews/20261023-133358-e3a04a` ~ `20261023-134045-f3c3bb` (25개, 13:33:58~13:41:03, 후보당 약 18초)
- '분류'와 '기대' 칸은 실행 전에 manifest.json 에 적은 값 그대로다. 결과를 보고 고치지 않았다 (노트북의 manifest.json 이 배포한 파일과 같음을 확인).

## 요약
- 통과/차단: 25개 모두 기대와 같다 (통과 4 = correct-design, pass-two-blocks, pass-rule-desc, sg-desc-replace / 차단 21).
- 멈춘 단계 (기대 단계를 적어 둔 새 후보 15개): 14개 같음. provisioner-exec 는 기대(V5)보다 앞, 검사 전 정책 확인에서 막혔다 (차단 결과는 같음).
- 같은 15개를 샌드박스(OpenTofu 1.10.6)에서 돌린 결과(RESULTS_2026-10-23_sandbox.md)와 단계별 판정이 15개 모두 같다
  → 샌드박스 문서의 '노트북 Terraform 1.16.1 에서 다시 확인 필요' 항목은 확인됨.
- 기존 후보 10개는 어제(03:35~03:46) 기록과 단계별 판정이 모두 같다. 단 하나, 아래 도구 오류 기록만 다르다.
- sg-desc-replace 는 1차 검사를 통과한다 (기대대로). 보안 그룹 설명을 바꾸면 실제로는 보안 그룹이 교체되는데, 1차 검사는 AWS 상태 없이
  plan 하므로 교체를 보지 못한다 — 1차 검사의 한계를 보여 주는 후보 (실제 상태 plan 에서 '-/+' 가 보이는지는 아직 확인 안 함).

## 어제 기록 중 도구 오류 1건 — 지우지 않고 남김
- 기록 `20261023-034254-46e6fa` (correct-design): V3 FAIL. 진단 문구 "Failed to load plugin schemas … failed to instantiate provider … %1 is not a valid Win32 application".
  진단에 파일 위치(range)가 없다 = 후보 코드가 아니라 Terraform 이 provider 실행 파일을 띄우지 못한 것.
- 원인: IaCPatch 창 두 개가 같은 시간에 검사를 돌렸다 (03:42:54 이 기록과 03:42:56 ai-claude-r3 기록이 2초 차이로 시작). 같은 provider 파일을 동시에 쓰다가 깨진 것으로 본다.
- 후보 코드 문제가 아닌 근거: 같은 후보 파일(sha256 6082c7dc…)이 다른 기록 4개(033738, 034005, 124957, 133358)에서 V1~V6 모두 통과.
- 고친 것: (1) provider 를 띄우지 못한 validate 실패는 FAIL 이 아니라 ERROR(판정 불가 · 도구 오류)로 기록한다 — 이 기록의 실제 진단으로 시험해 ERROR 가 나오는 것 확인
  (2) 검사·측정은 PC 전체에서 한 번에 하나만 돈다 (`data/.job.lock` 파일 잠금 — 다른 창에서 누르면 '다른 작업이 끝나기를 기다려 주세요').
- 평가 표에서는 오늘 기록 `20261023-133358-e3a04a` 를 쓴다. 어제 기록은 그대로 두고 이 문서에 대체 이유를 남긴다.

## 2차 검사 (실제 AWS 시험 환경) — correct-design
- 수정 전 (원본 배포): `data/measurements/20261023-125118` — V7 실패 2건 (인터넷→Bastion 22, 웹→MySQL 3306),
  V8 시험 25건 중 21건 기대대로 · 4건 실패 (웹→MySQL 3306, 웹→Bastion 22, API→Bastion 22, 인터넷 지점→Bastion 22)
- 반영: 사람이 plan 확인 후 apply — "0 added, 2 changed, 0 destroyed" (aws_security_group.bastion, aws_security_group.db 제자리 수정)
- 수정 후: `data/reviews/20261023-124957-af6f0b/postdeploy/20261023-130149` — VERIFIED. V7 통과 (설계 통신 9개 열림, 설계 밖 0개),
  V8 25건 모두 기대대로 (열림 9 · 막힘 16), 측정 지점 5곳 모두 측정 시작 뒤 새로 잰 값, 설계 통신 9개 전부 시험
- 수정 전→후로 바뀐 것: 위 4개 통로가 '연결됨'에서 '응답 없음'으로. 나머지 21건은 수정 전·후 모두 기대대로 (설계 통신이 끊기지 않음)
- 삭제: destroy 뒤 상태 파일의 resources 0개 (13:10:48). 시험 환경 파일은 원본으로 되돌림 (`data/testbed_switch.jsonl`)
- 2차 기록은 12:21 빌드로 만든 correct-design 기록(124957-af6f0b)에 붙어 있다. 오늘 기록(133358-e3a04a)과 후보 파일이 같다 (sha256 6082c7dc…).

## 표
| 후보 | 분류 (실행 전) | 기대 | 실제 | 같은가 | 기록 | 단계별 판정 |
|---|---|---|---|---|---|---|
| correct-design | correct | 통과 | V1~V6 통과 | 같음 | 20261023-133358-e3a04a | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| flagged-only-fix | unapproved | 차단 | V6 실패 → 차단 | 같음 | 20261023-133416-fddfc6 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-vpc-cidr | breaks_required | 차단 | V6 실패 → 차단 | 같음 | 20261023-133435-a843d9 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-single-ip | breaks_required | 차단 | V6 실패 → 차단 | 같음 | 20261023-133454-ce0f52 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-cidr-split | deceptive | 차단 | V6 실패 → 차단 | 같음 | 20261023-133512-8c9485 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| db-vpc-wide | unapproved | 차단 | V6 실패 → 차단 | 같음 | 20261023-133530-bf0b80 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| ssh-vpc-wide | unapproved | 차단 | V5 실패 → 차단 | 같음 | 20261023-133548-02c2c5 | V1:PASS V2:PASS V3:PASS V4:PASS V5:FAIL V6:FAIL |
| ai-claude-r1 | unapproved | 차단 | V6 실패 → 차단 | 같음 | 20261023-133606-e0b2bc | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| ai-claude-r2 | unapproved | 차단 | V6 실패 → 차단 | 같음 | 20261023-133623-271be3 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| ai-claude-r3 | unapproved | 차단 | V6 실패 → 차단 | 같음 | 20261023-133641-975c22 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| pass-two-blocks | correct | PASS | V1~V6 통과 | 같음 | 20261023-133659-1b6594 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| pass-rule-desc | correct | PASS | V1~V6 통과 | 같음 | 20261023-133717-903600 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| sg-desc-replace | unapproved | PASS(1차) · 실제 plan 에서 교체 | V1~V6 통과 | 같음 | 20261023-133734-67b6cb | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| db-only-fix | unapproved | V1 | V1 실패 → 차단 | 같음 | 20261023-133752-c8bee0 | V1:FAIL V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-ipv6-open | deceptive | V1 | V1 실패 → 차단 | 같음 | 20261023-133810-0b2f6c | V1:FAIL V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| web-rdp-open | unapproved | V2 | V2 실패 → 차단 | 같음 | 20261023-133828-483019 | V1:PASS V2:FAIL V3:PASS V4:PASS V5:PASS V6:FAIL |
| ref-undeclared | invalid | V3 | V3 실패 → 차단 | 같음 | 20261023-133846-30fecf | V1:PASS V2:PASS V3:FAIL V4:ERROR V5:NOT_RUN V6:NOT_RUN |
| var-no-default | invalid | V4 | V4 실패 → 차단 | 같음 | 20261023-133859-a65ca2 | V1:PASS V2:PASS V3:PASS V4:FAIL V5:NOT_RUN V6:NOT_RUN |
| provisioner-exec | unapproved | V5 | 검사 전 정책 확인에서 차단 (금지 문구 provisioner·local-exec) | 다름 (차단은 같음) | 20261023-133913-591146 | (V1~V6 실행 안 함) |
| too-many-changes | unapproved | V5 | V5 실패 → 차단 | 같음 | 20261023-133914-ccccee | V1:PASS V2:PASS V3:PASS V4:PASS V5:FAIL V6:PASS |
| sg-rename | unapproved | V5 | V5 실패 → 차단 | 같음 | 20261023-133933-ebf3c1 | V1:PASS V2:PASS V3:PASS V4:PASS V5:FAIL V6:PASS |
| web-to-api-direct | unapproved | V6 | V6 실패 → 차단 | 같음 | 20261023-133950-08b355 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| redis-from-web | unapproved | V6 | V6 실패 → 차단 | 같음 | 20261023-134008-b86335 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| alb-admin-only | breaks_required | V6 | V6 실패 → 차단 | 같음 | 20261023-134026-dede56 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-to-db | unapproved | V6 | V6 실패 → 차단 | 같음 | 20261023-134045-f3c3bb | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |

## 이 결과로 말할 수 없는 것
- 후보 25개는 시험용으로 일부러 만든 후보(seeded) 22개 + AI 가 만든 후보 3개다. 실제 AI 출력이 어떤 분포로 나오는지를 대표하지 않는다.
- AI 후보 3개(ai-claude-r1~r3)는 1차에서 모두 V6 에서 차단되어 2차 검사 대상이 없다.
- 2차 검사는 축소 시험 환경 기준이다 (서버 1대씩, DB·Redis 는 포트만 여는 대역 프로그램).
