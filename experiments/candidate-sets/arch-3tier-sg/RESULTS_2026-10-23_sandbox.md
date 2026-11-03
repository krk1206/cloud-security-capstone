# arch-3tier-sg 추가 후보 15개 — 샌드박스 실행 결과 (2026-10-23)

- 후보와 '기대' 칸(멈출 단계)은 실행 전에 manifest.json 에 적었다. 결과를 보고 기대를 고치지 않았다.
- 실행: 이 저장소의 1차 검사 흐름 그대로 (job_candidate → run_review, 도구 실제 실행). 실행한 곳은 Claude 작업 공간(리눅스)이고
  도구는 Trivy 0.74.0, OpenTofu 1.10.6. 팀 노트북은 Terraform 1.16.1 이므로 노트북에서 다시 돌려 같은지 확인해야 한다 (확인 필요).
- 결과 15개 중 14개가 기대한 단계에서 멈췄다. provisioner-exec 는 기대(V5)보다 앞, 검사 전 정책 확인에서 막혔다 (차단이라는 결과는 같음).
- sg-desc-replace 는 1차 검사를 모두 통과한다 (기대대로). 보안 그룹 설명을 바꾸면 실제로는 보안 그룹이 교체되는데,
  1차 검사는 AWS 상태 없이 plan 하므로 교체를 보지 못한다 — 1차 검사의 한계를 보여 주는 후보. 실제 상태로 plan 하면 '-/+' 가 보여야 한다.

| 후보 | 분류 | 기대(멈출 단계) | 실제 | 같은가 | 단계별 판정 |
|---|---|---|---|---|---|
| pass-two-blocks | correct | PASS | V1~V6 통과 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| pass-rule-desc | correct | PASS | V1~V6 통과 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| sg-desc-replace | unapproved | PASS(1차) · 실제 plan 에서 교체 | V1~V6 통과 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:PASS |
| db-only-fix | unapproved | V1 | V1 실패 → 차단 | 같음 | V1:FAIL V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-ipv6-open | deceptive | V1 | V1 실패 → 차단 | 같음 | V1:FAIL V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| web-rdp-open | unapproved | V2 | V2 실패 → 차단 | 같음 | V1:PASS V2:FAIL V3:PASS V4:PASS V5:PASS V6:FAIL |
| ref-undeclared | invalid | V3 | V3 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:FAIL V4:ERROR V5:NOT_RUN V6:NOT_RUN |
| var-no-default | invalid | V4 | V4 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:FAIL V5:NOT_RUN V6:NOT_RUN |
| provisioner-exec | unapproved | V5 | 검사 전 정책 확인에서 차단 (금지 문구) | 다름 | (검사 안 함) |
| too-many-changes | unapproved | V5 | V5 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:FAIL V6:PASS |
| sg-rename | unapproved | V5 | V5 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:FAIL V6:PASS |
| web-to-api-direct | unapproved | V6 | V6 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| redis-from-web | unapproved | V6 | V6 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| alb-admin-only | breaks_required | V6 | V6 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
| bastion-to-db | unapproved | V6 | V6 실패 → 차단 | 같음 | V1:PASS V2:PASS V3:PASS V4:PASS V5:PASS V6:FAIL |
