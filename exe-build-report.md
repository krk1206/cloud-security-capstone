<!-- iacpatch-exe-build -->
## IaCPatch.exe 빌드 (Windows 러너, run 37213269577)

| 단계 | 결과 |
|---|---|
| 러너 Python 으로 단위 테스트 (Windows) | success |
| exe 스모크 (--exec, --console --report-only) | success |
| 창 없는 exe 실행 확인 | success |
| exe 안에서 단위 테스트 (참고용) | failure |

아티팩트 IaCPatch-portable 은 스모크가 통과했을 때만 올라간다. 아래는 각 로그의 끝부분 (전문은 브랜치 ci-logs).

<details><summary>win-unittest.log (끝 60줄)</summary>

```
recovery for review 20261004-153102-7c7394 → D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline
step 1: restore pre-patch files (from run record) into the Terraform directory
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\main.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\outputs.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\provider.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\variables.tf
step 2: git commit as a revert (human)  →  step 3: terraform plan  →  step 4: terraform apply (human-approved)
step 5: terraform plan -detailed-exitcode must report NO changes, and describe-security-groups is recorded → RECOVERED
preview only (--execute not given). Nothing was changed.
PR preparation for review 20261004-153102-a53af8 (decision=LIGHT_REVIEW)
  branch : iacpatch/pr-t-20261004-153102-a53af8
........................s........................................................................................................sssssss......................................................s..............................................
----------------------------------------------------------------------
Ran 237 tests in 23.321s

OK (skipped=9)
  title  : [iacpatch] pr-t: AVD-AWS-0107 on aws_security_group.vulnerable_ssh
  files  : main.tf -> infrastructure/sg-baseline/
  body   : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-d1rnjzul\20261004-153102-a53af8\pr_body.md
  script : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-d1rnjzul\20261004-153102-a53af8\pr_commands.sh
preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.
refusing to create a PR: review record not found: D:\a\cloud-security-capstone\cloud-security-capstone\data\reviews\no-such-review
PR preparation for review 20261004-153102-976b04 (decision=LIGHT_REVIEW)
  branch : iacpatch/pr-t-20261004-153102-976b04
  title  : [iacpatch] pr-t: AVD-AWS-0107 on aws_security_group.vulnerable_ssh
  files  : main.tf -> infrastructure/sg-baseline/
  body   : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-n_hvr3j9\20261004-153102-976b04\pr_body.md
  script : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-n_hvr3j9\20261004-153102-976b04\pr_commands.sh
preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.
refusing to create a PR: review level is 'PENDING' (검증 미완(NOT_RUN/UNKNOWN 남음)); only LIGHT_REVIEW / FULL_REVIEW may become PRs. state=REVIEW_REQUIRED verification=PENDING review_level=PENDING
refusing to create a PR: review level is 'BLOCKED' (정책 위반 또는 검증 FAIL); only LIGHT_REVIEW / FULL_REVIEW may become PRs. state=VALIDATION_FAILED verification=FAILED review_level=BLOCKED
```
</details>
<details><summary>smoke.log (끝 40줄)</summary>

```
=== 1) IaCPatch-console.exe --selfcheck (root/frozen/tools/install check)
root      : D:\a\cloud-security-capstone\cloud-security-capstone
frozen    : True  (_MEIPASS=C:\Users\RUNNER~1\AppData\Local\Temp\_MEI000024502)
executable: D:\a\cloud-security-capstone\cloud-security-capstone\IaCPatch-console.exe
python    : 3.14.7 Windows 2025Server
cwd       : D:\a\cloud-security-capstone\cloud-security-capstone
trivy     : 없음  (trivy)  ← 없음
terraform : 없음  (terraform)  ← 없음
selfcheck : OK
=== exit 0
=== 2) IaCPatch-console.exe --exec scripts/pyver.py
=== exit 0
=== 3) IaCPatch-console.exe --console --report-only --no-open
trivy    : 없음  (trivy)  ← 없음: 해당 계층은 NOT_RUN
terraform: 없음  (terraform)  ← 없음: 해당 계층은 NOT_RUN
terraform 이 없으면 V3~V6 이 NOT_RUN 이 된다. scripts/setup_tools.bat 를 먼저 돌려라.
설치 상태 검사 OK (python 3.14.7)

================ 리포트 생성
→ D:\a\cloud-security-capstone\cloud-security-capstone\report\index.html

완료. 리포트: D:\a\cloud-security-capstone\cloud-security-capstone\report\index.html
=== exit 0
=== report\index.html written: 68348 bytes
```
</details>
<details><summary>exe-unittest.log (끝 60줄)</summary>

```
s....s..................s........................................................................................................sssssss...................................recovery for review 20261004-153218-675268 → D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline
step 1: restore pre-patch files (from run record) into the Terraform directory
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\main.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\outputs.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\provider.tf
   - D:\a\cloud-security-capstone\cloud-security-capstone\infrastructure\sg-baseline\variables.tf
step 2: git commit as a revert (human)  →  step 3: terraform plan  →  step 4: terraform apply (human-approved)
step 5: terraform plan -detailed-exitcode must report NO changes, and describe-security-groups is recorded → RECOVERED
preview only (--execute not given). Nothing was changed.
.PR preparation for review 20261004-153218-fb6f2a (decision=LIGHT_REVIEW)
  branch : iacpatch/pr-t-20261004-153218-fb6f2a
  title  : [iacpatch] pr-t: AVD-AWS-0107 on aws_security_group.vulnerable_ssh
  files  : main.tf -> infrastructure/sg-baseline/
  body   : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-w_fw4lsk\20261004-153218-fb6f2a\pr_body.md
  script : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-w_fw4lsk\20261004-153218-fb6f2a\pr_commands.sh
preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.
.refusing to create a PR: review record not found: D:\a\cloud-security-capstone\cloud-security-capstone\data\reviews\no-such-review
.PR preparation for review 20261004-153218-7e4cf5 (decision=LIGHT_REVIEW)
  branch : iacpatch/pr-t-20261004-153218-7e4cf5
  title  : [iacpatch] pr-t: AVD-AWS-0107 on aws_security_group.vulnerable_ssh
  files  : main.tf -> infrastructure/sg-baseline/
  body   : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-dxa4f2ks\20261004-153218-7e4cf5\pr_body.md
  script : C:\Users\runneradmin\AppData\Local\Temp\iacpatch-pr-review-dxa4f2ks\20261004-153218-7e4cf5\pr_commands.sh
preview only. Review pr_body.md, then either run the script above yourself or re-run with --execute.
.refusing to create a PR: review level is 'PENDING' (검증 미완(NOT_RUN/UNKNOWN 남음)); only LIGHT_REVIEW / FULL_REVIEW may become PRs. state=REVIEW_REQUIRED verification=PENDING review_level=PENDING
refusing to create a PR: review level is 'BLOCKED' (정책 위반 또는 검증 FAIL); only LIGHT_REVIEW / FULL_REVIEW may become PRs. state=VALIDATION_FAILED verification=FAILED review_level=BLOCKED
...............s...............................F..............
======================================================================
FAIL: test_build_info_from_git_or_file (test_update.UpdateTests.test_build_info_from_git_or_file)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "D:\a\cloud-security-capstone\cloud-security-capstone\tests\unit\test_update.py", line 122, in test_build_info_from_git_or_file
    self.assertEqual(len(info["sha"] or ""), 40)
    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError: 0 != 40

----------------------------------------------------------------------
Ran 237 tests in 16.002s

FAILED (failures=1, skipped=11)
```
</details>
