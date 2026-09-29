"""`iacpatch pr --review <id>` — 실험에 쓰는 review 기록으로 PR 을 준비한다 (미리보기만; git/네트워크 없음).

- LIGHT_REVIEW / FULL_REVIEW 만 PR 준비를 허용하고, PENDING(검증 미완)·BLOCKED 는 거부한다.
- 후보 파일은 기록의 candidate/ 에서 기록의 tf_dir 로 복사하는 명령이 만들어진다.
- 구 기록(tf_dir 없음)은 --tf-dir 를 요구한다.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.config import load_settings
from iacpatch.models import ReviewLevel, ReviewState
from iacpatch.review.flow import ReviewOptions, run_review
from iacpatch.tools.github import load_pr_source, prepare_pr

TF_DIR = "infrastructure/sg-baseline"
TRIVY = "infrastructure/sg-baseline/baseline-scan.json"
EX = ROOT / "examples" / "bc"


class PrFromReviewTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="iacpatch-pr-review-"))
        self.settings = load_settings(str(ROOT))
        self.orig_main = (ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8")

    def tearDown(self):
        self.assertEqual((ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8"), self.orig_main)  # 미리보기는 원본을 건드리지 않는다
        shutil.rmtree(self.out, ignore_errors=True)

    def _opt(self, candidate, **kw):
        base = dict(tf_dir=TF_DIR, trivy_json=TRIVY, candidate=candidate, scenario="pr-t", rule="AVD-AWS-0107", out_dir=str(self.out))
        base.update(kw)
        return ReviewOptions(**base)

    def _intent(self):
        p = self.out / "intent.json"
        d = json.loads((ROOT / "tests/fixtures/intents/sg-baseline.test.json").read_text(encoding="utf-8"))
        d["targets"]["security_groups"] = ["aws_security_group.baseline"]
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["10.0.0.0/8"]
        d["required_access"][0]["source_cidr"] = "10.0.0.0/8"
        p.write_text(json.dumps(d), encoding="utf-8")
        return str(p)

    def _light_review_record(self):
        res = run_review(self.settings, self._opt(
            "mock:sg_baseline_ok", verification=str(EX / "verification" / "example_all_pass.json"),
            baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"),
            candidate_plan=str(ROOT / "tests/fixtures/plans/00b-baseline-fixed/plan.json"), intent=self._intent()))
        self.assertEqual(res.state, ReviewState.REVIEW_REQUIRED, res.message)
        self.assertEqual(res.level, ReviewLevel.LIGHT_REVIEW)
        return res

    def test_light_review_record_prepares_pr_preview(self):
        res = self._light_review_record()
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(st["tf_dir"], TF_DIR)                       # 기록에 되돌릴 위치가 남는다
        rc = prepare_pr(self.settings, review_id=str(res.run_dir))    # 기록 폴더 경로로도 받는다
        self.assertEqual(rc, 0)
        script = (res.run_dir / "pr_commands.sh").read_text(encoding="utf-8")
        rd = res.run_dir.resolve()   # prepare_pr 는 기록 경로를 resolve() 해서 쓴다 — Windows 의 임시 폴더는 짧은 이름(RUNNER~1)과 긴 이름이 다르다 (CI 실측 2026-09-28)
        self.assertIn(f"{rd / 'candidate' / 'main.tf'} {ROOT / TF_DIR / 'main.tf'}", script)
        self.assertIn("git push -u origin iacpatch/pr-t-", script)
        self.assertIn(f"--body-file {rd / 'pr_body.md'}", script)
        msg = (res.run_dir / "commit_message.txt").read_text(encoding="utf-8")
        self.assertIn("[iacpatch] pr-t: AVD-AWS-0107 on aws_security_group.", msg)   # 리소스 이름은 시나리오의 것
        self.assertNotIn("[approval required]", msg)                 # LIGHT_REVIEW 는 승인 표시 없음
        self.assertIn("a human must review and approve", msg)
        self.assertFalse((res.run_dir / "pr.json").exists())         # 미리보기: PR 생성 안 함

    def test_pending_and_blocked_records_are_refused(self):
        pending = run_review(self.settings, self._opt("mock:sg_baseline_ok"))   # 검증 없음 → PENDING
        self.assertEqual(pending.level, ReviewLevel.PENDING)
        self.assertEqual(prepare_pr(self.settings, review_id=str(pending.run_dir)), 3)
        self.assertFalse((pending.run_dir / "pr_commands.sh").exists())
        blocked = run_review(self.settings, self._opt("mock:sg_baseline_cidr_split", verification=str(EX / "verification" / "example_all_pass.json"),
                                                       baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"),
                                                       candidate_plan=str(ROOT / "tests/fixtures/plans/01-cidr-split/plan.json"), intent=self._intent()))
        self.assertIn(blocked.level, (ReviewLevel.BLOCKED,), blocked.message)
        self.assertEqual(prepare_pr(self.settings, review_id=str(blocked.run_dir)), 3)

    def test_old_record_without_tf_dir_needs_override(self):
        res = self._light_review_record()
        st_path = res.run_dir / "state.json"
        st = json.loads(st_path.read_text(encoding="utf-8")); st.pop("tf_dir")
        st_path.write_text(json.dumps(st), encoding="utf-8")
        src = load_pr_source(self.settings, review_id=str(res.run_dir))
        self.assertIn("--tf-dir", src.refusal)
        self.assertEqual(prepare_pr(self.settings, review_id=str(res.run_dir), tf_dir=TF_DIR), 0)

    def test_missing_record_and_bad_args(self):
        self.assertEqual(prepare_pr(self.settings, review_id="no-such-review"), 2)
        with self.assertRaises(ValueError):
            load_pr_source(self.settings)


if __name__ == "__main__":
    unittest.main()
