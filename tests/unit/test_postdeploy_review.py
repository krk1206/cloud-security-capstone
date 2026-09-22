"""`postdeploy --review` / `recover --review` — 배포 후 검증(V7/V8)과 복구를 실험 기록(data/reviews)에 연결한다.
실제 AWS 는 호출하지 않는다 (FakeCli). terraform 도 호출하지 않는다 (tf_dir 의 state 매핑은 실패해도 --sg-ids 로 대체).
"""
import json
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from helpers import ROOT
from test_postdeploy import FakeCli, perm

from iacpatch.config import load_settings
from iacpatch.metrics import collect, render_table
from iacpatch.models import ReviewLevel, ReviewState
from iacpatch.postdeploy import run_postdeploy, run_recover
from iacpatch.review.flow import ReviewOptions, run_review

TF_DIR = "infrastructure/sg-baseline"
TRIVY = "infrastructure/sg-baseline/baseline-scan.json"
EX = ROOT / "examples" / "bc"


class _Listener:
    def __enter__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self):
        try:
            c, _ = self.sock.accept()
            c.close()
        except OSError:
            pass

    def __exit__(self, *a):
        self.sock.close()


class PostdeployReviewTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="iacpatch-pd-review-"))
        self.settings = load_settings(str(ROOT))
        self.orig_main = (ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8")

    def tearDown(self):
        self.assertEqual((ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8"), self.orig_main)
        shutil.rmtree(self.out, ignore_errors=True)

    def _intent_path(self):
        p = self.out / "intent.json"
        d = json.loads((ROOT / "tests/fixtures/intents/sg-baseline.test.json").read_text(encoding="utf-8"))
        d["targets"]["security_groups"] = ["aws_security_group.baseline"]
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["10.0.0.0/8"]
        d["required_access"][0]["source_cidr"] = "10.0.0.0/8"
        p.write_text(json.dumps(d), encoding="utf-8")
        return str(p)

    def _record(self, level_ok=True):
        kw = dict(tf_dir=TF_DIR, trivy_json=TRIVY, candidate="mock:sg_baseline_ok", scenario="pd-t", rule="AVD-AWS-0107", out_dir=str(self.out / "reviews"))
        if level_ok:
            kw.update(verification=str(EX / "verification" / "example_all_pass.json"),
                      baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"),
                      candidate_plan=str(ROOT / "tests/fixtures/plans/00b-baseline-fixed/plan.json"), intent=self._intent_path())
        res = run_review(self.settings, ReviewOptions(**kw))
        self.assertEqual(res.state, ReviewState.REVIEW_REQUIRED, res.message)
        self.assertEqual(res.level, ReviewLevel.LIGHT_REVIEW if level_ok else ReviewLevel.PENDING)
        return res

    def _state(self, res):
        return json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))

    def test_preview_records_unverified(self):
        res = self._record()
        out = run_postdeploy(self.settings, self._intent_path(), ["sg-aaa"], None, execute=False, review_id=str(res.run_dir), cli=FakeCli([]))
        self.assertIn("post_deploy=UNVERIFIED", out)
        st = self._state(res)
        self.assertEqual(st["post_deploy"]["status"], "UNVERIFIED")
        self.assertEqual(st["post_deploy"]["layers"], {"V7": "SKIPPED", "V8": "UNKNOWN"})
        self.assertFalse(st["post_deploy"]["executed"])
        self.assertEqual(st["review_level"], "LIGHT_REVIEW")          # 배포 전 축은 그대로
        self.assertTrue((res.run_dir / st["post_deploy"]["path"] / "verification_post.json").exists())

    def test_executed_pass_and_fail_paths(self):
        res = self._record()
        intent = self._intent_path()
        # V7 PASS (실제 상태가 승인 출처만) + V8 없음 → UNVERIFIED (V8 UNKNOWN 은 통과가 아니다)
        ok = FakeCli([{"GroupId": "sg-aaa", "GroupName": "x", "IpPermissions": [perm(v4=["10.0.0.0/8"])], "IpPermissionsEgress": []}])
        out = run_postdeploy(self.settings, intent, ["sg-aaa"], None, execute=True, review_id=str(res.run_dir), cli=ok)
        self.assertIn("post_deploy=UNVERIFIED", out)
        self.assertEqual(self._state(res)["post_deploy"]["layers"]["V7"], "PASS")
        # V8 스펙까지 주면 VERIFIED: 승인 출처에서 열림(로컬 리스너) + 승인 밖 vantage 의 closed 관측값
        with _Listener() as l:
            spec = self.out / "v8.json"
            spec.write_text(json.dumps({"checks": [
                {"label": "ok-open", "service_label": "ssh", "host": "127.0.0.1", "port": l.port, "expect": "open", "vantage": "local", "source_class": "approved", "timeout_s": 3},
                {"label": "ssh-closed", "service_label": "ssh", "host": "x", "port": 22, "expect": "closed", "vantage": "remote", "source_class": "unapproved", "observed": "timeout"},
                {"label": "rdp-closed", "service_label": "rdp", "host": "x", "port": 3389, "expect": "closed", "vantage": "remote", "source_class": "unapproved", "observed": "refused"},
            ]}), encoding="utf-8")
            out = run_postdeploy(self.settings, intent, ["sg-aaa"], str(spec), execute=True, review_id=str(res.run_dir), cli=ok)
        self.assertIn("post_deploy=VERIFIED", out)
        st = self._state(res)
        self.assertEqual(st["post_deploy"]["status"], "VERIFIED")
        self.assertEqual(len(st["post_deploy_history"]), 2)
        # V7 FAIL (실제 상태가 여전히 전체 개방) → DEPLOY_FAILED + 복구 안내
        bad = FakeCli([{"GroupId": "sg-aaa", "GroupName": "x", "IpPermissions": [perm(v4=["0.0.0.0/0"])], "IpPermissionsEgress": []}])
        out = run_postdeploy(self.settings, intent, ["sg-aaa"], None, execute=True, review_id=str(res.run_dir), cli=bad)
        self.assertIn("post_deploy=DEPLOY_FAILED", out)
        self.assertIn("recover --review", out)
        self.assertEqual(self._state(res)["post_deploy"]["status"], "DEPLOY_FAILED")
        # metrics 표에 배포 후 축이 나타난다
        rows = collect([self.out / "reviews"])
        self.assertEqual(rows[0]["post_deploy"], "DEPLOY_FAILED")
        self.assertEqual(rows[0]["layers"]["V7"], "FAIL")
        table = render_table(rows, "t")
        self.assertIn("| V7 | V8 | 배포후 |", table)
        self.assertIn("DEPLOY_FAILED", table)

    def test_recover_preview_from_review_original(self):
        res = self._record()
        rc = run_recover(self.settings, None, execute=False, tf_dir=None, review_id=str(res.run_dir))
        self.assertEqual(rc, 0)
        st = self._state(res)
        self.assertEqual(st["recovery"]["status"], "RECOVERY_PENDING")
        self.assertFalse(st["recovery"]["executed"])
        self.assertEqual((res.run_dir / "original" / "main.tf").read_text(encoding="utf-8"), self.orig_main)

    def test_pending_record_is_refused(self):
        res = self._record(level_ok=False)
        out = run_postdeploy(self.settings, self._intent_path(), ["sg-aaa"], None, execute=False, review_id=str(res.run_dir), cli=FakeCli([]))
        self.assertTrue(out.startswith("refusing"), out)
        self.assertNotIn("post_deploy", self._state(res))
        self.assertTrue(run_postdeploy(self.settings, self._intent_path(), [], None, False, review_id="nope", cli=FakeCli([])).startswith("review record not found"))


if __name__ == "__main__":
    unittest.main()
