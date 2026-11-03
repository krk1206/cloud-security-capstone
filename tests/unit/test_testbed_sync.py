"""시험 환경 '반영 상태' 판단 (web/proof_api._testbed_files · _sync_basis).

2026-10-27 실제 사례: 원본 배포 뒤 시험 환경 파일을 후보 → 원본으로 바꿨다 되돌리자 내용은 원본 그대로인데 수정 시각만 새로워졌다.
화면은 '파일 변경 후 apply 미실행' 으로 보고 원본 재배포만 안내했고, 원본 재배포 plan 은 '변경 없음' 이라 실행할 수 없어 진행이 막혔다.

지켜야 하는 것
  - 수정 시각이 상태 파일보다 나중이어도, 내용이 마지막 apply 와 같고 상태 파일 번호(serial)가 그대로면 반영 상태로 본다
  - 그 뒤 이 내용으로 한 원본 반영 plan 이 '변경 없음'(NO_CHANGES)이면 반영 상태로 본다 (plan 실패는 근거가 아니다)
  - 이 기록의 plan 확인이 '변경 없음' 이고 그때와 상태 파일 번호가 같으면 반영 상태로 본다
  - 상태 파일 번호가 바뀌었거나(앱 밖 apply·destroy), 마지막 apply 가 다른 내용이거나, 그 뒤 destroy 가 있으면 반영 상태로 보지 않는다
  - 측정 시작 조건(job_measure)도 같은 판단을 쓰고, 측정 증거(tempenv)에 근거를 남긴다
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from helpers import ROOT

SCEN = ROOT / "scenarios" / "arch" / "webapp-3tier"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class TestbedSyncTest(unittest.TestCase):
    SERIAL = 213

    def setUp(self):
        from iacpatch.web import proof_api as pa
        self.pa, self._root, self._reviews = pa, pa._root, pa._reviews
        self.tmp = Path(tempfile.mkdtemp())
        self.tb = self.tmp / pa.TESTBED
        self.tb.mkdir(parents=True)
        (self.tmp / "scenarios/arch/webapp-3tier").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCEN / "security_groups.tf", self.tmp / "scenarios/arch/webapp-3tier/security_groups.tf")
        self.sg = self.tb / "security_groups.tf"
        shutil.copy(SCEN / "security_groups.tf", self.sg)
        self.orig_sha = sha(self.sg)
        self.write_state(self.SERIAL)
        (self.tmp / "data").mkdir(parents=True, exist_ok=True)
        pa._root = lambda: self.tmp
        pa._reviews = lambda: self.tmp / "data" / "reviews"

    def tearDown(self):
        self.pa._root, self.pa._reviews = self._root, self._reviews
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- 준비 도우미
    def write_state(self, serial: int, resources: int = 36):
        (self.tb / "terraform.tfstate").write_text(json.dumps({"version": 4, "serial": serial, "resources": [{"type": "x"}] * resources}), encoding="utf-8")

    def times(self, state_age: float = 1300, file_age: float = 300):
        """상태 파일(= 마지막 apply)은 오래전, 보안 그룹 파일은 그 뒤에 다시 씀."""
        now = time.time()
        os.utime(self.tb / "terraform.tfstate", (now - state_age, now - state_age))
        os.utime(self.sg, (now - file_age, now - file_age))

    def log(self, *entries):
        with (self.tmp / "data" / "testbed_ops.jsonl").open("a", encoding="utf-8") as fh:
            for e in entries:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    def apply_entry(self, sha_: str, serial: int, ok: bool = True):
        return {"at": "2026-10-27T01:53:13+09:00", "op": "apply", "kind": "apply_original", "ok": ok, "testbed_sha256": sha_,
                "state_serial_after": serial, "state_resources_after": 36, "dir": "data/testbed_ops/x-apply"}

    def plan_entry(self, sha_: str, serial: int, *, verdict: str = "NO_CHANGES", counts=None, name: str = "p1"):
        d = self.tmp / "data" / "testbed_ops" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "plan_summary.json").write_text(json.dumps({"verdict": verdict, "error": None}), encoding="utf-8")
        zero = {"replace": 0, "delete": 0, "update": 0, "create": 0, "other": 0}
        return {"at": "2026-10-27T02:18:08+09:00", "op": "plan", "kind": "apply_original", "plan_id": None, "eligible": False,
                "why": "변경 없음 — 반영할 내용 없음", "counts": zero if counts is None else counts, "testbed_sha256": sha_,
                "state_serial": serial, "dir": f"data/testbed_ops/{name}"}

    # ---- 시험
    def test_time_order_still_works(self):
        self.times(state_age=100, file_age=500)               # apply 가 파일보다 나중 — 이전과 같은 판단
        f = self.pa._testbed_files()
        self.assertTrue(f["applied_after_change"])
        self.assertIsNone(f["sync_basis"])

    def test_same_content_rewrite_after_app_apply(self):
        """10-27 사례: 내용은 마지막 apply 와 같고 수정 시각만 새로움 → 반영 상태."""
        self.times()
        self.log(self.apply_entry(self.orig_sha, self.SERIAL))
        f = self.pa._testbed_files()
        self.assertTrue(f["applied_after_change"])
        self.assertEqual(f["sync_basis"], "apply")
        m = self.pa.measure_setup("")
        self.assertTrue(m["applied_after_change"])
        self.assertEqual(m["sync_basis"], "apply")
        fn = self.pa.job_measure({"record_id": "", "profile": "x", "region": "ap-northeast-2"})   # 수정 전 측정 시작 조건 통과 (실행은 안 함)
        self.assertTrue(callable(fn))

    def test_state_changed_outside_app(self):
        self.times()
        self.log(self.apply_entry(self.orig_sha, self.SERIAL))
        self.write_state(self.SERIAL + 1)                     # PowerShell 등 앱 밖에서 apply → 번호가 바뀜
        self.times()
        f = self.pa._testbed_files()
        self.assertFalse(f["applied_after_change"])
        with self.assertRaises(ValueError) as e:
            self.pa.job_measure({"record_id": "", "profile": "x", "region": "ap-northeast-2"})
        self.assertIn("apply 미실행", str(e.exception))

    def test_last_apply_was_other_content(self):
        self.times()
        self.log(self.apply_entry("0" * 64, self.SERIAL))     # 마지막 apply 는 다른 파일(후보)
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])

    def test_failed_apply_is_not_basis(self):
        self.times()
        self.log(self.apply_entry(self.orig_sha, self.SERIAL, ok=False))
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])

    def test_destroy_after_apply(self):
        self.times()
        self.log(self.apply_entry(self.orig_sha, self.SERIAL), {"at": "x", "op": "destroy", "ok": True, "testbed_sha256": self.orig_sha, "state_serial_after": self.SERIAL})
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])

    def test_zero_change_plan_is_basis(self):
        """마지막 apply 는 다른 내용이었지만, 그 뒤 이 내용으로 한 원본 반영 plan 이 '변경 없음' → 반영 상태."""
        self.times()
        self.log(self.apply_entry("0" * 64, self.SERIAL - 1), self.plan_entry(self.orig_sha, self.SERIAL))
        f = self.pa._testbed_files()
        self.assertTrue(f["applied_after_change"])
        self.assertEqual(f["sync_basis"], "plan")

    def test_failed_or_unverified_plan_is_not_basis(self):
        self.times()
        self.log(self.plan_entry(self.orig_sha, self.SERIAL, counts={}, name="err"))           # plan 실패 (요약 없음)
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])
        self.log(self.plan_entry(self.orig_sha, self.SERIAL, verdict="ERROR", name="err2"))     # 요약 파일 판정이 '변경 없음' 이 아님
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])
        self.log(self.plan_entry(self.orig_sha, self.SERIAL - 1, name="old"))                  # 상태 번호가 다른 때의 plan
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])

    def test_record_plan_check_no_changes(self):
        self.times()
        rd = self.tmp / "data" / "reviews" / "20261027-000000-aaaaaa"
        (rd / "candidate").mkdir(parents=True)
        shutil.copy(self.sg, rd / "candidate" / "security_groups.tf")
        pc_dir = rd / "plancheck" / "20261027-021900"
        pc_dir.mkdir(parents=True)
        (pc_dir / "plan_summary.json").write_text(json.dumps({"verdict": "NO_CHANGES", "state_serial": self.SERIAL}), encoding="utf-8")
        entry = {"run_id": "20261027-021900", "at": "2026-10-27T02:19:00+09:00", "verdict": "NO_CHANGES", "candidate_sha256": self.orig_sha,
                 "path": "plancheck/20261027-021900"}
        (rd / "state.json").write_text(json.dumps({"scenario": "ui/arch-3tier-sg/correct-design", "review_level": "LIGHT_REVIEW",
                                                   "plan_check": entry, "plan_check_history": [entry]}), encoding="utf-8")
        self.assertFalse(self.pa._testbed_files()["applied_after_change"])                   # 기록 없이 보면 근거 없음
        f = self.pa._testbed_files(rd)
        self.assertTrue(f["applied_after_change"])
        self.assertEqual(f["sync_basis"], "plan_check")
        self.assertEqual(self.pa.measure_setup(rd.name)["sync_basis"], "plan_check")


if __name__ == "__main__":
    unittest.main()
