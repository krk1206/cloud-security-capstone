"""A 의 독립 V2 스크립트(src/verify/v2_finding_diff.py, 2026-09-28) 와 파이프라인 V2(iacpatch.verify.layers.v2_finding_diff) 가
같은 Trivy JSON 쌍에서 같은 '새 finding 집합' 을 내는지 — 두 구현이 따로 살아 있으니 갈라지면 여기서 잡는다.

알려진 설계 차이 (일부러 맞추지 않음, 팀 결정 항목):
  - A 스크립트: 새 finding 이 하나라도 있으면 FAIL. 키 = (룰, 리소스).
  - 파이프라인 V2: 새 finding 중 policy.v2_block_severities(HIGH/CRITICAL) 만 FAIL, 나머지는 WARN. 키 = 룰|파일|리소스.
  - A 스크립트의 룰 ID 는 Trivy 출력 그대로(AWS-0107), 파이프라인은 AVD- 접두어를 붙인다.
  그래서 비교하는 것은 '새로 생긴 (룰, 리소스) 집합' 과 'PASS 여부(새 finding 0)' 다.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from helpers import ROOT, py_cmd

from iacpatch.tools.trivy import TrivyScan, parse_findings, scan_summary
from iacpatch.verify.layers import v2_finding_diff

A_SCRIPT = ROOT / "src" / "verify" / "v2_finding_diff.py"
FIX = ROOT / "tests" / "fixtures" / "trivy"


def _scan(path: Path) -> TrivyScan:
    rep = json.loads(path.read_text(encoding="utf-8"))
    return TrivyScan(True, rep, parse_findings(rep), scan_summary(rep), "fixture")


def _run_a(before: Path, after: Path):
    r = subprocess.run(py_cmd(str(A_SCRIPT), str(before), str(after)), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=60)
    self_check = r.returncode in (0, 1)
    return self_check, r.returncode, json.loads(r.stdout) if r.stdout.strip() else {}


def _strip(rule: str) -> str:
    return rule[4:] if rule.startswith("AVD-") else rule


class V2AgreementTests(unittest.TestCase):
    def test_a_script_exists_and_runs(self):
        self.assertTrue(A_SCRIPT.exists(), "A 의 V2 스크립트가 main 합치기에서 빠졌다")
        ok, rc, rep = _run_a(FIX / "00-baseline.json", FIX / "00-baseline.json")
        self.assertTrue(ok)
        self.assertEqual(rep["verdict"], "PASS")
        self.assertEqual(rc, 0)

    def test_new_finding_sets_agree_on_all_fixture_pairs(self):
        before = FIX / "00-baseline.json"
        pairs = sorted(p for p in FIX.glob("*.json") if p.name != before.name)
        self.assertGreaterEqual(len(pairs), 5)
        compared = 0
        for after in pairs:
            ok, rc, rep = _run_a(before, after)
            self.assertTrue(ok, f"A 스크립트 비정상 종료 {rc} on {after.name}")
            ours = v2_finding_diff(_scan(before), _scan(after))
            ours_new = {(_strip(f["rule_id"]), f["resource"]) for f in ours.details["new"]}
            a_new = {tuple(x) for x in rep["added"]}
            self.assertEqual(a_new, ours_new, f"{after.name}: 새 finding 집합이 다름 (A={a_new}, 파이프라인={ours_new})")
            # PASS 는 '새 finding 0' 과 동치여야 한다 (둘 다)
            self.assertEqual(rep["verdict"] == "PASS", not ours_new, after.name)
            self.assertEqual(ours.verdict.value == "PASS", not ours_new, after.name)
            compared += 1
        self.assertEqual(compared, len(pairs))

    def test_a_script_refuses_bad_input_instead_of_passing(self):
        ok, rc, rep = _run_a(FIX / "00-baseline.json", ROOT / "src" / "verify" / "testdata" / "empty.json")
        self.assertFalse(ok)            # 2 = 입력 오류. 절대 PASS(0) 가 아니다
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
