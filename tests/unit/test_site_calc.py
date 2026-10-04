"""공유 사이트의 JS 계산기(scripts/site/calc.js)가 Python 원본(policy/risk.py 경유 rubric_demo.calc_risk, gate_demo)과 같은 답을 내는지. node 가 없으면 skip."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch import rubric_demo as rd

CALC = ROOT / "scripts" / "site" / "calc.js"


@unittest.skipIf(shutil.which("node") is None, "node 없음")
class SiteCalcTests(unittest.TestCase):
    def test_js_port_matches_python_on_fixed_cases_and_all_gate_combos(self):
        _, rubric = rd.load_policy_and_rubric(ROOT)
        cases = [{"target_kind": "SG"}, {"target_kind": "IAM"}, {"target_kind": "SG", "deleted": True}, {"target_kind": "IAM", "trust_policy": True},
                 {"target_kind": "SG", "attachment_points": 2, "external_sg": True}, {"target_kind": "SG", "resources_touched": 5, "new_resources": 3, "lines": 80, "files": 2},
                 {"target_kind": "SG", "changed_attrs": "ingress,name", "outside_family": True, "resources_touched": 2}, {"target_kind": "IAM", "oracle_partial": True, "replaced": True}]
        gates = [(rl, p, v, ok) for rl in ["LOW", "MEDIUM", "HIGH"] for p in [None, "LOW", "MEDIUM", "HIGH"] for v in ["PASS", "FAIL", "INCOMPLETE"] for ok in [True, False]]
        with tempfile.TemporaryDirectory() as td:
            inp = Path(td) / "in.json"; inp.write_text(json.dumps({"rubric": rubric, "cases": cases, "gates": gates}), encoding="utf-8")
            run = Path(td) / "run.js"
            run.write_text("const fs=require('fs');const c=require(process.argv[3]);const d=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));"
                           "process.stdout.write(JSON.stringify({calc:d.cases.map(x=>c.calcRisk(x,d.rubric)),gates:d.gates.map(([r,p,v,o])=>c.gateDecide(r,p,v,o))}));", encoding="utf-8")
            r = subprocess.run(["node", str(run), str(inp), str(CALC)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        js = json.loads(r.stdout)
        for c, j in zip(cases, js["calc"]):
            p = rd.calc_risk(c, rubric)
            self.assertEqual((p["level"], p["cap"], p["score"]), (j["level"], j["cap"], j["score"]), c)
            self.assertEqual(sorted((f["factor"], f["points"]) for f in p["factors"]), sorted((f["factor"], f["points"]) for f in j["factors"]), c)
        for g, j in zip(gates, js["gates"]):
            p = rd.gate_demo(*g)
            self.assertEqual((p["final"], p["action"], p["cap"]), (j["final"], j["action"], j["cap"]), g)


if __name__ == "__main__":
    unittest.main()
