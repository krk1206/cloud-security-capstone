"""아키텍처 과제(2026-10-02, 지도교수 9/29 지시): Terraform → Trivy → 결과물 → AI 해석 등록 → 패치 세트.

도구 없이 도는 것: 인벤토리·표 렌더·프롬프트·해석 등록 대조·intent targets 범위·cc 케이스.
도구 있을 때만(TERRAFORM_BIN/TRIVY_BIN 또는 tools/): scenarios/arch/webapp-2tier 의 validate + 오프라인 plan + trivy 실측(17 리소스, finding 18).
"""
from __future__ import annotations

import copy
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

from helpers import INTENT_TEMPLATE, ROOT

from iacpatch import archinterp as ai
from iacpatch import archscan as asn
from iacpatch.config import load_json
from iacpatch.intent import IntentError, parse_intent
from iacpatch.models import RequiredAccess, ServiceSpec

sys.path.insert(0, str(ROOT / "scripts"))
import cc_cases  # noqa: E402
import cc_prompt  # noqa: E402

ARCH = ROOT / "scenarios" / "arch" / "webapp-2tier"
MAPPING = load_json(ROOT / "policy" / "cis_mapping.json")
POLICY = load_json(ROOT / "policy" / "patch_policy.json")


def _tool(name: str) -> str | None:
    win = platform.system() == "Windows"
    p = ROOT / "tools" / (name + (".exe" if win else ""))
    if p.exists():
        return str(p)
    env = os.environ.get(name.upper() + "_BIN")
    return env if env and (Path(env).exists() or __import__("shutil").which(env)) else None


def _fake_scan_summary(scan_id="t1"):
    return {
        "schema": "iacpatch-arch-scan-v1", "scan_id": scan_id, "tf_dir": "scenarios/arch/webapp-2tier",
        "files": [{"name": "security_groups.tf", "lines": 10, "resources": ["aws_security_group.web"], "data_sources": []}],
        "tools": {"terraform": {"available": False}, "trivy": {"available": True, "version": "0.74.0"}},
        "plan": {"status": "NOT_RUN"},
        "scan": {"status": "PASS", "trivy_version": "0.74.0", "successes": 1, "failures": 2, "checks_executed": 3, "parse_errors": [], "by_severity": {"HIGH": 1, "CRITICAL": 1}},
        "findings": [
            {"severity": "HIGH", "rule_id": "AVD-AWS-0107", "title": "ssh open", "resource": "aws_security_group.web", "file": "security_groups.tf", "line": 23, "end_line": 29,
             "message": "m", "resolution": "r", "references": [], "cis": asn.cis_lookup("AVD-AWS-0107", MAPPING), "scope": asn.classify_scope("AVD-AWS-0107", POLICY)},
            {"severity": "CRITICAL", "rule_id": "AVD-AWS-0104", "title": "egress", "resource": "aws_security_group.web", "file": "security_groups.tf", "line": 31, "end_line": 37,
             "message": "m", "resolution": "r", "references": [], "cis": asn.cis_lookup("AVD-AWS-0104", MAPPING), "scope": asn.classify_scope("AVD-AWS-0104", POLICY)},
        ],
    }


class ArchInventoryTests(unittest.TestCase):
    def test_inventory_counts_17_resource_blocks_in_9_files(self):
        inv = asn.inventory(ARCH)
        self.assertEqual(len(inv), 9)
        self.assertEqual(sum(len(f.resources) for f in inv), 17)
        names = {f.name for f in inv}
        self.assertIn("security_groups.tf", names); self.assertIn("iam.tf", names); self.assertIn("storage.tf", names)
        self.assertIn("aws_security_group.web", next(f for f in inv if f.name == "security_groups.tf").resources)

    def test_cis_lookup_and_scope(self):
        c = asn.cis_lookup("AVD-AWS-0107", MAPPING)
        self.assertTrue(c["in_table"]); self.assertEqual(c["level"], "직접"); self.assertTrue(any(it["section"] == "5.2" for it in c["items"]))
        self.assertFalse(asn.cis_lookup("AVD-AWS-9999", MAPPING)["in_table"])
        self.assertEqual(asn.classify_scope("AVD-AWS-0107", POLICY), "패치 파이프라인 대상")
        self.assertEqual(asn.classify_scope("AVD-AWS-0086", POLICY), "탐지·해석만 (파이프라인 밖)")

    def test_findings_md_and_prompt_list_every_finding(self):
        res = _fake_scan_summary()
        md = asn.render_findings_md(res)
        self.assertIn("Finding 2개", md); self.assertIn("`AVD-AWS-0107`", md); self.assertIn("security_groups.tf:23", md); self.assertIn("## AI 해석", md)
        prompt = asn.render_prompt(res, ARCH)
        self.assertIn("AVD-AWS-0104", prompt); self.assertIn("iacpatch-arch-interpretation-v1", prompt); self.assertIn("### security_groups.tf", prompt)
        self.assertIn("misconfiguration", prompt)

    def test_protected_provider_files_are_not_editable_by_candidates(self):
        names = {p.name for p in ARCH.glob("*.tf")}
        for n in ("versions.tf", "provider.tf"):
            self.assertIn(n, names); self.assertIn(n, POLICY["protected_file_names"])


class ArchInterpretationTests(unittest.TestCase):
    def _resp(self, findings, extra=None):
        d = {"schema": ai.SCHEMA, "scan_id": "t1", "model": "test", "findings": findings, "summary": {"fix_order": [], "overall": "x"}}
        d.update(extra or {})
        return d

    def _f(self, rule, res, **kw):
        base = {"rule_id": rule, "resource": res, "file": "security_groups.tf", "line": 23, "what": "w", "why_risky": "y", "fix": "f", "fix_risk": "LOW"}
        base.update(kw)
        return base

    def test_register_cross_checks_fabricated_missing_and_cis(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td) / "scan"; sd.mkdir()
            (sd / "summary.json").write_text(json.dumps(_fake_scan_summary()), encoding="utf-8")
            (sd / "findings.md").write_text("# x\n\n## AI 해석\n\n아직 없음.\n", encoding="utf-8")
            resp = self._resp([
                self._f("AVD-AWS-0107", "aws_security_group.web", cis_section="5.2"),
                self._f("AWS-0104", "aws_security_group.web", line=31, cis_section="5.9"),      # AVD- 없는 표기도 같은 룰, 매핑표는 'CIS 없음' → 불일치
                self._f("AVD-AWS-9999", "aws_instance.web", file="compute.tf", line=6),         # 지어낸 finding
            ])
            rp = Path(td) / "resp.md"; rp.write_text("설명\n```json\n" + json.dumps(resp, ensure_ascii=False) + "\n```\n", encoding="utf-8")
            rec = ai.register(sd, rp, MAPPING, note="unit")
            ch = rec["checks"]
            self.assertEqual(ch["coverage"], "2/2"); self.assertEqual([e["rule_id"] for e in ch["fabricated"]], ["AVD-AWS-9999"])
            self.assertEqual(ch["missing"], []); self.assertEqual(ch["cis_mismatch"], 1)
            self.assertTrue(ch["checked"][0]["cis"].startswith("일치"))
            self.assertTrue((sd / "interpretation.json").exists()); md = (sd / "interpretation.md").read_text(encoding="utf-8")
            self.assertIn("지어냄", md); self.assertIn("claude-code-manual", md)
            fm = (sd / "findings.md").read_text(encoding="utf-8")
            self.assertEqual(fm.count("## AI 해석"), 1); self.assertNotIn("아직 없음", fm)

    def test_missing_findings_are_reported_not_filled(self):
        with tempfile.TemporaryDirectory() as td:
            sd = Path(td) / "scan"; sd.mkdir()
            (sd / "summary.json").write_text(json.dumps(_fake_scan_summary()), encoding="utf-8")
            rp = Path(td) / "r.json"; rp.write_text(json.dumps(self._resp([self._f("AVD-AWS-0107", "aws_security_group.web")])), encoding="utf-8")
            rec = ai.register(sd, rp, MAPPING)
            self.assertEqual(rec["checks"]["coverage"], "1/2"); self.assertEqual(rec["checks"]["missing"][0]["rule_id"], "AVD-AWS-0104")

    def test_shape_errors_block_registration(self):
        bad = self._resp([{"rule_id": "AVD-AWS-0107", "resource": "aws_security_group.web", "what": "w"}])   # why_risky/fix 없음
        self.assertTrue(ai.validate_shape(bad))
        bad2 = self._resp([self._f("AVD-AWS-0107", "aws_security_group.web", fix_risk="SEVERE")])
        self.assertTrue(any("fix_risk" in e for e in ai.validate_shape(bad2)))
        self.assertEqual(ai.validate_shape(self._resp([self._f("AVD-AWS-0107", "aws_security_group.web")])), [])
        with self.assertRaises(ai.InterpretationError):
            ai.extract_json("no json here")


class IntentRequiredTargetsTests(unittest.TestCase):
    def test_required_access_targets_parsed_and_validated(self):
        d = copy.deepcopy(INTENT_TEMPLATE)
        d["targets"]["security_groups"] = ["aws_security_group.web", "aws_security_group.app"]
        d["required_access"][0]["targets"] = ["aws_security_group.web"]
        spec = parse_intent(d)
        self.assertEqual(spec.required_access[0].targets, ["aws_security_group.web"])
        d["required_access"][0]["targets"] = ["aws_security_group.nope"]
        with self.assertRaises(IntentError):
            parse_intent(d)

    def test_required_access_without_targets_keeps_old_behaviour(self):
        r = RequiredAccess(ServiceSpec("ingress", "tcp", 22, 22), "10.0.0.0/8", "x")
        self.assertEqual(r.targets, [])

    def test_arch_intent_requires_http_only_on_web_sg(self):
        spec = parse_intent(load_json(ROOT / "experiments" / "candidate-sets" / "arch-webapp-sg" / "intents" / "arch-webapp-sg.json"))
        self.assertEqual(spec.target_security_groups, ["aws_security_group.web", "aws_security_group.app"])
        http = next(r for r in spec.required_access if r.label == "public-http")
        self.assertEqual(http.targets, ["aws_security_group.web"]); self.assertEqual(http.source_cidr, "0.0.0.0/0")
        app = next(g for g in spec.guarded_services if g.service.from_port == 8080)
        self.assertEqual(app.approved.security_group_refs, ["aws_security_group.web"])


class ArchClaudeCodeCasesTests(unittest.TestCase):
    def test_arch_cases_resolve_to_the_architecture_and_build_prompts(self):
        self.assertIn("arch-sg", cc_cases.all_cases()); self.assertIn("arch-iam", cc_cases.all_cases())
        info = cc_cases.case_info("arch-sg")
        self.assertEqual(info["tf_dir"], "scenarios/arch/webapp-2tier"); self.assertEqual(info["resource"], "aws_security_group.web")
        p, st = cc_prompt.build("arch-sg")
        self.assertEqual(st, "ok"); self.assertIn("security_groups.tf", p); self.assertIn("10.0.0.0/8", p); self.assertIn("aws_security_group.web", p)
        p2, st2 = cc_prompt.build("arch-iam")        # 0345 는 같은 리소스·줄에 finding 2개 → 하나로 본다 (ambiguous 아님)
        self.assertEqual(st2, "ok"); self.assertIn("iam.tf", p2); self.assertIn("iacpatch-webapp-assets-demo", p2)
        self.assertEqual(cc_cases.resolve("00-baseline")[0], "sg")   # 기존 케이스는 그대로

    def test_manifests_fix_expected_before_run_and_opt_out_of_week4_table(self):
        for sid in ("arch-webapp-sg", "arch-webapp-iam"):
            m = load_json(ROOT / "experiments" / "candidate-sets" / sid / "manifest.json")
            self.assertIs(m["week4_label_replay"], False)
            self.assertEqual(m["tf_dir"], "scenarios/arch/webapp-2tier")
            for c in m["candidates"]:
                self.assertIn(c["expected"], ("correct", "deceptive", "unapproved", "breaks_required"))
                self.assertIn(c["expected_risk"], ("LOW", "MEDIUM", "HIGH"))
                if c["candidate"].startswith("manual:"):
                    self.assertTrue((ROOT / "experiments" / "candidate-sets" / sid / c["candidate"][7:]).exists())


@unittest.skipUnless(_tool("terraform") and _tool("trivy"), "terraform/trivy 없음 — 아키텍처 실측은 도구 있는 환경에서")
class ArchWithToolsTests(unittest.TestCase):
    def test_offline_plan_and_trivy_scan_of_the_architecture(self):
        with tempfile.TemporaryDirectory() as td:
            res = asn.run_scan(ARCH, Path(td) / "out", root=ROOT, log=lambda s: None)
            self.assertEqual(res["plan"]["status"], "PASS", res["plan"])
            self.assertEqual(res["plan"]["resource_count"], 17); self.assertEqual(res["plan"]["actions"], {"create": 17})
            self.assertEqual(res["scan"]["status"], "PASS", res["scan"])
            self.assertEqual(res["scan"]["parse_errors"], [])
            rules = {r["rule_id"] for r in res["findings"]}
            for want in ("AVD-AWS-0107", "AVD-AWS-0345", "AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093"):
                self.assertIn(want, rules)
            self.assertEqual(sum(1 for r in res["findings"] if r["rule_id"] == "AVD-AWS-0107"), 1)     # SSH 개방은 웹 SG 하나뿐
            self.assertTrue((Path(td) / "out" / "findings.md").exists()); self.assertTrue((Path(td) / "out" / "interpret_prompt.md").exists())


if __name__ == "__main__":
    unittest.main()


class SoloKitTests(unittest.TestCase):
    """혼자 A·B·C 하기용 도구 (2026-10-04): V8 체크 생성기, exe 용 CLI 래퍼."""

    def test_v8_checks_cover_every_guarded_service_from_the_unapproved_pc(self):
        import arch_v8_checks as g
        from iacpatch.postdeploy import v8_connectivity
        doc = g.build("203.0.113.10", "10.0.2.50")
        intent = parse_intent(load_json(ROOT / "experiments" / "candidate-sets" / "arch-webapp-sg" / "intents" / "arch-webapp-sg.json"))
        guarded = {gs.service.label for gs in intent.guarded_services}
        closed_local = {c["service_label"] for c in doc["checks"] if c["expect"] == "closed" and c["source_class"] == "unapproved" and c["vantage"] == "local"}
        self.assertTrue(guarded <= closed_local, (guarded, closed_local))          # ssh·rdp·app-8080 전부 이 PC 에서 closed 검사 가능
        self.assertTrue(any(c["port"] == 80 and c["expect"] == "open" for c in doc["checks"]))
        r = v8_connectivity(doc, intent, execute=False)
        self.assertEqual(r.verdict.value, "SKIPPED")                              # --execute 없이는 실행하지 않는다
        with self.assertRaises(ValueError):
            g.build("not-an-ip", "10.0.2.50")

    def test_cli_wrapper_runs_a_read_only_subcommand(self):
        import contextlib, io
        import iacpatch_cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = iacpatch_cli.main(["findings", "--trivy-json", "experiments/arch-webapp-2tier/trivy-scan.json", "--rule", "AVD-AWS-0107"])
        self.assertEqual(rc, 0)
        self.assertIn("aws_security_group.web", buf.getvalue())
