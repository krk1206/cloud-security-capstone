"""B·C 3~4주차 로컬 검토 흐름 통합 테스트 — 외부 도구/API/AWS/네트워크 없이 실행된다.

입력은 A 가 커밋한 실제 Trivy JSON(infrastructure/sg-baseline/baseline-scan.json)과 원본 Terraform 이고,
후보는 mock fixture 또는 examples/bc/ 의 수동 예제다 (둘 다 사람이 만든 것; LLM 출력 아님).
검증 결과 fixture(examples/bc/verification/*.json) 의 PASS 는 예제 값이며 실제 실행 결과가 아니다 — 리포트의 '결과 출처' 열로 구분된다.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch.config import load_settings
from iacpatch.models import ReviewLevel, ReviewState, Verdict
from iacpatch.review.flow import ReviewOptions, run_review
from iacpatch.review.inputs import FindingSelector, TrivyInputError, list_findings, load_trivy_report, select_findings

TF_DIR = "infrastructure/sg-baseline"
TRIVY = "infrastructure/sg-baseline/baseline-scan.json"
EX = ROOT / "examples" / "bc"


class ReviewFlowTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp(prefix="iacpatch-reviews-"))
        self.settings = load_settings(str(ROOT))
        self.orig_main = (ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8")

    def tearDown(self):
        # 원본이 바뀌지 않았는지 매 테스트마다 확인
        self.assertEqual((ROOT / TF_DIR / "main.tf").read_text(encoding="utf-8"), self.orig_main)
        shutil.rmtree(self.out, ignore_errors=True)

    def _opt(self, candidate, **kw):
        base = dict(tf_dir=TF_DIR, trivy_json=TRIVY, candidate=candidate, scenario=kw.pop("scenario", "t"), rule="AVD-AWS-0107", out_dir=str(self.out))
        base.update(kw)
        return ReviewOptions(**base)

    # 1) 정상 입력으로 후보·diff·리포트 생성 (mock + manual 3형식)
    def test_normal_mock_creates_records_and_reports(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok"))
        self.assertEqual(res.state, ReviewState.REVIEW_REQUIRED, res.message)
        self.assertEqual(res.level, ReviewLevel.PENDING)          # 검증 결과가 없으므로 PENDING
        d = res.run_dir
        for rel in ("state.json", "input/trivy.json", "input/findings.json", "input/selected_finding.json", "input/source_check.json",
                    "original/main.tf", "candidate/main.tf", "candidate.diff", "candidate.json", "policy.json", "verification.json", "risk.json", "review.md", "pr_body.md"):
            self.assertTrue((d / rel).exists(), rel)
        st = json.loads((d / "state.json").read_text(encoding="utf-8"))
        self.assertEqual([h["state"] for h in st["history"]], ["INPUT_READY", "CANDIDATE_READY", "VALIDATION_PENDING", "REVIEW_REQUIRED"])
        self.assertEqual(st["verification_status"], "PENDING")
        self.assertEqual(st["candidate_origin"], "mock")
        review = (d / "review.md").read_text(encoding="utf-8")
        self.assertIn("검증 대기", review)
        self.assertIn("모델이 분석한 결과가 아니다", review)
        self.assertNotIn("AI 분석", review)
        self.assertIn("mock fixture", review)
        self.assertTrue(all(l.verdict == Verdict.NOT_RUN for l in res.validity.layers))

    def test_manual_dir_json_and_tf_forms(self):
        for cand in (f"manual:{EX / 'manual_candidate_ok'}", f"manual:{EX / 'manual_candidate_ok.json'}", f"manual:{EX / 'manual_candidate_ok_main.tf'}"):
            res = run_review(self.settings, self._opt(cand, candidate_note="개발 중 작성한 예제"))
            self.assertEqual(res.state, ReviewState.REVIEW_REQUIRED, f"{cand}: {res.message}")
            self.assertEqual(res.candidate.origin, "manual")
            self.assertIn("203.0.113.0/24", (res.run_dir / "candidate" / "main.tf").read_text(encoding="utf-8"))
            self.assertIn("개발 중 작성한 예제", (res.run_dir / "review.md").read_text(encoding="utf-8"))
        # 단일 .tf 는 수정 이유가 없으므로 needs_info 에 기록된다
        self.assertTrue(any("수정 이유" in n for n in res.candidate.needs_info))

    # 2) finding 없음
    def test_no_finding(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", rule="AVD-AWS-9999"))
        self.assertEqual(res.state, ReviewState.NO_FINDING)
        self.assertFalse((res.run_dir / "candidate.json").exists())

    # 3) 중복 finding → 임의 선택 금지
    def test_duplicate_findings_are_not_auto_picked(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", rule=None))   # 0104 + 0107 둘 다 일치
        self.assertEqual(res.state, ReviewState.AMBIGUOUS_FINDING)
        self.assertEqual(len(res.ambiguous), 2)
        self.assertTrue((res.run_dir / "input" / "ambiguous.json").exists())
        # 줄 번호로 좁히면 진행된다
        res2 = run_review(self.settings, self._opt("mock:sg_baseline_ok", rule=None, line=11))
        self.assertEqual(res2.state, ReviewState.REVIEW_REQUIRED, res2.message)

    # 4) 잘못된 JSON / 형식 오류 / 파일 없음
    def test_invalid_trivy_json(self):
        bad = self.out / "bad.json"
        bad.write_text("{ not json", encoding="utf-8")
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", trivy_json=str(bad)))
        self.assertEqual(res.state, ReviewState.INPUT_ERROR)
        bad.write_text('{"foo": 1}', encoding="utf-8")
        self.assertEqual(run_review(self.settings, self._opt("mock:sg_baseline_ok", trivy_json=str(bad))).state, ReviewState.INPUT_ERROR)
        self.assertEqual(run_review(self.settings, self._opt("mock:sg_baseline_ok", trivy_json=str(self.out / "missing.json"))).state, ReviewState.INPUT_ERROR)
        with self.assertRaises(TrivyInputError):
            load_trivy_report(bad.with_suffix(".none"))

    def test_scan_source_mismatch_is_input_error(self):
        # 원본을 복사해 지목된 줄을 바꾸면 "같은 시점 자료가 아님" 으로 막힌다
        tfcopy = self.out / "tf"
        shutil.copytree(ROOT / TF_DIR, tfcopy, ignore=shutil.ignore_patterns(".terraform", "*.json"))
        main = tfcopy / "main.tf"
        main.write_text(main.read_text(encoding="utf-8").replace('cidr_blocks = ["0.0.0.0/0"]\n  }\n\n  egress', 'cidr_blocks = ["10.0.0.0/8"]\n  }\n\n  egress', 1), encoding="utf-8")
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", tf_dir=str(tfcopy)))
        self.assertEqual(res.state, ReviewState.INPUT_ERROR)
        self.assertIn("일치하지 않는다", res.message)

    # 5) 수정 후보 누락·빈 파일·원본과 동일·읽기 불가·형식 오류
    def test_candidate_missing_empty_identical_unreadable(self):
        self.assertEqual(run_review(self.settings, self._opt(f"manual:{self.out / 'nope.tf'}")).state, ReviewState.CANDIDATE_INVALID)
        r = run_review(self.settings, self._opt(f"manual:{EX / 'manual_candidate_empty.tf'}"))
        self.assertEqual(r.state, ReviewState.CANDIDATE_INVALID)
        self.assertIn("빈 후보", r.message)
        r = run_review(self.settings, self._opt(f"manual:{EX / 'manual_candidate_identical.tf'}"))
        self.assertEqual(r.state, ReviewState.CANDIDATE_INVALID)
        self.assertIn("원본과 동일", r.message)
        self.assertEqual(run_review(self.settings, self._opt("mock:does_not_exist")).state, ReviewState.CANDIDATE_INVALID)
        self.assertEqual(run_review(self.settings, self._opt("mock:sg_baseline_garbage")).state, ReviewState.CANDIDATE_INVALID)
        self.assertEqual(run_review(self.settings, self._opt("mock:sg_baseline_truncated")).state, ReviewState.CANDIDATE_INVALID)
        self.assertEqual(run_review(self.settings, self._opt("nonsense")).state, ReviewState.CANDIDATE_INVALID)
        binary = self.out / "bin.tf"
        binary.write_bytes(b"\xff\xfe\x00\x01")
        self.assertEqual(run_review(self.settings, self._opt(f"manual:{binary}")).state, ReviewState.CANDIDATE_INVALID)

    def test_info_insufficient_and_policy_block(self):
        self.assertEqual(run_review(self.settings, self._opt("mock:sg_baseline_insufficient")).state, ReviewState.INFO_INSUFFICIENT)
        r = run_review(self.settings, self._opt("mock:sg_baseline_edits_provider"))
        self.assertEqual(r.state, ReviewState.POLICY_BLOCKED)
        self.assertEqual(r.level, ReviewLevel.BLOCKED)
        self.assertTrue((r.run_dir / "review.md").exists())

    # 6) 필요한 검증 결과 없음 → PENDING (PASS 를 만들어내지 않는다)
    def test_missing_verification_stays_pending(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok"))
        self.assertEqual(res.validity.validity.value, "INCOMPLETE")
        self.assertEqual(res.level, ReviewLevel.PENDING)
        self.assertNotIn("PASS", [l.verdict.value for l in res.validity.layers])

    def test_partial_verification_file(self):
        v = self.out / "partial.json"
        v.write_text(json.dumps({"schema": "iacpatch-verification-v1", "source": "example", "layers": [
            {"layer": "V1", "verdict": "PASS", "summary": "x"}, {"layer": "V3", "verdict": "PASS", "summary": "y"}]}), encoding="utf-8")
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", verification=str(v)))
        L = {l.layer: l.verdict for l in res.validity.layers}
        self.assertEqual(L["V1"], Verdict.PASS)
        self.assertEqual(L["V2"], Verdict.NOT_RUN)
        self.assertEqual(res.level, ReviewLevel.PENDING)
        review = (res.run_dir / "review.md").read_text(encoding="utf-8")
        self.assertIn("검증 대기: V2, V4, V5, V6", review)
        self.assertIn("example", review)   # 결과 출처 표시

    # 7) 검증 실패 결과가 들어온 경우
    def test_verification_failure_blocks(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", verification=str(EX / "verification" / "example_v1_fail.json")))
        self.assertEqual(res.state, ReviewState.VALIDATION_FAILED)
        self.assertEqual(res.level, ReviewLevel.BLOCKED)
        self.assertIn("검증 실패", (res.run_dir / "pr_body.md").read_text(encoding="utf-8"))

    def test_verification_all_pass_with_plans_gives_light_review(self):
        # V1~V4 는 예제 파일, V5/V6 는 plan fixture 로 로컬 계산 → 모두 결과가 있으면 검토 수준이 정해진다
        res = run_review(self.settings, self._opt(
            "mock:sg_baseline_ok", verification=str(EX / "verification" / "example_all_pass.json"),
            baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"), candidate_plan=str(ROOT / "tests/fixtures/plans/00b-baseline-fixed/plan.json"),
            intent=str(ROOT / "tests/fixtures/intents/sg-baseline.test.json")))
        # 주의: plan fixture 의 리소스 주소(aws_security_group.baseline)와 intent 대상(vulnerable_ssh)이 달라 V6 는 FAIL(대상 없음) 이 된다 → 차단
        L = {l.layer: l.verdict for l in res.validity.layers}
        self.assertEqual(L["V5"], Verdict.PASS)
        self.assertEqual(L["V6"], Verdict.FAIL)
        self.assertEqual(res.state, ReviewState.VALIDATION_FAILED)
        # 같은 fixture 에 맞는 intent 를 주면 V6 도 PASS → 경량 검토
        intent = self.out / "intent.json"
        d = json.loads((ROOT / "tests/fixtures/intents/sg-baseline.test.json").read_text(encoding="utf-8"))
        d["targets"]["security_groups"] = ["aws_security_group.baseline"]
        d["guarded_services"][0]["approved_sources"]["cidrs_v4"] = ["10.0.0.0/8"]
        d["required_access"][0]["source_cidr"] = "10.0.0.0/8"
        intent.write_text(json.dumps(d), encoding="utf-8")
        res2 = run_review(self.settings, self._opt(
            "mock:sg_baseline_ok", verification=str(EX / "verification" / "example_all_pass.json"),
            baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"), candidate_plan=str(ROOT / "tests/fixtures/plans/00b-baseline-fixed/plan.json"),
            intent=str(intent)))
        self.assertEqual(res2.state, ReviewState.REVIEW_REQUIRED, res2.message)
        self.assertEqual(res2.level, ReviewLevel.LIGHT_REVIEW)
        review = (res2.run_dir / "review.md").read_text(encoding="utf-8")
        self.assertIn("example-fixture", review)         # V1~V4 가 예제 값임이 드러난다
        self.assertIn("local:v6_intent_oracle", review)  # V6 는 로컬 계산
        self.assertNotIn("자동 반영 가능", review)

    def test_verification_candidate_hash_mismatch_is_ignored(self):
        v = self.out / "other.json"
        v.write_text(json.dumps({"schema": "iacpatch-verification-v1", "source": "x", "candidate_sha256": "deadbeef",
                                 "layers": [{"layer": "V1", "verdict": "PASS", "summary": "x"}]}), encoding="utf-8")
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", verification=str(v)))
        L = {l.layer: l.verdict for l in res.validity.layers}
        self.assertEqual(L["V1"], Verdict.NOT_RUN)
        self.assertTrue(any("다른 후보" in u for u in json.loads((res.run_dir / "verification.json").read_text(encoding="utf-8"))["notes"]))

    def test_broken_verification_file_does_not_crash(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok", verification=str(EX / "verification" / "broken.json")))
        self.assertEqual(res.state, ReviewState.REVIEW_REQUIRED)
        st = json.loads((res.run_dir / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(any("검증 결과 파일" in e for e in st["errors"]))

    # 8) 위험도 판정 근거 부족 / 삭제 의심 / 잠정 기준표 표시
    def test_risk_insufficient_basis(self):
        broken = self.out / "broken.tf"
        broken.write_text("this is not hcl { { {", encoding="utf-8")
        v = str(EX / "verification" / "example_all_pass.json")
        res = run_review(self.settings, self._opt(f"manual:{broken}", verification=v,
                                                  baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json"),
                                                  candidate_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json")))
        # V5 는 두 plan 이 같아 WARN(변경 없음), V6 는 intent 없어 NOT_RUN → PENDING 이 우선. 근거 부족은 위험도 표에 남는다
        self.assertTrue(any(f["factor"] in ("insufficient_basis", "hcl_unparsable") for f in res.risk.factors))
        self.assertEqual(res.risk.risk_level.value, "HIGH")

    def test_risk_deleted_resource_is_hard_high(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_deletes_sg"))
        self.assertEqual(res.risk.risk_level.value, "HIGH")
        self.assertTrue(any("removed" in f["factor"] for f in res.risk.factors))
        self.assertIn("잠정", res.risk.rubric_version)

    def test_risk_low_for_cidr_only_change_and_text_basis_marked(self):
        res = run_review(self.settings, self._opt("mock:sg_baseline_ok"))
        self.assertEqual(res.risk.risk_level.value, "LOW")
        self.assertTrue(any(f["factor"] == "undetermined" for f in res.risk.factors))
        self.assertIn("text basis", res.risk.rubric_version)

    # 9) 반복 실행 시 이전 결과와 원본 보존
    def test_repeated_runs_keep_previous_records(self):
        a = run_review(self.settings, self._opt("mock:sg_baseline_ok", scenario="r1"))
        b = run_review(self.settings, self._opt("mock:sg_baseline_cidr_split", scenario="r2"))
        self.assertNotEqual(a.run_dir, b.run_dir)
        self.assertTrue((a.run_dir / "review.md").exists() and (b.run_dir / "review.md").exists())
        self.assertIn("0.0.0.0/0", (a.run_dir / "original" / "main.tf").read_text(encoding="utf-8"))
        self.assertIn("128.0.0.0/1", (b.run_dir / "candidate" / "main.tf").read_text(encoding="utf-8"))

    def test_pr1_real_duplicate_findings(self):
        # A 의 PR #1 사본: 같은 룰이 ssh(11줄)·rdp(33줄) 두 리소스에 → 임의 선택 금지, 리소스 지정 시 진행
        tf = "scenarios/dev/pr1-two-defects"
        tj = "scenarios/dev/pr1-two-defects/trivy-scan.json"
        r = run_review(self.settings, self._opt("mock:sg_baseline_ok", tf_dir=tf, trivy_json=tj))
        self.assertEqual(r.state, ReviewState.AMBIGUOUS_FINDING)
        self.assertEqual(sorted(f.resource for f in r.ambiguous), ["aws_security_group.vulnerable_rdp", "aws_security_group.vulnerable_ssh"])
        r2 = run_review(self.settings, self._opt(f"manual:{EX / 'manual_candidate_ok_main.tf'}", tf_dir=tf, trivy_json=tj, resource="aws_security_group.vulnerable_ssh"))
        # 후보는 sg-baseline 원본 기준이라 rdp 블록이 사라진다 → 텍스트 근거로 '삭제 의심' HIGH, 리포트는 생성된다
        self.assertEqual(r2.state, ReviewState.REVIEW_REQUIRED, r2.message)
        self.assertEqual(r2.risk.risk_level.value, "HIGH")
        self.assertIn("aws_security_group.vulnerable_rdp", json.loads((r2.run_dir / "risk.json").read_text(encoding="utf-8"))["hcl_change"]["removed_resources"])

    def test_findings_selector(self):
        report = load_trivy_report(ROOT / TRIVY)
        fs = list_findings(report)
        self.assertEqual(len(select_findings(fs, FindingSelector(rule_id="AWS-0107"))), 1)
        self.assertEqual(len(select_findings(fs, FindingSelector(filename="main.tf"))), 2)
        self.assertEqual(len(select_findings(fs, FindingSelector(resource="aws_security_group.vulnerable_ssh", start_line=19))), 1)
        self.assertEqual(select_findings(fs, FindingSelector(resource="aws_security_group.vulnerable_ssh", start_line=19))[0].rule_id, "AVD-AWS-0104")


class MetricsTests(unittest.TestCase):
    def test_metrics_over_review_records(self):
        from iacpatch.metrics import collect, render_table, summarize
        out = Path(tempfile.mkdtemp(prefix="iacpatch-metrics-"))
        s = load_settings(str(ROOT))
        for fx, sc in (("sg_baseline_ok", "correct-1"), ("sg_baseline_cidr_split", "deceptive-1")):
            run_review(s, ReviewOptions(tf_dir=TF_DIR, trivy_json=TRIVY, candidate=f"mock:{fx}", scenario=sc, rule="AVD-AWS-0107", out_dir=str(out),
                                        candidate_plan=str(ROOT / f"tests/fixtures/plans/{'00b-baseline-fixed' if fx == 'sg_baseline_ok' else '01-cidr-split'}/plan.json"),
                                        baseline_plan=str(ROOT / "tests/fixtures/plans/00-baseline/plan.json")))
        rows = collect([out])
        self.assertEqual(len(rows), 2)
        summ = summarize(rows, labels={"correct-1": "correct", "deceptive-1": "deceptive"})
        self.assertEqual(summ["by_origin"], {"mock": 2})
        table = render_table(rows, "t", labels={"correct-1": "correct", "deceptive-1": "deceptive"})
        self.assertIn("LLM 출력이 아님", table)
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
