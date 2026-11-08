"""AI 수정(llmfix, D-27) — Claude Code 대신 '시험용 대역'(미리 적어 둔 답만 돌려주는 작은 스크립트)으로 프로그램 흐름만 시험한다.

여기서 확인하는 것: 요청문에 정답(기대 결과 · 후보 이름)이 없는가 · 도구 끔/빈 폴더/API 키 · AWS 자격증명 제거로 부르는가 ·
막히면 검사 결과(무엇 · 왜 · 어떻게)를 붙여 다시 요청하는가 · 기록(run.json · 프롬프트 · 응답 원문 · 검사 기록 id)이 남는가.
여기서 확인하지 않는 것: 실제 AI 의 수정 품질 — PC 에서 진짜 Claude 로 따로 잰다 (대역은 평가에 쓰지 않는다).
대역은 실행 파일 스크립트라 Windows(exe 안 시험)에서는 건너뛴다.
"""
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from helpers import FROZEN, ROOT, tools_available

from iacpatch import llmfix

SET = "arch-3tier-sg"
CANDS = ROOT / "experiments" / "candidate-sets" / SET / "candidates"
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
log = os.path.join(here, "calls.jsonl")
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("9.9.9 (test double)"); sys.exit(0)
if args[:2] == ["auth", "status"]:
    print(json.dumps({"loggedIn": True, "authMethod": "claude.ai"})); sys.exit(0)
prompt = sys.stdin.read()
n = (sum(1 for _ in open(log, encoding="utf-8")) if os.path.exists(log) else 0) + 1
with open(log, "a", encoding="utf-8") as f:
    f.write(json.dumps({"n": n, "argv": args, "cwd": os.getcwd(), "cwd_files": os.listdir(os.getcwd()),
                        "env_keys": sorted(os.environ), "prompt": prompt}, ensure_ascii=False) + "\n")
answers = json.load(open(os.path.join(here, "answers.json"), encoding="utf-8"))
body = answers[min(n, len(answers)) - 1]
if body == "__ERROR__":
    print(json.dumps({"type": "result", "is_error": True, "result": "test error", "session_id": "x"})); sys.exit(1)
print(json.dumps({"type": "result", "is_error": False, "result": body, "session_id": "fake-%d" % n, "total_cost_usd": 0,
                  "modelUsage": {"fake-model": {}}}, ensure_ascii=False))
'''


def block(text: str, lead: str = "") -> str:
    return f"{lead}```hcl\n{text}```\n"


@unittest.skipIf(os.name == "nt" or FROZEN, "시험용 대역은 POSIX 실행 스크립트")
class LlmFixBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="iacpatch-llm-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        fake = self.tmp / "claude"
        fake.write_text(FAKE, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        env = {"IACPATCH_CLAUDE_BIN": str(fake), "IACPATCH_LLM_RUNS_DIR": str(self.tmp / "runs"), "IACPATCH_DESIGNS_DIR": str(self.tmp / "designs"),
               "IACPATCH_REVIEWS_DIR": str(self.tmp / "reviews"), "ANTHROPIC_API_KEY": "must-not-reach-ai", "AWS_PROFILE": "must-not-reach-ai",
               "AWS_ACCESS_KEY_ID": "must-not-reach-ai"}
        for k, v in env.items():
            old = os.environ.get(k)
            os.environ[k] = v
            self.addCleanup(lambda k=k, old=old: os.environ.pop(k, None) if old is None else os.environ.__setitem__(k, old))
        llmfix._STATUS.update(at=0.0, value=None)

    def answers(self, *bodies):
        (self.tmp / "answers.json").write_text(json.dumps(list(bodies), ensure_ascii=False), encoding="utf-8")

    def calls(self):
        p = self.tmp / "calls.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


class PromptAndCallTests(LlmFixBase):
    def test_prompt_has_no_answer_key(self):
        task = llmfix.load_task(ROOT, SET)
        man = json.loads((ROOT / "experiments" / "candidate-sets" / SET / "manifest.json").read_text(encoding="utf-8"))
        for ctx in ("trivy", "design"):
            p = llmfix.build_prompt(task, ctx)
            for c in man["candidates"]:
                self.assertNotIn(c["id"], p)                        # 후보 이름
                self.assertNotIn(c["expected_reason"][:30], p)      # 기대 결과 문장
            self.assertNotIn("expected", p)
            self.assertIn("AVD-AWS-0107", p)
        self.assertIn("고객 설계도", llmfix.build_prompt(task, "design"))
        self.assertNotIn("고객 설계도 (이 구조를", llmfix.build_prompt(task, "trivy"))

    def test_extract_exactly_one_block(self):
        self.assertEqual(llmfix.extract_file("앞말\n```hcl\na = 1\n```\n뒷말")[0], "a = 1\n")
        self.assertIsNotNone(llmfix.extract_file("```hcl\na\n```\n```hcl\nb\n```")[1])
        self.assertIsNotNone(llmfix.extract_file("코드 없음")[1])
        self.assertIsNotNone(llmfix.extract_file("```hcl\n\n```")[1])

    def test_call_runs_without_tools_in_empty_dir_without_keys(self):
        self.answers(block("x = 1\n"))
        res = llmfix.call_claude("요청")
        self.assertTrue(res["ok"], res)
        c = self.calls()[0]
        argv = c["argv"]
        i = argv.index("--tools")
        self.assertEqual(argv[i + 1], "")                                       # 도구 전부 끔
        self.assertIn("mcp__*", argv)
        self.assertEqual(c["cwd_files"], [])                                    # 빈 폴더
        self.assertNotEqual(Path(c["cwd"]).resolve(), ROOT.resolve())
        for k in ("ANTHROPIC_API_KEY", "AWS_PROFILE", "AWS_ACCESS_KEY_ID"):
            self.assertNotIn(k, c["env_keys"])                                  # 과금 경로 · AWS 자격증명 없음
        self.assertEqual(c["prompt"], "요청")                                   # 요청문은 표준 입력으로만

    def test_status_reads_version_and_login(self):
        st = llmfix.claude_status(refresh=True)
        self.assertTrue(st["found"])
        self.assertTrue(st["logged_in"])
        self.assertIn("9.9.9", st["version"])

    def test_ai_error_stops_without_review(self):
        self.answers("__ERROR__")
        rec = llmfix.run_fix(ROOT, SET, "trivy", 3, lambda s: None, reviews_dir=self.tmp / "reviews")
        self.assertEqual(rec["status"], "AI_ERROR")
        self.assertEqual(len(rec["attempts"]), 1)
        self.assertIsNone(rec["attempts"][0]["record_id"])
        run = json.loads((self.tmp / "runs" / rec["run_id"] / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(run["status"], "AI_ERROR")                             # 실패도 기록에 남긴다

    def test_missing_claude_is_reported(self):
        os.environ["IACPATCH_CLAUDE_BIN"] = str(self.tmp / "none")
        old = os.environ.get("PATH", "")
        (self.tmp / "empty").mkdir()
        os.environ["PATH"] = str(self.tmp / "empty")
        self.addCleanup(os.environ.__setitem__, "PATH", old)
        home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.tmp)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", home) if home else os.environ.pop("HOME", None))
        self.assertIsNone(llmfix.claude_bin())
        self.assertFalse(llmfix.call_claude("x")["ok"])


class OutcomeTests(unittest.TestCase):
    """결과 분류 · 종료 코드 (D-36, 2026-11-02 검토 문서 1번): 검증 통과만 0. 실행 오류 · 검증 불가는 AI 재요청 없이 중단.
    도구 없이 돈다 — 검사 기록 요약(_record_brief 모양)을 직접 만들어 넣는다."""

    def test_exit_codes_only_pass_is_zero(self):
        self.assertEqual(llmfix.exit_code("PASSED"), 0)
        for st in ("GAVE_UP", "REPEATED", "AI_ERROR", "TOOL_ERROR", "UNDECIDABLE", "RUNNING", None, "???"):
            self.assertNotEqual(llmfix.exit_code(st), 0, st)
        self.assertEqual(llmfix.exit_code("GAVE_UP"), 1)                      # 전에는 0 — CI 가 성공으로 봤다
        self.assertEqual(llmfix.exit_code("REPEATED"), 1)
        self.assertEqual(llmfix.exit_code("AI_ERROR"), 2)
        self.assertEqual(llmfix.exit_code("TOOL_ERROR"), 3)
        self.assertEqual(llmfix.exit_code("UNDECIDABLE"), 4)
        self.assertEqual(len({llmfix.exit_code(s) for s in ("PASSED", "GAVE_UP", "AI_ERROR", "TOOL_ERROR", "UNDECIDABLE")}), 5)   # 서로 구분
        for st in llmfix.EXIT_CODES:
            self.assertIn(st, llmfix.STATUS_KO)
            self.assertIn(st, llmfix.NEXT_KO)

    def test_classify_three_failure_kinds(self):
        ok = {"passed": True, "tone": "good", "state": "REVIEW_REQUIRED", "level": "FULL_REVIEW", "validity": "COMPLETE", "layers": {"V1": "PASS"}}
        self.assertEqual(llmfix.classify_attempt(ok), "PASSED")
        # 수정안 부적합 → 다시 요청
        bad = {"passed": False, "tone": "bad", "state": "VALIDATION_FAILED", "level": "BLOCKED", "validity": "FAIL", "layers": {"V1": "PASS", "V6": "FAIL"}}
        self.assertEqual(llmfix.classify_attempt(bad), "BLOCKED")
        policy = {"passed": False, "tone": "bad", "state": "POLICY_BLOCKED", "level": "BLOCKED", "validity": "NOT_RUN", "layers": {}}
        self.assertEqual(llmfix.classify_attempt(policy), "BLOCKED")
        garbage = {"passed": False, "tone": "muted", "state": "CANDIDATE_INVALID", "level": None, "validity": None, "layers": {}}
        self.assertEqual(llmfix.classify_attempt(garbage), "BLOCKED")                   # AI 가 형식을 어김 — 수정안의 문제
        wide = {"passed": False, "tone": "warn", "state": "REVIEW_REQUIRED", "level": "REPORT_ONLY", "validity": "COMPLETE", "layers": {"V1": "PASS", "V6": "PASS"}}
        self.assertEqual(llmfix.classify_attempt(wide), "BLOCKED")                      # 검사는 다 돌았고 위험도 HIGH — 더 좁은 수정안
        # 실행 오류 → 중단 (AI 에게 다시 묻지 않음)
        tool = {"passed": False, "tone": "warn", "state": "REVIEW_REQUIRED", "level": "PENDING", "validity": "INCOMPLETE", "layers": {"V1": "PASS", "V3": "ERROR", "V4": "NOT_RUN"}}
        self.assertEqual(llmfix.classify_attempt(tool), "TOOL_ERROR")
        inp = {"passed": False, "tone": "muted", "state": "INPUT_ERROR", "level": None, "validity": None, "layers": {}}
        self.assertEqual(llmfix.classify_attempt(inp), "TOOL_ERROR")
        # 검증 불가 → 사람
        und = {"passed": False, "tone": "warn", "state": "REVIEW_REQUIRED", "level": "PENDING", "validity": "INCOMPLETE", "layers": {"V1": "PASS", "V6": "UNKNOWN"}}
        self.assertEqual(llmfix.classify_attempt(und), "UNDECIDABLE")
        und2 = {"passed": False, "tone": "warn", "state": "REVIEW_REQUIRED", "level": "REPORT_ONLY", "validity": "INCOMPLETE", "layers": {"V4": "SKIPPED"}}
        self.assertEqual(llmfix.classify_attempt(und2), "UNDECIDABLE")                  # 위험도 근거 부족 + 미실행 — 판정 불가
        # 관문은 다 통과했지만 설계도가 초안(확정 전, D-38) — 코드 문제가 아니라 기준 문제: AI 재요청 없이 사람에게
        draft = {"passed": False, "tone": "warn", "draft_design": True, "state": "REVIEW_REQUIRED", "level": "LIGHT", "validity": "COMPLETE", "layers": {"V1": "PASS", "V6": "PASS"}}
        self.assertEqual(llmfix.classify_attempt(draft), "UNDECIDABLE")
        self.assertIn("초안", llmfix.DRAFT_STATUS_KO)
        self.assertIn("③", llmfix.DRAFT_NEXT_KO)

    def test_run_view_separates_run_error_from_api_error(self):
        """실행 기록의 error(AI 오류 · 검증 불가 이유)는 run_error 로 — API 오류(error)와 섞이면 화면이 그 실행을 열지 못한다 (E2E J18 에서 발견)."""
        import tempfile
        from iacpatch.web import llm_api
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get("IACPATCH_LLM_RUNS_DIR")
            os.environ["IACPATCH_LLM_RUNS_DIR"] = td
            try:
                rid = "20261102-000000-abcdef"
                (Path(td) / rid).mkdir()
                (Path(td) / rid / "run.json").write_text(json.dumps({"run_id": rid, "status": "UNDECIDABLE", "error": "설계도가 아직 초안", "attempts": []}), encoding="utf-8")
                v = llm_api.run_view(rid)
                self.assertNotIn("error", v)
                self.assertEqual(v["run_error"], "설계도가 아직 초안")
                self.assertTrue(v["ok"])
                self.assertIn("error", llm_api.run_view("20261102-000000-ffffff"))       # 없는 실행 = API 오류
            finally:
                if old is None:
                    os.environ.pop("IACPATCH_LLM_RUNS_DIR", None)
                else:
                    os.environ["IACPATCH_LLM_RUNS_DIR"] = old

    def test_summary_markdown_states_exit_code_and_next(self):
        rec = {"status": "GAVE_UP", "target": {"rule": "AVD-AWS-0107", "resource": "aws_security_group.bastion", "file": "security_groups.tf", "line": 1},
               "context": "design", "max_attempts": 3, "attempts": [{"n": 1, "status": "BLOCKED", "title": "막힘", "layers": {"V6": "FAIL"}}]}
        md = llmfix.summary_markdown(rec)
        self.assertIn("GAVE_UP", md)
        self.assertIn("종료 코드 1", md)
        self.assertIn("고친 파일 올리기", md)                                     # 수동 수정으로 이어지는 안내
        self.assertNotIn("성공", md.split("\n")[0])


@unittest.skipUnless(tools_available(), "terraform · trivy 필요 (V1~V6 를 실제로 돌린다)")
class RetryLoopTests(LlmFixBase):
    def test_repeated_candidate_stops_without_review(self):
        """시도 1 막힘 → 시도 2 가 같은 파일 → 검사하지 않고 REPEATED 로 중단 (3번째 요청 없음). 종료 코드 1."""
        same = block((CANDS / "flagged-only-fix.tf").read_text(encoding="utf-8"))
        self.answers(same, same, block((CANDS / "correct-design.tf").read_text(encoding="utf-8")))
        rec = llmfix.run_fix(ROOT, SET, "trivy", 3, lambda s: None, reviews_dir=self.tmp / "reviews")
        self.assertEqual(rec["status"], "REPEATED", rec)
        self.assertEqual([a["status"] for a in rec["attempts"]], ["BLOCKED", "REPEATED"])
        self.assertIsNone(rec["attempts"][1]["record_id"])
        self.assertEqual(len(self.calls()), 2)                                   # 3번째 요청은 하지 않았다
        self.assertEqual(rec["exit_code"], 1)
        self.assertIn("같은 수정안", rec["status_ko"])

    def test_cli_exit_code_is_nonzero_when_ai_never_passes(self):
        """명령줄(GitHub Actions 경로): 3번 모두 막힘 → GAVE_UP → 종료 코드 1 · 상태 파일 'GAVE_UP' (전에는 0 이라 CI 가 성공으로 봤다)."""
        bodies = [block((CANDS / n).read_text(encoding="utf-8")) for n in ("flagged-only-fix.tf", "db-only-fix.tf", "ssh-vpc-wide.tf")]
        self.answers(*bodies)
        summ, stf = self.tmp / "s.md", self.tmp / "status.txt"
        rc = llmfix.main(["--set", SET, "--max-attempts", "3", "--summary", str(summ), "--status-file", str(stf), "--root", str(ROOT)])
        self.assertEqual(rc, 1)
        self.assertEqual(stf.read_text(encoding="utf-8").strip(), "GAVE_UP")
        self.assertIn("GAVE_UP", summ.read_text(encoding="utf-8"))
    def test_blocked_then_fixed_with_feedback(self):
        """시도 1 = Trivy 지적만 고친 파일 (웹 → MySQL 남음) → V6 에서 막힘. 시도 2 요청문에 그 이유가 붙고, 대역이 설계대로 고친 파일 → 통과."""
        self.answers(block((CANDS / "flagged-only-fix.tf").read_text(encoding="utf-8"), "수정했어.\n\n"),
                     block((CANDS / "correct-design.tf").read_text(encoding="utf-8")))
        rec = llmfix.run_fix(ROOT, SET, "trivy", 3, lambda s: None, reviews_dir=self.tmp / "reviews")
        self.assertEqual(rec["status"], "PASSED", rec)
        a1, a2 = rec["attempts"]
        self.assertEqual(a1["status"], "BLOCKED")
        self.assertEqual(a1["layers"]["V6"], "FAIL")
        self.assertEqual(a2["status"], "PASSED")
        p2 = self.calls()[1]["prompt"]
        self.assertIn("통과하지 못했다", p2)
        self.assertIn("MySQL", p2)                                               # 검사 결과의 '무엇'
        self.assertIn("앞에서 낸 수정안", p2)
        rd = self.tmp / "runs" / rec["run_id"]
        meta = json.loads((rd / "attempt-1" / "candidate" / "candidate.json").read_text(encoding="utf-8"))
        self.assertEqual((meta["origin"], meta["generator"], meta["attempt"]), ("llm", "claude-code:cli", 1))
        self.assertEqual(meta["prompt_sha256"], a1["prompt_sha256"])
        st = json.loads((self.tmp / "reviews" / a2["record_id"] / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(str(st.get("scenario")).startswith(f"ui/{SET}/ai-{rec['run_id']}-a2"))
        self.assertEqual(st.get("candidate_label"), "AI 수정 · 시도 2")
        md = llmfix.summary_markdown(rec)
        self.assertIn("| 1 |", md)
        self.assertIn("FAIL", md)


if __name__ == "__main__":
    unittest.main()
