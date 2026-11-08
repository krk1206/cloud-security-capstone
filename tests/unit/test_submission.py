"""2026-10-31 교수 피드백 반영 1단계 — 후보 화면 중립화 · 수정 코드 제출(.tf 여러 개 · 폴더) · 설계도 버전 기록.

지켜야 하는 것
  - 후보 목록 자료에 기대 결과(expected · expected_reason) · 작성 메모(note) · 후보 파일 이름이 없다. 화면 이름은 '후보 NN'
  - '후보 NN' 번호 순서는 sha256(세트/id) 순서 — manifest 작성 순서와 다르다 (첫 후보가 늘 01 이 아니다)
  - 제출 파일: 경로를 평평하게 합치지 않는다. '..' · 절대 경로는 받지 않고, 숨김 · 하위 폴더 · .tf 아닌 파일은 이유와 함께 목록에 남긴다
  - 원본과 같은 파일은 후보에서 빠지고, 원본에 없는 파일은 후보에 들어가 검사(새 파일 금지)가 막는다
  - 제출 파일은 저장소 원본 폴더가 아니라 data/cache/submissions/ 에 저장된다
  - 검사 기록에 설계 기준(id · 버전 · sha256)과 바이트 그대로의 사본이 남고, 화면 자료가 지금 설계도와 같은지 알려 준다
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import ROOT, tools_available

from iacpatch.review.change_summary import summarize
from iacpatch.web import cases as cs
from iacpatch.web.submission import analyze

TF_DIR = ROOT / "scenarios" / "arch" / "webapp-3tier"
SG = (TF_DIR / "security_groups.tf").read_text(encoding="utf-8")
_I = SG.index('description = "SSH for administrators"')                 # Bastion 의 SSH 규칙 (파일의 첫 0.0.0.0/0 은 ALB 443)
FIXED = SG[:_I] + SG[_I:].replace('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]', 1)
INTENT = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"
ANSWER_WORDS = ("정답", "correct", "deceptive", "breaks", "unapproved", "expected", "시험용 후보 —")


class LabelTest(unittest.TestCase):
    def test_labels_are_hash_ordered_and_neutral(self):
        # 11차 (D-47): 화면에 보이는 수정안(featured)은 manifest 순서대로 '수정안 1~4' (정답이 1번이 아니다), 나머지는 이름 해시 순서 '수정안 05~'
        man, _ = cs._manifest("arch-3tier-sg")
        labels = cs.display_labels("arch-3tier-sg", man)
        ids = [c["id"] for c in man["candidates"]]
        feat = man["featured"]
        self.assertEqual(len(feat), 4)
        self.assertEqual([labels[i] for i in feat], ["수정안 1", "수정안 2", "수정안 3", "수정안 4"])
        self.assertNotEqual(feat[0], "correct-design")                        # 순서로 정답이 드러나지 않게
        rest = [i for i in ids if i not in feat]
        self.assertEqual(sorted(labels[i] for i in rest), [f"수정안 {i:02d}" for i in range(5, len(ids) + 1)])
        by_label = [cid for cid, _ in sorted(((i, labels[i]) for i in rest), key=lambda kv: kv[1])]
        self.assertNotEqual(by_label, rest)                                   # 작성 순서와 다르다
        expect = sorted(rest, key=lambda i: hashlib.sha256(f"arch-3tier-sg/{i}".encode()).hexdigest())
        self.assertEqual(by_label, expect)
        self.assertEqual(cs.featured_ids("arch-3tier-sg", man), feat)
        self.assertEqual(cs.featured_ids("arch-webapp-sg"), [])              # featured 없는 묶음 = 전부 (예전 방식)

    def test_label_for_records(self):
        labels = {"x": "후보 03"}
        self.assertEqual(cs.label_for("s", "x", labels=labels), "후보 03")
        self.assertEqual(cs.label_for("s", "x-rb", labels=labels), "후보 03 (규칙 기반 생성)")
        self.assertEqual(cs.label_for("s", "paste-171", "2026-10-31T14:02:11+09:00", labels), "직접 제출 · 10/31 14:02")
        self.assertEqual(cs.label_for("s", "upload-20261031-140211-abc", "2026-10-31T14:02", labels), "직접 제출 · 10/31 14:02")
        self.assertEqual(cs.label_for("s", "unknown-id", labels=labels), "목록 밖 수정안")
        self.assertEqual(cs.record_label({"scenario": "ui/arch-3tier-sg/correct-design"}),
                         cs.display_labels("arch-3tier-sg")["correct-design"])
        self.assertEqual(cs.record_label({"scenario": "ui/x/y", "candidate_label": "후보 09"}), "후보 09")
        # 12차 (D-48): 목록에 있는 후보는 저장된 옛 이름('후보 08')이 아니라 지금 이름 — ⑤ 버튼 '수정안 3' 과 그림 제목이 같아야 한다
        now = cs.display_labels("arch-3tier-sg")["correct-design"]
        self.assertEqual(cs.record_label({"scenario": "ui/arch-3tier-sg/correct-design", "candidate_label": "후보 08"}), now)
        self.assertTrue(now.startswith("수정안 "))
        # 목록 밖(지워진 후보 · AI · 직접 제출 · 옛 형식)은 저장된 이름 그대로
        self.assertEqual(cs.record_label({"scenario": "ui/arch-3tier-sg/no-such-candidate", "candidate_label": "후보 99"}), "후보 99")
        self.assertEqual(cs.record_label({"scenario": "ui/arch-3tier-sg/ai-20261101-120000-abcdef-a2", "candidate_label": "AI 수정 · 시도 2"}), "AI 수정 · 시도 2")
        self.assertEqual(cs.record_label({"scenario": "ui/arch-3tier-sg/paste-171", "candidate_label": "직접 제출 · 10/31 14:02"}), "직접 제출 · 10/31 14:02")
        self.assertEqual(cs.record_label({"scenario": "weird", "candidate_label": "옛 기록"}), "옛 기록")

    def test_candidates_payload_has_no_answers(self):
        out = cs.candidates("webapp-3tier")
        items = out["sets"][0]["candidates"]
        self.assertTrue(items)
        for it in items:
            self.assertTrue(set(it) <= {"id", "label", "origin", "summary", "changes", "latest", "post", "featured"}, set(it))
            shown = json.dumps({k: it[k] for k in ("label", "origin", "summary", "changes")}, ensure_ascii=False)
            for w in ANSWER_WORDS:
                self.assertNotIn(w, shown, f"{it['id']}: {w}")
            self.assertNotIn(it["id"], shown)                                  # 화면에 보이는 칸에 id 가 없다
            self.assertTrue(it["summary"])
        # 사람이 적은 설명(manifest change_summary)은 화면 자료로 보내지 않는다 — 코드에서 자동으로 센 '바뀐 블록'만 (10-31 '후보 밑 정답 내용 삭제')
        man = json.loads((ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "manifest.json").read_text(encoding="utf-8"))
        human = {c["id"]: c.get("change_summary") for c in man["candidates"] if c.get("change_summary")}
        for it in items:
            if it["id"] in human:
                self.assertNotEqual(it["summary"], human[it["id"]], it["id"])


class ChangeSummaryTest(unittest.TestCase):
    def test_blocks_and_counts(self):
        s = summarize({"security_groups.tf": SG}, {"security_groups.tf": FIXED})
        self.assertEqual(s["files"][0]["blocks"], ["aws_security_group.bastion"])
        self.assertEqual((s["added"], s["removed"]), (1, 1))
        self.assertEqual(s["text"], "보안 그룹 bastion 변경 (+1 −1줄)")
        self.assertEqual(summarize({"a.tf": SG}, {"a.tf": SG})["text"], "원본과 같음 — 바뀐 줄 없음")
        s2 = summarize({"a.tf": SG}, {"a.tf": SG + '\nvariable "x" {\n  default = 1\n}\n'})
        self.assertIn("변수 x", s2["text"])


class SubmissionAnalyzeTest(unittest.TestCase):
    def test_folder_paths_kept_and_reasons(self):
        files = [
            {"path": "proj/security_groups.tf", "content": FIXED},
            {"path": "proj/network.tf", "content": (TF_DIR / "network.tf").read_text(encoding="utf-8").replace("\n", "\r\n")},
            {"path": "proj/modules/net/main.tf", "content": "x"},
            {"path": "proj/terraform.tfvars", "content": "a = 1"},
            {"path": "proj/README.md", "content": "hi"},
            {"path": "proj/.terraform/", "content": None, "aggregated": True, "count": 12},
            {"path": "proj/extra.tf", "content": 'resource "aws_security_group" "x" {}\n'},
            {"path": "proj/../evil.tf", "content": "x"},
            {"path": "proj/big.tf", "content": None, "size": 2_000_000},
        ]
        r = analyze(TF_DIR, files, folder=True)
        st = {f["path"]: (f["status"], f["reason"]) for f in r["files"]}
        self.assertEqual(len(r["files"]), len(files))                         # 제출한 줄은 전부 목록에 남는다
        self.assertEqual(st["security_groups.tf"][0], "changed")
        self.assertEqual(st["network.tf"][0], "same")                          # 줄바꿈(CRLF)만 다르면 같은 파일
        self.assertIn("하위 폴더", st["modules/net/main.tf"][1])                # 평평하게 합치지 않는다
        self.assertIn(".tfvars", st["terraform.tfvars"][1])
        self.assertIn(".tf 파일 아님", st["README.md"][1])
        self.assertIn("숨김 폴더", r["files"][5]["reason"])
        self.assertEqual(st["extra.tf"][0], "new")
        self.assertEqual(r["files"][7]["status"], "rejected")                  # '..'
        self.assertIn("한도", st["big.tf"][1])
        self.assertEqual(sorted(r["candidate_files"]), ["extra.tf", "security_groups.tf"])
        self.assertIn("보안 그룹 bastion", r["summary"])

    def test_files_mode_and_nothing_changed(self):
        r = analyze(TF_DIR, [{"path": "security_groups.tf", "content": SG}], folder=False)
        self.assertFalse(r["ok"])
        self.assertIn("검사할 변경 파일 없음", r["error"])
        r2 = analyze(TF_DIR, [{"path": "C:/Users/x/security_groups.tf", "content": FIXED}], folder=False)
        self.assertEqual(r2["files"][0]["status"], "rejected")


class DesignRecordTest(unittest.TestCase):
    def test_record_design_copy_and_hash(self):
        from iacpatch.review.flow import record_design
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        des = record_design(INTENT, d, ROOT)
        raw = INTENT.read_bytes()
        self.assertEqual(des["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual((d / "input" / "design.json").read_bytes(), raw)      # 바이트 그대로
        self.assertEqual(des["intent_id"], "arch-3tier-flows")
        self.assertEqual(des["path"], "experiments/candidate-sets/arch-3tier-sg/intents/arch-3tier-flows.json")

    def test_design_view_compares_with_current(self):
        from iacpatch.web.server import design_view
        sinfo = {"intent_path": "experiments/candidate-sets/arch-3tier-sg/intents/arch-3tier-flows.json"}
        cur = hashlib.sha256(INTENT.read_bytes()).hexdigest()
        self.assertTrue(design_view({"design": {"sha256": cur}}, sinfo)["same_as_current"])
        self.assertFalse(design_view({"design": {"sha256": "0" * 64}}, sinfo)["same_as_current"])
        self.assertIsNone(design_view({}, sinfo)["same_as_current"])           # 10/31 이전 기록: 기록 없음


@unittest.skipUnless(tools_available(), "trivy/terraform 없음")
class UploadFlowTest(unittest.TestCase):
    """화면 API 로 파일을 제출해 1차 검사까지 — 기록에 제출 목록 · 설계 기준 · 표시 이름이 남는다."""

    @classmethod
    def setUpClass(cls):
        from test_web import _Srv
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["IACPATCH_REVIEWS_DIR"] = cls.tmp.name
        cls.before = set((ROOT / "data" / "cache" / "submissions").glob("*")) if (ROOT / "data" / "cache" / "submissions").is_dir() else set()
        cls.s = _Srv()

    @classmethod
    def tearDownClass(cls):
        cls.s.close()
        os.environ.pop("IACPATCH_REVIEWS_DIR", None)
        cls.tmp.cleanup()
        sub = ROOT / "data" / "cache" / "submissions"
        for p in (set(sub.glob("*")) if sub.is_dir() else set()) - cls.before:
            shutil.rmtree(p, ignore_errors=True)

    def test_check_then_review(self):
        files = [{"path": "p/security_groups.tf", "content": FIXED}, {"path": "p/variables.tf", "content": (TF_DIR / "variables.tf").read_text(encoding="utf-8")}]
        st, chk = self.s.post("/api/submission/check", {"set_id": "arch-3tier-sg", "files": files, "folder": True})
        self.assertEqual(st, 200, chk)
        self.assertTrue(chk["ok"])
        self.assertEqual([f["status"] for f in chk["files"]], ["changed", "same"])
        self.assertIn("security_groups.tf", chk["originals"])
        self.assertEqual(chk["max_patch_files"], 2)
        sg_before = (TF_DIR / "security_groups.tf").read_bytes()
        st, j = self.s.post("/api/review", {"case_id": "webapp-3tier", "set_id": "arch-3tier-sg", "upload": {"files": files, "folder": True}})
        self.assertTrue(j["started"], j)
        done = self.s.wait_job()
        self.assertFalse(done["error"], done)
        self.assertEqual((TF_DIR / "security_groups.tf").read_bytes(), sg_before)   # 원본 폴더는 그대로
        rid = done["result"]["record_id"]
        st, rec = self.s.getj("/api/record?id=" + rid)
        self.assertTrue(rec["candidate_label"].startswith("직접 제출"))
        self.assertEqual([f["status"] for f in rec["submission"]["files"]], ["changed", "same"])
        self.assertTrue(rec["design"]["same_as_current"])
        self.assertEqual(rec["design"]["recorded"]["sha256"], hashlib.sha256(INTENT.read_bytes()).hexdigest())
        self.assertNotIn("scenario", rec)
        rd = Path(self.tmp.name) / rid
        self.assertEqual((rd / "input" / "design.json").read_bytes(), INTENT.read_bytes())
        self.assertTrue((rd / "input" / "submission.json").exists())
        state = json.loads((rd / "state.json").read_text(encoding="utf-8"))
        self.assertTrue(state["scenario"].startswith("ui/arch-3tier-sg/upload-"))
        self.assertEqual(state["candidate_summary"], chk["summary"])
        log = "\n".join(str(x) for x in done.get("log") or [])
        self.assertIn("후보 직접 제출", log)                                   # 로그에는 표시 이름만
        self.assertNotIn("submissions", log.split("후보 직접 제출", 1)[1].split("\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
