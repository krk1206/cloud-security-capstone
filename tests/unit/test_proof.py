"""탐지 방식 증거 (proof/*) 와 2차 검사 측정(measure.py) — 도구·AWS 없이 돌아가는 부분.

- recheck: 대역 계산 별도 구현이 오라클(NetSet)과 같은 답을 내는지
- hcl_lines / topomap: 설계도 ↔ 코드 줄 번호 대응
- measure: AWS 응답·측정기 콘솔 출력을 흉내 낸 값으로 V7·V8 판정 규칙 (원본 = 실패, 올바른 수정 = 통과, 갱신 안 된 값·콘솔 못 읽음 = 판정 불가)
- postcards / cards: 기록 파일에서 카드가 만들어지는지 (판정 값은 기록 그대로)
"""
import base64
import json
import shutil
import tempfile
import time
import types
import unittest
from pathlib import Path

from helpers import ROOT

from iacpatch import measure
from iacpatch.config import load_settings
from iacpatch.evidence_log import CommandLog
from iacpatch.models import Verdict
from iacpatch.proof import cards, hcl_lines, postcards, recheck, topomap
from iacpatch.tools.awscli import AwsCli, AwsError
from iacpatch.topology_intent import load_topology_intent

SCEN = ROOT / "scenarios" / "arch" / "webapp-3tier"
INTENT = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"
CANDS = ROOT / "experiments" / "candidate-sets" / "arch-3tier-sg" / "candidates"
ADMIN = ["203.0.113.0/24", "198.51.100.0/24"]


class RecheckTest(unittest.TestCase):
    def test_split_cidr_is_whole_internet(self):
        r = recheck.union_check(["0.0.0.0/1", "128.0.0.0/1"], ADMIN)
        self.assertTrue(r["covers_internet"])
        self.assertEqual(r["outside_addresses"], 2 ** 32 - 512)

    def test_differential_no_mismatch(self):
        d = recheck.differential(300, seed=7)
        self.assertEqual(d["mismatches"], 0)
        self.assertEqual(d["cases"], 300)

    def test_bad_cidr(self):
        self.assertIsNone(recheck.v4_interval("10.0.0.1/8"))
        self.assertFalse(recheck.union_check(["x"])["ok"])


class HclLinesTest(unittest.TestCase):
    def test_locate_db_web_rule(self):
        src = {"security_groups.tf": (SCEN / "security_groups.tf").read_text(encoding="utf-8")}
        loc = hcl_lines.locate_rule(src, "aws_security_group.db#ingress[1]")
        self.assertIsNotNone(loc)
        lines = src["security_groups.tf"].split("\n")[loc["start"] - 1:loc["end"]]
        self.assertIn("aws_security_group.web.id", "\n".join(lines))
        self.assertIn("3306", "\n".join(lines))

    def test_bastion_ssh_rule(self):
        src = {"security_groups.tf": (SCEN / "security_groups.tf").read_text(encoding="utf-8")}
        loc = hcl_lines.locate_rule(src, "aws_security_group.bastion#ingress[0]")
        body = "\n".join(src["security_groups.tf"].split("\n")[loc["start"] - 1:loc["end"]])
        self.assertIn('"0.0.0.0/0"', body)
        self.assertIn("22", body)


    def test_set_order_differs_from_code_order(self):
        """ingress 는 집합이라 계획의 순서(ingress[0])가 코드 순서와 다를 수 있다 → 계획의 값(설명·포트)으로 블록을 고른다."""
        src = {"security_groups.tf": (CANDS / "web-to-api-direct.tf").read_text(encoding="utf-8")}
        origin = "aws_security_group.api#ingress[0]"
        by_index = hcl_lines.locate_rule(src, origin)
        hint = {"description": "API calls straight from the web tier", "from_port": 8080, "to_port": 8080, "protocol": "tcp"}
        by_plan = hcl_lines.locate_rule(src, origin, hint)
        body = lambda loc: "\n".join(src["security_groups.tf"].split("\n")[loc["start"] - 1:loc["end"]])
        self.assertIn("through the NLB", body(by_index))           # 순서로만 찾으면 다른 블록
        self.assertIn("straight from the web tier", body(by_plan))
        self.assertEqual(by_plan["matched_by"], "content")


class TopomapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = {p.name: p.read_text(encoding="utf-8") for p in SCEN.glob("*.tf")}
        cls.m = topomap.build_map(src, json.loads(INTENT.read_text(encoding="utf-8")), "scenarios/arch/webapp-3tier")

    def test_every_flow_has_a_block(self):
        self.assertEqual(len(self.m["flows"]), 9)
        for f in self.m["flows"]:
            self.assertTrue(f["rules"], f["id"])

    def test_admin_flow_source_differs_in_original(self):
        f = next(x for x in self.m["flows"] if x["id"] == "admin-bastion")
        self.assertIs(f["rules"][0]["same_text"], False)
        self.assertEqual(f["rules"][0]["source_code"], "0.0.0.0/0")

    def test_web_db_block_outside_design(self):
        ux = self.m["rules_outside_design"]
        self.assertEqual([u["origin"] for u in ux], ["aws_security_group.db#ingress[1]"])

    def test_placement(self):
        kinds = {t["id"]: {m["subnet_kind"] for m in t["members"]} for t in self.m["tiers"]}
        self.assertEqual(kinds["bastion"], {"public"})
        self.assertEqual(kinds["alb"], {"public"})
        self.assertIn("private", kinds["web"])        # 시작 템플릿 → 자동 확장 그룹 → 비공개 서브넷
        self.assertIn("private", kinds["db"])         # 서브넷 그룹 경유

    def test_iam_chain(self):
        tiers = {tuple(r["tiers"]) for r in self.m["iam"]}
        self.assertIn(("웹 서버",), tiers)
        self.assertIn(("API 서버",), tiers)


# ----------------------------------------------------------------------------- 2차 검사 흉내
SG_IDS = {f"aws_security_group.{n}": f"sg-0{n}000000000001" for n in ("alb", "bastion", "web", "nlb", "api", "redis", "db")}
INST = {"aws_instance.web": "i-0web", "aws_instance.api": "i-0api", "aws_instance.bastion": "i-0bastion",
        "aws_instance.admin_vantage": "i-0admin", "aws_instance.outsider": "i-0outsider", "aws_instance.db": "i-0db", "aws_instance.redis": "i-0redis"}
IID2KEY = {"i-0web": "web", "i-0api": "api", "i-0bastion": "bastion", "i-0admin": "admin", "i-0outsider": "outsider"}


def _aws_sgs(fixed: bool):
    gid = lambda n: SG_IDS[f"aws_security_group.{n}"]
    def perm(port, cidrs=(), refs=()):
        return {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": c} for c in cidrs],
                "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": [{"GroupId": gid(r), "UserId": "123456789012"} for r in refs]}
    rules = {
        "alb": [perm(443, ["0.0.0.0/0"])],
        "bastion": [perm(22, ADMIN if fixed else ["0.0.0.0/0"])],
        "web": [perm(80, refs=["alb"]), perm(22, refs=["bastion"])],
        "nlb": [perm(8080, refs=["web"])],
        "api": [perm(8080, refs=["nlb"]), perm(22, refs=["bastion"])],
        "redis": [perm(6379, refs=["api"])],
        "db": [perm(3306, refs=["api"] if fixed else ["api", "web"])],
    }
    return [{"GroupId": gid(n), "GroupName": f"tb-{n}-sg", "OwnerId": "123456789012", "IpPermissions": r,
             "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "UserIdGroupPairs": [], "PrefixListIds": [], "Ipv6Ranges": []}]}
            for n, r in rules.items()]


def _world(fixed: bool):
    """위 보안 그룹 규칙이 실제로 만드는 결과 (측정 지점별 목적지·포트·결과). 원본: Bastion 22 가 전 세계에, DB 3306 이 웹에도 열림."""
    t, o = "timeout", "open"
    return {
        "web": [("nlb", 8080, o), ("api", 8080, t), ("db", 3306, t if fixed else o), ("redis", 6379, t), ("bastion", 22, t if fixed else o)],
        "api": [("db", 3306, o), ("redis", 6379, o), ("bastion", 22, t if fixed else o), ("web", 80, t), ("nlb", 8080, t)],
        "bastion": [("web", 22, o), ("api", 22, o), ("db", 3306, t), ("redis", 6379, t), ("nlb", 8080, t), ("web", 80, t), ("api", 8080, t)],
        "admin": [("bastion", 22, o), ("web", 22, t), ("api", 22, t), ("db", 3306, t)],
        "outsider": [("bastion", 22, t if fixed else o), ("alb", 443, o)],
    }


class _FakeTestbed:
    """측정기 흉내. 결과를 읽을 때마다(= 시간이 흐름) 측정기 seq 가 1씩 는다. advance=False 면 멈춘 측정기."""

    def __init__(self, fixed: bool, advance: bool = True, deny_console: bool = False, alb_http: bool = True, alb_web_503: bool = False):
        self.fixed, self.advance, self.deny, self.alb_http, self.alb_web_503 = fixed, advance, deny_console, alb_http, alb_web_503
        self.seq = {k: 7 for k in measure.VANTAGES}      # 측정 전부터 돌던 측정기
        self.lines = {k: [] for k in measure.VANTAGES}

    def doc(self, key: str):
        at = f"2026-10-23T10:{self.seq[key]:02d}:00Z"
        pr = [{"to": to, "host": f"10.0.0.{i}", "port": port, "result": r, "ms": 3 if r == "open" else 3000}
              for i, (to, port, r) in enumerate(_world(self.fixed)[key])]
        d = {"v": 2, "from": key, "at": at, "seq": self.seq[key], "probes": pr, "fetch": []}
        if key == "web":
            d["fetch"] = [{"name": "api-via-nlb", "url": "http://nlb.example:8080/probe.json", "status": 200, "ms": 5}]
        if key == "outsider":
            d["fetch"] = [{"name": "web-via-alb", "url": "http://alb.example:443/", "error": "HTTPError: HTTP Error 503: Service Unavailable", "ms": 9}
                          if self.alb_web_503 else
                          {"name": "web-via-alb", "url": "http://alb.example:443/", "status": 200, "ms": 9, "text": "iacpatch testbed: web\n"}]
        return d

    def tick(self, key: str):
        if self.advance:
            self.seq[key] += 1

    def console(self, iid: str) -> str:
        key = IID2KEY[iid]
        self.tick(key)
        brief = self.doc(key)        # probe.py 와 같이: 콘솔 줄에는 fetch 의 본문(body·text)을 싣지 않는다
        brief["fetch"] = [{k: v for k, v in f.items() if k not in ("body", "text")} for f in brief["fetch"]]
        self.lines[key].append("IACPATCH-PROBE " + json.dumps(brief, separators=(",", ":")))
        noise = ["[   12.345678] cloud-init[1234]: ok", "IACPATCH-PROBE {broken json", "[  100.1] random: crng init done"]
        return "\r\n".join(noise + self.lines[key][-5:]) + "\r\n"

    def fetch(self, url, clog, step):
        if not self.alb_http:
            return None, "URLError: <urlopen error timed out>"
        self.tick("web")
        self.tick("api")
        web = self.doc("web")
        web["fetch"][0]["body"] = self.doc("api")
        return web, "HTTP 200"


def _fake_call(fixed: bool, tb: _FakeTestbed):
    def call(self, *args, timeout=120):
        if args[:2] == ("ec2", "describe-security-groups"):
            ids = list(args[3:])
            return {"SecurityGroups": [g for g in _aws_sgs(fixed) if g["GroupId"] in ids]}
        if args[:2] == ("ec2", "describe-network-interfaces"):
            sid = args[3].split("Values=")[1]
            return {"NetworkInterfaces": [{"NetworkInterfaceId": f"eni-{sid[3:9]}", "Groups": [{"GroupId": sid}]}]}
        if args[:2] == ("ec2", "get-console-output"):
            assert "--latest" in args
            if tb.deny:
                raise AwsError("An error occurred (UnauthorizedOperation) when calling the GetConsoleOutput operation: "
                               "User: arn:aws:iam::123456789012:user/b is not authorized to perform: ec2:GetConsoleOutput")
            iid = args[args.index("--instance-id") + 1]
            return {"InstanceId": iid, "Output": tb.console(iid), "Timestamp": "2026-10-23T10:00:00+00:00"}
        raise AssertionError(args)
    return call


class MeasureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.spec = load_topology_intent(INTENT)
        self._orig = (measure.testbed_state, measure.tcp_probe, measure._fetch_json, measure.time, measure.WAIT_FRESH_S, AwsCli.call, AwsCli.available)
        measure.testbed_state = lambda tf, testbed, clog: {
            "ok": True, "sg_ids": dict(SG_IDS),
            "instances": {a: {"id": i, "private_ip": "10.0.0.1", "public_ip": None} for a, i in INST.items()},
            "outputs": {"alb_dns_name": "alb.example", "nlb_dns_name": "nlb.example", "bastion_public_ip": "203.0.113.200"}}
        measure.tcp_probe = lambda host, port, timeout=4.0: {"result": "open", "ms": 20}
        measure.time = types.SimpleNamespace(time=time.time, monotonic=time.monotonic, sleep=lambda s: None,
                                             strftime=time.strftime, gmtime=time.gmtime)      # 기다리지 않는다 (가상 시간)
        AwsCli.available = lambda self: True

    def tearDown(self):
        (measure.testbed_state, measure.tcp_probe, measure._fetch_json, measure.time, measure.WAIT_FRESH_S,
         AwsCli.call, AwsCli.available) = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, fixed: bool, name: str, **kw):
        tb = _FakeTestbed(fixed, **kw)
        measure._fetch_json = tb.fetch
        AwsCli.call = _fake_call(fixed, tb)
        s = load_settings(str(ROOT))
        return measure.run_measure(s, testbed=self.tmp, intent_path=INTENT, out_dir=self.tmp / name, label=name, record_dir=None, log=lambda *_: None)

    @staticmethod
    def _lay(doc):
        return {l["layer"]: l for l in doc["layers"]}

    def test_original_fails_both(self):
        doc = self._run(False, "before")
        lay = self._lay(doc)
        self.assertEqual(lay["V7"]["verdict"], "FAIL")
        ex = {(e["src"], e["dst"], e["ports"]) for e in lay["V7"]["details"]["excess"]}
        self.assertIn(("web", "db", "3306"), ex)
        self.assertTrue(any(e[1] == "bastion" and e[2] == "22" for e in ex))
        d8 = lay["V8"]["details"]
        self.assertEqual(lay["V8"]["verdict"], "FAIL", lay["V8"]["summary"])
        failed = {(c["from"], c["to"], c["port"]) for c in d8["checks"] if c["verdict"] == "FAIL"}
        self.assertEqual(failed, {("web", "db", 3306), ("outsider", "bastion", 22), ("web", "bastion", 22), ("api", "bastion", 22)})
        self.assertTrue(all(v["fresh"] for v in d8["vantages"]))
        self.assertTrue(all(c["verdict"] == "INFO" for c in d8["checks"] if c["role"] == "참고"))
        self.assertEqual(doc["status"], "DEPLOY_FAILED")
        raw = (self.tmp / "before" / "aws_raw.json").read_text(encoding="utf-8")
        self.assertIn("123456789012", raw)                  # 원문은 그대로 저장 (이 PC 에만)
        self.assertNotIn("123456789012", postcards.mask_account(raw))
        self.assertTrue(list((self.tmp / "before").glob("console_outsider_*.txt")))   # 콘솔 원문을 증거로 남김

    def test_correct_design_passes(self):
        doc = self._run(True, "after")
        lay = self._lay(doc)
        self.assertEqual(lay["V7"]["verdict"], "PASS", lay["V7"]["summary"])
        d8 = lay["V8"]["details"]
        self.assertEqual(lay["V8"]["verdict"], "PASS", lay["V8"]["summary"])
        self.assertEqual(d8["not_measured"], [])
        self.assertEqual({f["status"] for f in d8["flows"]}, {"열림 확인"})
        self.assertEqual(len(d8["flows"]), 9)
        main = [c for c in d8["checks"] if c["role"] == "주"]
        self.assertEqual(len(main), 5 + 5 + 7 + 4 + 2 + 2)     # TCP 23 + HTTP 경로 2
        by = {(c["from"], c["to"], c["port"], c["kind"]): c for c in main}
        self.assertEqual(by[("admin", "bastion", 22, "tcp")]["expect"], "open")       # 허용 목록 안 → 열려야
        self.assertEqual(by[("outsider", "bastion", 22, "tcp")]["expect"], "closed")  # 허용 목록 밖 → 막혀야
        self.assertEqual(by[("web", "api", 8080, "tcp")]["expect"], "closed")         # NLB 를 건너뛴 직접 호출
        self.assertEqual(set(by[("web", "api", 8080, "path")]["flows"]), {"web-nlb", "nlb-api"})
        self.assertGreaterEqual(min(v["seq"] - v["base_seq"] for v in d8["vantages"]), measure.FRESH_STEP)
        self.assertEqual(doc["status"], "VERIFIED")

    def test_stale_probe_is_unknown_not_pass(self):
        measure.WAIT_FRESH_S = 30
        doc = self._run(True, "stale", advance=False)
        d8 = self._lay(doc)["V8"]
        self.assertEqual(d8["verdict"], "UNKNOWN")
        self.assertEqual(len(d8["details"]["not_measured"]), 9)
        self.assertTrue(all(c["verdict"] == "UNKNOWN" for c in d8["details"]["checks"] if c["role"] == "주"))
        self.assertTrue(all("신규 측정값 아님" in c["reason"] for c in d8["details"]["checks"] if c["role"] == "주"))
        self.assertEqual(doc["status"], "UNVERIFIED")

    def test_console_denied_http_alone_is_not_enough(self):
        doc = self._run(True, "denied", deny_console=True)
        d8 = self._lay(doc)["V8"]
        self.assertEqual(d8["verdict"], "UNKNOWN")
        nm = {n["id"] for n in d8["details"]["not_measured"]}
        self.assertEqual(nm, {"user-alb", "alb-web", "admin-bastion", "bastion-web", "bastion-api"})
        errs = json.dumps(d8["details"]["vantages"], ensure_ascii=False)
        self.assertIn("콘솔 출력 조회 실패", errs)
        self.assertNotIn("123456789012", errs)

    def test_pc_rows_never_decide(self):
        measure.tcp_probe = lambda host, port, timeout=4.0: {"result": "timeout", "ms": 4000}     # 학교망이 막은 경우
        doc = self._run(True, "pcblocked", alb_http=False)
        d8 = self._lay(doc)["V8"]
        self.assertEqual(d8["verdict"], "PASS", d8["summary"])
        ref = [c for c in d8["details"]["checks"] if c["role"] == "참고"]
        self.assertTrue(ref and all(c["verdict"] == "INFO" for c in ref))
        self.assertTrue(any(c["observed"] == "FAIL" and "불일치" in c["reason"] for c in ref))

    def test_alb_error_page_is_not_open(self):
        doc = self._run(True, "alb503", alb_web_503=True)
        d8 = self._lay(doc)["V8"]
        self.assertEqual(d8["verdict"], "FAIL")
        row = next(c for c in d8["details"]["checks"] if c["from"] == "outsider" and c["kind"] == "path")
        self.assertEqual(row["verdict"], "FAIL")
        self.assertIn("503", row["detail"])

    def test_fresh_rules(self):
        f = measure.is_fresh
        b = {"seq": 8, "at": "2026-10-23T10:08:00Z"}
        self.assertFalse(f({"seq": 8, "at": "2026-10-23T10:08:00Z"}, b))
        self.assertFalse(f({"seq": 9, "at": "2026-10-23T10:09:00Z"}, b))
        self.assertTrue(f({"seq": 10, "at": "2026-10-23T10:10:00Z"}, b))
        self.assertTrue(f({"seq": 2, "at": "2026-10-23T10:20:00Z"}, b))      # 측정기가 다시 시작됨 → 새 실행의 2번째 결과
        self.assertFalse(f({"seq": 1, "at": "2026-10-23T10:20:00Z"}, b))
        self.assertFalse(f({"seq": 3, "at": "2026-10-23T10:01:00Z"}, b))     # 더 옛날 결과
        self.assertFalse(f(None, b))
        self.assertFalse(f({"seq": 10, "at": "x"}, None))

    def test_parse_console(self):
        line = 'IACPATCH-PROBE {"v":2,"from":"admin","at":"2026-10-23T10:00:00Z","seq":4,"probes":[]}'
        other = 'IACPATCH-PROBE {"v":2,"from":"web","at":"2026-10-23T10:00:05Z","seq":9,"probes":[]}'
        text = "[ 1.0] boot\r\n" + line + "\r\nIACPATCH-PROBE {cut\r\n" + other + "\r\n"
        self.assertEqual(measure.parse_console(text, "admin")["seq"], 4)
        self.assertEqual(measure.parse_console(base64.b64encode(text.encode()).decode(), "admin")["seq"], 4)   # 안 풀린 base64 도 처리
        self.assertIsNone(measure.parse_console("[ 1.0] boot\n", "admin"))
        self.assertEqual(measure.parse_console("kernel: x" + line, "admin")["seq"], 4)   # 커널 메시지와 같은 줄에 붙어도

    def test_fetch_result_rules(self):
        fr = measure._fetch_result
        self.assertEqual(fr("web-via-alb", {"status": 200, "text": "iacpatch testbed: web\n"})[0], "open")
        self.assertEqual(fr("web-via-alb", {"status": 200})[0], "open")          # 콘솔 줄: 본문 없음, ALB 는 200 을 만들지 않음
        self.assertEqual(fr("web-via-alb", {"status": 200, "text": "something else"})[0], "fail")
        self.assertEqual(fr("web-via-alb", {"error": "HTTPError: HTTP Error 502: Bad Gateway"})[0], "fail")
        self.assertEqual(fr("api-via-nlb", {"error": "HTTPError: HTTP Error 404: File not found"})[0], "open")   # 4계층 NLB: 응답 = API 서버
        self.assertEqual(fr("api-via-nlb", {"error": "URLError: <urlopen error timed out>"})[0], "timeout")
        self.assertEqual(fr("api-via-nlb", {"error": "URLError: <urlopen error [Errno 111] Connection refused>"})[0], "refused")

    def test_judge_rules(self):
        self.assertEqual(measure.judge("closed", "timeout")[0], "PASS")
        self.assertEqual(measure.judge("closed", "open")[0], "FAIL")
        self.assertEqual(measure.judge("closed", "refused")[0], "UNKNOWN")     # 서버까지 갔다 = 보안 그룹이 막은 증거 아님
        self.assertEqual(measure.judge("closed", "error:gaierror")[0], "UNKNOWN")
        self.assertEqual(measure.judge("open", "refused")[0], "FAIL")
        self.assertEqual(measure.judge("open", "open", stale=True)[0], "UNKNOWN")

    def test_post_cards_before_after(self):
        self._run(False, "b")
        root = self.tmp / "root"
        (root / "data" / "measurements").mkdir(parents=True)
        shutil.copytree(self.tmp / "b", root / "data" / "measurements" / "20261023-100000")
        rec = root / "data" / "reviews" / "r1"
        (rec / "postdeploy").mkdir(parents=True)
        self._run(True, "a")
        shutil.copytree(self.tmp / "a", rec / "postdeploy" / "20261023-101000")
        pc = postcards.build_post_cards(rec, root)
        te, v7, v8 = pc["cards"]
        self.assertEqual(te["layer"], "임시")
        self.assertEqual(te["verdict"], "FAIL")        # 이 시험에는 후보 파일·시험 환경 파일이 없다 → 배포 확인 안 됨
        self.assertEqual((v7["verdict"], v8["verdict"]), ("PASS", "PASS"))
        titles = [b.get("title") or "" for b in v7["evidence"]]
        self.assertTrue(any("수정 전 → 수정 후" in t for t in titles))
        t8 = {b.get("title") or "": b for b in v8["evidence"]}
        changed = t8["수정 전 → 수정 후 결과 변화"]["rows"]
        self.assertEqual(len(changed), 4)                       # 원본에서 실패한 4건이 수정 후 막힘으로 바뀜
        self.assertTrue(any(k.startswith("측정 지점 5곳") for k in t8))
        self.assertTrue(any("get-console-output" in (c.get("cmd") or "") for c in v8["method"]["commands"]))
        self.assertNotIn("123456789012", json.dumps(pc, ensure_ascii=False))
        self.assertEqual((v7.get("scope"), v8.get("scope")), ("after", "after"))

    def test_before_only_is_labeled_as_original(self):
        """이 기록의 수정 후 측정이 없으면 원본 측정을 보여 주되, 이 후보의 판정으로 읽히지 않게 '수정 전' 을 붙인다."""
        self._run(False, "b")
        root = self.tmp / "root"
        (root / "data" / "measurements").mkdir(parents=True)
        shutil.copytree(self.tmp / "b", root / "data" / "measurements" / "20261023-100000")
        rec = root / "data" / "reviews" / "r2"
        rec.mkdir(parents=True)
        te, v7, v8 = postcards.build_post_cards(rec, root)["cards"]
        for c in (v7, v8):
            self.assertEqual(c["verdict"], "FAIL")              # 판정 값은 원본 측정 그대로
            self.assertEqual(c["scope"], "before")
            self.assertTrue(c["verdict_ko"].startswith("수정 전 "), c["verdict_ko"])
            self.assertTrue(c["summary"].startswith("수정 전(원본) 측정"), c["summary"])
            self.assertIn("시험 환경 측정 기록 없음", c["reason"])


class SettleGateTest(unittest.TestCase):
    """apply 직후에는 측정을 받지 않는다 (콘솔 출력이 늦게 보여 바뀌기 전 결과를 쓸 수 있으므로)."""

    def setUp(self):
        from iacpatch.web import proof_api as pa
        self.pa, self._root = pa, pa._root
        self.tmp = Path(tempfile.mkdtemp())
        tb = self.tmp / pa.TESTBED
        tb.mkdir(parents=True)
        (self.tmp / "scenarios/arch/webapp-3tier").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCEN / "security_groups.tf", self.tmp / "scenarios/arch/webapp-3tier/security_groups.tf")
        shutil.copy(SCEN / "security_groups.tf", tb / "security_groups.tf")
        self.state = tb / "terraform.tfstate"
        self.state.write_text("{}")
        pa._root = lambda: self.tmp

    def tearDown(self):
        self.pa._root = self._root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_just_applied_is_refused(self):
        with self.assertRaises(ValueError) as e:
            self.pa.job_measure({"record_id": "", "profile": "x", "region": "ap-northeast-2"})
        self.assertIn("초 후 측정 가능", str(e.exception))

    def test_after_two_minutes_ok(self):
        import os
        t = time.time() - 130
        os.utime(self.state, (t, t))
        os.utime(self.tmp / self.pa.TESTBED / "security_groups.tf", (t - 10, t - 10))
        self.assertTrue(callable(self.pa.job_measure({"record_id": "", "profile": "x", "region": "ap-northeast-2"})))


class PrimaryEvidenceTest(unittest.TestCase):
    """화면은 key 증거만 펼친다 — 어떤 블록을 먼저 보일지만 정하고 값은 그대로."""

    def test_marks(self):
        from iacpatch.proof import primary
        c = primary.mark({"layer": "V6", "evidence": [{"t": "table", "title": "설계 기준 경로 9개", "rows": [["a", "80", "허용"]]},
                                                      {"t": "table", "title": "설계 외 허용 경로", "rows": []}]})
        self.assertEqual([b["key"] for b in c["evidence"]], [False, False])    # '없음' 표는 앞에 두지 않는다 (답 한 줄이 같은 말)
        c = primary.mark({"layer": "V6", "evidence": [{"t": "table", "title": "설계 기준 경로 9개", "rows": [["a", "443", "누락"]]},
                                                      {"t": "table", "title": "설계 외 허용 경로", "rows": [["웹 서버 → Redis", "6379", "x", "y"]]}]})
        self.assertEqual([b["key"] for b in c["evidence"]], [True, True])      # 필수 통신 누락 · 설계 외 허용 경로가 있으면 앞에
        c = primary.mark({"layer": "V1", "verdict": "PASS", "evidence": [{"t": "diffline", "title": "변경 행", "old": [], "new": []},
                                                                         {"t": "kv", "title": "수정 후 결과 (trivy_after.json)", "rows": []}]})
        self.assertEqual([b["key"] for b in c["evidence"]], [True, False])
        c["verdict"] = "FAIL"
        self.assertEqual([b["key"] for b in primary.mark(c)["evidence"]], [True, True])   # 실패면 남은 지적도 앞에

    def test_every_stage_has_rule(self):
        from iacpatch.proof import primary
        for layer in ("V1", "V2", "V3", "V4", "V5", "V6", "임시", "V7", "V8"):
            self.assertIn(layer, primary.KEY_TITLES)

    def test_v5_fail_shows_what_changed_not_the_same_sentence_twice(self):
        from iacpatch.proof import primary
        s = "아니다 — 허용 범위 밖 변경 1건: 한 번에 리소스 5개를 바꿈 — 팀 정책은 3개까지만 허용"
        c = primary.mark({"layer": "V5", "verdict": "FAIL", "summary": s, "evidence": [
            {"t": "table", "title": "변경 위치", "rows": [["ALB 보안 그룹", "태그", "허용"]] * 5},
            {"t": "table", "title": "규칙 변경 내용 (실행 계획 기준 계산)", "rows": [["Bastion", "삭제", "x"]]},
            {"t": "table", "title": "정책 위반", "rows": [["한 번에 리소스 5개를 바꿈 — 팀 정책은 3개까지만 허용"]]}]})
        self.assertEqual([b["key"] for b in c["evidence"]], [True, False, False])   # 답 한 줄과 같은 문장(정책 위반 1건)은 다시 보이지 않음
        c = primary.mark({"layer": "V6", "verdict": "FAIL", "summary": "다르다 — 설계도에 없는 통신 1개가 열림 (웹 서버 → Redis, Redis 6379)", "evidence": [
            {"t": "table", "title": "설계 외 허용 경로", "rows": [["웹 서버 → Redis", "Redis 6379", "설계도에 없는 통신", "security_groups.tf 169~175번째 줄"]]}]})
        self.assertTrue(c["evidence"][0]["key"])                                       # 코드 위치처럼 답에 없는 값이 있으면 그대로 앞에


class PlainWordsTest(unittest.TestCase):
    """화면 한 줄을 쉬운 말로 — 판정 값은 그대로, 원문은 증거에 남는다."""

    def test_terraform_errors(self):
        from iacpatch.proof import plain
        raw = ('--- stderr ---\n\nError: No value for required variable\n\n  on security_groups.tf line 4:\n   4: variable "admin_cidrs" {\n\n'
               'The root module input variable "admin_cidrs" is not set, and has no default\nvalue.')
        self.assertEqual(plain.tf_error_ko(raw), "기본값 없는 변수에 값 미지정 (admin_cidrs)")
        self.assertEqual(plain.tf_error_ko('Reference to undeclared resource A managed resource "aws_security_group" "admin" has not been declared in the root module.'),
                         "선언되지 않은 리소스 참조 (aws_security_group.admin)")
        self.assertEqual(plain.tf_error_ko("validate failed, plan not attempted"), "V3(구문·속성·참조 검사) 실패로 plan 미실행")
        self.assertEqual(plain.tf_error_ko("Error: Something new happened\nmore"), "Something new happened")   # 모르는 오류는 원문 첫 줄

    def test_requirements_style_v6(self):
        """설계도 대신 요구사항 목록으로 판정한 기록(2계층 사례) — 무엇이 어긋났는지 쉬운 말로."""
        svc = lambda sid, label, v, eff, exc=(), whole=False: {"service_id": sid, "label": label, "verdict": v, "effective_v4": list(eff), "excess_v4": list(exc),
                                                                 "covers_entire_internet_v4": whole}
        d = {"targets": [{"target": "aws_security_group.web", "scopes": [{"scope_id": "aws_instance.web", "services": [
            svc("ingress/tcp/22-22", "ssh", "FAIL", ["0.0.0.0/0"], ["128.0.0.0/1"], True), svc("ingress/tcp/3389-3389", "rdp", "PASS", [])],
            "required": [{"label": "admin-ssh", "service_id": "ingress/tcp/22-22", "source_cidr": "10.0.0.0/8", "verdict": "PASS"},
                         {"label": "public-http", "service_id": "ingress/tcp/80-80", "source_cidr": "0.0.0.0/0", "verdict": "FAIL"}]}]}]}
        vw = cards._sg_oracle_view(d)
        self.assertEqual(vw["lim"], [["웹 서버", "SSH 22", "허용 출발지 밖까지 허용 — 인터넷 전체", "0.0.0.0/0"]])   # 닫힌 RDP 는 표에 없음
        self.assertEqual(vw["bad"], ["허용 출발지 밖 허용 — 웹 서버 SSH 22 (인터넷 전체)", "필수 통신 허용 규칙 없음 — 웹 서버 HTTP 80 ← 0.0.0.0/0"])

    def test_legacy_topology_phrases(self):
        """예전 빌드가 기록 파일에 남긴 문장 → 지금 용어 (기록 파일은 그대로, 표시할 때만)."""
        from iacpatch.proof import plain, postcards
        self.assertEqual(plain.legacy("사용자(인터넷) 중 0.0.0.0/0 일부 은(는) 443번 포트로 들어올 수 없습니다"),
                         "사용자(인터넷) 중 0.0.0.0/0 일부: 443번 포트 허용 규칙 없음 (필수 통신)")
        self.assertEqual(plain.legacy("인터넷 에서 ALB 로 가는 443 규칙이 없습니다"), "인터넷 → ALB 443 허용 규칙 없음 (필수 통신)")
        self.assertEqual(plain.legacy("IPv6 출처 ::/0 — 설계도에 IPv6 통신이 없습니다"), "IPv6 출발지 ::/0 — 설계도에 IPv6 통신 없음")
        for new in ("VPC 내 모든 서버", "인터넷 → ALB 443 허용 규칙 없음 (필수 통신)", "설계 외 허용 경로"):
            self.assertEqual(plain.legacy(new), new)                                   # 지금 문구는 바뀌지 않는다
        old = {"src_label": "VPC 안 모든 서버", "dst_label": "MySQL", "ports": "3306"}
        new = {"src_label": "VPC 내 모든 서버", "dst_label": "MySQL", "ports": "3306"}
        self.assertEqual(postcards._excess_key(old), postcards._excess_key(new))       # 빌드가 달라도 같은 경로끼리 짝지음 (수정 전·후, V6·V7 비교)

    def test_flow_port(self):
        from iacpatch.proof import plain
        self.assertEqual(plain.flow_port("MySQL", 3306), "MySQL 3306")
        self.assertEqual(plain.flow_port("Bastion", "22"), "Bastion SSH 22")

    def test_skipped_stage_says_which_stage_stopped_it(self):
        cs = [{"layer": "V3", "name": "terraform validate", "verdict": "FAIL", "summary": "틀렸다"},
              {"layer": "V4", "name": "terraform plan", "verdict": "ERROR", "summary": ""},
              {"layer": "V5", "name": "변경 범위", "verdict": "NOT_RUN", "summary": ""},
              {"layer": "V6", "name": "설계도 비교", "verdict": "PASS", "summary": "똑같다"}]
        cards._skip_summaries(cs)
        self.assertEqual(cs[1]["summary"], "미실행 — 앞 단계 V3(terraform validate) 실패로 검사 진행 안 함")
        self.assertIn("V3(terraform validate)", cs[2]["summary"])
        self.assertEqual(cs[3]["summary"], "똑같다")                                       # 결과가 있는 단계는 그대로
        cs = [{"layer": "V4", "name": "terraform plan", "verdict": "FAIL", "summary": "x"}, {"layer": "V5", "name": "변경 범위", "verdict": "NOT_RUN", "summary": ""}]
        cards._skip_summaries(cs)
        self.assertIn("V4(terraform plan) 실패로", cs[1]["summary"])


class TempEnvCardTest(unittest.TestCase):
    """임시 환경 배포(apply) 카드 — 측정 기록의 파일 해시·시각으로만 확인한다."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "root"
        self.rec = self.root / "data" / "reviews" / "r1"
        (self.rec / "candidate").mkdir(parents=True)
        self.cand = (CANDS / "correct-design.tf").read_text(encoding="utf-8")
        (self.rec / "candidate" / "security_groups.tf").write_text(self.cand, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _after(self, text):
        import hashlib
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return {"started_at": "2026-10-23T13:01:49+09:00", "identity": {"testbed_security_groups_sha256": sha, "matches": []},
                "state": {"ok": True, "sg_ids": {f"aws_security_group.s{i}": f"sg-{i}" for i in range(7)}},
                "tempenv": {"since_apply_s": 290, "resources": 39}, "layers": []}

    def test_candidate_deployed(self):
        (self.root / "data").mkdir(parents=True, exist_ok=True)
        (self.root / "data" / "testbed_switch.jsonl").write_text(
            json.dumps({"at": "2026-10-23T12:55:03+09:00", "which": "candidate", "record": "r1", "from_sha256": "d2fe" * 16, "to_sha256": "6082" * 16}) + "\n"
            + json.dumps({"at": "2026-10-23T13:30:00+09:00", "which": "candidate", "record": "r1", "from_sha256": "x", "to_sha256": "y"}) + "\n", encoding="utf-8")
        c = postcards.card_tempenv(self.rec, self.root, self._after(self.cand), None, self.tmp / "a", None)
        self.assertEqual((c["verdict"], c["verdict_ko"]), ("PASS", "반영 확인"))
        rows = dict(c["evidence"][0]["rows"])
        self.assertIn("12:55:03", rows["후보 적용 시각"])           # 측정 전의 마지막 기록 (13:30 기록은 측정 뒤라 쓰지 않음)
        self.assertIn("4분 50초", rows["apply 확인"])
        self.assertIn("일치", rows["시험 환경 파일"])
        st = dict(c["evidence"][1]["rows"])
        self.assertEqual(st["상태 파일 리소스"], "39개")
        self.assertTrue(c["summary"].startswith("반영 확인"), c["summary"])

    def test_other_file_deployed_is_not_confirmed(self):
        c = postcards.card_tempenv(self.rec, self.root, self._after(self.cand + "# 다른 내용\n"), None, self.tmp / "a", None)
        self.assertEqual(c["verdict"], "FAIL")
        self.assertIn("불일치", c["summary"])

    def test_no_measurement(self):
        c = postcards.card_tempenv(self.rec, self.root, None, None, None, None)
        self.assertEqual(c["status"], "pending")


class DestroyedTestbedTest(unittest.TestCase):
    """destroy 뒤에는 상태 파일이 남아도 리소스가 0개 — 배포된 것으로 보지 않는다."""

    def setUp(self):
        from iacpatch.web import proof_api as pa
        self.pa, self._root = pa, pa._root
        self.tmp = Path(tempfile.mkdtemp())
        tb = self.tmp / pa.TESTBED
        tb.mkdir(parents=True)
        (self.tmp / "scenarios/arch/webapp-3tier").mkdir(parents=True, exist_ok=True)
        shutil.copy(SCEN / "security_groups.tf", self.tmp / "scenarios/arch/webapp-3tier/security_groups.tf")
        shutil.copy(SCEN / "security_groups.tf", tb / "security_groups.tf")
        import os
        st = tb / "terraform.tfstate"
        st.write_text(json.dumps({"version": 4, "resources": []}))
        t0 = time.time() - 600
        os.utime(tb / "security_groups.tf", (t0 - 10, t0 - 10))
        os.utime(st, (t0, t0))
        pa._root = lambda: self.tmp

    def tearDown(self):
        self.pa._root = self._root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_destroyed_is_not_deployed(self):
        f = self.pa._testbed_files()
        self.assertEqual(f["state_resources"], 0)
        with self.assertRaises(ValueError) as e:
            self.pa.job_measure({"record_id": "", "profile": "x", "region": "ap-northeast-2"})
        self.assertIn("리소스 0개", str(e.exception))

    def _record(self, scenario, level="LIGHT_REVIEW"):
        rd = self.tmp / "data" / "reviews" / "r-case"
        (rd / "candidate").mkdir(parents=True, exist_ok=True)
        (rd / "candidate" / "security_groups.tf").write_text("# other case\n", encoding="utf-8")
        (rd / "state.json").write_text(json.dumps({"scenario": scenario, "state": "REVIEW_REQUIRED", "review_level": level}), encoding="utf-8")
        return rd

    def test_other_case_never_goes_into_3tier_testbed(self):
        """2계층 사례의 후보 파일을 3계층 시험 환경에 넣으면 보안 그룹이 통째로 바뀐다 — 서버가 거부한다."""
        rd = self._record("ui/arch-webapp-sg/rule-based")
        before = (self.tmp / self.pa.TESTBED / "security_groups.tf").read_bytes()
        reviews = self.pa._reviews
        self.pa._reviews = lambda: self.tmp / "data" / "reviews"
        try:
            with self.assertRaises(ValueError) as e:
                self.pa.testbed_use({"which": "candidate", "record_id": rd.name})
        finally:
            self.pa._reviews = reviews
        self.assertIn("3계층", str(e.exception))
        self.assertEqual((self.tmp / self.pa.TESTBED / "security_groups.tf").read_bytes(), before)   # 파일은 그대로
        self.assertFalse(self.pa.testbed_case_ok(rd))
        self.assertTrue(self.pa.testbed_case_ok(self._record("ui/arch-3tier-sg/correct-design")))
        post = postcards.build_post_cards(self._record("ui/arch-webapp-sg/rule-based"), self.tmp)
        self.assertIn("3계층", post["na"])
        self.assertEqual([c["status"] for c in post["cards"]], ["pending"] * 3)
        self.assertIsNone(post["before"]["dir"])                                              # 3계층 '수정 전' 측정을 붙이지 않음


class ToolErrorAndLockTest(unittest.TestCase):
    def test_provider_start_failure_is_error_not_fail(self):
        """provider 실행 파일을 못 띄운 validate 실패 = 도구 오류 (후보 코드 문제 아님)."""
        from iacpatch.models import Verdict
        from iacpatch.tools.terraform import StepOutput
        from iacpatch.verify.layers import v3_validate
        init = StepOutput(ok=True, result=None)
        bad = StepOutput(ok=False, result=None, error="error: Failed to load plugin schemas ...",
                         data={"valid": False, "diagnostics": [{"severity": "error", "summary": "Failed to load plugin schemas",
                               "detail": "Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider "
                                         "registry.terraform.io/hashicorp/aws: failed to instantiate provider ... is not a valid Win32 application"}]})
        self.assertEqual(v3_validate({"init": init, "validate": bad}, "t").verdict, Verdict.ERROR)
        code = StepOutput(ok=False, result=None, error="error: Reference to undeclared resource",
                          data={"valid": False, "diagnostics": [{"severity": "error", "summary": "Reference to undeclared resource",
                                "detail": "A managed resource \"aws_security_group\" \"admin\" has not been declared", "range": {"filename": "security_groups.tf"}}]})
        self.assertEqual(v3_validate({"init": init, "validate": code}, "t").verdict, Verdict.FAIL)

    def test_second_window_cannot_start_while_first_runs(self):
        import threading
        from iacpatch.web import server
        tmp = Path(tempfile.mkdtemp())
        orig = server._job_lock_path
        server._job_lock_path = lambda: tmp / ".job.lock"
        try:
            a, b = server.Job(), server.Job()        # 같은 잠금 파일을 쓰는 두 '창'
            gate = threading.Event()
            self.assertTrue(a.start("a", lambda log, prog: gate.wait(5)))
            self.assertFalse(b.start("b", lambda log, prog: None))
            self.assertTrue(b.busy_other)
            gate.set()
            a.thread.join(5)
            self.assertTrue(b.start("b", lambda log, prog: None))
            b.thread.join(5)
        finally:
            server._job_lock_path = orig
            shutil.rmtree(tmp, ignore_errors=True)


class CardsTest(unittest.TestCase):
    """도구 없이 만든 작은 기록으로 카드가 기록 값 그대로 나오는지."""

    def test_cards_from_minimal_record(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            d = tmp / "20261023-000000-test"
            for sub in ("original", "candidate", "input", "local_verify"):
                (d / sub).mkdir(parents=True)
            orig = (SCEN / "security_groups.tf").read_text(encoding="utf-8")
            (d / "original" / "security_groups.tf").write_text(orig, encoding="utf-8")
            (d / "candidate" / "security_groups.tf").write_text((CANDS / "ai-claude-r1.tf").read_text(encoding="utf-8"), encoding="utf-8")
            (d / "input" / "selected_finding.json").write_text(json.dumps({"rule_id": "AVD-AWS-0107", "filename": "security_groups.tf",
                                                                           "resource": "aws_security_group.bastion", "severity": "HIGH"}), encoding="utf-8")
            ex = [{"src": "web", "dst": "db", "src_label": "웹 서버", "dst_label": "MySQL", "ports": "3306", "detail": "설계도에 없는 통신",
                   "kind": "not_designed", "rule": "aws_security_group.db#ingress[1]"}]
            layers = [{"layer": "V1", "verdict": "PASS", "summary": "x"}, {"layer": "V6", "verdict": "FAIL", "summary": "y",
                                                                           "details": {"flows": [], "excess": ex}}]
            (d / "verification.json").write_text(json.dumps({"report": {"layers": layers}}), encoding="utf-8")
            (d / "state.json").write_text(json.dumps({"scenario": "ui/arch-3tier-sg/test", "finished_at": "x"}), encoding="utf-8")
            CommandLog(d / "local_verify" / "commands.json").add("trivy:baseline", "V1", ["/x/trivy", "config", str(d / "local_verify")], returncode=0, ok=True)
            out = cards.build_cards(d, ROOT)
            by = {c["layer"]: c for c in out["cards"]}
            self.assertEqual(by["V1"]["verdict"], "PASS")
            self.assertEqual(by["V6"]["verdict"], "FAIL")
            self.assertEqual(by["V3"]["status"], "pending")          # 기록에 없는 계층은 판정을 만들지 않는다
            v6_rows = next(b for b in by["V6"]["evidence"] if b.get("title") == "설계 외 허용 경로")["rows"]
            self.assertIn("security_groups.tf", v6_rows[0][3])
            cmd = by["V1"]["method"]["commands"][0]["cmd"]
            self.assertTrue(cmd.startswith("trivy config <기록>"), cmd)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ReportTest(unittest.TestCase):
    """증거 보고서: 맨 위 요약 표, 정책 차단 절, 검증 도구 사전 점검 '통과' 기준."""

    def _view(self):
        cal = {"id": "c1", "summary": {"trivy_correct": 2, "trivy_total": 2, "known_limit_reproduced": True, "cidr_mismatches": 0, "validate_ok": True},
               "cidr": {"differential": {"cases": 2000, "mismatches": 0}}, "trivy": [], "probe": [], "validate": {}}
        c1 = {"layer": "V1", "name": "Trivy 재검사", "verdict": "PASS", "verdict_ko": "통과", "status": "done", "summary": "지적 사라짐", "method": {}, "evidence": []}
        c6 = {"layer": "V6", "name": "설계도 비교", "verdict": "FAIL", "verdict_ko": "실패", "status": "done", "summary": "설계도에 없는 통신 1개", "method": {}, "evidence": []}
        te = {"layer": "임시", "name": "시험 환경 반영 (apply)", "verdict": None, "status": "pending", "reason": "측정 기록 없음", "method": {}, "evidence": []}
        return {"record": "r1", "calibration": cal, "cards": [c1, c6], "post": {"cards": [te]},
                "blocked_before": {"stage": "정책 확인 (검사 전)", "violations": ["forbidden_pattern:local-exec"], "file": "policy.json"}}

    def test_glance_table_and_policy_section(self):
        from iacpatch.proof import report
        h = report.render_report(self._view())
        self.assertIn("<h2>요약</h2>", h)
        self.assertLess(h.index("<h2>요약</h2>"), h.index("0 · 검증 도구 사전 점검"))      # 요약이 맨 위
        self.assertIn('href="#s-V6"', h)
        self.assertIn('id="s-V6"', h)
        self.assertIn('id="s-policy"', h)
        self.assertIn("forbidden_pattern:local-exec", h)
        self.assertNotIn('href="#s-tmp"', h)                         # 측정 전 단계는 절이 없으므로 링크도 없다
        self.assertIn('검증 도구 사전 점검</a></td><td><span class="v ok">통과</span>', h)

    def test_unmeasured_post_cards_are_not_this_records_result(self):
        from iacpatch.proof import report
        v = self._view()
        v["blocked_before"] = None
        v["level"] = "FULL_REVIEW"
        v7 = {"layer": "V7", "name": "배포된 설정 조회", "verdict": "FAIL", "verdict_ko": "수정 전 실패", "status": "done", "scope": "before",
              "summary": "수정 전(원본) 측정 — 설계도 밖 열린 통신 2", "method": {}, "evidence": []}
        v["post"] = {"cards": [v7]}
        h = report.render_report(v)
        self.assertIn("측정 전", h)
        self.assertNotIn('id="s-V7"', h)                          # 원본 측정은 이 기록의 절로 넣지 않는다
        self.assertNotIn("수정 전 실패", h)
        v["level"] = "BLOCKED"
        self.assertIn("대상 아님", report.render_report(v))

    def test_blocked_record_merges_unrun_layers(self):
        from iacpatch.proof import report
        v = self._view()
        v["cards"] = [{"layer": k, "name": k, "status": "pending", "reason": "정책 확인에서 막힘", "method": {}, "evidence": []} for k in ("V1", "V2", "V3", "V4", "V5", "V6")]
        h = report.render_report(v)
        self.assertIn("V1~V6", h)
        self.assertEqual(h.count("정책 확인에서 막힘"), 0)            # 같은 이유를 6번 되풀이하지 않는다
        self.assertNotIn('id="s-V1"', h)

    def test_cal_ok_needs_samples_to_run(self):
        from iacpatch.proof import report
        self.assertFalse(report.cal_ok({"summary": {"trivy_correct": 0, "trivy_total": 0, "cidr_mismatches": 0, "validate_ok": True}}))
        self.assertTrue(report.cal_ok({"summary": {"trivy_correct": 2, "trivy_total": 2, "cidr_mismatches": 0, "validate_ok": True}}))
        self.assertFalse(report.cal_ok({"summary": {"trivy_correct": 1, "trivy_total": 2, "cidr_mismatches": 0, "validate_ok": True}}))


if __name__ == "__main__":
    unittest.main()
