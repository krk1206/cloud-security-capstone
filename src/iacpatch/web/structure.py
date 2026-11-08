"""그림에서 바꾸기 (2026-11-01 갈아엎기 5차, D-33) — '원하는 구조'(고객 설계도) = 자동 기준 + 사람이 그림에서 바꾼 것.

B (11-01): "설계도 굳이 꼭 완전히 넣을 필요 없잖아" → 설계도를 처음부터 입력하는 단계를 없앤다.

자동 기준 (v1 · 사람이 바꾼 것 없음)
  = 지금 코드의 보안 그룹 통신 그대로 (codetopo.draft_design) − 위험한 통신 (인터넷 전체 → 관리 포트 · 고위험 포트 · 모든 포트).
    위험한 통신은 기본값 '막을 예정' — 원하는 구조에 넣지 않으므로 V6 비교에서 '설계에 없는 연결' 로 보인다.
    VPC 대역처럼 어느 서버인지 모르는 출처도 넣을 수 없다 (같은 이유로 '설계에 없는 연결').
  자동 기준은 '사람이 확인한 고객 설계' 가 아니다 — 화면 · 기록에 그대로 적는다 (auto 표시).

그림에서 바꾸기 (선 · 상자를 누르고 고른 것) → 아래 규칙으로 설계도를 고침 → 형식 검사(designs.validate) → V6 와 같은 비교로 미리보기 → 저장(새 버전)
  선   keep   그대로 둠      = 원하는 구조에 그 통신을 둔다 (위험해서 빠져 있던 것을 사람이 허용)
       block  막기           = 원하는 구조에서 뺀다 → 코드의 그 규칙은 '설계에 없는 연결' (고칠 대상)
       narrow 출발지 좁히기  = 출발지를 IP 대역(예: 운영팀 사무실) 또는 다른 상자(그 상자의 보안 그룹)로 바꾼다
       port   포트 바꾸기    = 같은 출발 · 도착, 다른 포트
  상자 gone   빼기           = 그 상자로 들어오는 통신을 원하는 구조에서 모두 뺀다. 리소스 삭제가 아니다 (AI 의 리소스 삭제는 정책상 금지 — 사람이 코드에서)
  add         통신 추가      = 원하는 구조에 새 통신 → 코드에 없으면 '허용 규칙 없는 필수 통신' (고칠 대상)
  drop        원하는 구조에서 빼기 = 코드에 없는 통신(그림의 점선)을 원하는 구조에서 지운다
판정은 만들지 않는다 — 비교는 V6 오라클(verify/v6.py) 그대로. 그림의 선 = web/archmap.py (보안 그룹 규칙에서 계산).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from . import archmap, codetopo
from . import cases as cs

AUTO_NOTE = "자동 기준 (지금 코드 − 위험한 통신 · 사람이 바꾼 것 없음)"
OPS = ("keep", "block", "narrow", "port", "gone", "add", "drop")
MAX_EDITS = 60


def _short(sg: str) -> str:
    return codetopo.short(sg)


def _slug(s: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9_-]+", "-", str(s or "").lower()).strip("-_")[:30] or "c"
    if not re.match(r"^[a-z0-9]", base):
        base = "c" + base
    out, i = base, 2
    while out in used:
        out = f"{base}-{i}"
        i += 1
    used.add(out)
    return out


# ----------------------------------------------------------------------------- 지금 코드
def code(pid: str) -> Dict[str, Any]:
    """프로젝트의 지금 코드(원본 plan) → 구성도 모델 · 자체 검사 결과 · 설계도 초안 재료."""
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import scan
    from .product import _plan
    c = cs.get_case(pid)
    if c is None:
        return {"ok": False, "reason": f"프로젝트 없음: {pid}"}
    plan, sources, src = _plan(c)
    if plan is None:
        return {"ok": False, "reason": src, "case": c}
    try:
        sc = scan(build_world(plan, sources), codetopo.vpc_cidr(plan))
    except PlanParseError as e:
        return {"ok": False, "reason": f"plan 해석 실패: {e}", "case": c}
    return {"ok": True, "case": c, "plan": plan, "sources": sources, "plan_source": src, "sg_scan": sc,
            "arch": archmap.build(plan, sources, sc["findings"])}


def design_key(pid: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """설계도를 담은 세트 id (없으면 None) · 프로젝트."""
    from .product import design_set
    c = cs.get_case(pid) or {}
    ds = design_set(c) if c else None
    return (ds["set_id"] if ds else None), c


def auto_design(pid: str, cur: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """자동 기준 설계도 (저장 안 함). {ok, design, excluded: [{flow, why}], notes} — 위험한 통신은 빼고 무엇을 뺐는지 남긴다."""
    cur = cur or code(pid)
    if not cur.get("ok"):
        return {"ok": False, "reason": cur.get("reason")}
    c = cur["case"]
    m = codetopo.build(cur["plan"], cur["sources"], cur["sg_scan"]["findings"])
    if not m.get("ok"):
        return {"ok": False, "reason": m.get("reason") or "그림 모델 실패"}
    dr = codetopo.draft_design(m, f"{pid}-design", c["tf_dir"])
    risky = dr.get("draft_risky") or {}
    names = {x["id"]: x.get("label") or x["id"] for x in dr["tiers"] + dr["external"]}
    excluded = [{"flow": f"{names.get(f['from'], f['from'])} → {names.get(f['to'], f['to'])} {_port_txt(f)}", "why": risky[f["id"]]}
                for f in dr["flows"] if f["id"] in risky]
    flows = [f for f in dr["flows"] if f["id"] not in risky]
    used_ext = {f["from"] for f in flows}
    d = {k: dr[k] for k in ("kind", "intent_version", "intent_id", "status", "target_dir", "vpc_cidr")}
    d.update(description=AUTO_NOTE, tiers=dr["tiers"], external=[e for e in dr["external"] if e["id"] in used_ext], flows=flows)
    notes = [x for x in dr.get("draft_notes") or [] if not x.startswith("⚠")]
    return {"ok": True, "design": d, "excluded": excluded, "notes": notes}


def ensure_auto(pid: str) -> Dict[str, Any]:
    """설계도가 없으면 자동 기준을 v1 로 저장. 있으면 아무것도 안 함. (연결한 프로젝트는 점검 직후, 예제는 처음 열 때)"""
    from . import designs
    key, c = design_key(pid)
    if key is not None:
        return {"ok": True, "created": False, "set_id": key}
    a = auto_design(pid)
    if not a.get("ok"):
        return {"ok": False, "created": False, "reason": a.get("reason")}
    if not a["design"]["flows"]:
        return {"ok": False, "created": False, "reason": "위험한 통신을 빼면 남는 통신이 없어 자동 기준을 만들 수 없음 — 그림에서 원하는 통신을 정해 저장하세요",
                "excluded": a["excluded"]}
    r = designs.create_first(pid, a["design"], note=AUTO_NOTE, target_dir=c.get("tf_dir", ""),
                             meta={"auto": {"excluded": a["excluded"], "notes": a["notes"]}})
    if not r.get("ok"):
        return {"ok": False, "created": False, "reason": "; ".join(r.get("errors") or [])}
    return {"ok": True, "created": True, "version": 1, "excluded": a["excluded"]}


# ----------------------------------------------------------------------------- 그림에서 바꾼 것 → 설계도
def _port_txt(f: Dict[str, Any]) -> str:
    if f.get("protocol") == "-1":
        return "전체"
    if f.get("port") is not None:
        return str(f["port"])
    return f"{f.get('from_port')}-{f.get('to_port')}"


def _rng(f: Dict[str, Any]) -> Tuple[str, int, int]:
    p = str(f.get("protocol") or "tcp")
    if p == "-1":
        return p, 0, 65535
    lo = f.get("from_port", f.get("port"))
    hi = f.get("to_port", f.get("port"))
    return p, int(lo), int(hi)


def _overlap(a: Tuple[str, int, int], b: Tuple[str, int, int]) -> bool:
    if a[0] != b[0] and "-1" not in (a[0], b[0]):
        return False
    return a[1] <= b[2] and b[1] <= a[2]


def _flow(src: str, dst: str, rng: Tuple[str, int, int]) -> Dict[str, Any]:
    p, lo, hi = rng
    f: Dict[str, Any] = {"from": src, "to": dst, "protocol": p}
    if p != "-1":
        if lo == hi:
            f["port"] = lo
        else:
            f["from_port"], f["to_port"] = lo, hi
    return f


def parse_port(txt: Any, proto: Any = "tcp") -> Tuple[str, int, int]:
    p = str(proto or "tcp").lower()
    if p in ("all", "-1", "전체"):
        return "-1", 0, 65535
    if p not in ("tcp", "udp"):
        raise ValueError("프로토콜은 TCP · UDP · 전체 중 하나")
    m = re.match(r"^\s*(\d{1,5})\s*(?:-\s*(\d{1,5}))?\s*$", str(txt or ""))
    if not m:
        raise ValueError(f"포트가 숫자가 아님: {txt!r} (예: 443 또는 8000-8100)")
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    if not (0 <= lo <= hi <= 65535):
        raise ValueError(f"포트 범위가 올바르지 않음: {txt}")
    return p, lo, hi


def _split_port(x: Any) -> Tuple[Any, Any]:
    """'22' · 'udp 53' · '전체' · ['tcp', 22, 22] → (포트, 프로토콜)."""
    if isinstance(x, (list, tuple)) and len(x) == 3:
        return (f"{x[1]}-{x[2]}", x[0]) if str(x[0]) != "-1" else ("0", "-1")
    t = str(x or "").strip()
    if t in ("전체", "all"):
        return "0", "-1"
    m = re.match(r"^(tcp|udp)\s+(.+)$", t, re.I)
    if m:
        return m.group(2), m.group(1).lower()
    if "/" in t:
        port, proto = t.split("/", 1)
        return port, proto.lower()
    return t, "tcp"


def parse_cidr(txt: Any) -> str:
    try:
        net = ipaddress.ip_network(str(txt or "").strip(), strict=False)
    except ValueError:
        raise ValueError(f"IP 대역 형식이 아님: {txt!r} (예: 203.0.113.0/24)") from None
    if net.version != 4:
        raise ValueError("IPv4 대역만 (원하는 구조의 외부 출처는 IPv4)")
    if net.prefixlen == 0:
        raise ValueError("0.0.0.0/0(인터넷 전체)은 '좁히기' 가 아님 — 그대로 두려면 '그대로'")
    return str(net)


class _Doc:
    """설계도 사본 + 그림(지금 코드)의 상자 · 선 → 설계도의 구성요소 · 출처 찾기 (없으면 만든다)."""

    def __init__(self, design: Dict[str, Any], arch: Dict[str, Any]):
        import copy
        self.d = copy.deepcopy(design)
        self.d.setdefault("tiers", [])
        self.d.setdefault("external", [])
        self.d.setdefault("flows", [])
        self.arch = arch
        self.nodes = {n["id"]: n for n in arch.get("nodes") or []}
        self.edges = {e["id"]: e for e in arch.get("edges") or []}
        self.used = {t["id"] for t in self.d["tiers"]} | {e["id"] for e in self.d["external"]}

    def tier(self, sg: str, node: Optional[Dict[str, Any]] = None) -> str:
        t = next((x for x in self.d["tiers"] if x.get("security_group") == sg), None)
        if t:
            return t["id"]
        from .designs import TYPES
        tid = _slug(_short(sg), self.used)
        row = {"id": tid, "label": (node or {}).get("label") or _short(sg), "security_group": sg}
        icon = (node or {}).get("icon")
        if icon in TYPES:
            row["type"] = icon
        self.d["tiers"].append(row)
        return tid

    def ext(self, cidrs: List[str], label: str) -> str:
        key = sorted(cidrs)
        e = next((x for x in self.d["external"] if sorted(x.get("cidrs_v4") or []) == key), None)
        if e:
            return e["id"]
        eid = _slug("internet" if key == ["0.0.0.0/0"] else "ext", self.used)
        self.d["external"].append({"id": eid, "label": label or ", ".join(key), "cidrs_v4": key})
        return eid

    def node_tiers(self, nid: str) -> List[str]:
        n = self.nodes.get(nid)
        if n is None:
            raise ValueError(f"그림에 없는 상자: {nid} — 그림을 다시 불러오세요")
        sgs = n.get("sgs") or []
        if not sgs:
            raise ValueError(f"'{n.get('label')}' 에는 보안 그룹이 없음 — 통신 구조(보안 그룹 규칙)로 정할 수 없음 (권한은 IAM 화면 밖)")
        return [self.tier(sg, n) for sg in sgs]

    def edge(self, eid: str) -> Dict[str, Any]:
        e = self.edges.get(eid)
        if e is None:
            raise ValueError(f"그림에 없는 선: {eid} — 그림을 다시 불러오세요")
        if e["kind"] != "sg":
            raise ValueError("보안 그룹 허용 규칙(파란 · 빨간 선)만 바꿀 수 있음 — 요청 경로 · 권한 선은 설명용")
        return e

    def src_ids(self, e: Dict[str, Any], create: bool = True) -> Tuple[List[str], str]:
        """선의 출발 → 설계도의 출처 id 들. 넣을 수 없는 출처면 ([], 이유)."""
        if e.get("src_sgs"):
            node = self.nodes.get(e["src"])
            return ([self.tier(sg, node) for sg in e["src_sgs"]] if create else
                    [t["id"] for t in self.d["tiers"] if t.get("security_group") in e["src_sgs"]]), ""
        s = str(e["src"])
        if s.startswith("x:vpc:"):
            return [], "VPC 안 모든 서버(VPC 대역)는 어느 서버인지 몰라 원하는 구조에 넣을 수 없음 — '출발지 좁히기' 로 서비스를 고르세요"
        if s.startswith(("x:internet6", "x:v6:")):
            return [], "IPv6 출처는 원하는 구조에 넣을 수 없음 (IPv4 대역만)"
        if s == "x:internet" or s.startswith("x:cidr:"):
            cid = [c for c in e.get("cidrs") or [] if ":" not in c]
            if not cid:
                return [], "출처 대역을 확인할 수 없음"
            if not create:
                ids = [x["id"] for x in self.d["external"] if sorted(x.get("cidrs_v4") or []) == sorted(cid)]
                return ids, ""
            lab = "사용자(인터넷)" if cid == ["0.0.0.0/0"] else (self.nodes.get(s) or {}).get("label") or ", ".join(cid)
            return [self.ext(cid, lab)], ""
        return [], "출처를 확정할 수 없어(plan 밖 보안 그룹 · prefix list 등) 원하는 구조에 넣을 수 없음"

    def dst_ids(self, e: Dict[str, Any]) -> List[str]:
        node = self.nodes.get(e["dst"])
        return [self.tier(sg, node) for sg in e.get("dst_sgs") or []]

    def remove(self, srcs: List[str], dsts: List[str], rngs: List[Tuple[str, int, int]]) -> int:
        before = len(self.d["flows"])
        self.d["flows"] = [f for f in self.d["flows"] if not (f.get("from") in srcs and f.get("to") in dsts and any(_overlap(_rng(f), r) for r in rngs))]
        return before - len(self.d["flows"])

    def _new_id(self, f: Dict[str, Any]) -> str:
        p, lo, _hi = _rng(f)
        base_id = f"{f['from']}-{f['to']}-{'all' if p == '-1' else lo}" + ("" if p in ("tcp", "-1") else f"-{p}")
        have = {x.get("id") for x in self.d["flows"]}
        k, i = base_id, 2
        while k in have:
            k = f"{base_id}-{i}"
            i += 1
        return k

    def add(self, srcs: List[str], dsts: List[str], rngs: List[Tuple[str, int, int]]) -> int:
        n = 0
        for s in srcs:
            for t in dsts:
                for r in rngs:
                    if any(f.get("from") == s and f.get("to") == t and _rng(f) == r for f in self.d["flows"]):
                        continue
                    f = _flow(s, t, r)
                    f["id"] = self._new_id(f)        # 바로 id — 같은 목록의 뒤 바꾸기(빼기)가 가리킬 수 있게
                    self.d["flows"].append(f)
                    n += 1
        return n

    def finish(self) -> Dict[str, Any]:
        used = {f["from"] for f in self.d["flows"]}
        self.d["external"] = [e for e in self.d["external"] if e["id"] in used]
        seen: set = set()
        for f in self.d["flows"]:               # 원래 id 는 그대로 (없거나 겹칠 때만 새로)
            if not f.get("id") or f["id"] in seen:
                f["id"] = ""
                f["id"] = self._new_id(f)
            seen.add(f["id"])
        return self.d


def apply_edits(design: Dict[str, Any], arch: Dict[str, Any], edits: List[Dict[str, Any]]) -> Dict[str, Any]:
    """그림에서 바꾼 것들(순서대로) → 새 설계도. {ok, design, errors, done: [사람이 읽는 문장]}"""
    if not isinstance(edits, list) or len(edits) > MAX_EDITS:
        return {"ok": False, "errors": [f"바꾼 것 목록이 올바르지 않음 (최대 {MAX_EDITS}개)"], "done": []}
    doc = _Doc(design, arch)
    errs: List[str] = []
    done: List[str] = []
    nm = lambda nid: (doc.nodes.get(nid) or {}).get("label") or str(nid)  # noqa: E731
    for i, ed in enumerate(edits, 1):
        op = str((ed or {}).get("op") or "")
        try:
            if op not in OPS:
                raise ValueError(f"모르는 바꾸기: {op!r}")
            if op == "drop":
                fid = str(ed.get("flow") or "")
                hit = [f for f in doc.d["flows"] if f.get("id") == fid]
                if not hit:
                    raise ValueError(f"원하는 구조에 없는 통신: {fid}")
                doc.d["flows"] = [f for f in doc.d["flows"] if f.get("id") != fid]
                names = {x["id"]: x.get("label") or x["id"] for x in doc.d["tiers"] + doc.d["external"]}
                done.append(f"원하는 구조에서 뺌: {names.get(hit[0]['from'], hit[0]['from'])} → {names.get(hit[0]['to'], hit[0]['to'])} {_port_txt(hit[0])}")
                continue
            if op == "gone":
                tids = doc.node_tiers(str(ed.get("node")))
                before = len(doc.d["flows"])
                doc.d["flows"] = [f for f in doc.d["flows"] if f.get("to") not in tids]
                done.append(f"{nm(ed.get('node'))} 로 들어오는 통신을 모두 뺌 ({before - len(doc.d['flows'])}개)")
                continue
            if op == "add":
                rng = parse_port(ed.get("port"), ed.get("protocol"))
                dsts = doc.node_tiers(str(ed.get("to")))
                if ed.get("cidr"):
                    cidr = str(ed["cidr"]).strip()
                    srcs = [doc.ext(["0.0.0.0/0"], "사용자(인터넷)")] if cidr == "0.0.0.0/0" else [doc.ext([parse_cidr(cidr)], str(ed.get("label") or "").strip()[:40])]
                    stext = str(ed.get("label") or cidr)
                else:
                    srcs = doc.node_tiers(str(ed.get("from")))
                    stext = nm(ed.get("from"))
                if set(srcs) & set(dsts):
                    raise ValueError("출발과 도착이 같은 보안 그룹 — 통신 구조로 구분할 수 없음")
                doc.add(srcs, dsts, [rng])
                done.append(f"통신 추가: {stext} → {nm(ed.get('to'))} {_port_txt(_flow('', '', rng))}")
                continue
            es = [doc.edge(str(x)) for x in (ed.get("edges") or [])]
            if not es:
                raise ValueError("바꿀 선이 없음")
            only = [parse_port(*_split_port(x)) for x in (ed.get("only") or [])]
            for e in es:
                dsts = doc.dst_ids(e)
                rngs = [tuple(r) for r in e.get("port_ranges") or []]
                if only:            # 선 하나에 포트가 여럿이면 고른 포트만 (예: 22 · 80 중 22 만 좁히기)
                    rngs = [r for r in rngs if any(_overlap(r, o) for o in only)]
                    if not rngs:
                        continue
                label = f"{nm(e['src'])} → {nm(e['dst'])} :{codetopo._merge_ports(rngs)}"
                if op == "block":
                    srcs, why = doc.src_ids(e, create=False)
                    n = doc.remove(srcs, dsts, rngs) if srcs else 0
                    done.append(f"막기: {label}" + ("" if n else " (원하는 구조에 원래 없음 — 그대로 막을 예정)"))
                elif op == "keep":
                    srcs, why = doc.src_ids(e)
                    if not srcs:
                        raise ValueError(why)
                    doc.add(srcs, dsts, rngs)
                    done.append(f"그대로 둠: {label}")
                elif op == "port":
                    srcs, why = doc.src_ids(e)
                    if not srcs:
                        raise ValueError(why)
                    rng = parse_port(ed.get("port"), ed.get("protocol") or (rngs[0][0] if rngs else "tcp"))
                    doc.remove(srcs, dsts, rngs)
                    doc.add(srcs, dsts, [rng])
                    done.append(f"포트 바꾸기: {label} → {_port_txt(_flow('', '', rng))}")
                elif op == "narrow":
                    old, _why = doc.src_ids(e, create=False)
                    if ed.get("cidr"):
                        cidr = parse_cidr(ed.get("cidr"))
                        new = [doc.ext([cidr], str(ed.get("label") or "").strip()[:40] or cidr)]
                        ntext = str(ed.get("label") or cidr)
                    elif ed.get("via"):
                        new = doc.node_tiers(str(ed.get("via")))
                        ntext = nm(ed.get("via"))
                    else:
                        raise ValueError("좁힐 출발지(IP 대역 또는 상자)를 고르세요")
                    if set(new) & set(dsts):
                        raise ValueError("출발지와 도착이 같은 보안 그룹")
                    if old:
                        doc.remove(old, dsts, rngs)
                    doc.add(new, dsts, rngs)
                    done.append(f"출발지 좁히기: {label} → 출발지 {ntext}")
        except (ValueError, TypeError) as ex:
            errs.append(f"{i}번째 바꾸기 ({op or '?'}): {ex}")
    if errs:
        return {"ok": False, "errors": errs, "done": done}
    return {"ok": True, "design": doc.finish(), "errors": [], "done": done}


# ----------------------------------------------------------------------------- 미리보기 · 저장
def _base(pid: str, base_version: Optional[int], cur: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]], bool, Dict[str, Any]]:
    """(설계도 세트, 기준 설계도, 자동 기준인가, 자동 기준 정보)."""
    from . import designs
    key, _c = design_key(pid)
    if key is None:
        a = auto_design(pid, cur)
        return None, (a.get("design") if a.get("ok") else None), True, a
    d = designs.load(key, base_version)
    return key, d, bool((d or {}).get("auto")), {}


def compare(pid: str, design: Dict[str, Any], cur: Dict[str, Any], auto: Optional[bool] = None) -> Dict[str, Any]:
    """이 설계도로 지금 코드를 보면 (V6 오라클 그대로) + 설계도만 그린 그림(view) + 통신 목록(rows, ③ 6차)."""
    from ..topology_intent import parse_topology_intent
    from ..verify.v6 import v6_intent_oracle
    from . import designs
    errs = designs.validate(design)
    if errs:
        return {"ok": False, "errors": errs}
    lr = v6_intent_oracle(cur["plan"], cur["sources"], parse_topology_intent(design))
    det = lr.details if isinstance(lr.details, dict) else {}
    topo = {k: det.get(k) for k in ("flows", "excess", "tiers", "notes", "undesigned")}
    ov = archmap.overlay(cur["arch"], topo, design)
    rws = rows(cur["arch"], ov, bool(design.get("auto")) if auto is None else auto, design)
    return {"ok": True, "verdict": lr.verdict.value, "summary": lr.summary, "topology": topo, "overlay": ov, "counts": counts(topo),
            "view": archmap.design_view(cur["arch"], design), "rows": rws, "diff": len([r for r in rws if r["fix"]])}


# ----------------------------------------------------------------------------- ③ 통신 목록 (2026-11-01 6차 · D-34 — B: "너무 어려움")
def risk_reason(src: str, rng: Any) -> str:
    """자동 기준이 막는 이유 (codetopo._draft_risks 와 같은 기준 — 인터넷 전체 → 관리 · 고위험 · 모든 포트). 해당 없으면 ''."""
    from ..verify.sg_scan import EC2_19_PORTS, MGMT_PORTS
    if src != "x:internet" or not rng or len(rng) != 3:
        return ""
    p, lo, hi = str(rng[0]), int(rng[1]), int(rng[2])
    if p == "-1" or (lo <= 0 and hi >= 65535):
        return "인터넷 전체에 모든 포트가 열림"
    mg = [f"{n}({q})" for q, n in MGMT_PORTS.items() if lo <= q <= hi]
    if mg:
        return f"인터넷 전체 → 관리 포트 {', '.join(mg)}"
    hr = [f"{n}({q})" for q, n in EC2_19_PORTS.items() if lo <= q <= hi and q not in MGMT_PORTS]
    if hr:
        return f"인터넷 전체 → 고위험 포트 {', '.join(hr[:3])}{' 외' if len(hr) > 3 else ''}"
    return ""


def rows(arch: Dict[str, Any], ov: Optional[Dict[str, Any]], auto: bool = False, design: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """③ 통신 목록 — 한 줄 = 출발 → 도착 : 포트 하나. 판정은 만들지 않는다 (허용 여부 = V6 결과를 옮긴 overlay 그대로).
      ① 지금 코드의 보안 그룹 허용 (선 하나의 포트마다): allow = 설계도에 있음. 코드에 있는데 설계도에 없으면 fix (코드에서 막을 대상)
      ② 설계도에만 있는 통신 (코드에 허용 규칙이 없거나 출발지가 코드와 다름): allow = True.
         코드가 막고 있으면(missing) fix (코드에 열 대상). 코드가 더 넓게 허용 중이면(desired) 그 넓은 줄이 ①에서 fix
    줄마다 화면이 보낼 바꾸기(ops)에 쓰는 값(edge · only · flow)을 같이 준다."""
    nodes = {n["id"]: n for n in arch.get("nodes") or []}
    gn = {g["id"]: g for g in (ov or {}).get("ghost_nodes") or []}
    # 외부 출처 이름은 설계도의 이름으로 (설계도 그림과 같게 — 예: '사용자(인터넷)', '관리자 접속 허용 목록')
    dlab = {tuple(sorted(x.get("cidrs_v4") or [])): x.get("label") for x in (design or {}).get("external") or [] if x.get("label")}
    elab = {i: dlab[tuple(sorted(n.get("cidrs") or []))] for i, n in nodes.items()
            if n.get("cat") == "external" and tuple(sorted(n.get("cidrs") or [])) in dlab}
    nm = lambda i: elab.get(i) or (nodes.get(i) or gn.get(i) or {}).get("label") or str(i)  # noqa: E731
    oe = (ov or {}).get("edges") or {}
    known = bool((ov or {}).get("computed"))
    out: List[Dict[str, Any]] = []
    # 같은 출발 → 같은 보안 그룹(설계도의 구성요소 하나)으로 가는 선은 한 줄로 (예: web → primary · replica :3306 — 규칙 하나)
    groups: Dict[Tuple[str, Tuple[str, ...], str], Dict[str, Any]] = {}
    for e in arch.get("edges") or []:
        if e["kind"] != "sg":
            continue
        s = str(e["src"])
        st = oe.get(e["id"]) or {}
        exr = [tuple(r) for r in st.get("ranges") or []] if st.get("state") == "excess" else []
        dkey = tuple(e.get("dst_sgs") or []) or (str(e["dst"]),)
        for it in e.get("port_items") or []:
            rng = tuple(it.get("range") or ())
            allow = (not any(_overlap(rng, x) for x in exr)) if known and len(rng) == 3 else None
            g = groups.setdefault((s, dkey, it["text"]), {"s": s, "it": it, "rng": rng, "edges": [], "dsts": [], "allow": [], "risk": False})
            g["edges"].append(e["id"])
            g["dsts"].append(str(e["dst"]))
            g["allow"].append(allow)
            g["risk"] = g["risk"] or bool(it.get("risk"))
    for g in groups.values():
        s, it, rng = g["s"], g["it"], g["rng"]
        allow = None if None in g["allow"] else all(g["allow"])
        kind = "vpc" if s.startswith("x:vpc:") else "ip" if s == "x:internet" or s.startswith("x:cidr:") else "node" if not s.startswith("x:") else "other"
        why_not = {"vpc": "VPC 안 모든 서버는 어느 서버인지 몰라 설계도에 넣을 수 없음 — '이 서버만 허용' 으로 고르기",
                   "other": "출처를 확정할 수 없어(IPv6 · plan 밖 보안 그룹 · prefix list) 설계도에 넣을 수 없음"}.get(kind, "")
        why = risk_reason(s, rng) if allow is False else ""
        note = ((f"위험해서 자동으로 막음 — {why}" if auto else f"설계도에 없음 — 위험한 허용 ({why})") if why else
                "막음 — 어느 서버인지 모르는 출처" if allow is False and kind == "vpc" else
                "설계도에 없음 → 코드에서 막을 대상" if allow is False else "")
        dsts = list(dict.fromkeys(g["dsts"]))
        out.append({"key": f"{g['edges'][0]}|{it['text']}", "src": nm(s), "dst": " · ".join(nm(d) for d in dsts), "port": it["text"], "allow": allow,
                    "code": True, "fix": allow is False, "edge": g["edges"][0], "edges": g["edges"], "only": [it["text"]], "kind": kind,
                    "can_allow": kind in ("ip", "node"), "why_not": why_not, "note": note, "risk": g["risk"], "src_node": s, "dst_node": dsts[0]})
    by_flow: Dict[str, List[Dict[str, Any]]] = {}
    for g in (ov or {}).get("ghost_edges") or []:
        if g.get("flow"):
            by_flow.setdefault(g["flow"], []).append(g)
    for fid, gs in by_flow.items():
        st = gs[0].get("state")
        srcs = list(dict.fromkeys(nm(g["src"]) for g in gs))
        dsts = list(dict.fromkeys(nm(g["dst"]) for g in gs))
        note = {"missing": "코드에 허용 규칙이 없음 (지금은 막힘) → 코드에서 열 대상",
                "desired": "코드에는 이 출발지만 허용하는 규칙이 없음 (지금은 더 넓게 허용 중)",
                "unknown": "판정 불가 (출처 미확정)"}.get(str(st), "")
        out.append({"key": f"flow|{fid}", "src": " · ".join(srcs), "dst": " · ".join(dsts), "port": str(gs[0].get("ports") or ""), "allow": True,
                    "code": st == "desired", "fix": st == "missing", "flow": fid, "kind": "design", "can_allow": True, "why_not": "", "note": note,
                    "risk": False, "src_node": gs[0]["src"], "dst_node": gs[0]["dst"]})

    def pkey(p: str) -> Tuple[int, str]:
        m = re.match(r"\D*(\d+)", str(p or ""))
        return (int(m.group(1)) if m else 99999, str(p or ""))
    out.sort(key=lambda r: (r["dst"], r["src"], pkey(r["port"])))
    return out


def counts(topo: Dict[str, Any]) -> Dict[str, int]:
    t = topo or {}
    return {"excess": len([x for x in t.get("excess") or [] if x.get("kind") != "undesigned_target"]),
            "missing": len([f for f in t.get("flows") or [] if f.get("status") == "broken"]),
            "unknown": len([f for f in t.get("flows") or [] if f.get("status") == "unknown"]),
            "undesigned": len([u for u in t.get("undesigned") or [] if u.get("inbound")]),
            "ok": len([f for f in t.get("flows") or [] if f.get("status") == "ok"])}


def preview(pid: str, edits: List[Dict[str, Any]], base_version: Optional[int] = None) -> Dict[str, Any]:
    from . import designs
    cur = code(pid)
    if not cur.get("ok"):
        return {"ok": False, "errors": [cur.get("reason") or "지금 코드를 읽지 못함"]}
    _key, base, auto, a = _base(pid, base_version, cur)
    if base is None:
        return {"ok": False, "errors": [a.get("reason") or "기준 설계도 없음"]}
    r = apply_edits(base, cur["arch"], edits or [])
    if not r["ok"]:
        return {"ok": False, "errors": r["errors"], "done": r["done"]}
    cmp = compare(pid, r["design"], cur, auto=bool(auto and not edits))
    if not cmp.get("ok"):
        return {"ok": False, "errors": cmp.get("errors"), "done": r["done"]}
    return {"ok": True, "design": r["design"], "done": r["done"], "changes": designs.diff(base, r["design"]), "base_auto": auto, **cmp}


def save(pid: str, edits: List[Dict[str, Any]], note: str = "", base_version: Optional[int] = None) -> Dict[str, Any]:
    from . import designs
    if not edits:
        return {"ok": False, "errors": ["바꾼 것이 없음"]}
    cur = code(pid)
    if not cur.get("ok"):
        return {"ok": False, "errors": [cur.get("reason") or "지금 코드를 읽지 못함"]}
    key, _c = design_key(pid)
    created = None
    if key is None:                       # 설계도가 아직 없으면: 자동 기준 v1 을 먼저 남기고 그 위에 바꾼 것 (v2)
        created = ensure_auto(pid)
        key, _c = design_key(pid)
        if key is None:
            # 자동 기준을 만들 수 없는 코드(위험한 통신만 있음) → 바꾼 것만으로 처음 확정 (v1)
            a = auto_design(pid, cur)
            if not a.get("ok"):
                return {"ok": False, "errors": [a.get("reason") or created.get("reason") or "설계도 만들기 실패"]}
            r = apply_edits(a["design"], cur["arch"], edits)
            if not r["ok"]:
                return {"ok": False, "errors": r["errors"]}
            c = cur["case"]
            res = designs.create_first(pid, r["design"], note=str(note or "").strip() or "그림에서 정함", target_dir=c.get("tf_dir", ""),
                                       meta={"edits": {"by": "그림에서 바꾸기 (사람)", "done": r["done"]}})
            return {**res, "done": r["done"]}
        base_version = 1
    base = designs.load(key, base_version)
    if base is None:
        return {"ok": False, "errors": [f"기준 설계도 v{base_version} 없음"]}
    r = apply_edits(base, cur["arch"], edits)
    if not r["ok"]:
        return {"ok": False, "errors": r["errors"]}
    res = designs.save(key, r["design"], note=note, base_version=base_version or designs.active_version(key),
                       meta={"edits": {"by": "그림에서 바꾸기 (사람)", "done": r["done"]}})
    return {**res, "done": r["done"], "auto_created": bool(created and created.get("created"))}
