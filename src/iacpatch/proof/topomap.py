"""설계도 ↔ Terraform 코드 대응표.

설계도의 상자(계층)와 화살표(통신)가 Terraform 어느 파일 몇 번째 줄로 만들어지는지 코드에서 직접 읽어 만든다.
  상자  : 계층 보안 그룹 → 그 보안 그룹을 붙인 리소스 → 그 리소스가 놓인 서브넷 → 서브넷의 기본 경로(인터넷 게이트웨이/NAT)
  화살표: 받는 쪽 보안 그룹의 ingress 블록 중 포트가 맞고 출처가 보내는 쪽(보안 그룹 참조 또는 IP 대역)인 블록
  IAM   : 역할 → 정책 → 인스턴스 프로파일 → 시작 템플릿

읽는 방법: .tf 텍스트를 줄 단위로 읽어 리소스 블록·속성·참조(aws_xxx.이름)를 모은다 (hcl_lines 와 같은 방식, 완전한 HCL 파서 아님).
이 표는 판정이 아니다. 열림·막힘 판정은 V6(실행 계획으로 계산)이 한다. 둘을 같이 보여 주는 이유는
'판정에 쓰인 규칙이 코드 어디에 있나' 를 사람이 직접 따라가 보게 하려는 것.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

from . import hcl_lines

_REF = re.compile(r"\b((?:data\.)?aws_[a-z0-9_]+)\.([A-Za-z_][\w-]*)(\[[^\]]*\])?")
_VAR = re.compile(r"\bvar\.([A-Za-z_]\w*)")
_BLOCK_OPEN = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*(?:"[^"]*"\s*)*\{\s*$')
_ATTR = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.*)$")

SG_ATTACH = ("vpc_security_group_ids", "security_groups", "security_group_ids")
PLACEMENT = ("subnet_id", "subnets", "vpc_zone_identifier", "subnet_ids")
GROUP_PLACEMENT = ("db_subnet_group_name", "subnet_group_name")
EXPOSURE = ("associate_public_ip_address", "internal", "publicly_accessible", "map_public_ip_on_launch")

OUTSIDE_NOTE = {
    "aws_route53_zone": "도메인", "aws_route53_record": "도메인 레코드", "aws_acm_certificate": "인증서",
    "aws_acm_certificate_validation": "인증서 검증", "aws_cloudfront_distribution": "CloudFront", "aws_wafv2_web_acl": "WAF",
    "aws_wafv2_web_acl_association": "WAF 연결", "aws_s3_bucket": "S3 버킷", "aws_s3_bucket_public_access_block": "S3 공개 차단",
    "aws_s3_bucket_server_side_encryption_configuration": "S3 암호화", "aws_s3_bucket_versioning": "S3 버전 관리",
    "aws_cloudwatch_log_group": "로그 보관", "aws_cloudwatch_metric_alarm": "경보", "aws_eip": "고정 IP (NAT 용)",
    "aws_nat_gateway": "NAT 게이트웨이", "aws_lb_target_group": "대상 그룹", "aws_lb_listener": "리스너",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------- 읽기
def parse_sources(sources: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    """파일 이름 → 내용 에서 리소스 목록. addr → {type, name, file, start, end, count, attrs[]}.
    attrs: {path(블록.속성), line, text, refs[], vars[]}"""
    out: Dict[str, Dict[str, Any]] = {}
    for fname, text in sorted(sources.items()):
        lines = text.replace("\r", "").split("\n")
        struct = hcl_lines._structure(lines)
        for addr, (s, e) in hcl_lines.resource_blocks(text).items():
            if addr.startswith("data."):
                continue
            rtype, rname = addr.split(".", 1)
            attrs: List[Dict[str, Any]] = []
            stack: List[Tuple[str, int]] = []      # (블록 이름, 열 때 깊이)
            depth = 0
            last_attr: Optional[Dict[str, Any]] = None
            count = None
            for n in range(s, e + 1):
                raw = lines[n - 1]
                st = struct[n - 1]
                if n == s:
                    depth += st.count("{") - st.count("}")
                    continue
                opens, closes = st.count("{"), st.count("}")
                mb = _BLOCK_OPEN.match(st)
                ma = _ATTR.match(st) if not mb else None
                names = [b for b, _ in stack]
                if mb:
                    stack.append((mb.group(1), depth))
                    last_attr = None
                elif ma and st.strip():
                    path = ".".join(names + [ma.group(1)])
                    last_attr = {"path": path, "line": n, "text": raw.strip(), "refs": [], "vars": []}
                    attrs.append(last_attr)
                    if path == "count":
                        count = ma.group(2).strip()
                if st.strip() or raw.strip():
                    code = raw if st.strip() else ""
                    if code and last_attr is not None:
                        for m in _REF.finditer(code):
                            ref = f"{m.group(1)}.{m.group(2)}"
                            if ref != addr and ref not in last_attr["refs"]:
                                last_attr["refs"].append(ref)
                        for m in _VAR.finditer(code):
                            if m.group(1) not in last_attr["vars"]:
                                last_attr["vars"].append(m.group(1))
                depth += opens - closes
                while stack and depth <= stack[-1][1]:
                    stack.pop()
            out[addr] = {"addr": addr, "type": rtype, "name": rname, "file": fname, "start": s, "end": e, "count": count, "attrs": attrs}
    return out


def _attr(r: Dict[str, Any], *paths: str) -> List[Dict[str, Any]]:
    return [a for a in r["attrs"] if a["path"] in paths]


def _loc(r: Dict[str, Any], a: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"addr": r["addr"], "file": r["file"], "line": a["line"] if a else r["start"], "start": r["start"], "end": r["end"],
            "text": a["text"] if a else ""}


# ----------------------------------------------------------------------------- 네트워크
def _subnet_kinds(res: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """aws_subnet.X → {kind: public|private|?, route: 근거}"""
    rt_kind: Dict[str, Dict[str, Any]] = {}
    for r in res.values():
        if r["type"] != "aws_route_table":
            continue
        for a in r["attrs"]:
            if a["path"] == "route.gateway_id" and any(x.startswith("aws_internet_gateway.") for x in a["refs"]):
                rt_kind[r["addr"]] = {"kind": "public", "via": _loc(r, a), "word": "0.0.0.0/0 → 인터넷 게이트웨이 (인바운드·아웃바운드 경로)"}
            elif a["path"] == "route.nat_gateway_id":
                rt_kind.setdefault(r["addr"], {"kind": "private", "via": _loc(r, a), "word": "0.0.0.0/0 → NAT (아웃바운드만, 인바운드 경로 없음)"})
    out: Dict[str, Dict[str, Any]] = {}
    for r in res.values():
        if r["type"] != "aws_route_table_association":
            continue
        subs = [x for a in _attr(r, "subnet_id") for x in a["refs"] if x.startswith("aws_subnet.")]
        rts = [x for a in _attr(r, "route_table_id") for x in a["refs"] if x.startswith("aws_route_table.")]
        for sb in subs:
            for rt in rts:
                if rt in rt_kind:
                    k = dict(rt_kind[rt])
                    k["assoc"] = _loc(r, (_attr(r, "route_table_id") or [None])[0])
                    out[sb] = k
    for r in res.values():
        if r["type"] == "aws_subnet" and r["addr"] not in out:
            out[r["addr"]] = {"kind": "?", "via": None, "word": "코드에서 기본 경로 미확인"}
        if r["type"] == "aws_subnet":
            cidr = _attr(r, "cidr_block")
            out[r["addr"]]["cidr"] = cidr[0]["text"] if cidr else ""
            out[r["addr"]]["loc"] = _loc(r)
            out[r["addr"]]["count"] = r["count"]
    return out


def _placement(res: Dict[str, Dict[str, Any]], r: Dict[str, Any], subnets: Dict[str, Dict[str, Any]], seen: Optional[set] = None) -> List[Dict[str, Any]]:
    """리소스가 놓인 서브넷 경로. 직접(subnet_id 등) → 서브넷 그룹 경유 → 이 리소스를 쓰는 리소스(시작 템플릿 → 자동 확장 그룹)."""
    seen = seen or set()
    seen.add(r["addr"])
    hops: List[Dict[str, Any]] = []
    for a in _attr(r, *PLACEMENT):
        for x in a["refs"]:
            if x in subnets:
                hops.append({"how": a["path"], "from": _loc(r, a), "subnet": x, "kind": subnets[x]["kind"]})
    if hops:
        return hops
    for a in _attr(r, *GROUP_PLACEMENT):
        for x in a["refs"]:
            g = res.get(x)
            if not g:
                continue
            for b in _attr(g, "subnet_ids"):
                for y in b["refs"]:
                    if y in subnets:
                        hops.append({"how": f"{a['path']} → {g['addr']}.subnet_ids", "from": _loc(r, a), "via": _loc(g, b),
                                     "subnet": y, "kind": subnets[y]["kind"]})
    if hops:
        return hops
    for other in res.values():
        if other["addr"] in seen:
            continue
        uses = [a for a in other["attrs"] if r["addr"] in a["refs"] and a["path"] in ("launch_template.id", "launch_template.name")]
        if uses:
            for h in _placement(res, other, subnets, seen):
                h = dict(h)
                h["via_user"] = _loc(other, uses[0])
                hops.append(h)
    return hops


# ----------------------------------------------------------------------------- 보안 그룹 규칙
def _ingress_rules(text: str, sg: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for k, (s, e) in enumerate(hcl_lines.nested_blocks(text, sg["start"], sg["end"], "ingress")):
        body = text.replace("\r", "").split("\n")[s - 1:e]
        joined = "\n".join(body)

        def lit(name: str) -> str:
            m = re.search(r"^\s*" + name + r"\s*=\s*(.+?)\s*$", joined, re.M)
            return m.group(1).strip() if m else ""
        fp, tp, proto = lit("from_port"), lit("to_port"), lit("protocol").strip('"')
        cidrs = re.findall(r'"(\d+\.\d+\.\d+\.\d+/\d+)"', lit("cidr_blocks"))
        sgs = [f"{m.group(1)}.{m.group(2)}" for m in _REF.finditer(lit("security_groups"))]
        desc = lit("description").strip('"')
        try:
            lo, hi = int(fp), int(tp)
        except ValueError:
            lo = hi = None
        out.append({"index": k, "origin": f"{sg['addr']}#ingress[{k}]", "file": sg["file"], "start": s, "end": e,
                    "from_port": lo, "to_port": hi, "protocol": proto, "cidrs": cidrs, "sgs": sgs, "description": desc,
                    "lines": hcl_lines.excerpt(text, s, e)})
    return out


def _port_ok(rule: Dict[str, Any], port: int, proto: str) -> bool:
    if rule["protocol"] in ("-1", "all"):
        return True
    if rule["protocol"] != proto:
        return False
    if rule["from_port"] is None:
        return False
    if rule["from_port"] == 0 and rule["to_port"] == 0 and rule["protocol"] in ("-1",):
        return True
    return rule["from_port"] <= port <= rule["to_port"]


# ----------------------------------------------------------------------------- 대응표
def build_map(sources: Dict[str, str], intent: Dict[str, Any], target_dir: str = "") -> Dict[str, Any]:
    res = parse_sources(sources)
    subnets = _subnet_kinds(res)
    tiers_spec = intent.get("tiers") or []
    ext = {e["id"]: e for e in intent.get("external") or []}
    sg_of = {t["id"]: t["security_group"] for t in tiers_spec}
    label = {t["id"]: t["label"] for t in tiers_spec}
    label.update({e["id"]: e["label"] for e in ext.values()})

    attach: Dict[str, List[Dict[str, Any]]] = {}
    for r in res.values():
        if r["type"] == "aws_security_group":
            continue
        for a in _attr(r, *SG_ATTACH):
            for x in a["refs"]:
                if x.startswith("aws_security_group."):
                    attach.setdefault(x, []).append({"res": r, "attr": a})

    used: set = set()
    tiers: List[Dict[str, Any]] = []
    for t in tiers_spec:
        sga = t["security_group"]
        sg = res.get(sga)
        row: Dict[str, Any] = {"id": t["id"], "label": t["label"], "sg": _loc(sg) if sg else {"addr": sga, "file": "", "line": None},
                               "members": []}
        if sg:
            used.add(sga)
        for item in attach.get(sga, []):
            r, a = item["res"], item["attr"]
            used.add(r["addr"])
            pl = _placement(res, r, subnets)
            for h in pl:
                if h.get("via_user"):
                    used.add(h["via_user"]["addr"])
                if h.get("via"):
                    used.add(h["via"]["addr"])
            kinds = sorted({h["kind"] for h in pl})
            expo = [{"attr": x["path"], "text": x["text"], "line": x["line"], "file": r["file"]} for x in _attr(r, *EXPOSURE)]
            row["members"].append({"res": _loc(r), "type": r["type"], "count": r["count"], "attach": _loc(r, a), "placement": pl,
                                   "subnet_kind": kinds[0] if len(kinds) == 1 else ("/".join(kinds) if kinds else "?"), "exposure": expo})
        tiers.append(row)

    # 통신 → ingress 블록
    rules_by_sg: Dict[str, List[Dict[str, Any]]] = {}
    for t in tiers_spec:
        sg = res.get(t["security_group"])
        if sg:
            rules_by_sg[t["security_group"]] = _ingress_rules(sources.get(sg["file"], ""), sg)
    matched: set = set()
    flows: List[Dict[str, Any]] = []
    for f in intent.get("flows") or []:
        dst_sg = sg_of.get(f["to"])
        port, proto = int(f.get("port") or f.get("from_port") or 0), f.get("protocol", "tcp")
        hits = []
        for rule in rules_by_sg.get(dst_sg, []):
            if not _port_ok(rule, port, proto):
                continue
            if f["from"] in sg_of and sg_of[f["from"]] in rule["sgs"]:
                hits.append({"rule": rule, "source_code": sg_of[f["from"]], "source_design": label.get(f["from"])})
            elif f["from"] in ext and rule["cidrs"]:
                want = ext[f["from"]].get("cidrs_v4") or []
                hits.append({"rule": rule, "source_code": ", ".join(rule["cidrs"]), "source_design": ", ".join(want),
                             "same_text": sorted(rule["cidrs"]) == sorted(want)})
        for h in hits:
            matched.add(h["rule"]["origin"])
        flows.append({"id": f["id"], "from": f["from"], "to": f["to"], "from_label": label.get(f["from"]), "to_label": label.get(f["to"]),
                      "port": port, "protocol": proto, "label": f.get("label", ""),
                      "rules": [{"origin": h["rule"]["origin"], "file": h["rule"]["file"], "start": h["rule"]["start"], "end": h["rule"]["end"],
                                 "description": h["rule"]["description"], "source_code": h["source_code"], "source_design": h["source_design"],
                                 "same_text": h.get("same_text"), "lines": h["rule"]["lines"]} for h in hits]})
    unmatched = []
    sg_label = {v: label.get(k) for k, v in sg_of.items()}
    tier_by_sg = {v: k for k, v in sg_of.items()}
    for sga, rules in rules_by_sg.items():
        for rule in rules:
            if rule["origin"] in matched:
                continue
            src = ", ".join([sg_label.get(x) or x for x in rule["sgs"]] + rule["cidrs"]) or "?"
            unmatched.append({"origin": rule["origin"], "file": rule["file"], "start": rule["start"], "end": rule["end"],
                              "to": tier_by_sg.get(sga), "to_label": sg_label.get(sga), "source": src,
                              "ports": (str(rule["from_port"]) if rule["from_port"] == rule["to_port"] else f"{rule['from_port']}-{rule['to_port']}"),
                              "protocol": rule["protocol"], "description": rule["description"], "lines": rule["lines"]})

    # IAM: 역할 → 정책 / 인스턴스 프로파일 → 시작 템플릿
    iam = []
    for r in res.values():
        if r["type"] != "aws_iam_role":
            continue
        used.add(r["addr"])
        pols = [p for p in res.values() if p["type"] in ("aws_iam_role_policy", "aws_iam_role_policy_attachment")
                and any(r["addr"] in a["refs"] for a in _attr(p, "role"))]
        profs = [p for p in res.values() if p["type"] == "aws_iam_instance_profile" and any(r["addr"] in a["refs"] for a in _attr(p, "role"))]
        users = []
        for p in profs:
            used.add(p["addr"])
            for o in res.values():
                for a in o["attrs"]:
                    if p["addr"] in a["refs"] and a["path"].startswith("iam_instance_profile"):
                        users.append(_loc(o, a))
        for p in pols:
            used.add(p["addr"])
        tier_of_user = []
        for u in users:
            for t in tiers:
                if any(m["res"]["addr"] == u["addr"] for m in t["members"]):
                    tier_of_user.append(t["label"])
        iam.append({"role": _loc(r), "policies": [{"res": _loc(p), "actions": _policy_list(p, "Action"), "resources": _policy_list(p, "Resource"),
                                                     "lines": hcl_lines.excerpt(sources.get(p["file"], ""), p["start"], p["end"])} for p in pols],
                    "profiles": [_loc(p) for p in profs], "used_by": users, "tiers": sorted(set(tier_of_user))})

    # 네트워크 뼈대
    net = {"vpc": [_loc(r, (_attr(r, "cidr_block") or [None])[0]) for r in res.values() if r["type"] == "aws_vpc"],
           "igw": [_loc(r) for r in res.values() if r["type"] == "aws_internet_gateway"],
           "subnets": [{"addr": k, **v} for k, v in sorted(subnets.items())]}
    for r in res.values():
        if r["type"] in ("aws_vpc", "aws_internet_gateway", "aws_subnet", "aws_route_table", "aws_route_table_association"):
            used.add(r["addr"])

    outside = [{"addr": r["addr"], "type": r["type"], "file": r["file"], "line": r["start"], "what": OUTSIDE_NOTE.get(r["type"], "")}
               for r in res.values() if r["addr"] not in used]
    files = [{"name": n, "lines": len(t.replace("\r", "").split("\n")), "sha256": _sha(t),
              "resources": sum(1 for r in res.values() if r["file"] == n)} for n, t in sorted(sources.items())]
    return {"target_dir": target_dir, "files": files, "resources": len(res), "network": net, "tiers": tiers, "flows": flows,
            "rules_outside_design": unmatched, "iam": iam, "outside": outside,
            "note": "코드 기준 대응표 (판정 아님). 허용·차단 판정은 V6 에서 실행 계획 기준으로 계산."}


def _policy_list(p: Dict[str, Any], key: str) -> List[str]:
    vals: List[str] = []
    for a in p["attrs"]:
        if a["path"].split(".")[-1] == key:
            vals.extend(re.findall(r'"([^"]+)"', a["text"]))
    return vals
