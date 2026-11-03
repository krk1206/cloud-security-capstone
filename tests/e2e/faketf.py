"""가짜 terraform — 화면 테스트 전용 (실제 AWS 에 닿지 않는다).

시험 환경 폴더(webapp-3tier-testbed)에서 plan / show / apply 만 흉내 낸다. 그 밖의 명령·폴더는 진짜 tofu 로 넘긴다.
- plan [-destroy] -out=F : 상태 파일과 설정(.tf)을 비교해 plan JSON 을 만든다.
    상태가 비었으면 전부 create, -destroy 면 전부 delete,
    배포가 있으면 security_groups.tf 의 보안 그룹 블록을 '배포된 파일'과 비교해
    description/name 이 바뀌면 replace (replace_paths), 규칙만 바뀌면 update.
- show -json F : plan JSON 출력
- apply F : 상태 번호(serial)가 plan 때와 다르면 'Saved plan is stale' 로 거절. 아니면 줄 단위로 진행을 찍고 상태 파일을 바꾼다.
- destroy : 앱이 부르면 안 된다 → 실패로 끝낸다 (앱은 plan -destroy + apply <plan> 만 써야 한다).
"""
import hashlib
import json
import os
import re
import sys
import time

REAL = "/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/bin/tofu"
args = sys.argv[1:]
cwd = os.getcwd()
# 시나리오 '실행 오류' (E2E 가 bin/TF_FAIL 파일을 만들면): provider 를 못 받은 것처럼 init · plan · validate 가 실패한다 → 검사 계층 ERROR → AI 에게 다시 묻지 않음
if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "TF_FAIL")) and args and args[0] in ("init", "plan", "validate"):
    sys.stderr.write("Error: Failed to query available provider packages (시험용 실행 오류 — 네트워크 · provider 캐시 없음)\n")
    sys.exit(1)
if os.path.basename(cwd) != "webapp-3tier-testbed" or not args or args[0] not in ("plan", "show", "apply", "destroy"):
    os.execv(REAL, [REAL] + args)

CALLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "faketf_calls.jsonl")
with open(CALLS, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"at": time.time(), "argv": args, "cwd": cwd, "AWS_PROFILE": os.environ.get("AWS_PROFILE"),
                         "TF_IN_AUTOMATION": os.environ.get("TF_IN_AUTOMATION")}) + "\n")

STATE = os.path.join(cwd, "terraform.tfstate")
SGF = os.path.join(cwd, "security_groups.tf")
DELAY = float(os.environ.get("FAKETF_DELAY", "0.06"))


def out(s=""):
    print(s, flush=True)


def load_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"version": 4, "serial": 0, "lineage": "fake-e2e", "resources": []}


def blocks(text, kind="resource"):
    """resource "T" "N" { ... } 블록들 → [(T, N, body)]"""
    res = []
    for m in re.finditer(r'^%s\s+"([\w-]+)"\s+"([\w-]+)"\s*\{' % kind, text, re.M):
        i, depth = m.end(), 1
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        res.append((m.group(1), m.group(2), text[m.end():i - 1]))
    return res


def top_attrs(body):
    attrs, nested, depth = {}, {"ingress": [], "egress": []}, 0
    cur, buf = None, []
    for line in body.splitlines():
        s = line.strip()
        if depth == 0:
            m = re.match(r"(ingress|egress)\s*\{", s)
            if m:
                cur, buf, depth = m.group(1), [], 1
                continue
            m = re.match(r"(\w+)\s*=\s*(.+)$", s)
            if m:
                attrs[m.group(1)] = m.group(2).strip()
            depth += s.count("{") - s.count("}")
        else:
            depth += s.count("{") - s.count("}")
            if depth == 0:
                if cur is not None:
                    nested[cur].append(" ".join(" ".join(buf).split()))
                cur = None
            elif cur is not None:
                buf.append(s)
    return attrs, nested


def config_resources():
    res = []
    for fn in sorted(os.listdir(cwd)):
        if not fn.endswith(".tf"):
            continue
        with open(os.path.join(cwd, fn), encoding="utf-8") as fh:
            t = fh.read()
        for typ, name, body in blocks(t):
            m = re.search(r"^\s*count\s*=\s*(\d+)", body, re.M)
            res.append({"mode": "managed", "type": typ, "name": name, "count": int(m.group(1)) if m else None})
        for typ, name, body in blocks(t, "data"):
            res.append({"mode": "data", "type": typ, "name": name, "count": None})
    return res


def addresses(r):
    base = ("data." if r["mode"] == "data" else "") + f'{r["type"]}.{r["name"]}'
    return [f"{base}[{i}]" for i in range(r["count"])] if r.get("count") else [base]


def rc(addr, typ, acts, before=None, after=None, rp=None):
    d = {"address": addr, "mode": "managed", "type": typ, "name": addr.split(".")[1].split("[")[0],
         "change": {"actions": acts, "before": before, "after": after, "after_unknown": {}}}
    if rp:
        d["change"]["replace_paths"] = rp
        d["action_reason"] = "replace_because_cannot_update"
    return d


def sg_view(body):
    a, n = top_attrs(body)
    return {"name": a.get("name"), "description": (a.get("description") or "").strip('"'), "ingress": n["ingress"], "egress": n["egress"]}


def make_plan(destroy):
    st = load_state()
    managed = [r for r in st.get("resources") or [] if r.get("mode") == "managed"]
    changes, mode = [], ""
    with open(SGF, encoding="utf-8") as fh:
        sg_text = fh.read()
    if destroy:
        mode = "destroy"
        for r in managed:
            for a in addresses({"mode": "managed", "type": r["type"], "name": r["name"], "count": len(r.get("instances") or []) if len(r.get("instances") or []) > 1 else None}):
                changes.append(rc(a, r["type"], ["delete"], before={"id": "x"}, after=None))
    elif not managed:
        mode = "create"
        for r in config_resources():
            if r["mode"] != "managed":
                continue
            for a in addresses(r):
                changes.append(rc(a, r["type"], ["create"], before=None, after={"tags": {"Name": a}}))
    else:
        mode = "update"
        old = {n: sg_view(b) for t, n, b in blocks(st.get("fake_sg_text") or "") if t == "aws_security_group"}
        new = {n: sg_view(b) for t, n, b in blocks(sg_text) if t == "aws_security_group"}
        for n in sorted(set(old) | set(new)):
            addr = f"aws_security_group.{n}"
            if n not in new:
                changes.append(rc(addr, "aws_security_group", ["delete"], before=old[n], after=None))
            elif n not in old:
                changes.append(rc(addr, "aws_security_group", ["create"], before=None, after=new[n]))
            elif old[n] != new[n]:
                rp = [[k] for k in ("description", "name") if old[n][k] != new[n][k]]
                changes.append(rc(addr, "aws_security_group", ["delete", "create"] if rp else ["update"], before=old[n], after=new[n], rp=rp or None))
            else:
                changes.append(rc(addr, "aws_security_group", ["no-op"], before=old[n], after=new[n]))
    plan = {"format_version": "1.2", "terraform_version": "fake-1.9.0", "resource_changes": changes}
    return st, mode, sg_text, plan


cmd = args[0]
if cmd == "destroy":
    out("faketf: 'terraform destroy' 는 앱이 부르면 안 된다 (plan -destroy + apply <plan 파일> 만 허용)")
    sys.exit(2)

if cmd == "plan":
    outf = [a[5:] for a in args if a.startswith("-out=")]
    st, mode, sg_text, plan = make_plan("-destroy" in args)
    time.sleep(DELAY * 5)
    n = {k: sum(1 for c in plan["resource_changes"] if c["change"]["actions"] == v) for k, v in (("add", ["create"]), ("change", ["update"]), ("destroy", ["delete"]))}
    rep = sum(1 for c in plan["resource_changes"] if len(c["change"]["actions"]) == 2)
    for c in plan["resource_changes"]:
        if c["change"]["actions"] != ["no-op"]:
            out(f'  # {c["address"]} will be {"/".join(c["change"]["actions"])}')
    out(f'Plan: {n["add"] + rep} to add, {n["change"]} to change, {n["destroy"] + rep} to destroy.')
    if outf:
        with open(outf[0], "w", encoding="utf-8") as fh:
            json.dump({"fake_plan": True, "serial": st.get("serial"), "lineage": st.get("lineage"), "mode": mode, "sg_text": sg_text,
                       "config": config_resources(), "plan": plan}, fh)
        out(f"Saved the plan to: {outf[0]}")
    sys.exit(0)

if cmd == "show":
    with open(args[-1], encoding="utf-8") as fh:
        p = json.load(fh)
    print(json.dumps(p["plan"]))
    sys.exit(0)

if cmd == "apply":
    pf = args[-1]
    if not os.path.isfile(pf):
        out("faketf: apply 는 plan 파일로만 (이 테스트에서 plan 없는 apply 는 실패로 친다)")
        sys.exit(2)
    with open(pf, encoding="utf-8") as fh:
        p = json.load(fh)
    st = load_state()
    if (st.get("serial"), st.get("lineage")) != (p["serial"], p["lineage"]):
        out("╷\n│ Error: Saved plan is stale\n│\n│ The given plan file can no longer be applied because the state was changed by another operation after the plan was created.\n╵")
        sys.exit(1)
    added = changed = destroyed = 0
    for c in p["plan"]["resource_changes"]:
        acts = c["change"]["actions"]
        if acts == ["no-op"]:
            continue
        verb = {"create": ("Creating...", "Creation complete after 1s [id=%s]"), "update": ("Modifying... [id=%s]", "Modifications complete after 1s [id=%s]"),
                "delete": ("Destroying... [id=%s]", "Destruction complete after 1s")}
        rid = "sg-0" + hashlib.sha1(c["address"].encode()).hexdigest()[:16] if c["type"] == "aws_security_group" else "id-" + hashlib.sha1(c["address"].encode()).hexdigest()[:8]
        seq = ["delete", "create"] if len(acts) == 2 else acts
        for a in seq:
            s1, s2 = verb[a]
            out(f'{c["address"]}: {s1 % rid if "%s" in s1 else s1}')
            time.sleep(DELAY)
            out(f'{c["address"]}: {s2 % rid if "%s" in s2 else s2}')
        if len(acts) == 2:
            added += 1; destroyed += 1
        elif acts == ["create"]:
            added += 1
        elif acts == ["update"]:
            changed += 1
        elif acts == ["delete"]:
            destroyed += 1
    if p["mode"] == "destroy":
        res, sgt = [], ""
    elif p["mode"] == "create":
        res = [{"mode": r["mode"], "type": r["type"], "name": r["name"], "instances": [{}] * (r["count"] or 1)} for r in p["config"]]
        sgt = p["sg_text"]
    else:
        res, sgt = st.get("resources") or [], p["sg_text"]
    new = {"version": 4, "terraform_version": "fake-1.9.0", "serial": int(st.get("serial") or 0) + 1, "lineage": st.get("lineage") or "fake-e2e",
           "resources": res, "fake_sg_text": sgt}
    with open(STATE + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(new, fh)
    os.replace(STATE + ".tmp", STATE)
    out("")
    out(f"Apply complete! Resources: {added} added, {changed} changed, {destroyed} destroyed.")
    if p["mode"] != "destroy":
        out("\nOutputs:\n")
        out('alb_dns_name = "capstone-alb-1234567890.ap-northeast-2.elb.amazonaws.com"')
        out('caller_arn = "arn:aws:iam::123456789012:user/fake-e2e"')
        out('bastion_public_ip = "54.180.12.34"')
    sys.exit(0)
