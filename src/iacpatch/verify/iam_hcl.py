"""IAM 정책 문서를 Terraform 코드(HCL)에서 읽기 — plan 에 정책 값이 없을 때만 (15차, D-51).

왜: 팀 3계층(infrastructure/three-tier)처럼 권한 정책을 `data "aws_iam_policy_document"` 로 쓰고 Resource 가 버킷 ARN 을 참조하면
(`"${aws_s3_bucket.assets.arn}/*"`), 버킷 이름이 apply 때 정해져서(bucket_prefix) plan 의 policy 값이 비어 있다(unknown).
그러면 V6(IAM 요구사항 검사)는 '판정 불가' 밖에 낼 수 없다. 여기서는 그 data 블록의 statement 를 코드에서 읽고, 참조는
이름(토큰)으로 바꾼다:  "${aws_s3_bucket.assets.arn}/*" → "tf:aws_s3_bucket.assets.arn/*".
요구사항(intent)의 같은 참조도 같은 토큰으로 바꾸므로(iam_intent), '실제 버킷 이름은 모르지만 같은 리소스를 가리키는가' 를 비교할 수 있다.

믿는 범위 — 하나라도 벗어나면 (None, 이유) 를 돌려준다. 호출자(iam_oracle)는 그때 원래대로 UNKNOWN (PASS 로 만들지 않는다):
  - 루트 모듈의 정책 리소스(aws_iam_policy · aws_iam_role_policy …)의 policy 가 코드에 정확히 `data.aws_iam_policy_document.<이름>.json`
    (또는 minified_json) 이고, 그 data 블록이 코드 전체에 하나뿐일 때
  - statement 블록(정적)의 sid · effect · actions · not_actions · resources · not_resources. principals · not_principals ·
    condition 은 '있음' 으로만 표시한다 (오라클이 UNKNOWN 으로 처리)
  - 값: 글자("..."), 글자 목록, 글자 안의 보간 `${aws_<종류>.<이름>.arn|id|bucket}` (앞뒤 글자 포함), 따옴표 없는 참조 aws_x.y.arn
  - 그 밖: 변수 · locals · 함수 · for · 조건식 · 템플릿 지시자(%{) · heredoc · dynamic 블록 · count · for_each ·
    source/override_policy_documents · 모듈 · 인덱스([0]) → 모름
  - plan 의 configuration 에 있는 같은 data 블록과 대조한다: statement 수 · 글자 값(constant_value) · 참조한 리소스가 하나라도 다르면 모름
    (코드 읽기는 휴리스틱이라 plan 이 확인해 준 구조 안에서만 쓴다)
S3 만 하나 더: "arn:aws:s3:::${aws_s3_bucket.X.id}" 와 "...X.bucket}" 는 X 의 ARN 과 같다 (aws_s3_bucket 의 id · bucket = 버킷 이름,
ARN = "arn:aws:s3:::" + 이름, aws 파티션) → "tf:aws_s3_bucket.X.arn".

토큰은 'tf:' 로 시작한다. plan 에 값이 있는 정책(진짜 JSON)에 'tf:' 로 시작하는 글자가 있으면 오라클이 판정 불가로 둔다
(토큰을 흉내 내 승인 목록에 맞추는 것을 막는다). 코드의 글자 자체에 'tf:' 가 있어도 모름.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

TOKEN = "tf:"
DOC_TYPE = "aws_iam_policy_document"
JSON_ATTRS = ("json", "minified_json")
_REF_RE = re.compile(r"^(aws_[a-z0-9_]+)\.([A-Za-z0-9_-]+)\.(arn|id|bucket)$")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_S3_FIX_RE = re.compile(r"arn:aws:s3:::tf:(aws_s3_bucket\.[A-Za-z0-9_-]+)\.(?:id|bucket)")
_DISPLAY_RE = re.compile(r"tf:(aws_[a-z0-9_]+\.[A-Za-z0-9_-]+\.(?:arn|id|bucket))")
_STMT_KEYS = ("sid", "effect", "actions", "not_actions", "resources", "not_resources")
_STMT_BLOCKS = ("principals", "not_principals", "condition")
_DOC_ATTRS_OK = ("version", "policy_id")


class HclError(ValueError):
    """코드를 이 모듈이 믿는 범위 안에서 읽을 수 없음."""


def token(addr: str, attr: str) -> str:
    return f"{TOKEN}{addr}.{attr}"


def display(s: Any) -> str:
    """'tf:aws_s3_bucket.assets.arn/*' → '${aws_s3_bucket.assets.arn}/*' — 화면 · 메시지는 코드에 적힌 모양으로."""
    return _DISPLAY_RE.sub(lambda m: "${" + m.group(1) + "}", str(s))


def _s3_fix(s: str) -> str:
    return _S3_FIX_RE.sub(lambda m: f"{TOKEN}{m.group(1)}.arn", s)


def symbolize_pattern(s: str) -> str:
    """요구사항(intent)의 패턴: '${aws_s3_bucket.assets.arn}/*' → 'tf:aws_s3_bucket.assets.arn/*'. 다른 ${...} 는 그대로 둔다
    (그대로 남은 ${...} 는 후보의 어떤 값과도 같아지지 않는다 — 오라클은 그 승인 항목을 못 쓰는 것으로 본다)."""
    def rep(m: "re.Match[str]") -> str:
        inner = m.group(1).strip()
        return token(*inner.rsplit(".", 1)) if _REF_RE.match(inner) else m.group(0)
    return _s3_fix(re.sub(r"\$\{([^{}]*)\}", rep, str(s)))


# ----------------------------------------------------------------------------- 아주 작은 HCL 읽기 (블록 본문 · 식 원문)
def _skip_ws(t: str, i: int) -> int:
    """공백 · 줄바꿈 · 주석(#, //, /* */)을 건너뛴다."""
    n = len(t)
    while i < n:
        c = t[i]
        if c in " \t\r\n":
            i += 1
        elif c == "#" or t.startswith("//", i):
            j = t.find("\n", i)
            i = n if j < 0 else j + 1
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2)
            if j < 0:
                raise HclError("닫히지 않은 /* 주석")
            i = j + 2
        else:
            break
    return i


def _end_of_string(t: str, i: int) -> int:
    """t[i] == '"' 인 글자의 끝(닫는 따옴표 다음 위치). 보간 ${ ... } 안의 중괄호 · 글자도 따라간다."""
    n = len(t)
    j = i + 1
    while j < n:
        c = t[j]
        if c == "\\":
            j += 2
            continue
        if c == '"':
            return j + 1
        if c == "\n":
            raise HclError("한 줄 안에서 닫히지 않은 글자")
        if t.startswith("${", j) or t.startswith("%{", j):
            j = _end_of_balanced(t, j + 1, "{", "}")
            continue
        j += 1
    raise HclError("닫히지 않은 글자")


def _end_of_balanced(t: str, i: int, op: str, cl: str) -> int:
    """t[i] == op 인 괄호의 짝 다음 위치 (글자 · 주석 · 다른 괄호 고려)."""
    n = len(t)
    depth = 0
    j = i
    pairs = {"[": "]", "{": "}", "(": ")"}
    stack: List[str] = []
    while j < n:
        c = t[j]
        if c == '"':
            j = _end_of_string(t, j)
            continue
        if c == "#" or t.startswith("//", j) or t.startswith("/*", j):
            j = _skip_ws(t, j)
            continue
        if c in pairs:
            stack.append(pairs[c])
            depth += 1
        elif c in ")]}":
            if not stack or stack[-1] != c:
                raise HclError(f"괄호 짝이 맞지 않음 ({c})")
            stack.pop()
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    raise HclError(f"닫히지 않은 괄호 {op}")


def _end_of_expr(t: str, i: int) -> int:
    """속성 식의 끝: 괄호 밖에서 처음 만나는 줄바꿈(또는 본문 끝). heredoc 은 모름."""
    n = len(t)
    j = i
    while j < n:
        c = t[j]
        if c == "\n":
            return j
        if c == '"':
            j = _end_of_string(t, j)
            continue
        if t.startswith("<<", j):
            raise HclError("heredoc(<<) 식은 읽지 않음")
        if c == "#" or t.startswith("//", j):
            k = t.find("\n", j)
            return n if k < 0 else k
        if t.startswith("/*", j):
            k = t.find("*/", j + 2)
            if k < 0:
                raise HclError("닫히지 않은 /* 주석")
            j = k + 2
            continue
        if c in "[{(":
            j = _end_of_balanced(t, j, c, {"[": "]", "{": "}", "(": ")"}[c])
            continue
        j += 1
    return n


def _strip_comment_tail(expr: str) -> str:
    """식 원문 끝의 주석을 뗀다 (글자 안의 #, // 는 그대로)."""
    j = 0
    n = len(expr)
    while j < n:
        c = expr[j]
        if c == '"':
            j = _end_of_string(expr, j)
            continue
        if c == "#" or expr.startswith("//", j):
            return expr[:j].rstrip()
        j += 1
    return expr.strip()


def parse_body(body: str) -> Tuple[Dict[str, str], List[Tuple[str, Optional[str], str]]]:
    """블록 본문 → ({속성 이름: 식 원문}, [(블록 이름, 라벨 또는 None, 본문)]). 읽을 수 없는 모양이면 HclError."""
    attrs: Dict[str, str] = {}
    blocks: List[Tuple[str, Optional[str], str]] = []
    i, n = 0, len(body)
    while True:
        i = _skip_ws(body, i)
        if i >= n:
            break
        m = _IDENT_RE.match(body, i)
        if not m:
            raise HclError(f"읽을 수 없는 줄: {body[i:i + 30]!r}")
        name = m.group(0)
        j = m.end()
        while j < n and body[j] in " \t":
            j += 1
        label: Optional[str] = None
        if j < n and body[j] == '"':
            k = _end_of_string(body, j)
            label = body[j + 1:k - 1]
            j = k
            while j < n and body[j] in " \t":
                j += 1
        if j < n and body[j] == "=" and not body.startswith("==", j) and label is None:
            k = _end_of_expr(body, j + 1)
            expr = _strip_comment_tail(body[j + 1:k])
            if name in attrs:
                raise HclError(f"속성 {name} 이 두 번 있음")
            attrs[name] = expr
            i = k
        elif j < n and body[j] == "{":
            k = _end_of_balanced(body, j, "{", "}")
            blocks.append((name, label, body[j + 1:k - 1]))
            i = k
        else:
            raise HclError(f"읽을 수 없는 줄: {body[i:i + 30]!r}")
    return attrs, blocks


def find_block(sources: Dict[str, str], keyword: str, btype: str, bname: str) -> Tuple[Optional[str], Optional[str]]:
    """코드 전체에서 `<keyword> "<btype>" "<bname>" {` 블록 하나의 (파일, 본문). 없으면 (None, None), 둘 이상이면 HclError."""
    pat = re.compile(r'(?m)^[ \t]*%s[ \t]+"%s"[ \t]+"%s"[ \t]*\{' % (re.escape(keyword), re.escape(btype), re.escape(bname)))
    hits: List[Tuple[str, str]] = []
    for fn, text in sorted((sources or {}).items()):
        for m in pat.finditer(text):
            k = _end_of_balanced(text, m.end() - 1, "{", "}")
            hits.append((fn, text[m.end():k - 1]))
    if len(hits) > 1:
        raise HclError(f'{keyword} "{btype}" "{bname}" 블록이 {len(hits)}개 — 어느 것인지 모름')
    return hits[0] if hits else (None, None)


# ----------------------------------------------------------------------------- 값 읽기
def _split_list(expr: str) -> List[str]:
    """'[a, "b", c]' → ['a', '"b"', 'c'] (괄호 · 글자 · 주석 고려, 끝 쉼표 허용). 목록이 아니면 HclError."""
    e = expr.strip()
    if not (e.startswith("[") and _end_of_balanced(e, 0, "[", "]") == len(e)):
        raise HclError(f"목록 글자가 아님: {e[:40]!r}")
    inner = e[1:-1]
    items: List[str] = []
    cur_start = 0
    j, n = 0, len(inner)
    while j < n:
        c = inner[j]
        if c == '"':
            j = _end_of_string(inner, j)
            continue
        if c == "#" or inner.startswith("//", j) or inner.startswith("/*", j):
            k = _skip_ws(inner, j)
            inner = inner[:j] + " " * (k - j) + inner[k:]
            j = k
            continue
        if c in "[{(":
            j = _end_of_balanced(inner, j, c, {"[": "]", "{": "}", "(": ")"}[c])
            continue
        if c == ",":
            items.append(inner[cur_start:j].strip())
            cur_start = j + 1
        j += 1
    tail = inner[cur_start:].strip()
    if tail:
        items.append(tail)
    if any(not x for x in items):
        raise HclError("빈 목록 항목")
    return items


def _template(lit: str) -> Tuple[str, Set[str]]:
    """따옴표 안 글자(원문) → (토큰으로 바꾼 글자, 참조한 리소스 주소들). 지원하지 않는 보간 · 지시자 · 이스케이프는 HclError."""
    out: List[str] = []
    refs: Set[str] = set()
    j, n = 0, len(lit)
    while j < n:
        c = lit[j]
        if c == "\\":
            nxt = lit[j + 1:j + 2]
            if nxt not in ('"', "\\"):
                raise HclError(f"지원하지 않는 이스케이프 \\{nxt}")
            out.append(nxt)
            j += 2
            continue
        if lit.startswith("$${", j) or lit.startswith("%%{", j) or lit.startswith("%{", j):
            raise HclError("템플릿 지시자 · 이스케이프한 보간은 읽지 않음")
        if lit.startswith("${", j):
            k = lit.find("}", j + 2)
            if k < 0 or "{" in lit[j + 2:k]:
                raise HclError("읽을 수 없는 보간")
            inner = lit[j + 2:k].strip().lstrip("~").rstrip("~").strip()
            m = _REF_RE.match(inner)
            if not m:
                raise HclError(f"지원하지 않는 보간 ${{{inner}}} (리소스의 arn · id · bucket 참조만)")
            out.append(token(f"{m.group(1)}.{m.group(2)}", m.group(3)))
            refs.add(f"{m.group(1)}.{m.group(2)}")
            j = k + 1
            continue
        out.append(c)
        j += 1
    s = "".join(out)
    return _s3_fix(s), refs


def _value_item(item: str, allow_refs: bool) -> Tuple[str, Set[str]]:
    it = item.strip()
    if it.startswith('"'):
        if _end_of_string(it, 0) != len(it):
            raise HclError(f"글자 하나가 아님: {it[:40]!r}")
        raw = it[1:-1]
        if TOKEN in raw:
            raise HclError("코드의 글자에 'tf:' 가 있음 — 토큰과 구분할 수 없어 읽지 않음")
        val, refs = _template(raw)
    elif _REF_RE.match(it):
        m = _REF_RE.match(it)
        val, refs = token(f"{m.group(1)}.{m.group(2)}", m.group(3)), {f"{m.group(1)}.{m.group(2)}"}
    else:
        raise HclError(f"값을 읽을 수 없음: {it[:40]!r} (변수 · 함수 · locals 는 지원 안 함)")
    if refs and not allow_refs:
        raise HclError(f"이 자리에 참조는 지원 안 함: {it[:40]!r}")
    return val, refs


def _str_value(expr: str) -> str:
    v, _ = _value_item(expr, allow_refs=False)
    return v


def _list_value(expr: str, allow_refs: bool) -> Tuple[List[str], Set[str]]:
    vals: List[str] = []
    refs: Set[str] = set()
    for it in _split_list(expr):
        v, r = _value_item(it, allow_refs)
        vals.append(v)
        refs |= r
    return vals, refs


def parse_statement(body: str) -> Dict[str, Any]:
    """statement 본문 하나 → {sid, effect, actions, not_actions, resources, not_resources, has_principal, has_condition, refs{key: set}, present}."""
    attrs, blocks = parse_body(body)
    unknown_attrs = [k for k in attrs if k not in _STMT_KEYS]
    if unknown_attrs:
        raise HclError(f"statement 의 모르는 속성: {', '.join(unknown_attrs)}")
    for name, label, _b in blocks:
        if name == "dynamic":
            raise HclError(f'statement 안의 dynamic "{label}" 블록은 읽지 않음')
        if name not in _STMT_BLOCKS:
            raise HclError(f"statement 의 모르는 블록: {name}")
    st: Dict[str, Any] = {"present": set(attrs), "refs": {}, "has_principal": any(b[0] in ("principals", "not_principals") for b in blocks),
                          "has_condition": any(b[0] == "condition" for b in blocks), "blocks": sorted({b[0] for b in blocks})}
    st["sid"] = _str_value(attrs["sid"]) if "sid" in attrs else ""
    eff = _str_value(attrs["effect"]) if "effect" in attrs else "Allow"
    if eff not in ("Allow", "Deny"):
        raise HclError(f"effect 값이 Allow · Deny 가 아님: {eff!r}")
    st["effect"] = eff.lower()
    for key in ("actions", "not_actions", "resources", "not_resources"):
        if key in attrs:
            vals, refs = _list_value(attrs[key], allow_refs=key in ("resources", "not_resources"))
            st[key] = vals
            st["refs"][key] = refs
        else:
            st[key] = []
    return st


# ----------------------------------------------------------------------------- plan 의 configuration 과 대조
def _cfg_resources(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list((((plan or {}).get("configuration") or {}).get("root_module") or {}).get("resources") or [])


def _ref_bases(refs: List[Any]) -> Set[str]:
    out: Set[str] = set()
    for r in refs or []:
        parts = str(r).split(".")
        if len(parts) >= 2 and parts[0].startswith("aws_") and "[" not in parts[1]:
            out.add(f"{parts[0]}.{parts[1]}")
        else:
            out.add("?" + str(r))           # var. · local. · data. · 인덱스 참조 — 코드 읽기(리소스 참조만)와 같을 수 없게
    return out


def _check_against_config(i: int, st: Dict[str, Any], cfg_st: Dict[str, Any]) -> None:
    for key in _STMT_KEYS:
        in_code = key in st["present"]
        in_cfg = key in cfg_st
        if in_code != in_cfg:
            raise HclError(f"statement[{i}].{key}: 코드와 plan 이 다름 (코드 {'있음' if in_code else '없음'}, plan {'있음' if in_cfg else '없음'})")
        if not in_cfg:
            continue
        ex = cfg_st[key] if isinstance(cfg_st[key], dict) else {}
        if "constant_value" in ex:
            cv = ex["constant_value"]
            if key in ("sid", "effect"):
                want = st["sid"] if key == "sid" else st["effect"].capitalize()
                if str(cv) != want:
                    raise HclError(f"statement[{i}].{key}: 코드 {want!r} ≠ plan {cv!r}")
            else:
                if st["refs"].get(key) or not isinstance(cv, list) or [str(x) for x in cv] != st[key]:
                    raise HclError(f"statement[{i}].{key}: 코드와 plan 의 값이 다름")
        elif "references" in ex:
            if key in ("sid", "effect") or _ref_bases(ex.get("references") or []) != (st["refs"].get(key) or set()):
                raise HclError(f"statement[{i}].{key}: 코드가 참조한 리소스와 plan 이 다름")
        else:
            raise HclError(f"statement[{i}].{key}: plan 에 값도 참조도 없음 (함수 등)")
    for b in _STMT_BLOCKS:
        if (b in cfg_st) != (b in st["blocks"]):
            raise HclError(f"statement[{i}]: {b} 블록이 코드와 plan 에서 다름")


def policy_doc_from_source(policy_addr: str, plan: Dict[str, Any], sources: Dict[str, str]) -> Tuple[Optional[List[Dict[str, Any]]], str, List[str]]:
    """정책 리소스(plan 에 policy 값 없음) → (statement 목록, data 주소, 못 읽은 이유). 못 읽으면 (None, data 주소 또는 '', [이유…])."""
    if not sources:
        return None, "", ["코드(.tf) 없음"]
    if policy_addr.startswith("module.") or "[" in policy_addr:
        return None, "", ["모듈 안 · count/for_each 리소스는 코드에서 읽지 않음"]
    parts = policy_addr.split(".")
    if len(parts) != 2:
        return None, "", [f"주소를 읽을 수 없음: {policy_addr}"]
    cfg = {str(r.get("address")): r for r in _cfg_resources(plan)}
    pcfg = cfg.get(policy_addr) or {}
    refs = ((pcfg.get("expressions") or {}).get("policy") or {}).get("references") or []
    datas = sorted({".".join(str(r).split(".")[:3]) for r in refs if str(r).startswith(f"data.{DOC_TYPE}.")})
    if len(datas) != 1 or any(not str(r).startswith(f"data.{DOC_TYPE}.") for r in refs):
        return None, "", [f"policy 가 data.{DOC_TYPE} 하나만 참조하지 않음 (참조: {', '.join(map(str, refs)) or '없음'})"]
    via = datas[0]
    dname = via.split(".")[2]
    try:
        _f, rbody = find_block(sources, "resource", parts[0], parts[1])
        if rbody is None:
            return None, via, [f"코드에서 {policy_addr} 블록을 찾지 못함"]
        rattrs, _rb = parse_body(rbody)
        if any(k in rattrs for k in ("count", "for_each")):
            return None, via, ["count · for_each 가 있는 정책 리소스는 읽지 않음"]
        if (rattrs.get("policy") or "").strip() not in tuple(f"{via}.{a}" for a in JSON_ATTRS):
            return None, via, [f"policy = {rattrs.get('policy')!r} — data 블록의 json 을 그대로 쓰는 경우만 읽음"]
        _f2, dbody = find_block(sources, "data", DOC_TYPE, dname)
        if dbody is None:
            return None, via, [f"코드에서 {via} 블록을 찾지 못함"]
        dattrs, dblocks = parse_body(dbody)
        bad = [k for k in dattrs if k not in _DOC_ATTRS_OK]
        if bad:
            return None, via, [f"{via} 의 {', '.join(bad)} 는 읽지 않음 (다른 정책 합치기 · count 등)"]
        if any(b[0] != "statement" for b in dblocks):
            return None, via, [f"{via} 의 {', '.join(sorted({b[0] + (' ' + repr(b[1]) if b[1] else '') for b in dblocks if b[0] != 'statement'}))} 블록은 읽지 않음"]
        stmts = [parse_statement(b[2]) for b in dblocks]
        dcfg = cfg.get(via) or {}
        if dcfg.get("mode") != "data":
            return None, via, [f"plan 의 configuration 에 {via} 가 없음 — 코드 읽기를 확인할 수 없음"]
        cfg_stmts = (dcfg.get("expressions") or {}).get("statement") or []
        if not isinstance(cfg_stmts, list) or len(cfg_stmts) != len(stmts):
            return None, via, [f"statement 수가 코드({len(stmts)})와 plan({len(cfg_stmts) if isinstance(cfg_stmts, list) else '?'})에서 다름"]
        for i, (st, cst) in enumerate(zip(stmts, cfg_stmts)):
            _check_against_config(i, st, cst if isinstance(cst, dict) else {})
    except HclError as e:
        return None, via, [str(e)]
    if not stmts:
        return None, via, [f"{via} 에 statement 가 없음"]
    return stmts, via, []
