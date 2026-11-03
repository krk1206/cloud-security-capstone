""".tf 텍스트에서 블록의 줄 위치를 찾는다 (화면에서 '이 판정은 이 파일 이 줄 때문' 을 보여 주기 위해).

완전한 HCL 파서가 아니다. 문자열·주석·heredoc 을 건너뛰며 중괄호 짝만 맞춘다. 못 찾으면 None 을 돌려주고 화면은 줄 번호를 비운다
(추측한 줄 번호를 보여 주지 않는다).
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

_RES_RE = re.compile(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def _strip_line(line: str, in_block_comment: bool) -> Tuple[str, bool]:
    """한 줄에서 문자열 내용·주석을 지운 '구조만 남은' 문자열과, 줄 끝에서 블록 주석 안인지."""
    out = []
    i, n = 0, len(line)
    in_str = False
    while i < n:
        c = line[i]
        if in_block_comment:
            if line.startswith("*/", i):
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
                out.append('"')
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append('"')
            i += 1
            continue
        if c == "#" or line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block_comment = True
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block_comment


def _structure(lines: List[str]) -> List[str]:
    """줄마다 구조 문자열. heredoc 본문 줄은 빈 문자열로."""
    res: List[str] = []
    in_bc = False
    heredoc: Optional[str] = None
    for line in lines:
        if heredoc is not None:
            res.append("")
            if line.strip() == heredoc:
                heredoc = None
            continue
        s, in_bc = _strip_line(line, in_bc)
        m = re.search(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", s)
        if m:
            heredoc = m.group(1)
        res.append(s)
    return res


def _match_brace(struct: List[str], start_idx: int) -> Optional[int]:
    depth = 0
    started = False
    for i in range(start_idx, len(struct)):
        for c in struct[i]:
            if c == "{":
                depth += 1
                started = True
            elif c == "}":
                depth -= 1
                if started and depth == 0:
                    return i
    return None


def resource_blocks(text: str) -> Dict[str, Tuple[int, int]]:
    """'type.name' → (시작 줄, 끝 줄) 1부터. data 블록은 'data.type.name'."""
    lines = text.replace("\r", "").split("\n")
    struct = _structure(lines)
    out: Dict[str, Tuple[int, int]] = {}
    for i, line in enumerate(lines):
        m = _RES_RE.match(line)
        if not m:
            continue
        end = _match_brace(struct, i)
        if end is None:
            continue
        key = f"{m.group(2)}.{m.group(3)}" if m.group(1) == "resource" else f"data.{m.group(2)}.{m.group(3)}"
        out[key] = (i + 1, end + 1)
    return out


_TOP_RES_RE = re.compile(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{')
_TOP_NAMED_RE = re.compile(r'^\s*(variable|output|module|provider)\s+"([^"]+)"\s*\{')
_TOP_BARE_RE = re.compile(r'^\s*(locals|terraform)\s*\{')


def top_blocks(text: str) -> Dict[str, Tuple[int, int]]:
    """맨 바깥 블록 전부 → (시작 줄, 끝 줄) 1부터. 이름: 'type.name' · 'data.type.name' · 'variable.x' · 'output.x' · 'module.x' ·
    'provider.aws' · 'locals' · 'terraform' (locals 가 여러 개면 'locals#2' …). 바깥(깊이 0)에서 시작하는 줄만 본다."""
    lines = text.replace("\r", "").split("\n")
    struct = _structure(lines)
    out: Dict[str, Tuple[int, int]] = {}
    depth = 0
    i = 0
    while i < len(lines):
        if depth == 0:
            key = None
            m = _TOP_RES_RE.match(lines[i])
            if m:
                key = f"{m.group(2)}.{m.group(3)}" if m.group(1) == "resource" else f"data.{m.group(2)}.{m.group(3)}"
            else:
                m = _TOP_NAMED_RE.match(lines[i])
                if m:
                    key = f"{m.group(1)}.{m.group(2)}"
                else:
                    m = _TOP_BARE_RE.match(lines[i])
                    if m:
                        key = m.group(1)
            if key is not None:
                end = _match_brace(struct, i)
                if end is None:
                    break
                n, base = 2, key
                while key in out:
                    key, n = f"{base}#{n}", n + 1
                out[key] = (i + 1, end + 1)
                i = end + 1
                continue
        depth = max(0, depth + struct[i].count("{") - struct[i].count("}"))
        i += 1
    return out


def nested_blocks(text: str, start: int, end: int, name: str) -> List[Tuple[int, int]]:
    """리소스 블록(start~end 줄, 1부터) 바로 안쪽의 `name {` 블록들 (등장 순서). 예: ingress 블록 목록."""
    lines = text.replace("\r", "").split("\n")
    struct = _structure(lines)
    out: List[Tuple[int, int]] = []
    depth = 0
    i = start - 1
    pat = re.compile(r"^\s*" + re.escape(name) + r"\s*\{")
    while i < min(end, len(lines)):
        s = struct[i]
        if depth == 1 and pat.match(s):
            e = _match_brace(struct, i)
            if e is None:
                break
            out.append((i + 1, e + 1))
            i = e + 1
            continue
        depth += s.count("{") - s.count("}")
        i += 1
    return out


def _block_score(body: str, hint: Dict[str, object]) -> int:
    """중첩 블록 본문이 계획(plan)의 규칙 값과 얼마나 맞나. 설명 문장 3점, 포트·프로토콜 각 1점."""
    score = 0
    desc = hint.get("description")
    if desc and re.search(r'\bdescription\s*=\s*"' + re.escape(str(desc)) + r'"', body):
        score += 3
    for key in ("from_port", "to_port"):
        v = hint.get(key)
        m = re.search(r"\b" + key + r"\s*=\s*(-?\d+)", body)
        if v is not None and m and int(m.group(1)) == int(v):  # type: ignore[arg-type]
            score += 1
    pr = hint.get("protocol")
    m = re.search(r'\bprotocol\s*=\s*"([^"]+)"', body)
    if pr is not None and m and m.group(1) == str(pr):
        score += 1
    return score


def locate_rule(sources: Dict[str, str], origin: str, hint: Optional[Dict[str, object]] = None) -> Optional[Dict[str, object]]:
    """오라클의 규칙 위치 문자열(예: 'aws_security_group.db#ingress[1]', 'aws_vpc_security_group_ingress_rule.x')
    → {"file", "start", "end", "resource_start", "resource_end"}. 못 찾으면 None.

    ingress[N] 의 N 은 실행 계획(plan JSON)에서의 순서다. ingress 는 집합(set)이라 계획의 순서가 코드에 적은 순서와 다를 수 있다
    (2026-10-23 발견: web-to-api-direct 후보에서 다른 블록을 '원인 규칙' 으로 보여 줌). 그래서 hint(계획에 있는 그 규칙의 값 —
    description·포트·프로토콜)가 있으면 내용이 맞는 블록을 고르고, 없을 때만 순서로 찾는다."""
    if not origin:
        return None
    addr, _, rest = origin.partition("#")
    addr = re.sub(r"\[\d+\]$", "", addr.strip())       # count 인덱스는 블록 위치와 무관
    for fname, text in sources.items():
        blocks = resource_blocks(text)
        if addr not in blocks:
            continue
        rs, re_ = blocks[addr]
        hit: Dict[str, object] = {"file": fname, "start": rs, "end": re_, "resource_start": rs, "resource_end": re_, "matched_by": "resource"}
        m = re.match(r"(ingress|egress)\[(\d+)\]", rest or "")
        if m:
            nb = nested_blocks(text, rs, re_, m.group(1))
            k = int(m.group(2))
            lines = text.replace("\r", "").split("\n")
            if hint:
                scored = sorted(((_block_score("\n".join(lines[a - 1:b]), hint), i) for i, (a, b) in enumerate(nb)), key=lambda x: (-x[0], x[1]))
                if scored and scored[0][0] >= 2 and (len(scored) == 1 or scored[0][0] > scored[1][0]):
                    hit["start"], hit["end"] = nb[scored[0][1]]
                    hit["matched_by"] = "content"
                    return hit
            if k < len(nb):
                hit["start"], hit["end"] = nb[k]
                hit["matched_by"] = "index"
        return hit
    return None


def excerpt(text: str, start: int, end: int, context: int = 0, mark: Tuple[int, ...] = ()) -> List[Dict[str, object]]:
    lines = text.replace("\r", "").split("\n")
    a = max(1, start - context)
    b = min(len(lines), end + context)
    return [{"n": n, "text": lines[n - 1], "mark": n in mark} for n in range(a, b + 1)]
