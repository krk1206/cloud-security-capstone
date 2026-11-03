"""실행 전 안전 점검 v2 — 허용 목록 방식 (D-23 보완, 2026-10-31).

제출된 Terraform(사람 · AI 모두)은 검사 대상이지 신뢰된 프로그램이 아니다. terraform init / validate / plan 은 코드를 '실행' 한다:
모듈 · provider 를 내려받고, data 블록과 함수를 평가한다. Trivy 도 원격 모듈을 내려받는다 (공식 문서: 기본으로 켜져 있고
CLI 로 끌 수 없음). 그래서 도구를 돌리기 전에 아래 '허용 목록' 밖의 것이 있으면 멈춘다.

허용 목록
  - 함수: 순수 계산 함수만 (ALLOWED_FUNCS). 파일 · 경로 함수(file · templatefile · fileset …), provider 정의 함수(provider::…) 는 밖
  - 리소스 · data 종류: aws_ 로 시작하는 것만 (provider = aws 만)
  - 블록: module · check · import · moved · removed · provider · terraform · backend · cloud · provisioner · connection 은
          후보가 추가 · 변경 · 삭제할 수 없다

v1(금지 목록 + 줄 단위 검색)에서 2026-10-31 실제로 통과한 우회 (OpenTofu 로 실행해 확인):
  module m { … } (따옴표 없는 이름) · data local_file x { … } · (file 줄바꿈 ("/etc/passwd")) · check c { data dns… } 안의 data
v2 는 문자열 · 주석 · heredoc 을 구분하는 작은 스캐너로 '코드 부분'만 남긴 뒤(위치는 그대로) 블록 머리와 함수 호출을 찾는다.
따옴표 없는 이름 · 줄바꿈 · 보간("${…}") 모두 같은 규칙으로 잡는다.

두 가지 방식
  - diff(후보): 원본(신뢰한 사례 코드)에 없던 위반만. 같은 호출 원문이 원본에 있으면 통과 (인자를 바꾸면 새 호출 → 차단)
  - absolute(원본): 원본 자체를 검사 — 고객이 준 코드도 신뢰하지 않는다. 위반이 하나라도 있으면 그 코드로는 도구를 실행하지 않는다
이 점검은 허용 목록 밖의 '구문'을 막는다. OS 수준 격리(파일 · 네트워크 차단 실행 환경)는 아니다 — 그건 하지 않는다 (D-25).
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

ALLOWED_FUNCS = frozenset("""
abs ceil floor log max min parseint pow signum
chomp endswith format formatlist indent join lower regex regexall replace split startswith strcontains strrev substr title
trim trimprefix trimsuffix trimspace upper
alltrue anytrue chunklist coalesce coalescelist compact concat contains distinct element flatten index keys length lookup
matchkeys merge one range reverse setintersection setproduct setsubtract setunion slice sort sum transpose values zipmap
base64decode base64encode base64gzip base64gunzip csvdecode jsondecode jsonencode textdecodebase64 textencodebase64 urlencode
urldecode yamldecode yamlencode
base64sha256 base64sha512 md5 sha1 sha256 sha512 uuidv5 uuid
cidrhost cidrnetmask cidrsubnet cidrsubnets cidrcontains
can nonsensitive sensitive issensitive ephemeralasnull tobool tolist tomap tonumber toset tostring try type
formatdate timeadd timecmp timestamp plantimestamp basename dirname
list map set object tuple optional
""".split())

BLOCKED_BLOCKS = ("module", "check", "import", "moved", "removed", "provider", "terraform", "backend", "cloud", "provisioner", "connection")
KIND_KO = {"module": "module 블록 (terraform init · Trivy 가 외부에서 코드를 내려받을 수 있음)", "check": "check 블록 (plan 중 data 조회 실행)",
           "import": "import 블록 (기존 리소스 가져오기)", "moved": "moved 블록 (리소스 주소 이동)", "removed": "removed 블록 (상태에서 리소스 제거)",
           "provider": "provider 블록 (접속 설정)", "terraform": "terraform 블록 (provider · backend 설정)", "backend": "backend 블록 (상태 저장 위치)",
           "cloud": "cloud 블록 (원격 실행)", "provisioner": "provisioner (명령 실행)", "connection": "connection (원격 접속)"}

_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
_HEADER_RE = re.compile(r"(?m)^[ \t]*(" + _IDENT + r")((?:[ \t]+(?:\"[^\"\n]*\"|" + _IDENT + r"))*)[ \t]*\{")
_LABEL_RE = re.compile(r"\"[^\"\n]*\"|" + _IDENT)
_CALL_RE = re.compile(r"(" + r"[A-Za-z_][A-Za-z0-9_]*" + r")\s*\(")
_PROVIDER_FN_RE = re.compile(r"\bprovider\s*::")


def code_view(text: str) -> str:
    """원문과 길이가 같은 '코드 부분' — 주석 · 문자열 글자는 공백으로 바꾸고 (따옴표 · 줄바꿈은 남김),
    문자열 · heredoc 안의 보간(${ … } · %{ … }) 내용은 코드로 남긴다. 위치가 같아서 원문에서 같은 구간을 다시 읽을 수 있다."""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    out = list(t)
    n = len(t)
    i = 0
    stack: List[List] = [["code", 0]]          # 상태: code · str · heredoc · interp(깊이 = 열린 { 수)
    heredoc_end: List[str] = []

    def blank(k: int) -> None:
        if out[k] != "\n":
            out[k] = " "

    while i < n:
        st = stack[-1]
        c = t[i]
        if st[0] in ("code", "interp"):
            if c == "#" or t.startswith("//", i):
                while i < n and t[i] != "\n":
                    blank(i)
                    i += 1
                continue
            if t.startswith("/*", i):
                j = t.find("*/", i + 2)
                j = n if j < 0 else j + 2
                for k in range(i, j):
                    blank(k)
                i = j
                continue
            if c == '"':
                stack.append(["str", 0])
                i += 1
                continue
            m = re.match(r"<<-?\s*(" + _IDENT + r")[ \t]*\n", t[i:])
            if m:
                heredoc_end.append(m.group(1))
                stack.append(["heredoc", 0])
                i += m.end()
                continue
            if st[0] == "interp":
                if c == "{":
                    st[1] += 1
                elif c == "}":
                    if st[1] == 0:
                        blank(i)
                        stack.pop()
                        i += 1
                        continue
                    st[1] -= 1
            i += 1
            continue
        if st[0] == "str":
            if c == "\\" and i + 1 < n:
                blank(i)
                blank(i + 1)
                i += 2
                continue
            if t.startswith("$${", i) or t.startswith("%%{", i):
                for k in range(i, i + 3):
                    blank(k)
                i += 3
                continue
            if t.startswith("${", i) or t.startswith("%{", i):
                blank(i)
                blank(i + 1)
                stack.append(["interp", 0])
                i += 2
                continue
            if c == '"':
                stack.pop()
                i += 1
                continue
            blank(i)
            i += 1
            continue
        # heredoc: 줄 단위. 끝 표시만 있는 줄에서 끝난다
        line_start = i == 0 or t[i - 1] == "\n"
        if line_start:
            j = t.find("\n", i)
            j = n if j < 0 else j
            if t[i:j].strip() == heredoc_end[-1]:
                heredoc_end.pop()
                stack.pop()
                i = j
                continue
        if t.startswith("$${", i) or t.startswith("%%{", i):
            for k in range(i, i + 3):
                blank(k)
            i += 3
            continue
        if t.startswith("${", i) or t.startswith("%{", i):
            blank(i)
            blank(i + 1)
            stack.append(["interp", 0])
            i += 2
            continue
        blank(i)
        i += 1
    return "".join(out)


def _match(code: str, open_idx: int, op: str, cl: str) -> int:
    """code 의 open_idx(여는 괄호)에 맞는 닫는 괄호 위치. 못 찾으면 끝."""
    depth = 0
    for k in range(open_idx, len(code)):
        if code[k] == op:
            depth += 1
        elif code[k] == cl:
            depth -= 1
            if depth == 0:
                return k
    return len(code) - 1


def _norm(s: str) -> str:
    return " ".join(s.split())


def scan(text: str) -> Dict[str, object]:
    """블록 머리(종류 · 이름들 · 본문)와 함수 호출(이름 · 원문)."""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    code = code_view(t)
    blocks: List[Tuple[str, Tuple[str, ...], str, int]] = []
    for m in _HEADER_RE.finditer(code):
        kind = m.group(1)
        labels = tuple(x.strip('"') for x in _LABEL_RE.findall(t[m.start(2):m.end(2)]))
        brace = m.end() - 1
        end = _match(code, brace, "{", "}")
        blocks.append((kind, labels, _norm(t[brace + 1:end]), m.start()))
    calls: List[Tuple[str, str]] = []
    for m in _CALL_RE.finditer(code):
        name = m.group(1)
        before = code[max(0, m.start() - 2):m.start()]
        if before == "::":
            continue                                    # provider::x::f( — 아래 provider 함수 규칙이 잡는다
        paren = m.end() - 1
        end = _match(code, paren, "(", ")")
        calls.append((name, _norm(t[m.start():end + 1])))
    return {"blocks": blocks, "calls": calls, "provider_fn": len(_PROVIDER_FN_RE.findall(code))}


_REQ_PROVIDER_RE = re.compile(r"(?:^|[\s{}])(" + _IDENT + r")\s*=\s*\{")


def _violations(s: Dict[str, object], absolute: bool = False) -> Dict[str, Counter]:
    """허용 목록 밖의 것 → 종류별 Counter (같은 것이 몇 번 있나).
    absolute(원본 검사)에서는 원본에 원래 있어야 하는 provider "aws" · terraform 블록은 허용하고, 그 안의 backend · cloud ·
    aws 외 required_providers 를 본다. diff(후보)에서는 provider · terraform 블록을 바꾸는 것 자체가 위반이다."""
    bad_blocks: Counter = Counter()
    bad_types: Counter = Counter()
    for kind, labels, body, _pos in s["blocks"]:  # type: ignore[index]
        if absolute and kind == "provider" and labels and labels[0] == "aws":
            continue
        if absolute and kind == "terraform":
            continue
        if absolute and kind == "required_providers":
            for m in _REQ_PROVIDER_RE.finditer(body):
                if m.group(1) != "aws":
                    bad_types[("required_providers", (m.group(1),), "")] += 1
            continue
        if kind in BLOCKED_BLOCKS:
            bad_blocks[(kind, labels, body)] += 1
        elif kind in ("resource", "data") and labels:
            if not labels[0].startswith("aws_"):
                bad_types[(kind, labels, body)] += 1
    bad_calls: Counter = Counter(text for name, text in s["calls"] if name not in ALLOWED_FUNCS)  # type: ignore[union-attr]
    return {"blocks": bad_blocks, "types": bad_types, "calls": bad_calls, "provider_fn": Counter({"provider::": s["provider_fn"]}) if s["provider_fn"] else Counter()}


def _describe(kind: str, item: object) -> str:
    if kind == "blocks":
        k, labels, _body = item  # type: ignore[misc]
        return f"{KIND_KO.get(k, k)}: {k} {' '.join(labels)}".strip()
    if kind == "types":
        k, labels, _body = item  # type: ignore[misc]
        if k == "required_providers":
            return f"aws 외 provider 요구 (init 이 내려받아 plan 중 실행): {' '.join(labels)}"
        return f"aws 외 {'data' if k == 'data' else '리소스'} 종류 (허용 provider = aws, plan 중 파일 읽기 · 외부 접속 가능): {k} {' '.join(labels)}"
    if kind == "calls":
        name = str(item).split("(", 1)[0].strip()
        return f"허용 목록 밖 함수 {name}() (파일 읽기 · 외부 동작 가능성 — 순수 계산 함수만 허용): {str(item)[:120]}"
    return "provider 정의 함수 (provider::…, plan 중 임의 동작 가능)"


def check(content: str, base: Optional[str] = None) -> List[str]:
    """base 를 주면 diff 방식(원본보다 늘어난 위반만), 안 주면 absolute 방식(위반 전부). 화면용 문장 목록 — 비어 있으면 통과."""
    absolute = base is None
    cur = _violations(scan(content), absolute)
    old = _violations(scan(base)) if base is not None else {k: Counter() for k in cur}
    notes: List[str] = []
    for kind in ("blocks", "types", "calls", "provider_fn"):
        extra = cur[kind] - old[kind]
        for item, cnt in sorted(extra.items(), key=lambda kv: str(kv[0])):
            notes.append(_describe(kind, item) + (f" ×{cnt}" if cnt > 1 else ""))
        if base is not None and kind in ("blocks", "types"):
            gone = old[kind] - cur[kind]                # 원본에 있던 위험 블록을 바꾸거나 지운 것도 후보는 할 수 없다
            for item, cnt in sorted(gone.items(), key=lambda kv: str(kv[0])):
                k, labels, _b = item
                if not any(x[0] == k and x[1] == labels for x in cur[kind]):
                    notes.append(_describe(kind, item).replace(":", " 삭제:", 1))
    return notes


def check_files(files: Dict[str, str]) -> List[str]:
    """원본 폴더 전체(파일 이름 → 내용)를 absolute 방식으로. '파일: 문장' 목록 — 비어 있으면 통과.
    고객이 준 원본도 신뢰하지 않는다: 원본에 위반이 있으면 그 코드로는 Trivy · Terraform 을 실행하지 않는다."""
    out: List[str] = []
    for name in sorted(files):
        out += [f"{name}: {x}" for x in check(files[name])]
    return out
