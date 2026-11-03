"""수정 후보가 '무엇을 바꿨나' — 판정 없이 바뀐 블록과 줄 수만 (교수 피드백 7, 2026-10-31).

화면의 후보 목록·상세는 기대 결과 대신 이 요약을 보여 준다. 계산은 원본 파일과 후보 파일의 줄 비교(difflib)와
블록 위치(proof/hcl_lines.top_blocks)만 쓴다. 이 변경이 맞는지는 판단하지 않는다 — 그건 V1~V6 의 일이다.
"""
from __future__ import annotations

import difflib
from typing import Any, Dict, List, Set, Tuple

from ..proof.hcl_lines import top_blocks

KIND_KO = {
    "aws_security_group": "보안 그룹", "aws_vpc_security_group_ingress_rule": "인바운드 규칙", "aws_vpc_security_group_egress_rule": "아웃바운드 규칙",
    "aws_security_group_rule": "보안 그룹 규칙", "aws_iam_policy": "IAM 정책", "aws_iam_role": "IAM 역할", "aws_iam_role_policy": "IAM 역할 인라인 정책",
    "aws_iam_role_policy_attachment": "IAM 정책 연결", "aws_iam_instance_profile": "IAM 인스턴스 프로필", "aws_s3_bucket": "S3 버킷",
    "aws_s3_bucket_policy": "S3 버킷 정책", "aws_s3_bucket_public_access_block": "S3 공개 차단 설정", "aws_instance": "EC2 인스턴스",
    "aws_launch_template": "시작 템플릿", "aws_lb": "로드 밸런서", "aws_db_instance": "RDS DB",
    "variable": "변수", "output": "출력값", "module": "모듈", "provider": "provider 설정", "locals": "로컬 값", "terraform": "terraform 설정",
}
MAX_NAMES = 3


def block_label(addr: str) -> str:
    """'aws_security_group.bastion' → '보안 그룹 bastion'. 모르는 종류는 주소 그대로."""
    base = addr.split("#", 1)[0]
    if base in ("locals", "terraform"):
        return KIND_KO[base]
    parts = base.split(".")
    if parts[0] == "data" and len(parts) >= 3:
        return f"조회(data) {parts[1]}.{parts[2]}"
    if len(parts) >= 2:
        kind = KIND_KO.get(parts[0])
        return f"{kind} {'.'.join(parts[1:])}" if kind else base
    return base


def _lines(text: str) -> List[str]:
    return text.replace("\r", "").split("\n")


def _touched(blocks: Dict[str, Tuple[int, int]], a: int, b: int) -> Set[str]:
    """0부터 센 줄 구간 [a, b) 와 겹치는 블록 이름. 빈 구간(삽입 위치)이면 그 위치를 감싸는 블록."""
    out: Set[str] = set()
    for name, (s, e) in blocks.items():
        s0, e0 = s - 1, e - 1                       # 0부터, 끝 줄 포함
        if a == b:
            if s0 < a <= e0:
                out.add(name)
        elif a <= e0 and s0 < b:
            out.add(name)
    return out


def file_changes(original: str, candidate: str) -> Dict[str, Any]:
    A, B = _lines(original), _lines(candidate)
    ba, bb = top_blocks(original), top_blocks(candidate)
    added = removed = 0
    names: Set[str] = set()
    outside = False
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, A, B, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        added += j2 - j1
        removed += i2 - i1
        hit = _touched(ba, i1, i2) | _touched(bb, j1, j2)
        if hit:
            names |= hit
        elif any(x.strip() for x in A[i1:i2] + B[j1:j2]):
            outside = True                          # 빈 줄만 바뀐 것은 세지 않는다
    order = {n: (bb.get(n) or ba.get(n) or (0, 0))[0] for n in names}
    return {"blocks": sorted(names, key=lambda n: (order[n], n)), "added": added, "removed": removed, "outside_blocks": outside}


def summarize(original: Dict[str, str], candidate: Dict[str, str]) -> Dict[str, Any]:
    """original/candidate: 파일 이름 → 내용. 후보에 없는 파일 = 바꾸지 않음. 원본에 없는 파일 = 새 파일."""
    files: List[Dict[str, Any]] = []
    for name in sorted(candidate):
        new = candidate[name]
        old = original.get(name)
        if old is not None and _lines(old) == _lines(new):
            continue
        if old is None:
            ch = {"blocks": sorted(top_blocks(new)), "added": len(_lines(new)), "removed": 0, "outside_blocks": False}
        else:
            ch = file_changes(old, new)
        files.append({"file": name, "new_file": old is None, **ch, "labels": [block_label(b) for b in ch["blocks"]]})
    added = sum(f["added"] for f in files)
    removed = sum(f["removed"] for f in files)
    labels: List[str] = []
    for f in files:
        if f["new_file"]:
            labels.append(f"새 파일 {f['file']}")
        labels += [x for x in f["labels"] if x not in labels]
        if f["outside_blocks"] and "블록 밖 줄" not in labels:
            labels.append("블록 밖 줄")
    if not files:
        text = "원본과 같음 — 바뀐 줄 없음"
    else:
        head = " · ".join(labels[:MAX_NAMES]) + (f" 외 {len(labels) - MAX_NAMES}곳" if len(labels) > MAX_NAMES else "")
        text = f"{head} 변경 (+{added} −{removed}줄)"
    return {"files": files, "added": added, "removed": removed, "text": text}
