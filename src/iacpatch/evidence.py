"""Evidence Bundle — 생성기(LLM / Rule-based)에 넘기는 입력 묶음.

Trivy finding 원문 + 코드 컨텍스트(대상 디렉터리의 *.tf) + Intent(사람이 정한 승인 출처) + 정책 제약 + 도구 버전.
LLM 이 임의로 승인 CIDR 을 지어내지 못하도록, 승인 출처는 여기서 intent 로만 공급된다.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import EvidenceBundle, Finding

BUNDLE_VERSION = "evidence-v1"


def read_tf_files(target_dir: str | Path, globs: Optional[List[str]] = None) -> Dict[str, str]:
    """대상 디렉터리의 편집 대상 파일을 읽는다 (하위 디렉터리는 제외, .terraform 제외)."""
    globs = globs or ["*.tf"]
    d = Path(target_dir)
    out: Dict[str, str] = {}
    for p in sorted(d.iterdir()):
        if p.is_file() and any(fnmatch.fnmatch(p.name, g) for g in globs) and not p.name.startswith("zz_iacpatch_"):
            out[p.name] = p.read_text(encoding="utf-8")
    return out


def build_bundle(scenario_id: str, target_dir: str, finding: Finding, all_findings: List[Finding],
                 files: Dict[str, str], intent_raw: Optional[Dict[str, Any]], policy: Dict[str, Any],
                 cis_mapping: Dict[str, Any], tool_versions: Dict[str, str]) -> EvidenceBundle:
    protected = set(policy.get("protected_file_names") or [])
    editable = [f for f in files if f not in protected]
    constraints = {
        "allowed_change_resource_types": policy.get("allowed_change_resource_types", []),
        "allowed_create_resource_types": policy.get("allowed_create_resource_types", []),
        "allow_delete": policy.get("allow_delete", False),
        "allow_replace": policy.get("allow_replace", False),
        "forbidden_tokens": policy.get("forbidden_tokens", []),
        "max_patch_files": policy.get("max_patch_files", 2),
        "protected_file_names": sorted(protected),
    }
    related = [f for f in all_findings if f.key != finding.key]
    return EvidenceBundle(
        bundle_version=BUNDLE_VERSION,
        scenario_id=scenario_id,
        target_dir=target_dir,
        finding=finding,
        related_findings=related,
        files=files,
        editable_files=editable,
        intent=intent_raw or {},
        constraints=constraints,
        cis_mapping=(cis_mapping.get("rules") or {}).get(finding.rule_id, {}),
        tool_versions=tool_versions,
        created_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    )


def bundle_to_prompt_json(bundle: EvidenceBundle) -> str:
    """프롬프트에 넣는 JSON. 파일 내용은 그대로 포함하되, 승인 출처는 intent 에서만 온다."""
    d = bundle.to_dict()
    d.pop("tool_versions", None)
    return json.dumps(d, ensure_ascii=False, indent=2)
