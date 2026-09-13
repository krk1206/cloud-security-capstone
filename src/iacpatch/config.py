"""설정 로딩. 비밀값(API 키, AWS 키)은 절대 파일에 두지 않고 환경변수로만 받는다.

우선순위: CLI 인자 > 환경변수 > iacpatch.config.json (저장소 루트, 선택) > 기본값
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_FILENAME = "iacpatch.config.json"
SECRET_ENV_NAMES = ("LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN")


@dataclass
class Settings:
    repo_root: str
    data_dir: str = "data/runs"
    policy_file: str = "policy/patch_policy.json"
    rubric_file: str = "policy/risk_rubric.json"
    cis_file: str = "policy/cis_mapping.json"
    terraform_bin: str = "terraform"
    trivy_bin: str = "trivy"
    aws_bin: str = "aws"
    aws_profile: str = ""
    aws_region: str = "ap-northeast-2"
    offline_plan: bool = True             # 자격증명 없는 환경 기본값. 실제 배포 경로에서는 false 로.
    tf_var_file: str = ""                 # 예: terraform.tfvars.example (plan/trivy 에 전달)
    llm_provider: str = "mock"
    llm_model: str = ""
    llm_base_url: str = ""
    llm_mock_fixture: str = "sg_baseline_ok"
    prompt_version: str = "sg_v1"
    max_attempts: int = 2
    target_rule: str = "AVD-AWS-0107"
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else Path(self.repo_root) / p


def find_repo_root(start: Optional[str] = None) -> Path:
    p = Path(start or os.getcwd()).resolve()
    for cand in [p] + list(p.parents):
        if (cand / "policy" / "patch_policy.json").exists() or (cand / ".git").exists():
            return cand
    return p


def load_settings(repo_root: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Settings:
    root = find_repo_root(repo_root)
    data: Dict[str, Any] = {}
    cfg = root / CONFIG_FILENAME
    if cfg.exists():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"{cfg}: invalid JSON: {e}")
        for k in SECRET_ENV_NAMES:
            if k in data or k.lower() in data:
                raise ValueError(f"{cfg}: secrets must not be stored in the config file ({k}); use environment variables")
    env_map = {
        "terraform_bin": "TERRAFORM_BIN", "trivy_bin": "TRIVY_BIN", "aws_bin": "AWS_BIN", "aws_profile": "AWS_PROFILE",
        "aws_region": "AWS_REGION", "llm_provider": "LLM_PROVIDER", "llm_model": "LLM_MODEL", "llm_base_url": "LLM_BASE_URL",
        "llm_mock_fixture": "LLM_MOCK_FIXTURE", "prompt_version": "IACPATCH_PROMPT_VERSION", "data_dir": "IACPATCH_DATA_DIR",
        "tf_var_file": "IACPATCH_TF_VAR_FILE",
    }
    for k, envname in env_map.items():
        v = os.environ.get(envname)
        if v:
            data[k] = v
    if os.environ.get("IACPATCH_OFFLINE_PLAN") in ("0", "false", "False"):
        data["offline_plan"] = False
    elif os.environ.get("IACPATCH_OFFLINE_PLAN") in ("1", "true", "True"):
        data["offline_plan"] = True
    if os.environ.get("IACPATCH_MAX_ATTEMPTS"):
        data["max_attempts"] = int(os.environ["IACPATCH_MAX_ATTEMPTS"])
    for k, v in (overrides or {}).items():
        if v is not None:
            data[k] = v
    known = {f for f in Settings.__dataclass_fields__}
    clean = {k: v for k, v in data.items() if k in known and k != "repo_root"}
    extra = {k: v for k, v in data.items() if k not in known}
    return Settings(repo_root=str(root), extra=extra, **clean)


def load_json(path: str | Path) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
