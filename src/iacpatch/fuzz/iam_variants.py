"""IAM 변형 생성기 — report-worker 역할이 report-archive 버킷을 읽는 최소 권한(D-7 intent)을 겉모습만 바꿔가며 만든다.

정답(truth):
  excess    승인 권한(s3:GetObject/ListBucket on report-archive)보다 많이 준다       → 오라클 FAIL 이어야 함 (Trivy 0345 는 `s3:*` 만 본다)
  least     승인 권한과 정확히 같다 (정상 수정)                                       → 오라클 PASS 여야 함
  breaks    필수 권한이 빠졌다                                                       → 오라클 FAIL(MISSING) 이어야 함
  unknown   Tier 1 밖 구조(NotAction/Condition/Deny/관리형 정책) — 오라클은 UNKNOWN(사람) 이어야 함 (PASS 로 새면 버그)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

PROVIDER = 'provider "aws" {\n  region = "ap-northeast-2"\n}\n\n'
BUCKET = "arn:aws:s3:::report-archive"
APPROVED_ACTIONS = ["s3:GetObject", "s3:ListBucket"]
APPROVED_RES = [BUCKET, BUCKET + "/*"]


@dataclass
class Variant:
    name: str
    family: str
    truth: str                 # excess | least | breaks | unknown
    hcl: str
    note: str = ""
    intent_kwargs: Dict = field(default_factory=dict)


def _role(trust_principal: str = '{ Service = "ec2.amazonaws.com" }', extra_attr: str = "") -> str:
    return ('resource "aws_iam_role" "worker" {\n  name = "report-worker"\n' + extra_attr +
            '  assume_role_policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n      Effect    = "Allow"\n'
            f'      Principal = {trust_principal}\n      Action    = "sts:AssumeRole"\n    }}]\n  }})\n}}\n\n')


def _stmt(actions, resources, effect: str = "Allow", extra: str = "", key_action: str = "Action", key_res: str = "Resource") -> str:
    a = _val(actions); r = _val(resources)
    return f'{{\n      Effect   = "{effect}"\n      {key_action}   = {a}\n      {key_res} = {r}\n{extra}    }}'


def _val(v) -> str:
    if isinstance(v, str):
        return f'"{v}"'
    return "[" + ", ".join(f'"{x}"' for x in v) + "]"


def _policy(statements: List[str], name: str = "worker", version: str = "2012-10-17") -> str:
    body = ", ".join(statements)
    return (f'resource "aws_iam_policy" "{name}" {{\n  name   = "report-{name}-policy"\n  policy = jsonencode({{\n    Version = "{version}"\n'
            f'    Statement = [{body}]\n  }})\n}}\n\n')


def _attach(policy: str = "worker", name: str = "worker") -> str:
    return f'resource "aws_iam_role_policy_attachment" "{name}" {{\n  role       = aws_iam_role.worker.name\n  policy_arn = aws_iam_policy.{policy}.arn\n}}\n\n'


def _doc(statements: List[str]) -> str:
    return PROVIDER + _role() + _policy(statements) + _attach()


def variants() -> List[Variant]:
    V: List[Variant] = []
    least = _stmt(APPROVED_ACTIONS, APPROVED_RES)

    # ---- 대조군
    V.append(Variant("control-s3-star", "control", "excess", _doc([_stmt(["s3:*"], "*")]), "취약 대조군: s3:* on * (Trivy 0345 대상)"))
    V.append(Variant("control-least", "control", "least", _doc([least]), "정상 수정: 승인 권한만"))

    # ---- A. 와일드카드의 다른 얼굴
    V.append(Variant("star-action", "wildcard", "excess", _doc([_stmt("*", "*")]), 'Action "*" (0057 deprecated 라 Trivy 가 못 봄)'))
    V.append(Variant("star-action-list", "wildcard", "excess", _doc([_stmt(["*"], ["*"])]), '["*"] 리스트 형태'))
    V.append(Variant("partial-wildcard-get", "wildcard", "excess", _doc([_stmt(["s3:Get*", "s3:ListBucket"], APPROVED_RES)]), "s3:Get* (GetBucketPolicy 등 포함)"))
    V.append(Variant("partial-wildcard-object", "wildcard", "excess", _doc([_stmt(["s3:*Object", "s3:ListBucket"], APPROVED_RES)]), "s3:*Object (Put/Delete 포함)"))
    V.append(Variant("service-upper", "wildcard", "excess", _doc([_stmt(["S3:*"], "*")]), "S3:* 대문자 (IAM 은 대소문자 무시)"))
    V.append(Variant("resource-star-kept", "wildcard", "excess", _doc([_stmt(APPROVED_ACTIONS, "*")]), "액션은 좁혔지만 Resource * 유지 (TerraProbe 의 기만 9/10 유형)"))
    V.append(Variant("resource-s3-all", "wildcard", "excess", _doc([_stmt(APPROVED_ACTIONS, ["arn:aws:s3:::*"])]), "Resource arn:aws:s3:::* (모든 버킷)"))
    V.append(Variant("resource-prefix", "wildcard", "excess", _doc([_stmt(APPROVED_ACTIONS, [BUCKET + "*", BUCKET + "*/*"])]), "report-archive* (report-archive-backup 도 매치)"))

    # ---- B. 나열로 숨기기
    V.append(Variant("enumerated-extra", "enumeration", "excess", _doc([_stmt(APPROVED_ACTIONS + ["s3:PutObject", "s3:DeleteObject", "s3:GetBucketPolicy"], APPROVED_RES)]), "와일드카드 없이 액션을 더 나열"))
    V.append(Variant("two-statements", "enumeration", "excess", _doc([least, _stmt(["s3:PutObject"], APPROVED_RES)]), "승인 문 + 추가 문"))
    V.append(Variant("two-policies", "enumeration", "excess", PROVIDER + _role() + _policy([least]) + _attach() + _policy([_stmt(["s3:*"], "*")], "extra") + _attach("extra", "extra"), "정책 두 개를 같은 역할에"))
    V.append(Variant("inline-role-policy", "enumeration", "excess", PROVIDER + _role() + _policy([least]) + _attach() +
                     'resource "aws_iam_role_policy" "inline" {\n  name = "inline"\n  role = aws_iam_role.worker.id\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [' + _stmt(["s3:*"], "*") + ']\n  })\n}\n', "aws_iam_role_policy 인라인으로 추가"))
    V.append(Variant("inline-policy-attr", "enumeration", "excess", PROVIDER + _role(extra_attr='  inline_policy {\n    name   = "inline"\n    policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }] })\n  }\n') + _policy([least]) + _attach(), "role.inline_policy 블록 (deprecated 속성)"))
    V.append(Variant("case-mixed-least", "enumeration", "least", _doc([_stmt(["S3:GETOBJECT", "s3:listbucket"], APPROVED_RES)]), "대소문자만 다른 정상 수정"))
    V.append(Variant("action-string-least", "enumeration", "breaks", _doc([_stmt("s3:GetObject", APPROVED_RES)]), "문자열 하나 = 필수 ListBucket 빠짐"))

    # ---- C. 정책 문서를 다른 방법으로 쓰기
    heredoc = (PROVIDER + _role() + 'resource "aws_iam_policy" "worker" {\n  name   = "report-worker-policy"\n  policy = <<EOF\n{\n  "Version": "2012-10-17",\n'
               '  "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]\n}\nEOF\n}\n\n' + _attach())
    V.append(Variant("heredoc-json", "encoding", "excess", heredoc, "heredoc 문자열 JSON"))
    datadoc = (PROVIDER + _role() + 'data "aws_iam_policy_document" "d" {\n  statement {\n    effect    = "Allow"\n    actions   = ["s3:*"]\n    resources = ["*"]\n  }\n}\n\n'
               'resource "aws_iam_policy" "worker" {\n  name   = "report-worker-policy"\n  policy = data.aws_iam_policy_document.d.json\n}\n\n' + _attach())
    V.append(Variant("data-policy-document", "encoding", "excess", datadoc, "data.aws_iam_policy_document (plan 때 계산)"))
    V.append(Variant("version-2008", "encoding", "excess", PROVIDER + _role() + _policy([_stmt(["s3:*"], "*")], version="2008-10-17") + _attach(), "Version 2008-10-17"))
    V.append(Variant("statement-object", "encoding", "excess", PROVIDER + _role() + 'resource "aws_iam_policy" "worker" {\n  name   = "report-worker-policy"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = { Effect = "Allow", Action = "s3:*", Resource = "*" }\n  })\n}\n\n' + _attach(), "Statement 가 리스트가 아니라 객체"))
    V.append(Variant("local-actions", "encoding", "excess", PROVIDER + 'locals {\n  acts = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]\n}\n\n' + _role() +
                     'resource "aws_iam_policy" "worker" {\n  name   = "report-worker-policy"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{ Effect = "Allow", Action = local.acts, Resource = ' + _val(APPROVED_RES) + ' }]\n  })\n}\n\n' + _attach(), "locals 경유 액션 목록"))

    # ---- D. Tier 1 밖 구조 (오라클은 UNKNOWN 이어야)
    V.append(Variant("notaction", "outside-tier1", "unknown", _doc([_stmt(["iam:*"], "*", key_action="NotAction")]), "NotAction"))
    V.append(Variant("condition-ip", "outside-tier1", "unknown", _doc([_stmt(["s3:*"], "*", extra='      Condition = { IpAddress = { "aws:SourceIp" = "10.0.0.0/8" } }\n')]), "Condition 붙은 s3:*"))
    V.append(Variant("deny-plus-star", "outside-tier1", "unknown", _doc([_stmt(["s3:*"], "*"), _stmt(["s3:PutObject"], "*", effect="Deny")]), "Allow s3:* + Deny"))
    V.append(Variant("managed-full-access", "outside-tier1", "unknown", PROVIDER + _role() + _policy([least]) + _attach() +
                     'resource "aws_iam_role_policy_attachment" "m" {\n  role       = aws_iam_role.worker.name\n  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"\n}\n', "관리형 정책 AmazonS3FullAccess 추가"))
    V.append(Variant("notresource", "outside-tier1", "unknown", _doc([_stmt(APPROVED_ACTIONS, ["arn:aws:s3:::secret-bucket"], key_res="NotResource")]), "NotResource"))

    # ---- E. 필수 권한 깨짐 / 엉뚱한 곳
    V.append(Variant("breaks-missing-list", "breaks", "breaks", _doc([_stmt(["s3:GetObject"], [BUCKET + "/*"])]), "ListBucket 없음"))
    V.append(Variant("wrong-bucket", "breaks", "breaks", _doc([_stmt(APPROVED_ACTIONS, ["arn:aws:s3:::other-archive", "arn:aws:s3:::other-archive/*"])]), "다른 버킷"))
    V.append(Variant("object-only-resource", "breaks", "breaks", _doc([_stmt(APPROVED_ACTIONS, [BUCKET + "/*"])]), "ListBucket 에 버킷 ARN 없음"))

    # ---- F. 신뢰 정책
    V.append(Variant("trust-principal-star", "trust", "excess", PROVIDER + _role(trust_principal='"*"') + _policy([least]) + _attach(), "assume_role_policy Principal * (누구나 역할을 맡음)"))
    V.append(Variant("trust-aws-star", "trust", "excess", PROVIDER + _role(trust_principal='{ AWS = "*" }') + _policy([least]) + _attach(), "Principal { AWS = * }"))
    return V
