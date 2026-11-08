"""고객 요청서 (14차, D-50 — B 2026-11-06 "고객이 뭘 요청하는지 실제 요청한 것마냥 '이렇게 요청을 부탁했다' 하는 것도 넣어야지").

예제마다 **가상** 고객의 요청서(scenarios/requests/<예제>.md)와 그 요청 조건(아래 REQUESTS)을 둔다.
요청서는 Terraform 폴더 밖에 둔다 — PR 은 그 폴더를 통째로 git add 하고, 원본 plan 캐시 열쇠도 폴더 내용이라 코드와 섞이면 안 된다.
  - 요청서 원문: ② 맨 위 '고객 요청' 칸 · [요청서 보기] 창 · PR 본문
  - 조건마다의 결과: ⑤ (고른 수정안) · ⑥ · ⑧ · PR 본문
조건 결과는 새로 판정하지 않는다 — 기록에 이미 있는 값(V1 · V2 · V5 · V6 · ⑧ 결정 · ⑦ 시험 환경)을 조건에 적힌 대로 모을 뿐이다.
설계도 비교(V6)가 찾은 '설계도에 없는 통신' · '막힌 통신' 은 조건 하나에만 들어간다: 대상(계층 · 포트)을 정해 둔 조건이 먼저 가져가고,
나머지는 '그 밖' 조건(design_rest)이 가져간다 — 그래서 V6 가 FAIL 이면 어느 조건이든 하나는 '어김' 이 된다 (V6 와 어긋나지 않음).
설계도가 초안(확정 전)이면 V6 로 정하는 조건은 '지킴' 이 아니라 '초안 기준' (D-38 과 같은 규칙).
요청서 · 고객 · 날짜는 예제를 위해 만든 것이다 — 화면 · PR 에 '가상' 을 함께 적는다.

15차 (D-51, B 2026-11-06 "시나리오 고객 요청 건을 좀 더 늘리자"): 팀 3계층에 같은 가상 고객의 요청 3건 (seq 1 · 2 · 3 = 팀 README 시나리오 1 · 2 · 3).
  - 요청 3 (IAM): 조건 결과는 V6 IAM 오라클의 값(승인 밖 권한 excess · 꼭 필요한 권한 missing · 신뢰 정책)을 모은다 — 키 iam_limit · iam_required · iam_trust.
    V6 IAM 이 FAIL 이면 excess(신뢰 정책 포함) · missing 이 조건 셋 중 하나에 반드시 들어간다 (토폴로지와 같은 성질).
  - 요청 2 (S3): 팀 정책의 자동 수정 범위 밖 — 고칠 묶음이 없어 기록이 없다. 조건마다의 결과 대신 '사람에게 넘김' 칸(handoff)을 만든다:
    무엇이 문제(Trivy · plan 값) · 왜 자동으로 안 하나(정책 파일 내용 그대로) · 사람이 할 일 · 고친 뒤 확인 방법.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 조건 키 (한 조건에 여러 개를 함께 쓸 수 있다 — 모두 지켜야 '지킴')
#   trivy_fixed   : 이번 수정 대상인 Trivy 지적이 없어졌나 (V1)
#   flows_ok      : 설계도의 이 통신(id)이 허용돼 있나 (V6 flows status == ok)
#   no_extra_to   : [계층 id, 포트("" = 모든 포트)] 로 들어오는 '설계도에 없는 통신' 이 없나 (V6 excess)
#   design_rest   : 다른 조건이 가져가지 않은 V6 위반(설계도에 없는 통신 · 막힌 통신)이 없나
#   questions     : ⑥ 질문의 답 (scope = V5 허용 범위 · 정책, new = V2 새 문제)
#   approved      : ⑧ 에서 사람이 승인했나
#   aws_verified  : ⑦ AWS 시험 환경(샌드박스)에서 확인됐나
#   iam_limit     : (IAM, 15차) 요구사항이 허용한 권한 밖이 없나 (V6 IAM excess, 신뢰 정책 것은 빼고)
#   iam_required  : (IAM) 꼭 필요한 권한이 그대로 있나 (V6 IAM missing). required_good = 지켰을 때 보일 글 (요청마다 필요한 권한이 다름 — 16차 요청 6 은 올리기까지)
#   iam_trust     : (IAM) 역할을 맡을 수 있는 대상(신뢰 정책)을 누구나로 열지 않았나 (V6 IAM excess 중 trust policy)
_REST = "지적된 곳 말고는 바꾸지 말아 주세요. 설계에 없는 통신을 새로 열거나, 설계에 있는 통신을 막거나, 새 보안 문제를 만들면 안 됩니다."
REQUESTS: Dict[str, Dict[str, Any]] = {
    "three-tier-team": {
        "seq": 1,
        "path": "scenarios/requests/three-tier-team.md",
        "title": "Bastion SSH 전체 공개 — 점검 지적 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "외부 보안 점검에서 Bastion 서버의 SSH(22)가 인터넷 전체에 열려 있다는 지적을 받았습니다. 운영자 IP 에서만 접속되게 고쳐 주세요.",
        "items": [
            {"short": "SSH 는 운영자 IP 만", "text": "Bastion 서버 SSH(22)는 운영자 IP(203.0.113.10)에서만 접속되게 해 주세요.",
             "trivy_fixed": True, "flows_ok": ["admin-bastion-22"], "no_extra_to": [["bastion", "22"]]},
            {"short": "웹 서비스(80) 그대로", "text": "고객이 쓰는 웹 서비스(80)는 지금처럼 인터넷에서 접속돼야 합니다.",
             "flows_ok": ["internet-alb-80", "alb-web-80"]},
            {"short": "DB 는 웹 서버 · Bastion 만", "text": "데이터베이스(3306)는 웹 서버와 Bastion 에서만 접속돼야 합니다.",
             "flows_ok": ["web-db-3306", "bastion-db-3306"], "no_extra_to": [["db", ""]]},
            {"short": "다른 곳은 그대로", "text": _REST, "questions": ["scope", "new"], "design_rest": True},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요.", "approved": True},
        ],
    },
    "three-tier-team-s3": {
        "seq": 2,
        "path": "scenarios/requests/three-tier-team-s3.md",
        "title": "자산 버킷 공개 차단 꺼짐 — 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "자산 버킷(assets)의 퍼블릭 액세스 차단 설정 4개가 모두 꺼져 있다는 점검 결과를 받았습니다. 4개를 모두 켜 주세요.",
        "handoff": {"resource": "aws_s3_bucket_public_access_block.assets", "file": "s3.tf", "what": "S3 공개 차단",
                    "attrs": [{"name": n, "want": True} for n in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")],
                    "rules": ["AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093"],
                    "todo": ["s3.tf 의 aws_s3_bucket_public_access_block.assets 에서 block_public_acls · block_public_policy · ignore_public_acls · restrict_public_buckets 를 모두 true 로 (팀 원본 값 — 설계 문서 1.11절 · 결정 9)",
                             "버킷(aws_s3_bucket.assets)은 그대로 — bucket_prefix · 이름이 바뀌면 새 버킷이 만들어져 파일이 사라짐"],
                    "verify": ["웹 서버 역할의 버킷 읽기 권한(iam.tf)을 바꾸지 않았는지 — 요청 조건 2 (파일 읽기는 그대로)"]},
        "items": [
            {"short": "공개 차단 4개 켜기", "text": "자산 버킷의 퍼블릭 액세스 차단 4개(공개 ACL 막기 · 공개 정책 막기 · 공개 ACL 무시 · 공개 버킷 제한)를 모두 켜 주세요."},
            {"short": "파일 읽기는 그대로", "text": "웹 서버는 지금처럼 자산 버킷의 파일을 읽을 수 있어야 합니다."},
            {"short": "다른 곳은 그대로", "text": "지적된 곳 말고는 바꾸지 말아 주세요. 버킷을 새로 만들거나(이름이 바뀌면 파일이 사라집니다) 다른 설정을 바꾸면 안 됩니다."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-iam": {
        "seq": 3,
        "path": "scenarios/requests/three-tier-team-iam.md",
        "title": "웹 서버 역할 권한 과다 — 점검 지적 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "점검에서 웹 서버가 쓰는 IAM 역할이 모든 S3 리소스에 모든 작업(s3:*)을 할 수 있다는 지적을 받았습니다. 웹 서버가 실제로 쓰는 권한만 남겨 주세요.",
        "items": [
            {"short": "자산 버킷 읽기만", "text": "웹 서버 역할은 자산 버킷(assets)의 파일 읽기와 목록 보기만 할 수 있게 해 주세요. 다른 버킷 · 다른 서비스의 권한은 없어야 합니다.",
             "trivy_fixed": True, "iam_limit": True},
            {"short": "파일 읽기는 그대로", "text": "웹 서버는 지금처럼 자산 버킷의 파일을 읽을 수 있어야 합니다. 권한을 줄이다가 서비스가 멈추면 안 됩니다.",
             "iam_required": True},
            {"short": "다른 곳은 그대로", "text": "지적된 곳 말고는 바꾸지 말아 주세요. 이 역할을 쓸 수 있는 대상(EC2)을 바꾸거나, 새 보안 문제를 만들면 안 됩니다.",
             "iam_trust": True, "questions": ["scope", "new"]},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요.", "approved": True},
        ],
    },
    # ---- 16차 (D-52): 같은 가상 고객의 요청 4 ~ 11 (언제 도착하는지는 web/inbox.py)
    "three-tier-team-dbsg": {
        "seq": 4,
        "path": "scenarios/requests/three-tier-team-dbsg.md",
        "title": "DB 보안 그룹 전체 개방 — 점검 지적 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "점검 도구에서 데이터베이스 보안 그룹이 인터넷 전체에 모든 포트로 열려 있다는 알림이 왔습니다. DB 는 Bastion · 웹 서버에서 3306 으로만 접속되게 해 주세요.",
        "items": [
            {"short": "DB 는 Bastion · 웹 서버만", "text": "데이터베이스(3306)는 Bastion 과 웹 서버에서만 접속되게 해 주세요. 인터넷이나 다른 곳에서 DB 로 들어오는 길은 없어야 합니다.",
             "trivy_fixed": True, "flows_ok": ["bastion-db-3306", "web-db-3306"], "no_extra_to": [["db", ""]]},
            {"short": "웹 서비스(80) 그대로", "text": "고객이 쓰는 웹 서비스(80)는 지금처럼 인터넷에서 접속돼야 합니다.",
             "flows_ok": ["internet-alb-80", "alb-web-80"]},
            {"short": "SSH 는 운영자 IP 만", "text": "Bastion SSH(22)는 지난번(요청 1)처럼 운영자 IP 에서만 접속돼야 합니다.",
             "flows_ok": ["admin-bastion-22"], "no_extra_to": [["bastion", "22"]]},
            {"short": "다른 곳은 그대로", "text": _REST, "questions": ["scope", "new"], "design_rest": True},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요.", "approved": True},
        ],
    },
    "three-tier-team-dbpublic": {
        "seq": 5,
        "path": "scenarios/requests/three-tier-team-dbpublic.md",
        "title": "DB 공개 접속 켜짐 — 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "외부 분석 도구를 붙이려고 DB 의 공개 접속 설정을 켰다가 점검에서 지적을 받았습니다. 원래대로 꺼 주세요.",
        "handoff": {"resource": "aws_db_instance.mysql", "file": "rds.tf", "what": "RDS DB",
                    "attrs": [{"name": "publicly_accessible", "want": False}], "rules": ["AVD-AWS-0180"],
                    "todo": ["rds.tf 의 aws_db_instance.mysql 에서 publicly_accessible 를 false 로 (팀 원본 값 — 원본 주석 'Trivy AWS-0180')",
                             "외부 분석 도구는 DB 를 공개하지 말고 Bastion 을 거치거나 같은 VPC 안에서 붙는 방법을 고객과 정하기"],
                    "verify": ["DB 보안 그룹 규칙(요청 4)과 DB 서브넷은 그대로인지", "plan 에서 DB 가 새로 만들어지지 않는지(제자리 수정 1건)"]},
        "items": [
            {"short": "DB 공개 접속 끄기", "text": "데이터베이스는 공개 접속이 꺼진 상태(외부에서 주소로 바로 못 붙는 상태)여야 합니다."},
            {"short": "웹 · Bastion 접속 그대로", "text": "웹 서버와 Bastion 에서는 지금처럼 DB 에 접속돼야 합니다."},
            {"short": "DB 새로 만들지 않기", "text": "DB 를 새로 만들거나(데이터가 사라집니다) 다른 설정을 바꾸면 안 됩니다."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-upload": {
        "seq": 6,
        "path": "scenarios/requests/three-tier-team-upload.md",
        "title": "업로드 권한이 S3 전체 작업으로 열림 — 업로드만 되게 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "업로드 기능을 붙이면서 웹 서버 역할에 S3 전체 작업(s3:*)이 들어가 점검 지적을 받았습니다. 읽기 · 목록 · 올리기만 되게 해 주세요.",
        "items": [
            {"short": "읽기 · 목록 · 올리기만", "text": "웹 서버 역할은 자산 버킷(assets)의 파일 읽기 · 목록 보기 · 올리기(업로드)만 할 수 있게 해 주세요. 지우기 · 설정 바꾸기 같은 다른 작업은 없어야 합니다.",
             "trivy_fixed": True, "iam_limit": True},
            {"short": "읽기 · 올리기는 되게", "text": "웹 서버는 지금처럼 파일을 읽을 수 있어야 하고, 새로 파일을 올릴 수도 있어야 합니다. 권한을 줄이다가 업로드 기능이 멈추면 안 됩니다.",
             "iam_required": True, "required_good": "꼭 필요한 권한(자산 버킷 파일 읽기 · 목록 · 올리기)이 그대로 있음"},
            {"short": "다른 곳은 그대로", "text": "지적된 곳 말고는 바꾸지 말아 주세요. 이 역할을 쓸 수 있는 대상(EC2)을 바꾸거나, 새 보안 문제를 만들면 안 됩니다.",
             "iam_trust": True, "questions": ["scope", "new"]},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요.", "approved": True},
        ],
    },
    "three-tier-team-imds": {
        "seq": 7,
        "path": "scenarios/requests/three-tier-team-imds.md",
        "title": "웹 서버 메타데이터 보호(IMDSv2) 꺼짐 — 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "웹 서버가 토큰 없이도 인스턴스 메타데이터를 읽을 수 있다는 지적을 받았습니다. 토큰 방식(IMDSv2)으로만 읽게 해 주세요.",
        "handoff": {"resource": "aws_launch_template.web", "file": "web_asg.tf", "what": "시작 템플릿(웹 서버)",
                    "attrs": [{"name": "metadata_options.0.http_tokens", "want": "required"}], "rules": ["AVD-AWS-0130"],
                    "todo": ["web_asg.tf 의 시작 템플릿 metadata_options 에서 http_tokens 를 \"required\" 로 (팀 원본 값 — 원본 주석 'IMDSv2 강제')",
                             "토큰 방식을 못 쓰는 예전 모니터링 에이전트를 먼저 새 버전으로 — 안 하면 에이전트가 메타데이터를 못 읽음",
                             "시작 템플릿이 바뀌면 서버 묶음(ASG)의 서버를 새로 바꾸는 시점(인스턴스 새로 고침)을 고객과 정하기"],
                    "verify": ["새 서버에서 웹 페이지가 뜨는지 (시작 스크립트는 이미 토큰을 씀)"]},
        "items": [
            {"short": "토큰 방식(IMDSv2)만", "text": "웹 서버는 토큰 방식(IMDSv2)으로만 메타데이터를 읽게 해 주세요."},
            {"short": "웹 페이지 그대로", "text": "웹 페이지는 지금처럼 떠야 합니다 (서버 시작 스크립트는 이미 토큰을 씁니다)."},
            {"short": "서버 교체 시점은 같이", "text": "서버를 새로 바꾸는 시점은 저희와 정해 주세요 (사용자가 적은 시간에)."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-dbenc": {
        "seq": 8,
        "path": "scenarios/requests/three-tier-team-dbenc.md",
        "title": "DB 저장소 암호화 꺼짐 — 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "개인정보 점검에서 DB 저장소가 암호화되어 있지 않다는 지적을 받았습니다. 데이터는 하나도 잃지 않게 암호화해 주세요.",
        "handoff": {"resource": "aws_db_instance.mysql", "file": "rds.tf", "what": "RDS DB",
                    "attrs": [{"name": "storage_encrypted", "want": True}], "rules": ["AVD-AWS-0080"],
                    "replace": "이미 만든 DB 의 storage_encrypted 를 바꾸면 DB 를 새로 만드는 변경(교체)이 된다 — 팀 정책은 교체를 막는다(allow_replace: false)",
                    "todo": ["데이터를 옮기는 계획을 고객과 정하기: 스냅샷 → 암호화한 스냅샷 복사본 → 그 복사본으로 새 DB 복원 → 앱 연결 바꾸기 (멈추는 시간 · 되돌리는 방법 포함)",
                             "코드는 rds.tf 의 storage_encrypted = true (팀 원본 값) — plan 이 '교체' 로 나오는 것을 확인하고, 위 계획대로 사람이 반영"],
                    "verify": ["새 DB 에 데이터가 모두 있는지 (행 수 · 마지막 쓰기 시각)", "웹 서버가 새 DB 에 붙는지"]},
        "items": [
            {"short": "저장소 암호화", "text": "데이터베이스 저장소가 암호화되게 해 주세요."},
            {"short": "데이터 그대로", "text": "지금 들어 있는 데이터가 하나도 사라지면 안 됩니다."},
            {"short": "멈추는 시간은 미리", "text": "서비스가 멈추는 시간이 생기면 미리 알려 주시고, 시간을 저희와 정해 주세요."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-deletion": {
        "seq": 9,
        "path": "scenarios/requests/three-tier-team-deletion.md",
        "title": "DB 삭제 보호 꺼짐 — 운영 전환 준비 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "운영 전환을 앞두고 보니 DB 삭제 보호가 처음부터 꺼져 있었습니다(점검 결과의 중간 위험 항목). 켜 주시고, 지울 때 마지막 백업도 남게 해 주세요.",
        "handoff": {"resource": "aws_db_instance.mysql", "file": "rds.tf", "what": "RDS DB",
                    "attrs": [{"name": "deletion_protection", "want": True}, {"name": "skip_final_snapshot", "want": False}], "rules": ["AVD-AWS-0177"],
                    "todo": ["rds.tf 의 deletion_protection 을 true, skip_final_snapshot 을 false 로 (원본 주석: '운영이면 deletion_protection = true, skip_final_snapshot = false')",
                             "skip_final_snapshot = false 면 final_snapshot_identifier(마지막 스냅샷 이름)도 정해야 함",
                             "시험 환경은 destroy 가 막히므로 운영 · 시험 값을 변수로 나누기 (시험 환경을 지울 때는 먼저 삭제 보호를 끄는 순서를 문서로)"],
                    "verify": ["plan 에서 DB 가 새로 만들어지지 않는지(제자리 수정 1건)"]},
        "items": [
            {"short": "삭제 보호 · 마지막 백업", "text": "데이터베이스 삭제 보호를 켜 주세요. 지울 때 마지막 백업(스냅샷)도 남게 해 주세요."},
            {"short": "다른 설정 그대로", "text": "다른 설정은 바꾸지 말아 주세요."},
            {"short": "시험 환경 지우는 법", "text": "시험 환경을 지울 때는 어떻게 하는지 따로 알려 주세요."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-flowlog": {
        "seq": 10,
        "path": "scenarios/requests/three-tier-team-flowlog.md",
        "title": "VPC 흐름 로그 없음 — 감사 대응 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "분기 감사에서 네트워크 접속 기록(VPC 흐름 로그)이 남지 않는다는 항목이 나왔습니다(점검 결과의 중간 위험 항목). 흐름 로그를 남겨 주세요.",
        "handoff": {"resource": "aws_vpc.main", "file": "network.tf", "what": "VPC 흐름 로그",
                    "absent": {"type": "aws_flow_log", "label": "VPC 흐름 로그 (aws_flow_log)", "want": "1개 이상 (aws_vpc.main 대상)"},
                    "create": ["aws_flow_log", "aws_cloudwatch_log_group", "aws_iam_role", "aws_iam_role_policy"], "rules": ["AVD-AWS-0178"],
                    "todo": ["network.tf 에 aws_flow_log(vpc_id = aws_vpc.main.id, traffic_type 은 최소 REJECT) + 로그를 받을 로그 그룹 + 로그를 쓰는 IAM 역할을 새로 추가",
                             "로그 보관 기간 · 비용(로그 양에 비례)을 고객과 정하기"],
                    "verify": ["plan 에 aws_flow_log 1개가 새로 생기는지, 다른 리소스는 그대로인지"]},
        "items": [
            {"short": "흐름 로그 남기기", "text": "VPC 의 흐름 로그를 남겨 주세요 (적어도 막힌 접속 기록은 남게)."},
            {"short": "보관 기간 · 비용 먼저", "text": "로그를 얼마나 보관할지, 비용이 얼마나 드는지 먼저 알려 주세요."},
            {"short": "다른 설정 그대로", "text": "다른 설정은 바꾸지 말아 주세요."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "three-tier-team-backup": {
        "seq": 11,
        "path": "scenarios/requests/three-tier-team-backup.md",
        "title": "DB 자동 백업 보관 1일로 줄어듦 — 조치 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "summary": "비용을 줄이려고 DB 자동 백업 보관을 1일로 줄였다가 점검 지적을 받았습니다. 원래대로(7일) 돌려 주세요.",
        "handoff": {"resource": "aws_db_instance.mysql", "file": "rds.tf", "what": "RDS DB",
                    "attrs": [{"name": "backup_retention_period", "want": 7}], "rules": ["AVD-AWS-0077"],
                    "todo": ["rds.tf 의 backup_retention_period 를 7 로 (팀 원본 값 — 원본 주석 '자동 백업 7일 보관')",
                             "비용 문제라면 보관 기간을 고객과 다시 정하기 (Trivy 기준은 2일 이상)"],
                    "verify": ["plan 에서 DB 가 새로 만들어지지 않는지(제자리 수정 1건)"]},
        "items": [
            {"short": "백업 보관 7일", "text": "자동 백업 보관 기간을 원래대로(7일) 돌려 주세요."},
            {"short": "DB 새로 만들지 않기", "text": "DB 를 새로 만들거나 다른 설정을 바꾸면 안 됩니다."},
            {"short": "승인한 뒤에 반영", "text": "무엇이 바뀌는지 먼저 보여 주시고, 저희 담당자가 승인한 뒤에 반영해 주세요."},
        ],
    },
    "webapp-3tier": {
        "path": "scenarios/requests/webapp-3tier.md",
        "title": "접근 통제 점검 지적 조치 · 시험 환경 확인 요청",
        "from": "(가상) 3계층 웹 서비스 운영팀",
        "date": "2026-11-05",
        "summary": "보안 점검에서 Bastion 서버의 SSH(22)가 인터넷 전체에 열려 있다는 지적과, 웹 서버가 데이터베이스에 바로 붙어 있다는 의견을 받았습니다. 고치고 시험 환경에서 확인해 주세요.",
        "items": [
            {"short": "SSH 는 관리자 대역만", "text": "Bastion 서버 SSH(22)는 관리자 접속 대역(203.0.113.0/24 · 198.51.100.0/24)에서만 접속되게 해 주세요.",
             "trivy_fixed": True, "flows_ok": ["admin-bastion"], "no_extra_to": [["bastion", "22"]]},
            {"short": "사용자 접속(443) 그대로", "text": "사용자는 지금처럼 인터넷에서 HTTPS(443)로 접속할 수 있어야 하고, 웹 서버까지 요청이 전달돼야 합니다.",
             "flows_ok": ["user-alb", "alb-web"]},
            {"short": "DB 는 API 서버만", "text": "데이터베이스(3306)는 API 서버에서만 접속돼야 합니다. 웹 서버가 데이터베이스에 바로 붙으면 안 됩니다.",
             "flows_ok": ["api-db"], "no_extra_to": [["db", ""]]},
            {"short": "다른 곳은 그대로", "text": _REST, "questions": ["scope", "new"], "design_rest": True},
            {"short": "시험 환경 확인 · 승인 뒤 반영", "text": "운영에 반영하기 전에 시험 환경(샌드박스)에서 실제로 확인하고, 저희 담당자가 승인한 뒤에 반영해 주세요.",
             "aws_verified": True, "approved": True},
        ],
    },
}
LABEL = "고객 요청서"
WORD = {"good": "지킴", "bad": "어김", "unknown": "판정 불가", "wait": "아직", "dim": "승인 안 함"}
_RANK = {"bad": 0, "unknown": 1, "wait": 2, "dim": 3, "good": 4}
_Q_HOW = {"scope": "V5 허용 범위 · 정책", "new": "V2 새 문제"}
_Q_GOOD = {"scope": "지적된 곳 밖의 변경 없음 (허용 범위 안)", "new": "새로 생긴 보안 문제 없음"}


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def meta(case_id: str) -> Optional[Dict[str, Any]]:
    """화면 ② · [요청서 보기] 용 — 요청서 원문 + 조건 목록 (결과 없음). 요청서가 없는 사례(내 프로젝트 등)는 None."""
    r = REQUESTS.get(str(case_id or ""))
    if not r:
        return None
    p = _root() / r["path"]
    try:
        text = p.read_text(encoding="utf-8")[:20000]
    except OSError:
        text = ""
    from . import inbox
    arr = inbox.arrival(str(case_id))           # 16차: 팀 3계층 요청은 요청함이 받은 시각을 정한다 (요청서에는 날짜를 적지 않음)
    out = {"label": LABEL, "fictional": True, "title": r["title"], "from": r["from"],
           "date": (arr or {}).get("at_text") or r.get("date") or "", "summary": r["summary"],
           "path": r["path"], "text": text, "seq": r.get("seq"), "kind": _kind(r), "arrival": arr,
           "items": [{"n": i + 1, "short": it["short"], "text": it["text"]} for i, it in enumerate(r["items"])]}
    if r.get("handoff"):
        out["handoff"] = handoff(case_id)
    return out


def _kind(r: Dict[str, Any]) -> str:
    """요청이 무엇으로 검사되나: handoff(자동 수정 범위 밖 — 사람에게) · iam(권한 요구사항) · topology(통신 설계도)."""
    if r.get("handoff"):
        return "handoff"
    return "iam" if any(k in it for it in r.get("items") or [] for k in ("iam_limit", "iam_required", "iam_trust")) else "topology"


# ----------------------------------------------------------------------------- 자동 수정 범위 밖 → 사람에게 넘김 (15차 요청 2 S3, 16차 요청 5 · 7 ~ 11)
def _dig(vals: Any, path: str) -> Any:
    """plan 값에서 'a.0.b' 같은 경로 (목록은 숫자 칸)."""
    cur = vals
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _show(v: Any) -> str:
    if v is None:
        return "없음 (null)"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def handoff(case_id: str) -> Optional[Dict[str, Any]]:
    """정책이 자동 수정을 허용하지 않는 요청 → 사람에게 넘길 내용. 판정을 만들지 않는다 — Trivy 결과 · plan 값 · 정책 파일을 그대로 옮긴다.
    {resource, file, found[{rule, title, line, severity}], now[{attr, value, want, ok}], plan_note, why[], todo[], verify[], policy_note}
    요청마다(REQUESTS[...]["handoff"]): attrs = [{name, want}] (name 은 'metadata_options.0.http_tokens' 같은 경로도 됨),
    absent = 아직 없는 리소스 종류(예: aws_flow_log), replace = 고치면 교체가 되는 이유, create = 새로 만들어야 하는 리소스 종류."""
    r = REQUESTS.get(str(case_id or "")) or {}
    h = r.get("handoff")
    if not h:
        return None
    from ..config import load_json
    from . import cases as cs
    case = cs.get_case(case_id) or {}
    rules = list(h.get("rules") or [])
    res = str(h.get("resource") or "")
    attrs = [a if isinstance(a, dict) else {"name": str(a), "want": True} for a in h.get("attrs") or []]
    found: List[Dict[str, Any]] = []
    try:
        from ..review.inputs import list_findings, load_trivy_report
        rep_p = _root() / str(case.get("trivy_json") or "")
        for f in (list_findings(load_trivy_report(rep_p)) if rep_p.is_file() else []):
            if f.status == "FAIL" and f.rule_id in rules and f.resource == res:
                found.append({"rule": f.rule_id, "title": f.title, "line": f.start_line, "severity": f.severity, "file": Path(f.filename).name})
    except Exception:  # noqa: BLE001 — 결과 파일이 깨졌으면 '못 읽음' 으로 둔다
        found = []
    found.sort(key=lambda x: (x["line"], x["rule"]))
    now: List[Dict[str, Any]] = []
    plan_note = "원본 plan 없음 — ② 에서 점검하면 지금 값이 나옵니다"
    try:
        pp, _src = cs._baseline_plan_path(case) if case else (None, "")
        if pp is not None:
            plan = json.loads(Path(pp).read_text(encoding="utf-8"))
            rs = ((plan.get("planned_values") or {}).get("root_module") or {}).get("resources") or []
            vals = next((x.get("values") or {} for x in rs if x.get("address") == res), None)
            if vals is not None:
                for a in attrs:
                    v = _dig(vals, a["name"])
                    now.append({"attr": a["name"], "value": _show(v), "want": _show(a.get("want")), "ok": v == a.get("want")})
                ab = h.get("absent")
                if ab:
                    n = sum(1 for x in rs if x.get("type") == ab.get("type"))
                    now.append({"attr": ab.get("label") or ab.get("type"), "value": f"{n}개" + (" (코드에 없음)" if n == 0 else ""),
                                "want": ab.get("want") or "1개 이상", "ok": n > 0})
                plan_note = "원본 plan 의 값 (AWS 접속 없이 코드에서 계산)"
            else:
                plan_note = f"원본 plan 에 {res} 가 없음"
    except (OSError, ValueError):
        plan_note = "원본 plan 을 읽지 못함"
    try:
        pol = load_json(_root() / "policy" / "patch_policy.json") or {}
    except Exception:  # noqa: BLE001
        pol = {}
    sup = list(pol.get("supported_target_rules") or [])
    allowed = list(pol.get("allowed_change_resource_types") or [])
    creatable = list(pol.get("allowed_create_resource_types") or [])
    rtype = res.split(".")[0] if res else ""
    why: List[str] = []
    miss = [x for x in rules if x not in sup]
    if miss:
        why.append(f"팀 정책(policy/patch_policy.json)의 자동 수정 대상 규칙에 없음: {' · '.join(x.replace('AVD-', '') for x in miss)} "
                   f"(지금 대상 = {' · '.join(x.replace('AVD-', '') for x in sup) or '없음'})")
    if rtype and rtype not in allowed and not h.get("absent"):
        why.append(f"팀 정책의 바꿀 수 있는 리소스 종류(allowed_change_resource_types)에 없음: {rtype} — 수정안을 만들어도 V5(plan 비교)가 정책 위반으로 막음")
    need = [t for t in h.get("create") or [] if t not in creatable]
    if need:
        why.append(f"새 리소스를 만들어야 함 — 팀 정책이 새로 만들 수 있게 한 종류(allowed_create_resource_types)에 없음: {' · '.join(need)}")
    if h.get("replace"):
        why.append(str(h["replace"]))
    why.append(f"고친 뒤 '고객 요구를 지켰나' 를 재는 검사(V6)가 이 리소스({h.get('what') or rtype})에는 아직 없음")
    if not miss and (rtype in allowed or h.get("absent")) and not need and not h.get("replace"):
        why.insert(0, "정책은 허용하지만 이 예제에는 수정 묶음(요구사항 · 수정안)이 없음 — 검사기를 만든 뒤에 이어 갈 수 있음")
    todo = list(h.get("todo") or []) + ["고친 코드는 사람이 PR 로 올리고, 팀 승인 뒤 반영 (이 프로그램은 PR · 반영을 하지 않음)"]
    verify = [f"고친 코드로 다시 점검 → Trivy 지적 {' · '.join(x.replace('AVD-', '') for x in rules)} 이 없어졌는지"] + list(h.get("verify") or [])
    return {"resource": res, "file": h.get("file"), "found": found, "now": now, "plan_note": plan_note, "why": why,
            "todo": todo, "verify": verify,
            "policy_note": "자동 수정까지 가려면 팀이 정책을 넓힐지 정해야 함 (예제 README). 정책 파일은 사람만 고친다"}


def case_for_set(set_id: str) -> Optional[str]:
    """수정 묶음(set) id → 그 묶음을 가진 예제 id (요청서가 있는 것만)."""
    from . import cases as cs
    for c in cs.all_cases():
        if c.get("id") in REQUESTS and any(s.get("set_id") == set_id for s in c.get("sets") or []):
            return c["id"]
    return None


def _port_hit(want: str, text: Any) -> bool:
    """want(예: '22') 가 V6 의 포트 글자(예: '22' · '0-1023' · 'TCP 전체 포트' · '모든 프로토콜·포트')에 들어가나. want 가 비면 모든 포트."""
    if not want:
        return True
    t = str(text or "")
    if "전체" in t or "모든" in t:
        return True
    for part in t.replace(" ", "").split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit() and int(a) <= int(want) <= int(b):
                return True
        elif part == want:
            return True
    return False


def _line(e: Dict[str, Any]) -> str:
    return f"{e.get('src_label') or e.get('src')} → {e.get('dst_label') or e.get('dst')} :{e.get('ports')}"


_TRUST = "trust policy"
_UNK_KO = (("policy value unknown at plan time", "정책 값이 plan 에 없고 코드에서도 읽지 못함"),
           ("Condition not evaluated", "조건(Condition)이 있는 문은 판정하지 않음"),
           ("NotAction not supported", "NotAction 은 판정하지 않음"), ("NotResource not supported", "NotResource 는 판정하지 않음"),
           ("Effect=", "Deny 등 Allow 가 아닌 문은 판정하지 않음"),
           ("content not evaluated", "요구사항에 없는 AWS 관리형 정책이 붙음 (내용을 읽지 않음)"),
           ("internal reference token", "정책 글자가 내부 참조 표기(tf:)처럼 생겨 판정하지 않음"),
           ("is not evaluated in Tier 1", "다른 방식으로 붙는 정책(attachment 목록 등)은 판정하지 않음"))


def _res_ko(r: str) -> str:
    r = str(r).strip()
    return "모든 리소스(*)" if r == "*" else r


def _iam_findings(det: Dict[str, Any]) -> Dict[str, List[str]]:
    """V6 IAM details(to_dict) → {limit: [], required: [], trust: [], unknown: [], required_unknown: [], trust_unknown: []} (화면 글, 겹침 제거).
    excess 중 신뢰 정책(trust policy) 것은 trust 로, 나머지는 limit 으로. missing 은 required 로. 판정은 오라클 값 그대로."""
    out: Dict[str, List[str]] = {k: [] for k in ("limit", "required", "trust", "unknown", "required_unknown", "trust_unknown")}

    def add(k: str, v: str) -> None:
        if v not in out[k]:
            out[k].append(v)
    for sc in det.get("scopes") or []:
        for e in sc.get("excess") or []:
            t = str(e)
            if _TRUST in t:
                add("trust", "누구나 이 역할을 맡을 수 있음 — 신뢰 정책의 Principal 이 * (조건 없음)")
                continue
            m = re.match(r"^(.*?): (\S+) on (.+)$", t)
            add("limit", f"요구사항 밖 권한: {m.group(2)} → {_res_ko(m.group(3))}" if m else t[:160])
        for mm in sc.get("missing") or []:
            t = str(mm)
            m = re.match(r"^[^:]+: (\S+) on (.+?) not allowed", t)
            add("required", f"꼭 필요한 권한이 없음: {m.group(1)} → {_res_ko(m.group(2))}" if m else
                ("대상 역할이 plan 에서 사라짐 (지우거나 이름을 바꿈)" if "absent from the plan" in t else t[:160]))
        for u in sc.get("unknown_reasons") or []:
            t = str(u)
            ko = next((k for en, k in _UNK_KO if en in t), t[:140])
            if "only unevaluated statements could grant it" in t:
                add("required_unknown", "꼭 필요한 권한이 판정한 문에는 없음 — 판정하지 못한 문이 줄 수도 있어 판정 불가")
            elif "assume_role_policy" in t:
                add("trust_unknown", f"신뢰 정책 — {ko}")
            else:
                add("unknown", ko)
    return out


def _evaluate(spec: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    items = spec["items"]
    v6 = ctx.get("v6") or {}
    v6v = str(v6.get("verdict") or "")
    det = v6.get("details") if isinstance(v6.get("details"), dict) else {}
    flows = {str(f.get("id")): f for f in det.get("flows") or []}
    excess = list(det.get("excess") or [])
    # 대상을 정해 둔 조건이 먼저 가져간 V6 항목 — '그 밖' 조건(design_rest)에서는 뺀다
    claimed_flows = {fid for it in items for fid in it.get("flows_ok") or []}
    targets = [(t, p) for it in items for t, p in it.get("no_extra_to") or []]
    claimed_ex = {i for i, e in enumerate(excess) if any(e.get("dst") == t and _port_hit(p, e.get("ports")) for t, p in targets)}
    qs = {q.get("key"): q for q in ctx.get("questions") or []}
    dec = ctx.get("decision") or {}
    post = ctx.get("post") or {}
    draft = bool(ctx.get("draft"))
    out: List[Dict[str, Any]] = []
    for n, it in enumerate(items, 1):
        parts: List[Tuple[str, str]] = []      # (tone, 근거 한 줄)
        how: List[str] = []
        v6_parts: List[Tuple[str, str]] = []
        if it.get("trivy_fixed"):
            how.append("V1 Trivy 다시 검사")
            v1 = str(ctx.get("v1") or "")
            rule = ctx.get("rule") or "이번 지적"
            parts.append(("good", f"Trivy 다시 검사: {rule} 지적이 없어짐") if v1 == "PASS" else
                         ("bad", f"Trivy 다시 검사: {rule} 지적이 그대로 남음") if v1 == "FAIL" else
                         ("unknown", "Trivy 다시 검사를 하지 못함"))
        if it.get("flows_ok") or it.get("no_extra_to") or it.get("design_rest"):
            how.append("V6 설계도 비교")
            if v6v not in ("PASS", "FAIL"):
                why = (f"설계도 비교 판정 불가 — {str(v6.get('summary') or '')[:120]}" if v6v in ("UNKNOWN", "ERROR")
                       else "설계도 비교(V6)를 하지 못함 — 이 수정안은 그 앞 단계에서 멈춤")
                v6_parts.append(("unknown", why))
            else:
                for fid in it.get("flows_ok") or []:
                    f = flows.get(fid)
                    if not f:
                        v6_parts.append(("unknown", f"설계도에 이 통신({fid})이 없음 — ③ 에서 설계도를 바꿨다면 요청 조건과 다시 맞춰야 함"))
                    elif f.get("status") == "ok":
                        v6_parts.append(("good", f"{_line(f)} 허용됨"))
                    elif f.get("status") == "broken":
                        v6_parts.append(("bad", f"{_line(f)} — 허용 규칙 없음 (요청한 통신이 막힘)"))
                    else:
                        v6_parts.append(("unknown", f"{_line(f)} — 판정 불가"))
                for t, p in it.get("no_extra_to") or []:
                    hit = [e for e in excess if e.get("dst") == t and _port_hit(p, e.get("ports"))]
                    if hit:
                        v6_parts += [("bad", f"{_line(e)} — 요청에 없는 통신") for e in hit]
                    else:
                        lab = next((f.get("dst_label") for f in flows.values() if f.get("dst") == t), None) or t
                        v6_parts.append(("good", f"그 밖의 출발지에서 {lab}{' :' + p if p else ''} 로 들어오는 허용 없음"))
                if it.get("design_rest"):
                    rest = [("bad", f"{_line(e)} — 설계도에 없는 통신") for i, e in enumerate(excess) if i not in claimed_ex]
                    rest += [("bad", f"{_line(f)} — 허용 규칙 없음 (설계도에 있는 통신이 막힘)") for fid, f in flows.items()
                             if fid not in claimed_flows and f.get("status") == "broken"]
                    v6_parts += rest or [("good", "그 밖에 설계도와 다른 통신 없음")]
            if draft:      # D-38: 초안 기준으로는 '지킴' 이라고 하지 않는다
                v6_parts = [("unknown", f"{w} — 초안 기준") if t == "good" else (t, w) for t, w in v6_parts]
            parts += v6_parts
        if it.get("iam_limit") or it.get("iam_required") or it.get("iam_trust"):
            # 15차 (D-51): 권한 요구사항(V6 IAM) — 오라클의 excess · missing · unknown 을 조건에 나눠 담는다
            read_code = any("에서 읽음" in str(x) for x in det.get("info") or [])
            how.append("V6 IAM 요구사항 검사" + (" (정책은 코드에서 읽음)" if read_code else ""))
            ip: List[Tuple[str, str]] = []
            if v6v not in ("PASS", "FAIL"):
                f0 = _iam_findings(det) if det.get("kind") == "iam" else {"unknown": []}
                ip.append(("unknown", f"요구사항 검사 판정 불가 — {(f0.get('unknown') or [str(v6.get('summary') or '')[:120]])[0]}" if v6v in ("UNKNOWN", "ERROR")
                           else "요구사항 검사(V6)를 하지 못함 — 이 수정안은 그 앞 단계에서 멈춤"))
            elif det.get("kind") != "iam":
                ip.append(("unknown", "이 기록의 V6 는 권한(IAM) 검사가 아님 — 요구사항 파일을 확인"))
            else:
                f = _iam_findings(det)
                if it.get("iam_limit"):
                    ip += ([("bad", x) for x in f["limit"]] or [("unknown", x) for x in f["unknown"]]
                           or [("good", "요구사항이 허용한 권한 밖은 없음 (다른 버킷 · 다른 서비스 권한 없음)")])
                if it.get("iam_required"):
                    ip += ([("bad", x) for x in f["required"]] or [("unknown", x) for x in f["required_unknown"]]
                           or [("good", it.get("required_good") or "꼭 필요한 권한(자산 버킷 파일 읽기 · 목록)이 그대로 있음")])
                if it.get("iam_trust"):
                    ip += ([("bad", x) for x in f["trust"]] or [("unknown", x) for x in f["trust_unknown"]]
                           or [("good", "역할을 맡을 수 있는 대상(신뢰 정책)을 누구나로 열지 않음")])
            if draft:      # D-38 · D-51: 요구사항이 초안이면 '지킴' 이라고 하지 않는다
                ip = [("unknown", f"{w} — 초안 기준") if t == "good" else (t, w) for t, w in ip]
            parts += ip
        for key in it.get("questions") or []:
            how.append(_Q_HOW.get(key, key))
            q = qs.get(key) or {}
            tone = q.get("tone")
            first = str(((q.get("problems") or [{}])[0] or {}).get("what") or "") if q.get("problems") else ""
            first = first if len(first) <= 80 else first[:78] + "…"
            if tone == "good":
                parts.append(("good", _Q_GOOD.get(key, str(q.get("answer") or ""))))
            elif tone == "bad":
                parts.append(("bad", f"{q.get('question') or key} — {q.get('answer')}" + (f" ({first})" if first else "")))
            else:
                parts.append(("unknown", f"{q.get('question') or key} — {q.get('answer') or '검사 못 함'}"))
        if it.get("aws_verified"):
            how.append("⑦ AWS 시험 환경")
            st = str(post.get("status") or "")
            parts.append(("good", "AWS 시험 환경(샌드박스)에서 확인됨 — 운영 반영 뒤 확인은 아님") if st == "VERIFIED" else
                         ("bad", "AWS 시험 환경 적용 실패") if st == "DEPLOY_FAILED" else
                         ("bad", "AWS 시험 환경 반영 전 차단 (plan 에 교체 · 삭제)") if st == "PLAN_BLOCKED" else
                         ("unknown", "AWS 시험 환경 판정 불가") if st == "UNVERIFIED" else
                         ("wait", "아직 — ⑦ 시험 환경 검사 전"))
        if it.get("approved"):
            how.append("⑧ 사람 승인")
            d = str(dec.get("decision") or "")
            at = str(dec.get("at") or "")[:16].replace("T", " ")
            parts.append(("good", f"{dec.get('by') or '담당자'} 승인{' · ' + at if at else ''} — 반영(apply)은 이 프로그램이 하지 않음 (PR 병합 뒤 사람이)") if d == "APPROVED" else
                         ("wait", "아직 — ⑧ 에서 담당자가 승인하기 전 (이 프로그램은 반영하지 않음)") if not d else
                         ("dim", f"{ctx.get('decision_ko') or d} — 승인하지 않아 반영하지 않음"))
        tone = min((t for t, _ in parts), key=lambda t: _RANK[t]) if parts else "unknown"
        word = WORD[tone]
        if tone == "unknown" and draft and all(t == "good" or w.endswith("초안 기준") for t, w in parts):
            word = "지킴 — 초안 기준"
        # 근거 줄: 어긴 · 모르는 것 먼저, 지킨 것은 그 뒤 (예: CIDR 쪼개기 = '✕ 요청에 없는 통신' + '✓ Trivy 지적 없어짐' — Trivy 통과 ≠ 요청 충족)
        lines = sorted(parts, key=lambda x: _RANK[x[0]])[:4]
        out.append({"n": n, "short": it["short"], "text": it["text"], "tone": tone, "word": word, "how": " · ".join(how),
                    "lines": [{"tone": t, "text": w} for t, w in lines], "why": [w for _, w in lines]})
    cnt = {k: sum(1 for x in out if x["tone"] == k) for k in WORD}
    words = [f"{WORD[k]} {cnt[k]}" for k in ("good", "bad", "unknown", "wait", "dim") if cnt[k] or k == "good"]
    return {"items": out, "counts": cnt, "line": f"고객 요청 조건 {len(out)}개 — " + " · ".join(words)}


def check(case_id: str, ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """요청서가 있는 예제의 기록 하나 → 조건마다 결과. ctx: v1(V1 verdict) · v6(V6 layer: verdict · summary · details) · rule ·
    questions(⑥ 질문 행) · decision · decision_ko · post(post_deploy) · draft(설계도 초안 기준) · basis(설계도 출처)."""
    spec = REQUESTS.get(str(case_id or ""))
    if not spec:
        return None
    m = meta(case_id) or {}
    res = _evaluate(spec, ctx)
    note = ""
    iam = _kind(spec) == "iam"
    word, wga, wro = ("요구사항", "요구사항이", "요구사항으로") if iam else ("설계도", "설계도가", "설계도로")
    if ctx.get("draft"):
        note = f"{wga} 초안(확정 전)이라 {wro} 정하는 조건은 '초안 기준' — ③ 에서 담당자가 확정한 뒤 다시 검사해야 '지킴' 으로 봅니다."
    elif ctx.get("basis") == "manifest":
        note = f"{'요구사항 검사' if iam else '설계도 비교'}의 기준 = 팀이 작성한 평가 기준 {word} (고객이 확정한 {word} 아님)."
    return {**{k: m.get(k) for k in ("label", "fictional", "title", "from", "date", "summary", "path", "seq", "kind")}, **res, "note": note}


def record_ctx(record_dir: Path, rv: Dict[str, Any], questions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """기록 폴더(verification.json) + record_view + ⑥ 질문 → check() 의 ctx. 기록 값만 읽는다."""
    try:
        v = json.loads((record_dir / "verification.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        v = {}
    L = {l.get("layer"): l for l in (v.get("report") or {}).get("layers") or []}
    v1 = L.get("V1") or {}
    tgt = str(((v1.get("details") or {}) if isinstance(v1.get("details"), dict) else {}).get("target_key") or "")
    conf = (((rv.get("design") or {}).get("recorded") or {}).get("confirmation")) or None
    conf = conf if isinstance(conf, dict) else None
    return {"v1": v1.get("verdict"), "v6": L.get("V6") or {}, "rule": tgt.split("|")[0] if tgt else "",
            "questions": questions, "decision": rv.get("decision") or {}, "decision_ko": rv.get("decision_ko"),
            "post": rv.get("post_deploy") or {}, "draft": bool(conf) and not conf.get("confirmed"), "basis": (conf or {}).get("basis")}


def markdown(res: Optional[Dict[str, Any]]) -> str:
    """PR 본문 맨 위(끝맺음 아래)에 붙는 '고객 요청' 칸. res = check() 결과."""
    if not res or not res.get("items"):
        return ""
    lines = [f"## 고객 요청 (가상 · 예제) — {res.get('title')}", f"{res.get('from')} · {res.get('date')} · 요청서 `{res.get('path')}`", ""]
    for it in res["items"]:
        lines.append(f"{it['n']}. {it['text']} — **{it['word']}** ({it['how']}){': ' + it['why'][0] if it.get('why') else ''}")
    if res.get("note"):
        lines += ["", f"> {res['note']}"]
    return "\n".join(lines)
