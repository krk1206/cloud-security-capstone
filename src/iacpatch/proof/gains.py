"""우리에게 남는 것 — 단계마다 '이 결과로 우리 팀이 무엇을 말할 수 있고, 무엇은 아직 말할 수 없고, 그래서 다음에 무엇을 하나'.

프로그램이 남긴 파일(근거 파일)과는 다르다. 파일은 아래 문장들의 근거로 따로 보여 준다.
문장은 카드의 판정 값(기록에 있는 값)으로만 고른다. 이 모듈은 판정을 새로 내리지 않는다.
"""
from __future__ import annotations

from typing import Any, Dict, List

# 단계별 문장. {s} 자리에는 카드 요약(기록에서 꺼낸 숫자)이 들어간다.
_TEXT: Dict[str, Dict[str, Any]] = {
    "V1": {
        "PASS": "이 후보가 처음 지적된 문제를 없앴다고 말할 수 있다 — 같은 Trivy 로 수정 전·후를 다시 검사한 결과 ({s})",
        "FAIL": "이 후보는 처음 지적된 문제를 고치지 못했다 — 수정 후에도 같은 규칙이 다시 나왔다 ({s})",
        "not_yet": ["Trivy 가 모르는 방식으로 다시 열어 둔 경우(예: 0.0.0.0/0 을 두 대역으로 나눠 적기)는 아직 모른다 → V6 에서 대역을 합쳐 계산"],
    },
    "V2": {
        "PASS": "고치면서 Trivy 가 아는 새 문제(HIGH 이상)를 만들지 않았다고 말할 수 있다 ({s})",
        "FAIL": "고치면서 새 문제를 만들었다 ({s})",
        "not_yet": ["Trivy 규칙에 없는 새 문제, MEDIUM·LOW 지적은 이 단계로는 말할 수 없다"],
    },
    "V3": {
        "PASS": "후보 코드는 Terraform 이 읽을 수 있는 코드다 — 문법·스키마·참조가 맞다 ({s})",
        "FAIL": "후보 코드는 Terraform 이 읽지 못한다 — 그대로 배포하면 바로 실패한다 ({s})",
        "not_yet": ["문법이 맞다는 것만으로는 보안상 맞다고 말할 수 없다"],
    },
    "V4": {
        "PASS": "후보로 실행 계획을 만들 수 있고, 무엇이 만들어지는지 목록이 남았다 ({s})",
        "FAIL": "후보로 실행 계획을 만들지 못했다 — 배포 단계에서 실패할 코드다 ({s})",
        "not_yet": ["실제 AWS 상태와 비교했을 때 교체·삭제가 생기는지는 아직 모른다 → 2차 검사에서 실제 상태로 plan"],
    },
    "V5": {
        "PASS": "후보가 바꾼 것은 허용한 리소스·속성 안이다 — 다른 리소스를 건드리거나 지우지 않았다 ({s})",
        "FAIL": "후보가 허용 범위를 넘었다 — 확신도와 상관없이 막는다 ({s})",
        "not_yet": ["허용된 속성 안에서 값을 어떻게 바꿨는지(어디를 열었는지)는 이 단계로는 말할 수 없다 → V6"],
    },
    "V6": {
        "PASS": "보안 그룹 규칙을 계산하면 설계도 통신은 모두 열리고, 설계도에 없는 들어오는 통신은 모두 막힌다 ({s})",
        "FAIL": "후보를 적용하면 설계도와 다르게 열리거나 끊기는 통신이 생긴다 ({s})",
        "not_yet": ["계산 결과다 — 실제 AWS 에 적용된 값(V7)과 실제 연결(V8)은 2차 검사 전에는 말할 수 없다"],
    },
    "V7": {
        "PASS": "실제 AWS 에 적용된 보안 그룹을 읽어 같은 계산을 해도 설계도와 같다 ({s})",
        "FAIL": "실제 AWS 에 적용된 보안 그룹이 설계도와 다르다 ({s})",
        "not_yet": ["규칙이 맞아도 실제로 연결되는지는 V8 전에는 말할 수 없다"],
    },
    "V8": {
        "PASS": "시험 환경 안 측정 지점에서 실제로 연결해 보니 설계도 통신은 열리고 막아야 할 통신은 응답 없이 막혔다 ({s})",
        "FAIL": "실제 연결 결과가 설계도와 다르다 ({s})",
        "not_yet": ["축소판 시험 환경 기준이다 (서버 1대씩, DB·Redis 는 포트만 여는 대역 프로그램) — 실제 서비스 구성에서의 동작까지는 말할 수 없다"],
    },
}
_ORDER = ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"]
_NEXT_PASS = {"V1": "V2", "V2": "V3", "V3": "V4", "V4": "V5", "V5": "V6", "V6": "2차 검사 (V7·V8)", "V7": "V8"}


def for_card(c: Dict[str, Any]) -> Dict[str, Any]:
    """카드 한 장 → {say, not_yet, next}. 판정이 없거나 기록이 없으면 비운다."""
    layer = c.get("layer") or ""
    t = _TEXT.get(layer)
    v = c.get("verdict")
    if not t or c.get("status") != "done" or not v:
        return {"say": [], "not_yet": [], "next": ""}
    s = (c.get("summary") or c.get("reason") or "").strip()
    if v in ("PASS", "WARN"):
        say = [t["PASS"].format(s=s)]
        nxt = f"다음: {_NEXT_PASS[layer]}" if layer in _NEXT_PASS else "1·2차를 모두 통과 — 사람이 APPLY 여부를 결정할 수 있다"
        not_yet = list(t["not_yet"])
    elif v == "FAIL":
        say = [t["FAIL"].format(s=s)]
        nxt = "이 후보는 여기서 막는다 — 배포하지 않는다 (사람이 고쳐서 다시 넣거나 재생성 요청)"
        not_yet = []
    else:
        say = [f"이 단계는 판정하지 못했다 — 통과로 치지 않는다 ({s})"]
        nxt = "판정 불가의 이유를 해결하고 다시 검사한다"
        not_yet = list(t["not_yet"])
    return {"say": say, "not_yet": not_yet, "next": nxt}


def summary(cards: List[Dict[str, Any]], post_cards: List[Dict[str, Any]], blocked_before: Dict[str, Any] = None) -> Dict[str, Any]:
    """검사 전체 → 이 후보에 대해 지금 말할 수 있는 것 / 아직 말할 수 없는 것 / 결정."""
    if blocked_before:
        vio = "; ".join(blocked_before.get("violations") or []) or "policy.json 참고"
        return {"say": [{"layer": "정책", "verdict": "FAIL",
                         "text": f"이 후보에는 팀 정책이 막는 내용이 있다 ({vio}) — 검사(V1~V6)를 시작하기 전에 막았다. 확신도와 상관없다"}],
                "not_yet": ["검사를 시작하지 않았으므로 V1~V6 의 결과(지적이 사라졌는지, 설계도와 같은지)는 이 기록으로 말할 수 없다"],
                "decision": "차단 — 검사 전 정책 확인에서 막힘. 이 후보는 배포 대상이 아니다", "first_fail": "정책"}
    by = {c.get("layer"): c for c in list(cards) + list(post_cards)}
    say: List[Dict[str, str]] = []
    first_fail = None
    for k in _ORDER:
        c = by.get(k)
        if not c or c.get("status") != "done" or not c.get("verdict"):
            continue
        g = c.get("gains") or for_card(c)
        for line in g.get("say") or []:
            say.append({"layer": k, "text": line, "verdict": c.get("verdict")})
        if c.get("verdict") == "FAIL" and first_fail is None:
            first_fail = k
    done = {k for k in _ORDER if (by.get(k) or {}).get("status") == "done" and (by.get(k) or {}).get("verdict")}
    first_ok = all((by.get(k) or {}).get("verdict") in ("PASS", "WARN") for k in _ORDER[:6] if k in done) and all(k in done for k in _ORDER[:6])
    second_ok = all((by.get(k) or {}).get("verdict") == "PASS" for k in ("V7", "V8")) and {"V7", "V8"} <= done
    not_yet: List[str] = []
    if first_fail:
        decision = f"차단 — {first_fail} 에서 실패. 이 후보는 배포 대상이 아니다"
    elif not first_ok:
        decision = "1차 검사가 끝나지 않았거나 판정 불가가 있다 — 아직 통과가 아니다"
        not_yet.append("1차 검사(V1~V6) 중 끝나지 않았거나 판정하지 못한 단계가 있다")
    elif not second_ok:
        decision = "1차 통과 — 실제 AWS 에서 다시 재는 2차 검사(V7·V8) 대상"
        if not ({"V7", "V8"} & done):
            not_yet.append("실제 AWS 에 적용했을 때 설정이 같은지(V7)와 실제로 연결되는지(V8)는 아직 모른다 — 2차 검사 기록 없음")
        else:
            not_yet.append("2차 검사(V7·V8)에 통과하지 못한 단계가 있다 — 위 문장 참고")
    else:
        decision = "1·2차 통과 — 사람이 APPLY 를 결정할 수 있다 (자동 apply 는 하지 않는다)"
        not_yet.extend(_TEXT["V8"]["not_yet"])
    not_yet.append("이 검사가 보는 범위는 보안 그룹(들어오는 통신)이다 — IAM·S3 같은 다른 종류의 설정 오류는 이 기록으로 말할 수 없다")
    return {"say": say, "not_yet": not_yet, "decision": decision, "first_fail": first_fail}
