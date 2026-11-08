"""실제 AWS 검사 — 실제 AWS 시험 환경 측정 (V7 배포된 설정 조회, V8 접속 시험). 3계층 설계도(topology) 형식 전용.

하는 일 (전부 읽기·연결 시도만):
  1. 시험 환경 폴더에서 `terraform show -json` (이 PC 의 상태 파일 읽기, AWS 변경 없음)
     → 보안 그룹 주소 ↔ GroupId, 서버 인스턴스 ID, 출력값(ALB 주소)
  2. V7: `aws ec2 describe-security-groups` / `describe-network-interfaces` → 보안 그룹 규칙과 붙은 위치를 AWS 에서 직접 읽고
     설계도 비교(V6 와 같은 계산)를 다시 한다. 보안 그룹 이름은 GroupId 로 바꿔 계산하고 결과에서만 주소로 되돌린다.
  3. V8: 시험 환경 안 측정 지점 5곳(웹·API·Bastion·관리자 지점·인터넷 지점)이 잰 TCP 연결 결과를 모은다
     (측정기는 목적지를 차례로 시험하고 15초 쉰 뒤 다시 한다 — 응답 없음 1건이 3초라 한 바퀴는 2026-10-23 실측 약 19~28초).
       - `aws ec2 get-console-output --latest` (읽기 전용): 측정기가 직렬 콘솔에 찍은 'IACPATCH-PROBE {json}' 줄
       - HTTP: 이 PC → ALB 443 → 웹 80 의 /probe.json (웹이 NLB 8080 → API 8080 으로 받아 온 API 결과 포함)
     이 PC 에서 하는 연결 시험(ALB 443)과 HTTP 결과는 '참고' 로만 적는다 (학교망 방화벽·프록시 영향을 배제할 수 없음).
하지 않는 일: terraform apply / destroy, AWS 리소스 생성·변경·삭제. 시험 환경 배포·삭제는 사람이 한다.

판정 규칙 (V8)
  열려야 하는 통신(설계도 화살표): open → 통과, 그 밖 → 실패
  막혀야 하는 통신(설계도에 없음): timeout → 통과 (보안 그룹은 막을 때 응답 없이 버린다), open → 실패,
      refused → 판정 불가 (패킷이 서버까지 갔다는 뜻 — 보안 그룹이 막았다는 증거 아님), 오류 → 판정 불가
  새로 잰 값만: apply 가 끝나고 2분 뒤부터 측정하고(proof_api), 측정 시작 때 본 결과 번호(seq)보다 2 이상 커진 결과만 쓴다 (시계 차이와 무관).
      콘솔 출력은 20~40초 늦게 보일 수 있다 (2026-10-23 실측) — 두 규칙을 합쳐 apply 전에 시작된 측정을 판정에 쓰지 않는다.
  설계 통신 9개가 모두 시험 환경 안 측정 지점의 실제 시험으로 확인돼야 통과. 하나라도 못 재면 판정 불가.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import socket
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import Settings
from .evidence_log import CommandLog, now_iso, write_manifest
from .models import LayerResult, Verdict
from .tools.awscli import AwsCli, AwsError, build_world_from_aws
from .tools.terraform import TerraformAdapter
from .verify.combine import combine

ACCOUNT_RE = re.compile(r"\b\d{12}\b")


def _design_copy(intent_path: Path, out_dir: Path) -> Optional[Dict[str, Any]]:
    """실제 AWS 검사가 쓴 설계 기준 — 측정 폴더에 바이트 그대로 사본(design.json)을 두고 id · 버전 · sha256 을 돌려준다 (2026-10-31, 피드백 1).
    설계도가 나중에 바뀌어도 이 측정은 당시 기준으로 해석된다."""
    try:
        raw = intent_path.read_bytes()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "design.json").write_bytes(raw)
        meta = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return {"intent_id": str(meta.get("intent_id") or ""), "intent_version": str(meta.get("intent_version") or ""),
            "sha256": hashlib.sha256(raw).hexdigest(), "copy": "design.json"}


def mask(s: str) -> str:
    return ACCOUNT_RE.sub("############", s or "")


def _sha(p: Path) -> Optional[str]:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


class LoggedAws(AwsCli):
    """AwsCli 와 같고, 호출마다 명령·시각·걸린 시간·결과 크기를 기록한다 (출력 원문은 따로 저장)."""

    def __init__(self, clog: CommandLog, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.clog = clog
        self.layer = "V7"

    def call(self, *args: str, timeout: int = 120) -> Any:
        t0 = time.time()
        started = now_iso()
        try:
            out = super().call(*args, timeout=timeout)
        except AwsError as e:
            self.clog.add("aws:" + " ".join(args[:2]), self.layer, self._base() + list(args), returncode=1, started_at=started,
                          elapsed=round(time.time() - t0, 2), stderr=mask(str(e)), ok=False)
            raise
        self.clog.add("aws:" + " ".join(args[:2]), self.layer, self._base() + list(args), returncode=0, started_at=started,
                      elapsed=round(time.time() - t0, 2), ok=True, note=f"응답 {len(json.dumps(out))} bytes")
        return out


# ----------------------------------------------------------------------------- 시험 환경 상태
def testbed_state(tf: TerraformAdapter, testbed: Path, clog: CommandLog) -> Dict[str, Any]:
    out = tf.state_show_json(testbed)
    r = out.result
    clog.add("terraform:show-state", "V7", r.argv if r else None, cwd=str(testbed), returncode=r.returncode if r else None,
             started_at=out.started_at, elapsed=out.elapsed, stderr=(r.stderr if r else out.error)[-600:], ok=out.ok,
             note="이 PC 의 상태 파일만 읽음 (AWS 변경 없음)")
    if not out.ok:
        return {"ok": False, "error": out.error[:600]}
    vals = out.data.get("values") or {}
    ids: Dict[str, str] = {}
    hosts: Dict[str, Dict[str, Any]] = {}
    count = [0]

    def walk(mod: Dict[str, Any]) -> None:
        for res in mod.get("resources") or []:
            count[0] += 1
            v = res.get("values") or {}
            if res.get("type") == "aws_security_group" and v.get("id"):
                ids[res["address"]] = v["id"]
            if res.get("type") == "aws_instance":
                hosts[res["address"]] = {"private_ip": v.get("private_ip"), "public_ip": v.get("public_ip"), "id": v.get("id")}
        for c in mod.get("child_modules") or []:
            walk(c)
    walk(vals.get("root_module") or {})
    outputs = {k: (v or {}).get("value") for k, v in (vals.get("outputs") or {}).items()}
    return {"ok": True, "sg_ids": ids, "instances": hosts, "outputs": outputs, "resources": count[0]}


def translate_world(world: Any, id_to_addr: Dict[str, str]) -> Any:
    """AWS 에서 읽은 세계(GroupId 기준)를 설계도의 보안 그룹 주소 기준으로 바꾼다. 매핑에 없는 ID 는 그대로 둔다(→ 판정 불가 처리)."""
    new = {}
    for gid, m in world.security_groups.items():
        addr = id_to_addr.get(gid, gid)
        m.address = addr
        m.aws_id = gid
        for r in m.rules:
            for s in r.sources:
                if s.kind == "sg":
                    s.value = id_to_addr.get(s.value, s.value)
                elif s.kind == "self":
                    s.value = addr
            r.origin = f"{addr} ({gid}) {r.origin.split('#', 1)[-1]}"
        new[addr] = m
    world.security_groups = new
    for a in world.attachments:
        a.sg_refs = [id_to_addr.get(x, x) for x in a.sg_refs]
    return world


def v7_topology(cli: AwsCli, spec: Any, ids: Dict[str, str]) -> Tuple[LayerResult, Dict[str, Any]]:
    from .verify.topology_oracle import evaluate
    missing = [t.security_group for t in spec.tiers if t.security_group not in ids]
    if missing:
        return LayerResult("V7", "AWS 적용 규칙 조회", Verdict.UNKNOWN, f"상태 파일에 없는 보안 그룹: {missing}", {"missing": missing}, False, "aws cli"), {}
    if not cli.available():
        return LayerResult("V7", "AWS 적용 규칙 조회", Verdict.NOT_RUN, f"aws CLI 없음 ({cli.binary})", {}, False, "aws cli"), {}
    try:
        world, raw = build_world_from_aws(cli, [ids[t.security_group] for t in spec.tiers])
    except AwsError as e:
        return LayerResult("V7", "AWS 적용 규칙 조회", Verdict.ERROR, mask(str(e))[:600], {}, True, "aws cli"), {}
    id_to_addr = {v: k for k, v in ids.items()}
    translate_world(world, id_to_addr)
    rep = evaluate(world, spec)
    det = rep.to_dict()
    det["id_map"] = {k: v for k, v in ids.items()}
    det["attachments"] = [{"eni": a.address, "sgs": a.sg_refs} for a in world.attachments]
    det["rules"] = {addr: [{"direction": r.direction, "protocol": r.protocol, "from_port": r.from_port, "to_port": r.to_port,
                            "sources": [s.value if s.kind != "prefix_list" else f"{s.value}→{s.resolved_cidrs}" for s in r.sources],
                            "origin": r.origin} for r in m.rules if r.direction == "ingress"]
                    for addr, m in world.security_groups.items()}
    det["source"] = "AWS describe-security-groups / describe-network-interfaces (배포 후 실제 적용 값)"
    return LayerResult("V7", "AWS 적용 규칙 조회", rep.verdict, rep.summary[:1500], det, True, "aws cli"), raw


# ----------------------------------------------------------------------------- V8
def tcp_probe(host: str, port: int, timeout: float = 4.0) -> Dict[str, Any]:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(1.5)
                banner = s.recv(64).decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                pass
            return {"result": "open", "ms": int((time.time() - t0) * 1000), "banner": banner[:60]}
    except socket.timeout:
        return {"result": "timeout", "ms": int((time.time() - t0) * 1000)}
    except ConnectionRefusedError:
        return {"result": "refused", "ms": int((time.time() - t0) * 1000)}
    except OSError as e:
        return {"result": f"error:{e.__class__.__name__}", "ms": int((time.time() - t0) * 1000), "error": str(e)[:160]}


def judge(expect: str, result: str, stale: bool = False) -> Tuple[str, str]:
    """(PASS|FAIL|UNKNOWN, 이유)"""
    if stale:
        return "UNKNOWN", "측정 시작 후 신규 측정값 아님"
    if expect == "open":
        return ("PASS", "접속 성공") if result == "open" else ("FAIL", f"허용 경로인데 접속 실패: {result}")
    if result == "timeout":
        return "PASS", "접속 차단 (응답 없음 — 보안 그룹 차단)"
    if result == "open":
        return "FAIL", "차단 경로인데 접속 성공"
    if result == "refused":
        return "UNKNOWN", "연결 거부 — 패킷이 서버까지 도달 (보안 그룹 차단 증거 아님)"
    return "UNKNOWN", f"측정 오류 ({result})"


# ----------------------------------------------------------------------------- 측정 지점 (vantage)
# from 키 → 설계도의 출발 주체(entity)와 화면 이름, 상태 파일의 인스턴스 주소
VANTAGES: Dict[str, Dict[str, str]] = {
    "web": {"entity": "web", "label": "웹 서버", "instance": "aws_instance.web"},
    "api": {"entity": "api", "label": "API 서버", "instance": "aws_instance.api"},
    "bastion": {"entity": "bastion", "label": "Bastion", "instance": "aws_instance.bastion"},
    "admin": {"entity": "admin", "label": "관리자 지점 (허용 목록 내 198.51.100.10)", "instance": "aws_instance.admin_vantage"},
    "outsider": {"entity": "internet", "label": "인터넷 지점 (허용 목록 밖, 공인 IP)", "instance": "aws_instance.outsider"},
}
# 측정기가 HTTP 로 받아 오는 경로 시험: 이름 → 거치는 설계 구간(출발, 도착, 포트)과 '도착 서버가 직접 답했다' 는 표시
PATHS: Dict[str, Dict[str, Any]] = {
    "api-via-nlb": {"legs": [("web", "nlb", 8080), ("nlb", "api", 8080)], "to": "api", "port": 8080,
                    "how": "웹 서버가 NLB 8080 을 통해 API 서버의 /probe.json 수신",
                    "proof": "NLB 는 TCP 를 그대로 전달(4계층)하므로 HTTP 응답은 API 서버가 직접 보낸 것"},
    "web-via-alb": {"legs": [("internet", "alb", 443), ("alb", "web", 80)], "to": "web", "port": 80,
                    "how": "인터넷 지점이 ALB 443 을 통해 웹 서버 첫 화면 수신",
                    "proof": "HTTP 200 만 접속 성공으로 판정. ALB 자체 응답은 오류(502·503·504 등)뿐이므로 200 은 웹 서버 응답. "
                             "본문이 함께 온 경우(HTTP 경로)는 웹 서버 첫 화면 문자열('iacpatch testbed: web')까지 확인"},
}
WEB_INDEX_MARK = "iacpatch testbed: web"
CONSOLE_PREFIX = "IACPATCH-PROBE "
WAIT_FRESH_S = 180          # 측정 시작 뒤 측정기가 새 결과를 낼 때까지 기다리는 최대 시간
POLL_S = 10
FRESH_STEP = 2              # 측정 시작 때 본 seq 보다 이만큼 커진 결과만 '새로 잰 값'


def _decode_console(text: Optional[str]) -> str:
    """aws CLI 는 콘솔 출력(API 에서는 base64)을 풀어서 준다. 혹시 안 풀린 채로 오면 여기서 푼다."""
    t = (text or "").strip()
    if not t or CONSOLE_PREFIX in t or re.search(r"[^A-Za-z0-9+/=]", t):
        return text or ""
    try:
        return base64.b64decode(t, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return text or ""


def parse_console(text: Optional[str], vantage: str) -> Optional[Dict[str, Any]]:
    """콘솔 출력에서 이 측정기의 마지막 'IACPATCH-PROBE {json}' 줄. 깨진 줄(커널 메시지와 섞인 줄 등)은 건너뛴다."""
    last = None
    for line in _decode_console(text).replace("\r", "").split("\n"):
        i = line.find(CONSOLE_PREFIX)
        if i < 0:
            continue
        try:
            doc = json.loads(line[i + len(CONSOLE_PREFIX):].strip())
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("from") == vantage and isinstance(doc.get("seq"), int):
            last = doc
    return last


def read_console(cli: AwsCli, instance_id: str) -> Tuple[Optional[str], str]:
    try:
        d = cli.call("ec2", "get-console-output", "--instance-id", instance_id, "--latest")
    except AwsError as e:
        return None, mask(str(e))[:300]
    return (d or {}).get("Output") or "", ""


def _fetch_json(url: str, clog: CommandLog, step: str) -> Tuple[Optional[Dict[str, Any]], str]:
    t0 = time.time()
    started = now_iso()
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            body = r.read()
            st = r.status
        clog.add(step, "V8", ["GET", url], returncode=0, started_at=started, elapsed=round(time.time() - t0, 2), ok=st == 200,
                 note=f"HTTP {st}, {len(body)} bytes")
        return json.loads(body.decode("utf-8")), f"HTTP {st}"
    except Exception as e:  # noqa: BLE001
        clog.add(step, "V8", ["GET", url], returncode=1, started_at=started, elapsed=round(time.time() - t0, 2), ok=False, note=f"{type(e).__name__}: {str(e)[:120]}")
        return None, f"{type(e).__name__}: {str(e)[:120]}"


def _flows_for(spec: Any, entity: str, to: str, port: int) -> List[Any]:
    return [f for f in spec.flows if f.src == entity and f.dst == to and f.protocol in ("tcp", "-1") and f.from_port <= port <= f.to_port]


def _doc_key(doc: Dict[str, Any]) -> Tuple[str, int]:
    return (str(doc.get("at") or ""), int(doc.get("seq") or 0))


def is_fresh(doc: Optional[Dict[str, Any]], base: Optional[Dict[str, Any]]) -> bool:
    """측정 시작 때(또는 처음 본 때) 본 결과(base)보다 seq 가 FRESH_STEP 이상 커졌나.
    측정기가 다시 시작돼 seq 가 1부터 다시 세어진 경우(at 은 더 늦고 seq 는 더 작음)는 새 실행의 seq 가 FRESH_STEP 이상이면 새 값.
    근거: base 는 측정 시작(Ts) 때 보이던 가장 늦은 결과라 base+1 은 Ts 에 아직 안 보였다 → base+1 은 'Ts − 콘솔 지연' 뒤에 끝났고,
    base+2 는 그 뒤 15초 쉬고 시작한다. 즉 base+2 의 시험 시작 > Ts − 콘솔 지연 + 15초.
    측정은 apply 끝(T0)에서 2분 뒤부터 가능하므로(proof_api) 시험 시작 > T0 + 135초 − 콘솔 지연.
    콘솔 지연이 135초 미만이면 apply 뒤에 시작한 시험만 쓴다 (실측 지연 20~40초). HTTP 로 받은 결과는 지연이 거의 없다."""
    if not doc or not base:
        return False
    seq, bseq = int(doc.get("seq") or 0), int(base.get("seq") or 0)
    if seq >= bseq:
        return seq >= bseq + FRESH_STEP
    return str(doc.get("at") or "") > str(base.get("at") or "") and seq >= FRESH_STEP


class _Docs:
    """측정기별 최신 결과 (콘솔 출력 · HTTP 두 길 중 더 늦게 잰 쪽 — at, seq 순)."""

    def __init__(self) -> None:
        self.doc: Dict[str, Dict[str, Any]] = {}
        self.channel: Dict[str, str] = {}
        self.errors: Dict[str, List[str]] = {}

    def offer(self, key: str, doc: Optional[Dict[str, Any]], channel: str) -> None:
        if not doc or doc.get("from") != key or not isinstance(doc.get("seq"), int):
            return
        cur = self.doc.get(key)
        if cur is None or _doc_key(doc) > _doc_key(cur) or (_doc_key(doc) == _doc_key(cur) and channel.startswith("HTTP")
                                                             and not self.channel.get(key, "").startswith("HTTP")):
            self.doc[key] = doc
            self.channel[key] = channel

    def err(self, key: str, msg: str) -> None:
        self.errors.setdefault(key, []).append(msg)


def collect_vantages(cli: Optional[AwsCli], st: Dict[str, Any], clog: CommandLog, log: Callable[[str], None], out_dir: Optional[Path] = None,
                     console_reader: Optional[Callable[[str], Tuple[Optional[str], str]]] = None,
                     fetcher: Optional[Callable[[str, CommandLog, str], Tuple[Optional[Dict[str, Any]], str]]] = None,
                     wait_s: Optional[float] = None, poll_s: Optional[float] = None, sleep: Optional[Callable[[float], None]] = None) -> Dict[str, Any]:
    """처음 본 결과(seq)를 적어 두고, 모든 측정기가 그보다 FRESH_STEP 이상 새 결과를 낼 때까지 기다린다 (최대 wait_s).
    → 측정 버튼을 누르기 전에 잰(= 수정 반영 전일 수 있는) 결과로 판정하지 않는다. 이 PC 와 서버의 시계 차이와 무관."""
    wait_s = WAIT_FRESH_S if wait_s is None else wait_s
    poll_s = POLL_S if poll_s is None else poll_s
    sleep = sleep or time.sleep
    outputs = st.get("outputs") or {}
    inst = st.get("instances") or {}
    alb = outputs.get("alb_dns_name")
    fetch = fetcher or _fetch_json
    reader = console_reader or (lambda iid: read_console(cli, iid) if cli is not None else (None, "aws CLI 없음"))
    last = _Docs()
    base: Dict[str, Dict[str, Any]] = {}
    http_log: List[Dict[str, Any]] = []
    console_ok: Dict[str, bool] = {}

    def one_round(n: int) -> None:
        errs: Dict[str, List[str]] = {}
        if alb:
            doc, status = fetch(f"http://{alb}:443/probe.json", clog, f"http:web-probe:{n}")
            ok = bool(doc) and doc.get("from") == "web"
            http_log.append({"round": n, "status": status, "ok": ok, "seq": (doc or {}).get("seq"), "at": (doc or {}).get("at")})
            if ok:
                last.offer("web", doc, "HTTP · ALB 443 → 웹 80")
                for f in doc.get("fetch") or []:
                    if f.get("name") == "api-via-nlb" and isinstance(f.get("body"), dict):
                        last.offer("api", f["body"], "HTTP · 웹 → NLB 8080 → API 8080")
                if out_dir is not None:
                    (out_dir / f"http_web_probe_{n}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        for key, v in VANTAGES.items():
            iid = (inst.get(v["instance"]) or {}).get("id")
            if not iid:
                errs.setdefault(key, []).append(f"상태 파일에 {v['instance']} 없음 (시험 환경 구버전 또는 미배포)")
                continue
            text, e = reader(iid)
            if text is None:
                errs.setdefault(key, []).append(f"콘솔 출력 조회 실패: {e}")
                continue
            console_ok[key] = True
            text = _decode_console(text)
            if out_dir is not None:
                (out_dir / f"console_{key}_{n}.txt").write_text(mask(text)[-20000:], encoding="utf-8")
            doc = parse_console(text, key)
            if doc is None:
                errs.setdefault(key, []).append("콘솔 출력에 측정 결과 줄(IACPATCH-PROBE) 없음 (서버 시작 직후라면 1~3분 후 재시도)")
            last.offer(key, doc, "콘솔 출력 · get-console-output --latest")
        for key, msgs in errs.items():
            last.errors[key] = msgs
        for key, doc in last.doc.items():
            if key not in base:
                base[key] = {"seq": doc.get("seq"), "at": doc.get("at"), "round": n}

    t0 = time.monotonic()
    slept = 0.0
    rounds = 1
    log("V8 · 측정 결과 조회 (1회 — 기준 seq 기록)")
    one_round(1)
    while True:
        fresh = {k: is_fresh(last.doc.get(k), base.get(k)) for k in VANTAGES}
        if all(fresh.values()) or max(time.monotonic() - t0, slept) >= wait_s:
            break
        sleep(poll_s)
        slept += poll_s
        rounds += 1
        log(f"V8 · 측정 결과 재조회 ({rounds}회 — 측정 시작 후 신규 측정값 대기: "
            f"{', '.join(VANTAGES[k]['label'].split(' (')[0] for k, ok in fresh.items() if not ok)})")
        one_round(rounds)
    fresh = {k: is_fresh(last.doc.get(k), base.get(k)) for k in VANTAGES}
    return {"docs": last.doc, "channel": last.channel, "errors": last.errors, "base": base, "fresh": fresh, "rounds": rounds,
            "waited_s": round(max(time.monotonic() - t0, slept), 1), "http": http_log, "console_ok": console_ok}


def _fetch_result(name: str, f: Dict[str, Any]) -> Tuple[str, str]:
    """측정기의 HTTP 경로 시험 결과 → (open|timeout|refused|error:…|fail, 설명)."""
    status = f.get("status")
    err = str(f.get("error") or "")
    if name == "web-via-alb":
        if status == 200 and "text" not in f and "body" not in f:
            # 콘솔 줄에는 본문을 싣지 않는다 (줄 길이). ALB 가 직접 만드는 응답은 오류 코드뿐이라 200 = 웹 서버 응답
            return "open", "HTTP 200 · 웹 서버 응답 (콘솔 기록이라 본문 없음)"
        if status == 200 and WEB_INDEX_MARK in str(f.get("text") or ""):
            return "open", "HTTP 200 · 웹 서버 첫 화면 수신"
        if status is not None or err.startswith("HTTPError"):
            code = status if status is not None else (re.search(r"HTTP Error (\d+)", err) or [None, "?"])[1]
            return "fail", f"ALB 응답 {code} — 웹 서버 첫 화면 아님 (ALB 의 웹 서버 도달 실패 가능성)"
    else:
        if status is not None:
            body = f.get("body")
            ok_body = isinstance(body, dict) and body.get("from") == "api"
            return "open", f"HTTP {status} · " + ("API 서버 측정 결과 수신" if ok_body else "API 서버 응답")
        m = re.search(r"HTTP Error (\d+)", err)
        if m:
            return "open", f"API 서버 HTTP {m.group(1)} 응답 (경로 허용)"
    low = err.lower()
    if "timed out" in low or "timeout" in low:
        return "timeout", err[:160]
    if "refused" in low:
        return "refused", err[:160]
    return ("error:" + (err.split(":", 1)[0] or "unknown")), err[:160]


def v8_topology(spec: Any, st: Dict[str, Any], clog: CommandLog, log: Callable[[str], None], cli: Optional[AwsCli] = None,
                out_dir: Optional[Path] = None, collected: Optional[Dict[str, Any]] = None, pc_probe: Optional[Callable[[str, int], Dict[str, Any]]] = None) -> LayerResult:
    out = st.get("outputs") or {}
    label = spec.label_of
    checks: List[Dict[str, Any]] = []

    def row(frm: str, frm_label: str, entity: str, to: str, port: int, expect: str, result: Optional[str], how: str, channel: str,
            stale: bool, flows: List[str], why: str, role: str = "주", kind: str = "tcp", extra: Optional[Dict[str, Any]] = None) -> None:
        if result is None:
            v, reason = "UNKNOWN", "결과 없음"
        else:
            v, reason = judge(expect, result)
            if stale and v != "UNKNOWN":
                v, reason = "UNKNOWN", "측정 시작 후 신규 측정값 아님 (측정 결과 미갱신)"
        r = {"from": frm, "from_label": frm_label, "entity": entity, "to": to, "to_label": label(to), "port": port, "expect": expect,
             "result": result, "verdict": v, "reason": reason, "how": how, "channel": channel, "flows": flows, "why": why, "role": role,
             "kind": kind, "stale": stale}
        r.update(extra or {})
        checks.append(r)

    # 1) 시험 환경 안 측정 지점 (판정에 쓰는 결과)
    col = collected if collected is not None else collect_vantages(cli, st, clog, log, out_dir)
    docs, chan, fresh, base = col["docs"], col["channel"], col["fresh"], col.get("base") or {}
    for key, v in VANTAGES.items():
        doc = docs.get(key)
        if doc is None:
            continue
        stale = not fresh.get(key)
        meta = {"at": doc.get("at"), "seq": doc.get("seq"), "base_seq": (base.get(key) or {}).get("seq")}
        for p in doc.get("probes") or []:
            to, port = p.get("to"), int(p.get("port") or 0)
            fl = _flows_for(spec, v["entity"], to, port)
            exp = "open" if fl else "closed"
            why = (f"설계 기준 경로: {label(v['entity'])} → {label(to)} {fl[0].ports}" if fl else "설계 외 경로 → 접속 차단 기대")
            row(key, v["label"], v["entity"], to, port, exp, p.get("result"), f"{v['label'].split(' (')[0]} 내부 측정기 · TCP 연결 시험 (1회 순회 후 15초 대기 반복)",
                chan.get(key, ""), stale, [f.id for f in fl], why,
                extra=dict(meta, ms=p.get("ms"), banner=p.get("banner", ""), target=p.get("host")))
        for f in doc.get("fetch") or []:
            pth = PATHS.get(f.get("name") or "")
            if not pth:
                continue
            fl = [x for (s_, d_, port_) in pth["legs"] for x in _flows_for(spec, s_, d_, port_)]
            exp = "open" if len(fl) == len(pth["legs"]) else "closed"
            res, detail = _fetch_result(f["name"], f)
            row(key, f"{v['label'].split(' (')[0]} (HTTP 경로)", v["entity"], pth["to"], pth["port"], exp, res, pth["how"], chan.get(key, ""),
                stale, [x.id for x in fl], "설계 기준 경로: " + " → ".join([label(pth["legs"][0][0])] + [f"{label(d_)} {p_}" for (_, d_, p_) in pth["legs"]]),
                kind="path", extra=dict(meta, detail=detail, url=f.get("url"), proof=pth["proof"]))
    # 2) 이 PC (참고 — 판정에 넣지 않음)
    alb = out.get("alb_dns_name")
    if alb:
        probe = pc_probe or tcp_probe
        log(f"V8 · (참고) 이 PC → ALB {alb}:443")
        started = now_iso()
        r = probe(alb, 443)
        clog.add("tcp:pc->alb", "V8", ["TCP 연결", alb, "443"], returncode=0, started_at=started, elapsed=round((r.get("ms") or 0) / 1000, 3), ok=True,
                 note=f"결과 {r.get('result')}")
        row("pc", "이 PC (참고)", "internet", "alb", 443, "open", r.get("result"), "이 PC 에서 TCP 연결", "이 PC", False,
            [f.id for f in _flows_for(spec, "internet", "alb", 443)], "설계 기준 경로: 사용자 → ALB 443", role="참고", extra={"ms": r.get("ms")})
        http = col.get("http") or []
        if http:
            okr = [h for h in http if h.get("ok")]
            row("pc", "이 PC (참고, HTTP)", "internet", "web", 80, "open", "open" if okr else "fail", "GET http://ALB:443/probe.json (웹 서버 측정 결과)", "이 PC",
                False, [f.id for f in _flows_for(spec, "internet", "alb", 443) + _flows_for(spec, "alb", "web", 80)],
                "설계 기준 경로: 사용자 → ALB 443 → 웹 80", role="참고", kind="path",
                extra={"detail": f"{len(okr)}/{len(http)}회 성공 · 마지막: {http[-1].get('status')}"})
    for c in checks:
        if c["role"] != "참고":
            continue
        same = [x for x in checks if x["role"] == "주" and set(c["flows"]) & set(x["flows"]) and x["verdict"] in ("PASS", "FAIL")]
        c["observed"], c["observed_reason"] = c["verdict"], c["reason"]
        note = ("" if not same else " · AWS 측정 지점 결과와 일치" if all(x["verdict"] == c["verdict"] for x in same) else " · AWS 측정 지점 결과와 불일치")
        c["verdict"] = "INFO"
        c["reason"] = f"참고용 — 학교망 방화벽·프록시 영향 가능성으로 판정 제외 (관측: {c['observed_reason']}){note}"
    # 3) 설계 통신 9개가 각각 시험 환경 안 측정 지점의 실제 시험으로 확인됐나
    cover = []
    for f in spec.flows:
        direct = [i for i, c in enumerate(checks) if c["role"] == "주" and c["kind"] == "tcp" and f.id in c["flows"] and c["verdict"] in ("PASS", "FAIL")]
        path = [i for i, c in enumerate(checks) if c["role"] == "주" and c["kind"] == "path" and f.id in c["flows"] and c["verdict"] in ("PASS", "FAIL")]
        if any(checks[i]["verdict"] == "FAIL" for i in direct):
            s_ = "끊김"
        elif direct or any(checks[i]["verdict"] == "PASS" for i in path):
            s_ = "열림 확인"
        elif path:
            s_ = "끊김 의심 (경로 시험 실패 — 이 구간인지 다른 구간인지 모름)"
        else:
            s_ = "측정 못 함"
        cover.append({"id": f.id, "label": f"{label(f.src)} → {label(f.dst)} {f.ports}", "rows": direct + path, "status": s_})
    not_measured = [{"id": c["id"], "label": c["label"], "why": "이 경로를 직접 시험한 신규 결과 없음 (측정 결과 없음·미갱신)"}
                    for c in cover if c["status"] == "측정 못 함"]
    counted = [c for c in checks if c["role"] == "주"]
    fails = [c for c in counted if c["verdict"] == "FAIL"]
    unk = [c for c in counted if c["verdict"] == "UNKNOWN"]
    n_closed = sum(1 for c in counted if c["expect"] == "closed" and c["verdict"] in ("PASS", "FAIL"))
    n_open = sum(1 for c in counted if c["expect"] == "open" and c["verdict"] in ("PASS", "FAIL"))
    det = {"checks": checks, "flows": cover, "not_measured": not_measured,
           "vantages": [{"key": k, "label": v["label"], "instance": v["instance"], "channel": chan.get(k), "at": (docs.get(k) or {}).get("at"),
                         "seq": (docs.get(k) or {}).get("seq"), "base_seq": (base.get(k) or {}).get("seq"), "fresh": fresh.get(k),
                         "errors": (col.get("errors") or {}).get(k, []) if k not in docs or not fresh.get(k) else []} for k, v in VANTAGES.items()],
           "http": col.get("http") or [], "waited_s": col.get("waited_s"), "rounds": col.get("rounds"),
           "rule": "허용 경로: open(접속 성공)=통과 / 차단 경로: timeout(접속 차단)=통과, open=실패, refused·오류=판정 불가 / 측정 시작 시점 seq 보다 2 이상 증가한 결과만 사용 / "
                   "설계 기준 경로 9개 모두 시험 환경 내부 측정 지점에서 시험되어야 통과 / 이 PC 결과는 참고용",
           "assumption": "콘솔 출력(get-console-output --latest)은 실시간이 아님 — 2026-10-23 실측에서 새 줄 표시까지 20~40초 지연 사례. "
                         "따라서 (1) apply 완료 2분 후부터 측정 가능 (2) 측정 시작 시점 seq 보다 2 이상 증가한 결과만 사용. "
                         "seq+1 은 측정 시작 시 미표시였으므로 seq+2 의 시험은 '측정 시작 − 콘솔 지연 + 15초' 이후 시작 → "
                         "apply 완료 '135초 − 콘솔 지연' 이후. 콘솔 지연이 135초 미만이면 판정에 사용한 시험은 모두 apply 이후 시작 "
                         "(AWS 문서에 콘솔 지연 상한 수치 없음 — 실측값만 근거)."}
    summary_tail = f" · 설계 기준 경로 {len(cover)}개 중 시험 확인 {len(cover) - len(not_measured)}개"
    if fails:
        return LayerResult("V8", "통신 시험", Verdict.FAIL, "; ".join(f"{c['from_label']} → {c['to_label']} {c['port']}: {c['reason']}" for c in fails[:6]) + summary_tail, det, True, "socket")
    if unk or not_measured or n_closed == 0 or n_open == 0:
        why = "; ".join([f"{c['from_label']} → {c['to_label']} {c['port']}: {c['reason']}" for c in unk[:4]] + [f"미측정: {n['label']}" for n in not_measured[:4]])
        return LayerResult("V8", "통신 시험", Verdict.UNKNOWN, (why or "허용·차단 경로 시험이 모두 있어야 판정 가능") + summary_tail, det, True, "socket")
    return LayerResult("V8", "통신 시험", Verdict.PASS, f"통신 시험 {len(counted)}건 모두 기대 결과와 일치 (접속 성공 {n_open} · 접속 차단 {n_closed}){summary_tail}", det, True, "socket")


def _mask_ip(ip: Optional[str]) -> str:
    if not ip:
        return ""
    p = ip.split(".")
    return f"{p[0]}.x.x.{p[3]}" if len(p) == 4 else ip


# ----------------------------------------------------------------------------- 실행
def run_measure(settings: Settings, *, testbed: Path, intent_path: Path, out_dir: Path, label: str, record_dir: Optional[Path],
                profile: str = "", region: str = "", log: Callable[[str], None] = print,
                compare_files: Optional[Dict[str, Path]] = None, tempenv: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from .iam_intent import try_load_any_intent
    out_dir.mkdir(parents=True, exist_ok=True)
    clog = CommandLog(out_dir / "commands.json")
    spec, kind, err = try_load_any_intent(intent_path)
    if spec is None or kind != "topology":
        raise ValueError(f"설계도 형식 요구사항이 아님: {err or kind}")
    started = now_iso()
    t0 = time.time()
    tf = TerraformAdapter(settings.terraform_bin, region or settings.aws_region)
    log("시험 환경 상태 조회: terraform show -json (이 PC 의 상태 파일)")
    st = testbed_state(tf, testbed, clog)
    sg_file = testbed / "security_groups.tf"
    deployed_sha = _sha(sg_file)
    ident = {"testbed_security_groups_sha256": deployed_sha, "matches": []}
    for name, p in (compare_files or {}).items():
        if _sha(p) == deployed_sha and deployed_sha:
            ident["matches"].append(name)
    if not st.get("ok"):
        v7 = LayerResult("V7", "AWS 적용 규칙 조회", Verdict.ERROR, "상태 파일 조회 실패: " + mask(st.get("error", "")), {}, False, "terraform")
        v8 = LayerResult("V8", "통신 시험", Verdict.NOT_RUN, "시험 환경 주소 확인 불가", {}, False, "socket")
        raw: Dict[str, Any] = {}
    else:
        cli = LoggedAws(clog, settings.aws_bin, profile or settings.aws_profile or None, region or settings.aws_region)
        log("V7 · AWS 보안 그룹·네트워크 인터페이스 조회 (describe — 읽기 전용)")
        v7, raw = v7_topology(cli, spec, st["sg_ids"])
        log(f"V7 · {v7.verdict.value} — {v7.summary[:200]}")
        log(f"V8 · 통신 시험 (측정 지점 5곳 결과 중 측정 시작 후 신규 측정값만 사용 — 최대 {int(WAIT_FRESH_S // 60)}분 대기)")
        cli.layer = "V8"
        v8 = v8_topology(spec, st, clog, log, cli=cli, out_dir=out_dir)
        log(f"V8 · {v8.verdict.value} — {v8.summary[:200]}")
    report = combine("post_deploy", [v7, v8])
    design = _design_copy(Path(intent_path), out_dir)
    doc = {"schema": "iacpatch-measure-v1", "label": label, "started_at": started, "elapsed_s": round(time.time() - t0, 1),
           "testbed": str(testbed), "intent": str(intent_path), "design": design,
           "region": region or settings.aws_region, "profile": profile or settings.aws_profile or "",
           "identity": ident, "state": {"ok": st.get("ok"), "sg_ids": st.get("sg_ids"), "outputs": {k: v for k, v in (st.get("outputs") or {}).items()
                                                                                                      if k in ("alb_dns_name", "nlb_dns_name")},
                                        "bastion_public_ip": _mask_ip((st.get("outputs") or {}).get("bastion_public_ip"))},
           "validity": report.validity.value, "summary": report.summary, "layers": [l.to_dict() for l in report.layers],
           "record": record_dir.name if record_dir else None,
           # 시험 환경 반영 확인용: 측정 시작 때 본 파일 시각 (apply 가 끝났나·몇 초 전인가) + 상태 파일의 리소스 수
           "tempenv": dict(tempenv or {}, resources=st.get("resources"))}
    (out_dir / "measure.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if raw:
        (out_dir / "aws_raw.json").write_text(json.dumps(raw, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    write_manifest(out_dir)
    status = ("DEPLOY_FAILED" if any(l.verdict == Verdict.FAIL for l in report.layers)
              else "VERIFIED" if all(l.verdict == Verdict.PASS for l in report.layers) else "UNVERIFIED")
    doc["status"] = status
    (out_dir / "measure.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if record_dir is not None:
        stp = record_dir / "state.json"
        try:
            s = json.loads(stp.read_text(encoding="utf-8"))
            entry = {"run_id": out_dir.name, "at": now_iso(), "executed": True, "intent": spec.intent_id, "status": status,
                     "validity": report.validity.value, "layers": {l.layer: l.verdict.value for l in report.layers},
                     "summary": report.summary[:500], "path": str(out_dir.relative_to(record_dir)).replace("\\", "/"), "kind": "topology-testbed",
                     "deployed_file_matches": ident["matches"],
                     "design": dict(design, copy=f"{str(out_dir.relative_to(record_dir))}/design.json".replace("\\", "/")) if design else None}
            s["post_deploy"] = entry
            s["post_deploy_history"] = list(s.get("post_deploy_history") or []) + [entry]
            stp.write_text(json.dumps(s, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            write_manifest(record_dir)
        except (OSError, ValueError):
            pass
    log(f"측정 완료 · {status} · {out_dir}")
    return doc
