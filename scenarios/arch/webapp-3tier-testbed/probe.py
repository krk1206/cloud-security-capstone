"""시험 환경 서버 안에서 도는 측정기. 정해진 목적지로 차례로 TCP 연결을 시도하고 결과를 남긴 뒤 15초 쉬고 반복한다.

결과를 내보내는 길은 두 가지다 (보안 그룹을 하나도 열지 않고 받기 위해):
  1. 콘솔 출력: 한 줄 'IACPATCH-PROBE {json}' 을 직렬 콘솔(/dev/ttyS0)에 쓴다.
     프로그램이 `aws ec2 get-console-output --latest` (읽기 전용)로 가져간다. Bastion·관리자 지점·인터넷 지점은 이 길만 쓴다.
  2. 파일: 웹·API 서버는 같은 내용을 /srv/www/probe.json 으로도 쓰고 HTTP 로 내준다
     (웹: ALB 443 → 웹 80, API: 웹 → NLB 8080 → API 8080). 이 길로 받힌다는 것 자체가 설계 통신이 실제로 된다는 증거다.
표준 라이브러리만 쓴다 (비공개 서브넷이라 패키지를 받을 수 없다).

설정(JSON): from, interval, targets[{to, host, port}], out(선택), console(참/거짓), console_path(선택),
            fetch[{name, url}](선택), bind(선택 — 시험용 출발 주소)
"""
import json
import os
import socket
import sys
import time
import urllib.request

PREFIX = "IACPATCH-PROBE "


def tcp(host, port, timeout=3.0, bind=None):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if bind:
            s.bind((bind, 0))
        s.settimeout(timeout)
        s.connect((socket.gethostbyname(host), int(port)))
        connect_ms = int((time.time() - t0) * 1000)
        s.settimeout(1.0)
        try:
            banner = s.recv(64).decode("utf-8", "replace").strip()
        except (socket.timeout, OSError):
            banner = ""      # HTTP 처럼 먼저 말하지 않는 서버는 1초 기다린 뒤 빈 배너
        return {"result": "open", "ms": connect_ms, "banner": banner[:60]}
    except socket.timeout:
        return {"result": "timeout", "ms": int((time.time() - t0) * 1000)}
    except ConnectionRefusedError:
        return {"result": "refused", "ms": int((time.time() - t0) * 1000)}
    except OSError as e:
        return {"result": "error:" + e.__class__.__name__, "ms": int((time.time() - t0) * 1000)}
    finally:
        s.close()


def fetch(item):
    t0 = time.time()
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 프록시를 쓰지 않는다 (VPC 안 주소)
        with opener.open(item["url"], timeout=4) as resp:
            raw = resp.read(200000).decode("utf-8", "replace")
            out = {"name": item["name"], "url": item["url"], "status": resp.status, "ms": int((time.time() - t0) * 1000)}
            try:
                out["body"] = json.loads(raw)
            except ValueError:
                out["text"] = raw[:200]
            return out
    except Exception as e:  # noqa: BLE001
        return {"name": item["name"], "url": item["url"], "error": e.__class__.__name__ + ": " + str(e)[:120], "ms": int((time.time() - t0) * 1000)}


def console_write(line, path=None):
    data = (line + "\n").encode("utf-8")
    for p in ([path] if path else ["/dev/ttyS0", "/dev/console"]):
        try:
            # O_NOCTTY: 직렬 단말을 이 프로세스의 제어 단말로 잡지 않는다 (serial-getty 와 다투지 않게)
            fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOCTTY, 0o644)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            return p
        except OSError:
            continue
    return None


def main(cfg_path):
    cfg = json.load(open(cfg_path))
    seq = 0
    while True:
        seq += 1
        out = {"v": 2, "from": cfg["from"], "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seq": seq, "probes": []}
        for t in cfg.get("targets") or []:
            r = tcp(t["host"], int(t["port"]), bind=cfg.get("bind"))
            r.update({"to": t["to"], "host": t["host"], "port": int(t["port"])})
            out["probes"].append(r)
        out["fetch"] = [fetch(f) for f in cfg.get("fetch") or []]
        if cfg.get("out"):
            tmp = cfg["out"] + ".tmp"
            with open(tmp, "w") as fh:
                fh.write(json.dumps(out))
            os.replace(tmp, cfg["out"])
        if cfg.get("console"):
            brief = dict(out)
            # 콘솔 줄에는 받은 JSON 본문은 빼고, 글자 본문은 앞 40자만 싣는다 (웹 첫 화면 확인용)
            brief["fetch"] = [dict({k: v for k, v in f.items() if k not in ("body", "text")}, **({"text": f["text"][:40]} if "text" in f else {}))
                              for f in out["fetch"]]
            line = PREFIX + json.dumps(brief, separators=(",", ":"))
            console_write(line, cfg.get("console_path"))
            print(line, flush=True)
        time.sleep(int(cfg.get("interval", 15)))


if __name__ == "__main__":
    main(sys.argv[1])
