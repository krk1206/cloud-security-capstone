"""MySQL·Redis 대역(stand-in): 포트만 열어 두고 연결이 오면 한 줄을 보내고 닫는다. 실제 DB 가 아니다 — 보안 그룹이 이 포트를 열었는지만 본다.
사용: python3 listen.py <포트> <배너> [듣는 주소, 기본 0.0.0.0]"""
import socket
import sys

port, banner = int(sys.argv[1]), sys.argv[2]
host = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(64)
while True:
    c, _ = s.accept()
    try:
        c.sendall((banner + "\n").encode())
    except OSError:
        pass
    finally:
        c.close()
