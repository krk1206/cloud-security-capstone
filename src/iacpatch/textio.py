"""텍스트 파일 쓰기 — 줄바꿈을 LF('\\n') 로 고정한다.

왜 있나 (10-04 실측에서 나온 버그):
  Windows 의 Python 은 `Path.write_text()` / `open(path, "w")` 로 쓸 때 '\\n' 을 '\\r\\n' 으로 바꿔 쓴다.
  기록 폴더의 후보 파일 `candidate/security_groups.tf` 가 그렇게 CRLF 로 써졌고, 그 파일을 저장소(LF)의
  원본 위에 덮어쓰자 GitHub Desktop 이 "파일 전체가 바뀜" 으로 보여 줬다 (실제 변경은 한 줄).
  → 저장소로 되돌아갈 수 있는 파일(후보 .tf, 원본 사본, diff, PR 본문)은 전부 이 함수로 쓴다.

규칙:
  - 입력에 섞인 CRLF 도 LF 로 맞춘다 (원본이 CRLF 로 저장돼 있던 경우까지 포함).
  - 인코딩은 UTF-8, BOM 없음 (Terraform 은 BOM 을 못 읽는다).
"""
from __future__ import annotations

from pathlib import Path


def normalize_lf(text: str) -> str:
    """CRLF·CR 를 LF 로 바꾼 문자열을 돌려준다."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def write_text_lf(path: str | Path, text: str, *, encoding: str = "utf-8") -> Path:
    """`path` 에 `text` 를 LF 줄바꿈·UTF-8 로 쓴다. 상위 폴더가 없으면 만든다. 어느 OS 에서나 바이트가 같다."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding=encoding, newline="\n") as fh:   # newline="\n": OS 별 변환 없이 그대로 쓴다
        fh.write(normalize_lf(text))
    return p
