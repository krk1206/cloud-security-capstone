#!/usr/bin/env python3
"""
검증 B — 최소 쌍(minimal pair) 대조군 생성.

01-cidr-split 을 통째로 복사한 뒤 CIDR 값 '하나만' 바꿔서 01b-control 을 만든다.
다른 곳은 한 글자도 건드리지 않으므로, 두 케이스의 스캔 결과가 갈리면
원인이 CIDR 값이라는 것이 확정된다.

마지막에 diff 를 출력한다. 이 diff 자체가 '최소 쌍이 맞다'는 증거다.
"""
import re
import shutil
import sys
import difflib
from pathlib import Path

SRC = Path("cases/01-cidr-split")
DST = Path("cases/01b-control")

# "0.0.0.0/1" 과 "128.0.0.0/1" 이 한 리스트에 있는 형태를 통째로 잡는다.
# 공백/줄바꿈/따옴표 배치가 달라도 매칭되도록 여유를 둔다.
PATTERN = re.compile(
    r'\[\s*"0\.0\.0\.0/1"\s*,\s*"128\.0\.0\.0/1"\s*,?\s*\]'
    r'|\[\s*"128\.0\.0\.0/1"\s*,\s*"0\.0\.0\.0/1"\s*,?\s*\]'
)
REPLACEMENT = '["0.0.0.0/0"]'


def main():
    if not SRC.exists():
        print(f"[!] {SRC} 가 없다. trivy-sg-probe 디렉터리에서 실행해야 한다.")
        sys.exit(1)

    if DST.exists():
        shutil.rmtree(DST)
    shutil.copytree(SRC, DST)

    changed_files = 0
    total_subs = 0

    for tf in sorted(DST.rglob("*.tf")):
        original = tf.read_text(encoding="utf-8")
        patched, n = PATTERN.subn(REPLACEMENT, original)
        if n == 0:
            continue
        tf.write_text(patched, encoding="utf-8")
        changed_files += 1
        total_subs += n

        src_file = SRC / tf.relative_to(DST)
        print(f"=== diff: {src_file} → {tf} ===")
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=str(src_file),
            tofile=str(tf),
            n=1,
        )
        sys.stdout.writelines(diff)
        print()

    if total_subs == 0:
        print("[!] CIDR 패턴을 못 찾았다. 01-cidr-split/main.tf 를 열어서")
        print("    cidr_blocks 줄이 어떻게 적혀 있는지 확인하고 수동으로 만들어라.")
        print("    (예: 리스트가 여러 줄로 나뉘어 있거나 변수를 경유하는 경우)")
        sys.exit(2)

    print(f"[+] 파일 {changed_files}개에서 CIDR {total_subs}곳 치환 완료.")
    print("    위 diff 에 CIDR 줄 말고 다른 변경이 없으면 최소 쌍이 성립한다.")


if __name__ == "__main__":
    main()
