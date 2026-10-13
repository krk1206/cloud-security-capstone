"""IaCPatch.bat 가 쓸 파이썬을 고를 때 쓰는 한 줄 검사: 3.10 이상이면 0, 아니면 1."""
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
