"""Trivy JSON -> PR 댓글용 마크다운.
사용법: python3 src/pipeline/trivy_to_comment.py <trivy.json> [scan_dir] > comment.md
"""
import json
import sys
from pathlib import Path

MARK = "<!-- iac-scan-report -->"                  # 우리 봇 댓글임을 표시. 나중에 찾거나 갱신할 때 쓴다
ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}   # 심각도 정렬 순서

def findings(report):
    """Results[].Misconfigurations[] 를 finding 하나당 dict 하나로 펼친다."""
    for result in report.get("Results", []):            # 파일(Target) 단위 루프
        target = result.get("Target", "?")
        for m in result.get("Misconfigurations", []):   # 그 파일 안의 finding 단위 루프
            cause = m.get("CauseMetadata", {})
            yield {
                "severity": m.get("Severity", "UNKNOWN"),
                "id": m.get("ID", "?"),                  # 예: AWS-0107
                "file": target,
                "line": cause.get("StartLine", "?"),
                "resource": cause.get("Resource", "?"),  # 예: aws_security_group.vulnerable_ssh
                "title": m.get("Title", "").strip(),
                "fix": m.get("Resolution", "").strip(),
                "url": m.get("PrimaryURL", ""),
            }


def cell(text):
    """표 안에 '|' 가 들어가면 표가 깨지므로 이스케이프한다."""
    return str(text).replace("|", "\\|")



def render(report, scan_dir):
    rows = sorted(findings(report), key=lambda f: ORDER.get(f["severity"], 9))
    version = report.get("Trivy", {}).get("Version", "?")   # 재현성: 어떤 Trivy 버전으로 스캔했는지 기록
    out = [MARK, "## Trivy IaC 스캔 결과",
           f"- 대상: `{scan_dir}` · Trivy {version} · finding **{len(rows)}건**", ""]
    if not rows:
        out.append("finding 없음.")
        return "\n".join(out)
    out += ["| 심각도 | 룰 | 위치 | 리소스 | 내용 | 권장 조치 |",
            "| --- | --- | --- | --- | --- | --- |"]
    for f in rows:
        rule = f"[{f['id']}]({f['url']})" if f["url"] else f["id"]
        out.append(f"| {f['severity']} | {rule} | `{f['file']}:{f['line']}` | `{f['resource']}` "
                   f"| {cell(f['title'])} | {cell(f['fix'])} |")
    return "\n".join(out)


def main(argv):
    if len(argv) < 2:
        sys.exit("사용법: trivy_to_comment.py <trivy.json> [scan_dir]")
    report = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    scan_dir = argv[2] if len(argv) > 2 else "?"
    print(render(report, scan_dir))


if __name__ == "__main__":
    main(sys.argv)