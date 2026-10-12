#!/bin/bash
# WEB 인스턴스 초기화: nginx 설치 후 인스턴스 ID가 보이는 정적 페이지 생성
# 메타데이터는 IMDSv2(토큰 필수)로만 읽을 수 있게 설정했으므로 토큰을 먼저 받는다.
dnf install -y nginx
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
cat > /usr/share/nginx/html/index.html <<HTML
<html><body>
<h1>capstone three-tier - web tier</h1>
<p>instance: ${IID}</p>
<p>az: ${AZ}</p>
</body></html>
HTML
systemctl enable --now nginx
