# 컴퓨트 층: EC2 두 대. 웹 서버(public 서브넷, 퍼블릭 IP, nginx) 와 앱 서버(private 서브넷, 퍼블릭 IP 없음).
# key_name(SSH 키 페어)을 일부러 붙이지 않았다 — 시연용이라 SSH 로그인이 필요 없고, 열려 있는 22번 포트로 아무도 들어올 수 없게.

# 웹 서버. user_data 는 첫 부팅 때 한 번 실행되는 스크립트 — nginx 를 설치하고 안내 페이지를 띄운다.
# 정상 기능 확인(V8)의 기준이 이 페이지다: 패치 뒤에도 http://<퍼블릭 IP>/ 가 200 으로 응답해야 한다.
resource "aws_instance" "web" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name

  user_data = <<-EOF
    #!/bin/bash
    dnf install -y nginx
    echo "<h1>${var.project} web tier</h1><p>served by nginx on Amazon Linux 2023</p>" > /usr/share/nginx/html/index.html
    systemctl enable --now nginx
  EOF

  tags = {
    Name = "${var.project}-web"
    Tier = "web"
  }
}

# 앱 서버. 인터넷 경로가 없어 패키지 설치는 못 하지만 Amazon Linux 2023 에 기본으로 있는 python3 으로 8080 포트에 응답한다.
resource "aws_instance" "app" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]

  user_data = <<-EOF
    #!/bin/bash
    mkdir -p /srv/app && echo "app tier ok" > /srv/app/index.html
    cd /srv/app && nohup python3 -m http.server 8080 >/var/log/app.log 2>&1 &
  EOF

  tags = {
    Name = "${var.project}-app"
    Tier = "app"
  }
}
