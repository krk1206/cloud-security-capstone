# web_asg.tf - WEB 계층. 시작 템플릿(인스턴스 설계도) + Auto Scaling Group(개수 유지/조절).
# 인스턴스는 app 서브넷(private)에 뜨고 공인 IP가 없다. 들어오는 길은 ALB, 나가는 길은 NAT만.

resource "aws_launch_template" "web" {
  name_prefix   = "${var.project}-web-"
  image_id      = var.ami_id # [IaCPatch 사본] 원본: data.aws_ami.al2023.id
  instance_type = var.instance_type

  update_default_version = true

  vpc_security_group_ids = [aws_security_group.web.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.web.name # S3 읽기 + SSM 접속 권한
  }

  # [IaCPatch 사본] 원본: base64encode(file("${path.module}/web_user_data.sh")) — 같은 내용을 글자로 넣음 ($${...} = 글자 그대로의 ${...})
  user_data = base64encode(<<-EOT
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
    <p>instance: $${IID}</p>
    <p>az: $${AZ}</p>
    </body></html>
    HTML
    systemctl enable --now nginx
  EOT
  ) # 시작 템플릿은 base64 필수

  # IMDSv2 강제(Trivy AWS-0130)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # 루트 볼륨 암호화(Trivy AWS-0008). AL2023의 루트 디바이스 이름은 /dev/xvda
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 8
      volume_type = "gp3"
      encrypted   = true
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.project}-web", Tier = "app", Stack = "three-tier", Project = "capstone-2026" } # ASG가 띄우는 인스턴스는 default_tags를 못 받으므로 여기서 지정
  }
}

resource "aws_autoscaling_group" "web" {
  name                = "${var.project}-web-asg"
  min_size            = 1
  max_size            = 2
  desired_capacity    = var.web_desired
  vpc_zone_identifier = aws_subnet.app[*].id # AZ-a, AZ-c app 서브넷에 분산
  target_group_arns   = [aws_lb_target_group.web.arn]

  health_check_type         = "ELB" # ALB 헬스체크 실패 인스턴스를 교체
  health_check_grace_period = 300   # nginx 설치가 끝날 때까지 기다리는 시간(초)

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-web"
    propagate_at_launch = true
  }

  # 인스턴스가 뜨자마자 nginx를 설치하므로 NAT 경로가 먼저 있어야 한다. 없으면 설치 실패 -> 헬스체크 실패 -> 교체 반복
  depends_on = [aws_route.private_nat, aws_route_table_association.app]
}
