# 컴퓨트 층: Bastion 두 대(가용 영역마다 하나, 공개 서브넷)와 웹·API 서버 자동 확장 그룹(비공개 서브넷, 영역마다 최소 1대).
# 서버는 IMDSv2 만 쓰고(metadata http_tokens = required) 디스크는 암호화한다.

resource "aws_instance" "bastion" {
  count                       = 2
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[count.index].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.project}-bastion-${count.index + 1}"
    Tier = "bastion"
  }
}

resource "aws_launch_template" "web" {
  name_prefix            = "${var.project}-web-"
  image_id               = var.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.web.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.web.name
  }

  metadata_options {
    http_tokens = "required"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 8
      encrypted   = true
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    dnf install -y nginx
    echo "<h1>${var.project} web tier</h1>" > /usr/share/nginx/html/index.html
    systemctl enable --now nginx
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project}-web"
      Tier = "web"
    }
  }
}

resource "aws_autoscaling_group" "web" {
  name_prefix         = "${var.project}-web-"
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.web.arn]
  health_check_type   = "ELB"

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Tier"
    value               = "web"
    propagate_at_launch = true
  }
}

resource "aws_launch_template" "api" {
  name_prefix            = "${var.project}-api-"
  image_id               = var.ami_id
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.api.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.api.name
  }

  metadata_options {
    http_tokens = "required"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 8
      encrypted   = true
    }
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    mkdir -p /srv/api && echo "api tier ok" > /srv/api/index.html
    cd /srv/api && nohup python3 -m http.server 8080 >/var/log/api.log 2>&1 &
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project}-api"
      Tier = "api"
    }
  }
}

resource "aws_autoscaling_group" "api" {
  name_prefix         = "${var.project}-api-"
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.api.arn]
  health_check_type   = "ELB"

  launch_template {
    id      = aws_launch_template.api.id
    version = "$Latest"
  }

  tag {
    key                 = "Tier"
    value               = "api"
    propagate_at_launch = true
  }
}
