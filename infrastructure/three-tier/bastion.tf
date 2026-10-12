# bastion.tf - 운영자 진입점. public 서브넷(AZ-a), 공인 IP, SSH는 admin_cidr만.
# 대안은 SSM Session Manager(포트 개방 없이 접속)이며, 교수님 그림대로 Bastion을 두고 SSM은 설명으로 남긴다.

# 최신 Amazon Linux 2023 AMI를 이름 패턴으로 찾는다. owners를 지정해야 다른 계정의 같은 이름 AMI를 집지 않는다.
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_key_pair" "admin" {
  key_name   = "${var.project}-admin"
  public_key = var.ssh_public_key # 공개키만 AWS에 올라간다. 개인키는 내 PC(~/.ssh)에만 있다.
}

resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  key_name                    = aws_key_pair.admin.key_name
  associate_public_ip_address = true # 서브넷 자동 할당을 꺼 두었으므로 Bastion만 여기서 켠다

  user_data = file("${path.module}/bastion_user_data.sh") # mysql 클라이언트 설치

  # IMDSv2 강제(Trivy AWS-0028). 토큰 없이 메타데이터(자격증명 포함)를 못 읽게 한다.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # 루트 볼륨 암호화(Trivy AWS-0131)
  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = "${var.project}-bastion", Tier = "public" }

  # 부팅 직후 dnf가 인터넷에 나가야 하므로 public 라우트 연결이 먼저 있어야 한다
  depends_on = [aws_route.public_internet, aws_route_table_association.public]
}
