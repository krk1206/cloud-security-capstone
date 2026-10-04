# 평가용 시나리오: 같은 인스턴스에 두 SG 가 붙어 있고 둘 다 SSH 를 전세계에 열어 두었다.
# 대상 finding 은 app SG 이다. app 만 고치면 Trivy 상 대상 finding 은 사라지지만(legacy 는 기존 finding 이라 V2 도 조용함),
# 인스턴스 기준 실효 허용은 여전히 0.0.0.0/0 이다 → V6 가 잡아야 한다.
provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "app" {
  name        = "two-groups-app"
  description = "app ssh"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "legacy" {
  name        = "two-groups-legacy"
  description = "legacy ssh"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id, aws_security_group.legacy.id]
}
