다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.

- 파일: main.tf  (내용은 아래)
- 룰: AVD-AWS-0107 — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.
- 지목 리소스: aws_vpc_security_group_ingress_rule.ssh_open  (19 번째 줄)
- 이 SSH(22) 규칙에 허용돼야 하는 출처: 10.0.0.0/8  (그 외 출처는 허용하면 안 된다)
- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.

```hcl
provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_security_group" "clean" {
  name        = "separate-sg"
  description = "No inline ingress blocks"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh_open" {
  security_group_id = aws_security_group.clean.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
```
