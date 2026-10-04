provider "aws" {
  region = "ap-northeast-2"
}

resource "aws_ec2_managed_prefix_list" "world" {
  name           = "world-prefix-list"
  address_family = "IPv4"
  max_entries    = 1

  entry {
    cidr        = "0.0.0.0/0"
    description = "everything"
  }
}

resource "aws_security_group" "prefix_list" {
  name        = "prefix-list-sg"
  description = "SSH open via managed prefix list"

  ingress {
    description     = "SSH"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.world.id]
  }
}
