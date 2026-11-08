resource "aws_instance" "bastion" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.bastion.id]
  tags                   = { Name = "board-bastion", Tier = "bastion" }
}

resource "aws_instance" "web" {
  ami                    = "ami-0c9c942bd7bf113a2"
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.private_a.id
  vpc_security_group_ids = [aws_security_group.web.id]
  tags                   = { Name = "board-web", Tier = "web" }
}
