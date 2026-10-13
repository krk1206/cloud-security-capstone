# 네트워크 층: VPC 하나, 그 안에 public 서브넷(웹)과 private 서브넷(앱), 인터넷 게이트웨이, 라우팅.
# AWS 공식 기본 패턴 "VPC with public and private subnets" 를 NAT 게이트웨이 없이(비용 0) 줄인 것이다.

# VPC: 이 프로젝트만의 격리된 사설 네트워크. 안의 모든 리소스는 10.0.0.0/16 대역의 IP 를 받는다.
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true # 안에서 AWS DNS 를 쓸 수 있게
  enable_dns_hostnames = true # 퍼블릭 IP 를 받은 인스턴스에 ec2-...amazonaws.com 호스트 이름을 붙여 줌

  tags = {
    Name = "${var.project}-vpc"
  }
}

# 인터넷 게이트웨이: VPC 와 인터넷을 잇는 문. 이게 붙어야 public 서브넷이 "public" 이 된다.
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-igw"
  }
}

# public 서브넷: 웹 서버가 들어간다. map_public_ip_on_launch 가 true 라 여기서 뜨는 인스턴스는 퍼블릭 IP 를 자동으로 받는다.
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project}-public"
    Tier = "web"
  }
}

# private 서브넷: 앱 서버가 들어간다. 인터넷 게이트웨이로 가는 경로가 없어 밖에서 직접 들어올 수 없다.
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = var.availability_zone

  tags = {
    Name = "${var.project}-private"
    Tier = "app"
  }
}

# public 라우트 테이블: "목적지가 어디든(0.0.0.0/0) 인터넷 게이트웨이로 보내라".
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project}-rt-public"
  }
}

# 라우트 테이블을 public 서브넷에 연결. private 서브넷은 VPC 기본 라우트 테이블(VPC 안에서만 통신)을 그대로 쓴다.
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
