# 네트워크: VPC 1개, 가용 영역 2곳 × (공개 서브넷 + 비공개 서브넷).
# 원본 설계와 다른 점: NAT 게이트웨이 없음 (비공개 서버는 밖으로 나갈 일이 없다 — 측정기는 AMI 에 들어 있는 python3 만 쓴다).

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 1)
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-public-${count.index + 1}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 11)
  availability_zone = var.azs[count.index]

  tags = {
    Name = "${var.project}-private-${count.index + 1}"
    Tier = "private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# 비공개 서브넷: 기본 경로 없음 (VPC 안 통신만)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ----------------------------------------------------------------------------- 관리자 측정 지점 자리
# 관리자 허용 목록 대역(문서용 예시 대역)을 VPC 보조 CIDR 로 붙이고, 그 안에 작은 서브넷을 만든다.
# 이 서브넷의 서버가 보내는 패킷은 출발 주소가 허용 목록 안이라서, Bastion 보안 그룹의 '관리자 허용' 규칙을 실제로 시험할 수 있다.
# 인터넷 경로는 없다 (로컬 경로만) — 설계도의 '관리자 → Bastion 22' 를 VPC 안에서 재현한다.
resource "aws_vpc_ipv4_cidr_block_association" "admin" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.admin_vantage_cidr
}

resource "aws_subnet" "admin" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.admin_vantage_cidr, 2, 0)
  availability_zone = var.azs[0]

  tags = {
    Name = "${var.project}-admin-vantage"
    Tier = "test-vantage"
  }

  depends_on = [aws_vpc_ipv4_cidr_block_association.admin]
}

resource "aws_route_table_association" "admin" {
  subnet_id      = aws_subnet.admin.id
  route_table_id = aws_route_table.private.id
}
