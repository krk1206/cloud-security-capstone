# network.tf - VPC, 서브넷 6개(public/app/db x AZ 2), IGW, NAT Gateway 1개, 라우트 테이블
# 트래픽 경로: 인터넷 -> IGW -> public 서브넷(ALB, Bastion) -> app 서브넷(WEB) -> db 서브넷(RDS)
# 아웃바운드: app/db 서브넷 -> NAT Gateway(public 서브넷, AZ-a) -> IGW -> 인터넷

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true # RDS 엔드포인트 등 DNS 이름을 VPC 안에서 풀기 위해 필요

  tags = { Name = "${var.project}-vpc" }
}

# 인터넷 게이트웨이: VPC와 인터넷 사이의 양방향 출입구. public 서브넷의 라우트가 여기를 가리킨다.
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-igw" }
}

# count = 2 : azs 리스트 길이만큼 만든다. aws_subnet.public[0]이 AZ-a, [1]이 AZ-c
resource "aws_subnet" "public" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  # 서브넷 단위 자동 공인 IP는 끈다(Trivy AWS-0164). 공인 IP가 필요한 Bastion만 인스턴스에서 명시한다.
  map_public_ip_on_launch = false

  tags = { Name = "${var.project}-public-${substr(var.azs[count.index], length(var.azs[count.index]) - 1, 1)}", Tier = "public" }
}

resource "aws_subnet" "app" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.app_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = { Name = "${var.project}-app-${substr(var.azs[count.index], length(var.azs[count.index]) - 1, 1)}", Tier = "app" }
}

resource "aws_subnet" "db" {
  count             = length(var.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.db_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = { Name = "${var.project}-db-${substr(var.azs[count.index], length(var.azs[count.index]) - 1, 1)}", Tier = "db" }
}

# NAT Gateway는 public 서브넷에 놓이고 고정 공인 IP(EIP)를 가진다.
# private 인스턴스의 아웃바운드가 이 IP로 나간다. 교수님 그림은 AZ당 1개, 비용 때문에 AZ-a에 1개만.
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.project}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id # AZ-a public 서브넷
  tags          = { Name = "${var.project}-nat" }

  depends_on = [aws_internet_gateway.igw] # NAT가 인터넷으로 나가려면 IGW가 먼저 있어야 한다
}

# public 라우트 테이블: 0.0.0.0/0 -> IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-rt-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# private 라우트 테이블: 0.0.0.0/0 -> NAT Gateway. app, db 서브넷이 공유한다.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project}-rt-private" }
}

resource "aws_route" "private_nat" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

resource "aws_route_table_association" "app" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "db" {
  count          = length(var.azs)
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.private.id
}
