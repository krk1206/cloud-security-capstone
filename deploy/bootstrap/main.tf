# 워크플로 ③ (상시 환경 배포) 를 위한 AWS 준비물 — 사람이 한 번만 직접 apply 한다 (CI 가 돌리지 않는다).
#
# 만드는 것:
#   1) 상태 저장 S3 버킷: 상시 환경(deploy/sg-baseline-live)의 terraform state 를 실행 사이에 이어서 보관
#   2) 배포 역할(IAM role): GitHub Actions 가 OIDC 로 받는 역할. 액세스 키 없음.
#      이 역할은 GitHub Environment "sandbox" 에서 승인된 잡만 받을 수 있다 (신뢰 정책의 sub 조건).
#
# 쓰는 법 (팀 샌드박스 관리자 프로필로, 로컬에서):
#   cd deploy/bootstrap
#   terraform init
#   terraform plan  -var aws_profile=capstone-tf
#   terraform apply -var aws_profile=capstone-tf
#   → 출력된 deploy_role_arn, tfstate_bucket 을 GitHub 저장소 Settings → Variables 에 넣는다.
#
# 이 폴더의 상태 파일(terraform.tfstate)은 로컬에 생긴다. 저장소에 올리지 않는다 (.gitignore 확인).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "capstone-2026"
      ManagedBy = "terraform"
      Purpose   = "iacpatch-deploy-bootstrap"
    }
  }
}

data "aws_caller_identity" "me" {}

# GitHub OIDC 공급자는 terraform-plan 워크플로(5주차) 때 이미 만들어져 있다. 새로 만들지 않고 찾아서 쓴다.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  bucket = "capstone-tfstate-${data.aws_caller_identity.me.account_id}"
  # 워크플로 ③ 잡에는 environment: sandbox 가 걸려 있다 → OIDC 토큰의 sub 는 아래 한 가지다.
  oidc_sub = "repo:${var.github_repo}:environment:${var.github_environment}"
}

# ---------------------------------------------------------------------------
# 1) 상태 저장 버킷
# 아래 두 지적은 알고 남긴다:
#   AWS-0132 고객 관리 KMS 키 아님 — S3 관리 키(AES256)로 암호화한다. KMS 키는 월 비용이 들고, 이 버킷은 상태 파일 1개만 둔다.
#   AWS-0089 접근 로그 없음 — 로그용 버킷이 따로 필요하다. 접근은 배포 역할 하나로 제한하고, 버전 관리로 이력을 남긴다.
# ---------------------------------------------------------------------------
#trivy:ignore:AWS-0089
resource "aws_s3_bucket" "tfstate" {
  bucket = local.bucket
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 암호화 안 된 통신(HTTP)으로는 버킷에 접근 못 하게 한다
resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ---------------------------------------------------------------------------
# 2) 배포 역할 (OIDC, environment:sandbox 만)
# ---------------------------------------------------------------------------
resource "aws_iam_role" "deploy" {
  name                 = "capstone-github-deploy"
  description          = "IaCPatch workflow 3 (live deploy). Assumable only by GitHub Actions jobs in environment ${var.github_environment}."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.oidc_sub
        }
      }
    }]
  })
}

# 상시 환경이 만드는 것(VPC · 서브넷 · IGW · 라우트 · SG · EC2 1대)과 V7 측정(Describe)에 필요한 만큼만.
# EC2 쓰기 동작은 서울 리전으로 묶는다. IAM · RDS · 다른 서비스 권한은 없다.
resource "aws_iam_role_policy" "deploy" {
  name = "capstone-github-deploy"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StateBucketList"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.tfstate.arn
      },
      {
        Sid      = "StateObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.tfstate.arn}/live/*"
      },
      {
        Sid      = "Ec2Read"
        Effect   = "Allow"
        Action   = ["ec2:Describe*"]
        Resource = "*"
      },
      {
        Sid    = "Ec2WriteSeoulOnly"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway", "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ReplaceRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress", "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:ModifySecurityGroupRules",
          "ec2:RunInstances", "ec2:TerminateInstances", "ec2:StartInstances", "ec2:StopInstances",
          "ec2:ModifyInstanceAttribute", "ec2:ModifyInstanceMetadataOptions",
          "ec2:CreateTags", "ec2:DeleteTags"
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.region } }
      },
      {
        Sid       = "SmallInstancesOnly"
        Effect    = "Deny"
        Action    = "ec2:RunInstances"
        Resource  = "arn:aws:ec2:*:*:instance/*"
        Condition = { StringNotEquals = { "ec2:InstanceType" = ["t3.micro"] } }
      }
    ]
  })
}
