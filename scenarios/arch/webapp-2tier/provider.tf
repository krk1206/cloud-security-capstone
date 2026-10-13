# AWS provider — "어느 계정의 어느 리전에 만들 것인가". 자격증명(액세스 키)은 여기 적지 않는다.
# 자격증명은 실행하는 사람의 환경변수(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)에서 읽힌다 (docs/AWS_ACCESS_SETUP_B.md).
# 이 파일도 protected_file_names 에 들어 있어 AI 패치가 바꿀 수 없다.
provider "aws" {
  region = var.aws_region

  # 이 구성으로 만드는 모든 리소스에 같은 태그를 붙인다. 콘솔에서 "이 프로젝트가 만든 것" 을 한눈에 찾고, 지울 때 빠뜨리지 않기 위해.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Owner     = "B"
    }
  }
}
