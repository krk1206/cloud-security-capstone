# 상태는 S3 에 둔다. 버킷 이름 · 키 · 리전은 워크플로 ③ 이 terraform init -backend-config 로 넘긴다
# (버킷 이름은 GitHub Variables 의 TFSTATE_BUCKET — deploy/bootstrap 이 만든다).
# use_lockfile: 같은 상태를 두 실행이 동시에 바꾸지 못하게 S3 에 잠금 파일을 둔다 (Terraform 1.10 이상).
terraform {
  backend "s3" {}
}
