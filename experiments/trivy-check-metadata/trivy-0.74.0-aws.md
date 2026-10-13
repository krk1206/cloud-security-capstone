# Trivy 0.74.0 내장 체크 메타데이터 — AWS (자동 추출, 사람이 고치지 않음)

- 출처: trivy 바이너리 안의 rego `# METADATA` 블록 (`scripts/trivy_check_meta.py`). 체크 수: 175
- `frameworks` 열은 **Trivy 가 스스로 선언한 태그**다. 최신 CIS 판의 번호와 같다고 가정하지 않는다 → `docs/TRIVY_CIS_MAPPING.md` 에서 원문 대조.
- deprecated=true 인 체크는 규칙 본문이 비어 있을 수 있다 (AVD-AWS-0057 실측, D-8).

## service: ec2 (20개)

| AVD | 제목 | 심각도 | deprecated | Trivy 선언 프레임워크 태그 | 참고 링크 |
|---|---|---|---|---|---|
| AVD-AWS-0008 | Launch configuration with unencrypted block device. | HIGH |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html |
| AVD-AWS-0009 | Launch configuration should not have a public IP address. | HIGH |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html |
| AVD-AWS-0026 | EBS volumes must be encrypted | HIGH |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html |
| AVD-AWS-0027 | EBS volume encryption should use Customer Managed Keys | LOW |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html |
| AVD-AWS-0028 | aws_instance should activate session tokens for Instance Metadata Service. | HIGH |  | - | https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service |
| AVD-AWS-0029 | User data for EC2 instances must not contain sensitive AWS keys | CRITICAL |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html |
| AVD-AWS-0099 | Missing description for security group. | LOW |  | - | https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html |
| AVD-AWS-0101 | AWS best practice to not use the default VPC for workflows | HIGH |  | - | https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html |
| AVD-AWS-0102 | An Network ACL rule allows ALL ports. | CRITICAL |  | - | https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html |
| AVD-AWS-0104 | A security group rule should not allow unrestricted egress to any IP address. | CRITICAL |  | - | https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html |
| AVD-AWS-0105 | Network ACLs should not allow unrestricted ingress to SSH or RDP from any IP address. | MEDIUM |  | cis-aws-1.4: 5.1 | https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html, https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-21 |
| AVD-AWS-0107 | Security groups should not allow unrestricted ingress to SSH or RDP from any IP address. | HIGH |  | cis-aws-1.2: 4.1, 4.2 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html, https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-13 |
| AVD-AWS-0122 | Ensure all data stored in the launch configuration EBS is securely encrypted | HIGH |  | - | - |
| AVD-AWS-0124 | Missing description for security group rule. | LOW |  | - | https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html |
| AVD-AWS-0129 | User data for EC2 instances must not contain sensitive AWS keys | CRITICAL |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html |
| AVD-AWS-0130 | aws_instance should activate session tokens for Instance Metadata Service. | HIGH |  | - | https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service |
| AVD-AWS-0131 | Instance with unencrypted block device. | HIGH |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html |
| AVD-AWS-0164 | Instances in a subnet should not receive a public IP address by default. | HIGH |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses |
| AVD-AWS-0173 | Default security group should restrict all traffic | LOW |  | cis-aws-1.4: 5.3 | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html |
| AVD-AWS-0178 | VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet "Rejects" for VPCs. | MEDIUM |  | - | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/RootDeviceStorage.html |

## service: iam (24개)

| AVD | 제목 | 심각도 | deprecated | Trivy 선언 프레임워크 태그 | 참고 링크 |
|---|---|---|---|---|---|
| AVD-AWS-0056 | IAM Password policy should prevent password reuse. | MEDIUM |  | cis-aws-1.2: 1.10; cis-aws-1.4: 1.9 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0057 | IAM policy should avoid use of wildcards and instead apply the principle of least privilege | HIGH | 예 | cis-aws-1.4: 1.16 | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| AVD-AWS-0058 | IAM Password policy should have requirement for at least one lowercase character. | MEDIUM |  | cis-aws-1.2: 1.6 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0059 | IAM Password policy should have requirement for at least one number in the password. | MEDIUM |  | cis-aws-1.2: 1.8 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0060 | IAM Password policy should have requirement for at least one symbol in the password. | MEDIUM |  | cis-aws-1.2: 1.7 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0061 | IAM Password policy should have requirement for at least one uppercase character. | MEDIUM |  | cis-aws-1.2: 1.5 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0062 | IAM Password policy should have expiry less than or equal to 90 days. | MEDIUM |  | cis-aws-1.2: 1.11 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0063 | IAM Password policy should have minimum password length of 14 or more characters. | MEDIUM |  | cis-aws-1.2: 1.9; cis-aws-1.4: 1.8 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0123 | IAM groups should have MFA enforcement activated. | MEDIUM |  | - | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details |
| AVD-AWS-0140 | The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that the use of this account be avoided. | LOW |  | cis-aws-1.2: 1.1; cis-aws-1.4: 1.7 | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| AVD-AWS-0141 | The root user has complete access to all services and resources in an AWS account. AWS Access Keys provide programmatic access to a given account. | CRITICAL |  | cis-aws-1.2: 1.12; cis-aws-1.4: 1.4 | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| AVD-AWS-0142 | The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that this account have MFA enabled. | CRITICAL |  | cis-aws-1.4: 1.5; cis-aws-1.2: 1.13 | https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.14 |
| AVD-AWS-0143 | IAM policies should not be granted directly to users. | LOW |  | cis-aws-1.4: 1.15; cis-aws-1.2: 1.16 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0144 | Credentials which are no longer used should be disabled. | MEDIUM |  | cis-aws-1.2: 1.3 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0145 | IAM Users should have MFA enforcement activated. | MEDIUM |  | cis-aws-1.2: 1.2; cis-aws-1.4: 1.4 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0146 | Access keys should be rotated at least every 90 days | LOW |  | cis-aws-1.2: 1.4; cis-aws-1.4: 1.14 | https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automatically-rotate-iam-user-access-keys-at-scale-with-aws-organizations-and-aws-secrets-manager.html |
| AVD-AWS-0165 | The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that this account have hardware MFA enabled. | MEDIUM |  | cis-aws-1.4: 1.6 | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html |
| AVD-AWS-0166 | Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used. | LOW |  | cis-aws-1.4: 1.12 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0167 | No user should have more than one active access key. | LOW |  | cis-aws-1.4: 1.13 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0168 | Delete expired TLS certificates | LOW |  | cis-aws-1.4: 1.19 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0169 | Missing IAM Role to allow authorized users to manage incidents with AWS Support. | LOW | 예 | cis-aws-1.4: 1.17 | https://console.aws.amazon.com/iam/ |
| AVD-AWS-0342 | IAM Pass Role Filtering | MEDIUM |  | - | - |
| AVD-AWS-0345 | Disallow unrestricted S3 IAM Policies | HIGH |  | - | - |
| AVD-AWS-0346 | Reduce unnecessary unauthorized access or information disclosure of S3 buckets. | HIGH |  | - | https://www.aquasec.com/blog/shadow-roles-aws-defaults-lead-to-service-takeover/ |

## service: s3 (14개)

| AVD | 제목 | 심각도 | deprecated | Trivy 선언 프레임워크 태그 | 참고 링크 |
|---|---|---|---|---|---|
| AVD-AWS-0086 | S3 Access block should block public ACL | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html |
| AVD-AWS-0087 | S3 Access block should block public policy | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html |
| AVD-AWS-0088 | Unencrypted S3 bucket. | HIGH | 예 | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html |
| AVD-AWS-0089 | S3 Bucket Logging | LOW |  | - | - |
| AVD-AWS-0090 | S3 Data should be versioned | MEDIUM |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html, https://aws.amazon.com/blogs/storage/reduce-storage-costs-with-fewer-noncurrent-versions-using-amazon-s3-lifecycle/ |
| AVD-AWS-0091 | S3 Access Block should Ignore Public ACL | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html |
| AVD-AWS-0092 | S3 Buckets not publicly accessible through ACL. | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html |
| AVD-AWS-0093 | S3 Access block should restrict public bucket to limit access | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html |
| AVD-AWS-0094 | S3 buckets should each define an aws_s3_bucket_public_access_block | LOW |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html |
| AVD-AWS-0132 | S3 encryption should use Customer Managed Keys | HIGH |  | - | https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html |
| AVD-AWS-0170 | Buckets should have MFA deletion protection enabled. | LOW |  | cis-aws-1.4: 2.1.3 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html |
| AVD-AWS-0171 | S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. | LOW |  | cis-aws-1.4: 3.10 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html |
| AVD-AWS-0172 | S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. | LOW |  | cis-aws-1.4: 3.11 | https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-cloudtrail-logging-for-s3.html |
| AVD-AWS-0320 | S3 DNS Compliant Bucket Names | MEDIUM |  | - | - |

## 그 밖의 서비스 (117개) — 이 프로젝트 범위 밖, 목록만

AVD-AWS-0001(apigateway), AVD-AWS-0002(apigateway), AVD-AWS-0003(apigateway), AVD-AWS-0004(apigateway), AVD-AWS-0005(apigateway), AVD-AWS-0006(athena), AVD-AWS-0007(athena), AVD-AWS-0010(cloudfront), AVD-AWS-0011(cloudfront), AVD-AWS-0012(cloudfront), AVD-AWS-0013(cloudfront), AVD-AWS-0014(cloudtrail), AVD-AWS-0015(cloudtrail), AVD-AWS-0016(cloudtrail), AVD-AWS-0017(cloudwatch), AVD-AWS-0018(codebuild), AVD-AWS-0019(config), AVD-AWS-0020(documentdb), AVD-AWS-0021(documentdb), AVD-AWS-0022(documentdb), AVD-AWS-0023(dynamodb), AVD-AWS-0024(dynamodb), AVD-AWS-0025(dynamodb), AVD-AWS-0030(ecr), AVD-AWS-0031(ecr), AVD-AWS-0032(ecr), AVD-AWS-0033(ecr), AVD-AWS-0034(ecs), AVD-AWS-0035(ecs), AVD-AWS-0036(ecs), AVD-AWS-0037(efs), AVD-AWS-0038(eks), AVD-AWS-0039(eks), AVD-AWS-0040(eks), AVD-AWS-0041(eks), AVD-AWS-0042(elasticsearch), AVD-AWS-0043(elasticsearch), AVD-AWS-0045(elasticache), AVD-AWS-0046(elasticsearch), AVD-AWS-0047(elb), AVD-AWS-0048(elasticsearch), AVD-AWS-0049(elasticache), AVD-AWS-0050(elasticache), AVD-AWS-0051(elasticache), AVD-AWS-0052(elb), AVD-AWS-0053(elb), AVD-AWS-0054(elb), AVD-AWS-0064(kinesis), AVD-AWS-0065(kms), AVD-AWS-0066(lambda), AVD-AWS-0067(lambda), AVD-AWS-0070(mq), AVD-AWS-0071(mq), AVD-AWS-0072(mq), AVD-AWS-0073(msk), AVD-AWS-0074(msk), AVD-AWS-0075(neptune), AVD-AWS-0076(neptune), AVD-AWS-0077(rds), AVD-AWS-0078(rds), AVD-AWS-0079(rds), AVD-AWS-0080(rds), AVD-AWS-0083(redshift), AVD-AWS-0084(redshift), AVD-AWS-0085(redshift), AVD-AWS-0095(sns), AVD-AWS-0096(sqs), AVD-AWS-0097(sqs), AVD-AWS-0098(ssm), AVD-AWS-0109(workspaces), AVD-AWS-0110(sam), AVD-AWS-0111(sam), AVD-AWS-0112(sam), AVD-AWS-0113(sam), AVD-AWS-0114(sam), AVD-AWS-0116(sam), AVD-AWS-0117(sam), AVD-AWS-0119(sam), AVD-AWS-0120(sam), AVD-AWS-0121(sam), AVD-AWS-0125(sam), AVD-AWS-0126(elasticsearch), AVD-AWS-0127(redshift), AVD-AWS-0128(neptune), AVD-AWS-0133(rds), AVD-AWS-0134(ssm), AVD-AWS-0135(sqs), AVD-AWS-0136(sns), AVD-AWS-0137(emr), AVD-AWS-0138(emr), AVD-AWS-0139(emr), AVD-AWS-0147(cloudwatch), AVD-AWS-0148(cloudwatch), AVD-AWS-0149(cloudwatch), AVD-AWS-0150(cloudwatch), AVD-AWS-0151(cloudwatch), AVD-AWS-0152(cloudwatch), AVD-AWS-0153(cloudwatch), AVD-AWS-0154(cloudwatch), AVD-AWS-0155(cloudwatch), AVD-AWS-0156(cloudwatch), AVD-AWS-0157(cloudwatch), AVD-AWS-0158(cloudwatch), AVD-AWS-0159(cloudwatch), AVD-AWS-0160(cloudwatch), AVD-AWS-0161(cloudtrail), AVD-AWS-0162(cloudtrail), AVD-AWS-0163(cloudtrail), AVD-AWS-0174(cloudwatch), AVD-AWS-0175(accessanalyzer), AVD-AWS-0176(rds), AVD-AWS-0177(rds), AVD-AWS-0179(msk), AVD-AWS-0180(rds), AVD-AWS-0190(apigateway), AVD-AWS-0343(rds), AVD-AWS-0344(ami)
