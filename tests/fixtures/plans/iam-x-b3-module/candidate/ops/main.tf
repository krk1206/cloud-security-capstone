variable "role_name" { type = string }

resource "aws_iam_policy" "worker" {
  name   = "ops-admin"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = var.role_name
  policy_arn = aws_iam_policy.worker.arn
}
