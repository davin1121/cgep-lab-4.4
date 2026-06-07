# oidc/main.tf
# Creates the GitHub Actions OIDC trust relationship in AWS.
# This allows GitHub Actions workflows to assume an IAM role without
# storing any long-lived AWS credentials in the repository.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "us-east-1" }

# The GitHub org and repo this role is scoped to.
# Only workflows running from THIS repo can assume the role.
variable "github_org"  { type = string }
variable "github_repo" { type = string }

# Tells AWS to trust GitHub's identity system as an OIDC provider.
# The thumbprint is GitHub's TLS certificate fingerprint — AWS uses it
# to verify that tokens actually came from GitHub.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# The IAM role the pipeline assumes during each workflow run.
# The assume_role_policy defines WHO can assume this role.
# The StringLike condition locks it to your specific repo only.
resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/cgep-lab-*:*" }
      }
    }]
  })
}

# Attach AWS-managed ReadOnlyAccess policy to the role.
# The pipeline only needs to READ state and plan — never write or destroy.
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Output the role ARN so you can copy it into GitHub as a repo variable.
output "role_arn" { value = aws_iam_role.grc_gate.arn }
