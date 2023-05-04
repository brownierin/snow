# ok: incd-4846
resource "aws_ecr_repository" "repositories" {
  for_each             = var.repos
  name                 = "${var.namespace}/${each.key}"
  image_tag_mutability = var.image_tag_mutability
}

resource "aws_ecr_lifecycle_policy" "lifecycle_policy" {
  for_each   = var.repos
  repository = "${var.namespace}/${each.key}"

  policy = <<EOF
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Expire images older than ${var.expire_after_days} days",
            "selection": {
                "tagStatus": "${each.value}",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": ${var.expire_after_days}
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
EOF

}

data "aws_iam_policy_document" "access_policy_document" {
  statement {
    sid    = "PullOnly"
    effect = "Allow"

    # grant access to all machine roles
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    // Restrict to Slack org
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-my7fu6sieo"]
    }

    # hopefully just the perms to pull images
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
    ]
  }

  statement {
    sid    = "PushPull"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.push_access_roles
    }

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchDeleteImage",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:InitiateLayerUpload",
      "ecr:ListImages",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
  }
}

resource "aws_ecr_repository_policy" "access_policys" {
  for_each   = var.repos
  repository = "${var.namespace}/${each.key}"
  policy     = data.aws_iam_policy_document.access_policy_document.json
}

# ruleid: incd-4846
provider "aws" {
  region = "us-east-1"
}

resource "aws_ecr_repository" "repositories" {
  count                = length(var.repos)
  name                 = "${var.namespace}/${element(var.repos, count.index)}"
  image_tag_mutability = var.image_tag_mutability
}

resource "aws_ecr_lifecycle_policy" "lifecycle_policy" {
  count      = length(var.repos)
  repository = "${var.namespace}/${element(var.repos, count.index)}"

  policy = <<EOF
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Expire images older than ${var.expire_after_days} days",
            "selection": {
                "tagStatus": "any",
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "countNumber": ${var.expire_after_days}
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
EOF

}

data "aws_iam_policy_document" "access_policy_document" {
  statement {
    sid    = "PullOnly"
    effect = "Allow"

    # grant access to all machine roles
    principals {
      type        = "*"
      identifiers = ["*"]
    }

    # hopefully just the perms to pull images
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
    ]
  }

  statement {
    sid    = "PushPull"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = var.push_access_roles
    }

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchDeleteImage",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:InitiateLayerUpload",
      "ecr:ListImages",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
    ]
  }
}

resource "aws_ecr_repository_policy" "access_policys" {
  count      = length(var.repos)
  repository = "${var.namespace}/${element(var.repos, count.index)}"
  policy     = data.aws_iam_policy_document.access_policy_document.json
}
