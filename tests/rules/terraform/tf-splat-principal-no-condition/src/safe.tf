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
  }
}
  