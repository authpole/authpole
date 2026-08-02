# IAM Role for Authpole Compute Instances
resource "aws_iam_role" "authpole_instance_role" {
  name = "authpole-instance-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Fine-Grained IAM Policy for S3 CAS Storage CRUD Operations
resource "aws_iam_policy" "authpole_s3_policy" {
  name        = "authpole-s3-fine-grained-policy-${var.environment}"
  description = "Fine-grained S3 permissions for Authpole CAS object storage"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AuthpoleS3BucketList"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.authpole_storage.arn
        ]
      },
      {
        Sid    = "AuthpoleS3ObjectCRUD"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.authpole_storage.arn}/*"
        ]
      }
    ]
  })
}

# Attach Fine-Grained Policy to IAM Role
resource "aws_iam_role_policy_attachment" "authpole_s3_attach" {
  role       = aws_iam_role.authpole_instance_role.name
  policy_arn = aws_iam_policy.authpole_s3_policy.arn
}

# Instance Profile for Compute Instances
resource "aws_iam_instance_profile" "authpole_instance_profile" {
  name = "authpole-instance-profile-${var.environment}"
  role = aws_iam_role.authpole_instance_role.name
}

# Attach AWS-managed CloudWatch Agent policy (allows PutLogEvents, CreateLogStream, etc.)
resource "aws_iam_role_policy_attachment" "authpole_cloudwatch_attach" {
  role       = aws_iam_role.authpole_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Attach SSM policy so we can run remote commands / Session Manager for debugging
resource "aws_iam_role_policy_attachment" "authpole_ssm_attach" {
  role       = aws_iam_role.authpole_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
