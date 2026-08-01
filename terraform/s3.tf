# S3 Bucket for Authpole CAS Persistence
resource "aws_s3_bucket" "authpole_storage" {
  bucket        = var.s3_bucket_name
  force_destroy = false

  tags = {
    Name = "authpole-storage"
  }
}

# Enable Object Versioning (Mandatory for CAS Compare-And-Swap Header Matching)
resource "aws_s3_bucket_versioning" "authpole_storage_versioning" {
  bucket = aws_s3_bucket.authpole_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "authpole_storage_encryption" {
  bucket = aws_s3_bucket.authpole_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Public Access Block (Strictly Private Storage)
resource "aws_s3_bucket_public_access_block" "authpole_storage_private" {
  bucket = aws_s3_bucket.authpole_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
