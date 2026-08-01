#!/bin/bash
set -e

BUCKET_NAME="authpole-admin.swii.sh"
DISTRIBUTION_ID=$(aws cloudfront list-distributions --query "DistributionList.Items[?Aliases.Items && contains(Aliases.Items, '${BUCKET_NAME}')].Id" --output text 2>/dev/null || echo "")

echo "🚀 Deploying Admin Console UI to S3 Bucket s3://${BUCKET_NAME}..."

if [ ! -d "web/admin" ]; then
  echo "❌ Error: web/admin directory not found!"
  exit 1
fi

aws s3 sync web/admin "s3://${BUCKET_NAME}" --delete

echo "✅ Admin UI files uploaded to S3 bucket s3://${BUCKET_NAME}"

if [ -n "${DISTRIBUTION_ID}" ]; then
  echo "🔄 Invalidating CloudFront CDN cache for distribution ${DISTRIBUTION_ID}..."
  aws cloudfront create-invalidation --distribution-id "${DISTRIBUTION_ID}" --paths "/*"
  echo "✅ CloudFront cache invalidation triggered."
else
  echo "ℹ️ CloudFront distribution ID not found. Ensure CloudFront distribution is deployed."
fi

echo "🎉 Admin Console UI deployment complete: https://authpole-admin.swii.sh"
