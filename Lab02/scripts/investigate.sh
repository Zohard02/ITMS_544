#!/usr/bin/env bash
# INCIDENT RESPONSE: one timeline for a username from three independent sources.
# Usage: scripts/investigate.sh <username>
set -uo pipefail
export AWS_REGION="${AWS_REGION:-us-east-2}"
U="${1:?usage: $0 <username>}"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="lab02-nimbus-$ACCT"
echo "== 1. CloudTrail (AWS side: who did what to this IAM user, last 90 days, free)"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$U" --max-results 20 \
  --query 'Events[].[EventTime,EventName,Username]' --output table
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue="$U" --max-results 20 \
  --query 'Events[].[EventTime,EventName,Username]' --output table
echo "== 2. Registry audit trail (app side, S3)"
aws s3 ls "s3://$BUCKET/audit/" | grep -- "-$U.json" || echo "no audit entries for $U"
echo "== 3. Service logs (CloudWatch /lab02/app, structured JSON from all four instances)"
aws logs filter-log-events --log-group-name /lab02/app --filter-pattern "\"$U\"" --max-items 20 \
  --query 'events[].message' --output text || echo "no log events yet"
