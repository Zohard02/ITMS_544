#!/usr/bin/env bash
# DATA: rotate the service to service token with zero downtime.
# Parameter Store has no built in "previous" stage, so the lab keeps two parameters:
#   /nimbus/internal-token/current   and   /nimbus/internal-token/previous
# Rotation copies current to previous and writes a new current. Services accept both, so no restart is needed.
# Terraform created both parameters but ignores later changes to their values (lifecycle ignore_changes).
set -euo pipefail
export AWS_REGION="${AWS_REGION:-us-east-2}"
P=/nimbus/internal-token
OLD="$(aws ssm get-parameter --name $P/current --with-decryption --query Parameter.Value --output text)"
NEW="$(head -c 256 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | cut -c1-48)"
aws ssm put-parameter --name $P/previous --type SecureString --value "$OLD" --overwrite >/dev/null
aws ssm put-parameter --name $P/current  --type SecureString --value "$NEW" --overwrite >/dev/null
aws ssm get-parameters --names $P/current $P/previous --query 'Parameters[].[Name,Version,LastModifiedDate]' --output table
echo "rotated: the new value is current, the old value is previous. Services pick it up within about a minute."
