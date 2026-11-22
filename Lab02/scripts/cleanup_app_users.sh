#!/usr/bin/env bash
# Deletes every IAM user the APPLICATION created under the /nimbus/ path.
# Why this script exists: Terraform only knows about resources it created itself. The onboarding service
# creates IAM users at run time, so those users are not in the Terraform state. Terraform cannot delete them,
# and it cannot delete the groups and policies they are attached to until they are gone.
# Terraform runs this script automatically before it destroys the groups (see terraform/cleanup.tf).
set -uo pipefail
for U in $(aws iam list-users --path-prefix /nimbus/ --query 'Users[].UserName' --output text); do
  for P in $(aws iam list-attached-user-policies --user-name "$U" --query 'AttachedPolicies[].PolicyArn' --output text); do aws iam detach-user-policy --user-name "$U" --policy-arn "$P"; done
  for G in $(aws iam list-groups-for-user --user-name "$U" --query 'Groups[].GroupName' --output text); do aws iam remove-user-from-group --user-name "$U" --group-name "$G"; done
  for K in $(aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do aws iam delete-access-key --user-name "$U" --access-key-id "$K"; done
  for M in $(aws iam list-mfa-devices --user-name "$U" --query 'MFADevices[].SerialNumber' --output text); do aws iam deactivate-mfa-device --user-name "$U" --serial-number "$M"; aws iam delete-virtual-mfa-device --serial-number "$M"; done
  aws iam delete-login-profile --user-name "$U" 2>/dev/null || true
  aws iam delete-user --user-name "$U" && echo "deleted user $U"
done
exit 0
