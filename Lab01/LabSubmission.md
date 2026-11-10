# Lab01 Submission: Identity Lifecycle Management and Security Controls on the AWS Free Tier

**Student:** Pablo De la Cruz
**Course:** ITMS 564 Cloud Security
**Lab:** Lab01 (Nimbus Identity Console)

## Environment and deviations from the manual

I made three changes to what the manual prescribes. Each is explained where it matters (Q11, Q17, Q19):

1. I converted `lab01-trail` to a multi-Region trail during Part H, because the `lab01-risky-iam` alert never fired with the original single-Region trail.
2. I added `--region us-east-1` to the two `lookup-events` calls in `bootstrap/08-investigate.sh`, because IAM events live in the `us-east-1` event history.
3. I quoted the CloudWatch Logs filter pattern (`'"internal_token_refreshed"'`), because terms that contain `_` must be quoted.

---

## Part A: Run the Tests Locally

**Q1 (explore). Tests as security controls.**
Both suites passed before any deployment: `./run_tests.sh unit` reported 256 passed and `./run_tests.sh integration` reported 13 passed. Tests such as the ones in `tests/unit/test_free_tier_guard.py` (the launch script never opens port 22, never creates a NAT gateway, and creates only one trail) and `tests/unit/test_policies.py` (the onboarding role can attach only the MFA guard) are security statements written as code.

In a delivery pipeline, I would run them as required status checks on every pull request, with branch protection on `main`, so that a change that breaks a security property cannot be merged. I would run them again in the deployment pipeline immediately before any infrastructure is applied, so that nothing reaches production without passing them. Fast unit tests can also run in a pre-commit hook, but that is only a convenience, because developers can skip local hooks.

They cannot catch two important kinds of problem. The first is behavior that only the real cloud exhibits. My lab gave me a concrete example: the mock-based integration tests passed, yet in the real account EventBridge in `us-east-1` never received the `CreateAccessKey` event while the trail was single-Region, and console sign-in events were recorded in `us-east-2`, not `us-east-1`. A mock does not reproduce those regional delivery rules. The second is drift made outside the code path, such as a user created directly with the CLI (`mallory` in G3) or a key added by hand (G2 and G6). Tests check the code and templates, not the live account. They also cannot prove the absence of logic flaws in paths no test exercises.

Policy-as-code and analysis tools complement the tests. IAM Access Analyzer policy validation checks policies against IAM grammar and best practices, flags security warnings such as overly broad `iam:PassRole`, and can run custom policy checks (for example, "this policy must not grant new access compared with the previous version"). cfn-guard evaluates infrastructure-as-code templates against declarative rules, for example "every S3 bucket must have a TLS-only policy". Open Policy Agent (Rego, often through conftest) applies the same idea to any structured input, including Terraform plans and Kubernetes manifests. These tools understand policy semantics better than string-matching unit tests, but they still evaluate artifacts, not runtime behavior. The credential check in `create_repo.sh` is a narrow secret scanner: it greps for `AKIA…`, private-key headers and `ghp_…` tokens before the first commit. A dedicated scanner (gitleaks, trufflehog or GitHub push protection) covers many more credential formats and the full Git history, and blocks pushes server-side.

## Part B: IAM Groups and Policies

**Q2. Why does Nimbus-RequireMFA use BoolIfExists rather than Bool?**
The deny statement `DenyEverythingExceptMFASetupWhenNoMFA` uses `"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}`. With an `...IfExists` operator, the condition also evaluates to true when the key is absent from the request context. That is exactly the case for requests signed with long-term access keys, which do not carry `aws:MultiFactorAuthPresent` at all. With plain `Bool`, a missing key makes the condition false. The deny would then not apply, and a user without MFA could bypass the guard simply by creating and using an access key. `BoolIfExists` therefore denies everything except MFA and password setup both when MFA is explicitly false (a console session without MFA) and when MFA information is missing (long-term keys).

**Q3. In TechTeam-DevScoped, why is a Deny still useful when no Allow grants IAM access?**
The statement `DenyPrivilegeEscalationAndBilling` explicitly denies `aws-portal:*`, `billing:*` and the IAM actions used for privilege escalation (`CreateUser`, `CreateRole`, `CreatePolicy`, `CreatePolicyVersion`, `Attach*Policy`, `Put*Policy`, `AddUserToGroup`, `UpdateAssumeRolePolicy`, `PassRole`). Today the implicit deny already blocks these actions. However, permissions are the union of every policy attached to the user, directly or through any group. If someone later attaches a broader policy, adds a developer to a second group, or makes a mistake, an explicit Deny still wins over any Allow. The Deny is therefore a durable guarantee, or guardrail, that does not depend on the rest of the configuration staying correct. It is defense in depth, not redundancy.

**Q4 (explore). Group membership as an escalation path.**
The most valuable group to an attacker who controls the onboarding service is **SecurityTeam**, and the attack chain uses only permissions the onboarding role has. The attacker calls `/onboard` with persona `security-admin`. The service creates a user under `/nimbus/`, adds it to SecurityTeam, and creates a console password that the attacker now knows. The MFA guard blocks everything at first, but it deliberately lets the user enrol their own MFA device. Once MFA is enrolled, the user has the full `SecurityTeam-IAMAudit` policy. That policy allows `iam:Get*`, `iam:List*`, `cloudtrail:LookupEvents` and Access Analyzer reads, and its `AuthorOnlyNimbusPolicies` statement allows `iam:CreatePolicyVersion` on `policy/nimbus/*`. Every policy in the lab lives under that path, including `Nimbus-RequireMFA`, which is attached to every user, and `SecurityTeam-IAMAudit` itself. The attacker can create a new default version of either policy that allows `*:*`, removing the `NoApplicationDataOrSecrets` deny and gaining full administrator access. TechTeam would be second choice: it gives limited data access and is blocked from escalation by its own Deny. BusinessTeam gives only cost views.

Three ways to close the gap:
- **Condition on the group name** in the onboarding role (`iam:AddUserToGroup` limited to `group/nimbus/TechTeam` and `group/nimbus/BusinessTeam`, with SecurityTeam membership handled by a separate, human-approved process). This is cheap and precise, but it only fixes this one role.
- **Permissions boundary**: the onboarding role is allowed to create users only if it attaches a boundary (condition `iam:PermissionsBoundary`), and the boundary excludes `iam:CreatePolicyVersion` and other IAM writes. Whatever group the new user joins, the effective permissions cannot exceed the boundary. This is the strongest control inside one account, but it is more complex to design and test.
- **Service Control Policy**: deny `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` on `policy/nimbus/*` for every principal except a dedicated policy-administration role. This protects the whole account even against administrators, but it requires AWS Organizations and is coarse-grained.

I would choose the group-name condition immediately, because it is a one-line fix that removes the direct path, together with a permissions boundary for all users the service creates, because that also protects against future groups or policy mistakes. In an organization, I would add the SCP as an outer guardrail.

## Part C: Buckets, Secrets and Data Protection

**Q5. Name three places the admin password could have ended up without Secrets Manager. Why is each one worse?**
- **In the Git repository** (for example, in `docker-compose.yml` or a config file). The repository is public. Even in a private repository, every clone and fork has a copy forever, and removing it later leaves it in the history. It cannot be rotated without a code change and a redeploy.
- **In the `.env` file or EC2 user data on the server.** User data is readable by anyone who can call `ec2:DescribeInstanceAttribute` and, from inside the instance, through the metadata service. A `.env` file sits in plain text on disk, is copied into backups and AMIs, and has no access control beyond the OS. There is also no audit trail of who read it.
- **Baked into the Docker image or written to logs.** Image layers keep every value permanently and are pushed to registries. Logs are shipped to CloudWatch and read by many people. In this lab the logger masks any field whose name contains `password`, `token`, `secret` or `key` (I verified that the login log lines contain only `ts`, `service`, `event`, `remote` and `attempt`).

Secrets Manager instead encrypts the value at rest, allows reads only from named roles (`nimbus-web-svc` can read only its two secrets), records every `GetSecretValue` call in CloudTrail, and supports rotation without redeploying.

**Q6. What does the TLS-only bucket policy stop that Block Public Access does not?**
Block Public Access stops the bucket from being made available to anonymous or public principals through ACLs or public bucket policies. It says nothing about how authorized principals connect. The data bucket policy contains only Deny statements: `DenyInsecureTransport` (`"Bool": {"aws:SecureTransport": "false"}`) and `DenyOldTLS` (`"NumericLessThan": {"s3:TlsVersion": "1.2"}`). Together they stop authenticated, otherwise-authorized requests made over plain HTTP or old TLS, which could be read or tampered with in transit. I proved this in G5: the same `list-objects-v2` call by `lab-user`, who has AdministratorAccess, failed over `http://s3.us-east-2.amazonaws.com` with "explicit deny in a resource-based policy" and succeeded over HTTPS. Because the policy only denies, it can never accidentally grant access to anyone.

**Q7 (explore). Customer managed keys.**
SSE-S3 and the default Secrets Manager key protect against threats to the physical storage, but anyone with `s3:GetObject` or `secretsmanager:GetSecretValue` can read the data, because AWS decrypts it transparently. A customer managed KMS key adds a second, independent authorization layer: a principal must also be allowed `kms:Decrypt` by the key policy. This addresses several threats: an over-permissive IAM or bucket policy (data stays unreadable without key access), a compromised administrator in a separate team, cross-account sharing mistakes, and the need for crypto-shredding (disabling or scheduling deletion of the key makes all data unreadable at once). It also gives a separate CloudTrail record of every use of the key, plus control over rotation.

A key policy separates duties with two statements. One gives a key-administrators role `kms:Create*`, `kms:Describe*`, `kms:Enable*`, `kms:Put*`, `kms:Update*`, `kms:Revoke*`, `kms:Disable*`, `kms:ScheduleKeyDeletion` and similar actions, but **not** `kms:Encrypt`/`kms:Decrypt`. The other gives the service roles (for example `nimbus-web-svc`) only `kms:Decrypt` and `kms:GenerateDataKey`, optionally limited with `kms:ViaService` to `secretsmanager.us-east-2.amazonaws.com` or `s3.us-east-2.amazonaws.com`. The administrators can manage the key but not read data; the applications can use the key but not change or delete it.

The extra cost is about USD 1 per key per month plus about USD 0.03 per 10,000 requests (S3 Bucket Keys reduce the request count). The failure modes are real: a key policy that locks out every administrator, accidental deletion after the 7–30 day waiting period (which permanently destroys the data), throttling at KMS request quotas, and outages when the key is disabled.

## Part D: One IAM Role per Microservice

**Q8. Principal, Action, Resource and Request context for each simulator result, and the deciding statement.**

| # | Principal | Action | Resource | Request context | Result |
|---|---|---|---|---|---|
| 1 | `role/nimbus/nimbus-onboarding-svc` | `iam:AttachUserPolicy` | `user/nimbus/alice` | `iam:PolicyARN = arn:aws:iam::aws:policy/AdministratorAccess` | implicitDeny |
| 2 | `role/nimbus/nimbus-onboarding-svc` | `iam:AttachUserPolicy` | `user/nimbus/alice` | `iam:PolicyARN = …:policy/nimbus/Nimbus-RequireMFA` | allowed |
| 3 | `role/nimbus/nimbus-onboarding-svc` | `iam:CreateLoginProfile` | `user/lab-user` (path `/`) | none | implicitDeny |

In simulation 1, the only statement that mentions the action is `AttachOnlyTheMFAGuardPolicy`. The action and the resource (`user/nimbus/*`) match, but its condition `ArnEquals iam:PolicyARN = …/Nimbus-RequireMFA` is not satisfied, so the statement does not apply. No other Allow matches, and the result is an implicit deny.

In simulation 2, the same statement `AttachOnlyTheMFAGuardPolicy` matches on principal, action, resource and condition, so it allows the request.

In simulation 3, the action is allowed only by `CreateAndTagNimbusUsersOnly`, whose resource is `user/nimbus/*`. `lab-user` lives under the path `/`, so the resource does not match and the request falls to an implicit deny.

None of the three is an *explicit* deny: the role simply has no Allow that fits. This is least privilege working through narrow Allows rather than through Deny statements.

**Q9 (explore). Four containers, one host.**
The instance role `nimbus-ec2-instance` may call `sts:AssumeRole` on `role/nimbus/nimbus-*-svc`, and each service role trusts that instance role. IMDSv2 is required, but the hop limit is set to 2. Packets from a container on the Docker bridge network need one extra hop to reach `169.254.169.254`, so every container, not only the host, can obtain the instance role's temporary credentials. Nothing ties a role to a container: the `ROLE_NAME` environment variable only tells honest code which role to assume. An attacker with code execution in the web container can therefore fetch instance credentials and assume `nimbus-onboarding-svc` or `nimbus-offboarding-svc` directly. In addition, the web container holds the internal token and can call the other services over the Compose network.

Three redesigns compare as follows:
- **One instance per service** gives strong isolation (separate instance roles, hop limit 1, separate security groups). It costs roughly four times the compute, which exceeds the free tier, and it means four hosts to patch and monitor.
- **ECS task IAM roles** (on Fargate or ECS on EC2) give each task its own credentials from the ECS agent's credential endpoint. With the task role and blocked IMDS access on EC2 launch types, a container gets only its own role. Fargate costs per vCPU-second, with no host to manage, so operational effort is low once the team knows ECS.
- **Pod-level identity on Kubernetes** (EKS Pod Identity or IRSA) gives each service account its own role. Isolation per pod is good, but the EKS control plane costs about USD 0.10 per hour, and Kubernetes has the highest operational effort and complexity of the three.

For this workload I would choose ECS on Fargate with task roles: per-service identity with the least operational burden.

## Part E: Logging and Alerts

**Q10. Which two kinds of event does the lab alert on, and why alert instead of only storing them?**
The rule `lab01-risky-iam` alerts on IAM calls that create credentials or change permissions: `CreateAccessKey`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `UpdateAssumeRolePolicy` and `DeleteUserPermissionsBoundary`, plus `Attach{User,Group,Role}Policy` when the policy is `AdministratorAccess`. The rule `lab01-signin-without-mfa` alerts on successful console sign-ins where `MFAUsed` is `No`.

Stored logs are evidence, but nobody reads them until something has already gone wrong. These events are rare, high-signal and typical of persistence or account takeover, so a human must be told while it still matters. In my G6 drill, the alert email arrived within about a minute of the `CreateAccessKey` call (event at 04:10:26 UTC, email at about 04:10 UTC). Containment followed within five minutes, instead of the backdoor going unnoticed until someone happened to search CloudTrail.

**Q11 (explore). Blind spots in detection.**
My lab exposed two blind spots in the rules exactly as built, in addition to the gaps in the event list:
- **Regional delivery.** The console sign-in of `james` (03:03:26 UTC) was recorded only in `us-east-2`; `lookup-events` in `us-east-1` returned nothing, so the `us-east-1` rule never saw it. AWS sign-in redirects to a regional endpoint, and the event is delivered in that Region. Separately, `lab01-risky-iam` did not fire in G2: the `CreateAccessKey` event was in the `us-east-1` event history, but the rule's `MatchedEvents` metric stayed empty. The trail was single-Region in `us-east-2`, and EventBridge only receives "AWS API Call via CloudTrail" events where a logging trail covers that Region. After I converted the trail to multi-Region (still one trail, so still the free copy), the G6 alert arrived. Sign-in alerting needs a rule in every Region users can sign in through.
- **Missing events.** An attacker who controls an IAM principal can give an existing user a console password with `CreateLoginProfile` or reset one with `UpdateLoginProfile`, add a user to a powerful group with `AddUserToGroup`, attach a customer-managed policy that is effectively admin (the rule only matches the AWS-managed `AdministratorAccess`), or simply use stolen credentials from an unusual location. None of these trigger the current rules.

An event pattern for the first case:

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup"],
    "userIdentity": { "arn": [{ "anything-but": { "prefix": "arn:aws:sts::083163125365:assumed-role/nimbus-onboarding-svc/" } }] }
  }
}
```

It excludes the onboarding service, which creates login profiles legitimately, so that only out-of-band changes alert. That keeps the noise down.

Alert fatigue is the cost of adding rules. Every legitimate onboarding would page someone if the rule were not scoped, and people learn to ignore noisy channels. Good practice is to alert only on high-signal events, exclude known automation, route lower-severity events to a ticket queue instead of a page, and review false positives regularly. Amazon GuardDuty approaches the problem differently. Instead of fixed patterns, it analyses CloudTrail management events, VPC Flow Logs and DNS logs with threat intelligence and anomaly detection, and produces prioritized findings such as unusual API activity by a principal or instance credentials used from outside AWS (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`). It covers all Regions where it is enabled without hand-written rules, at a usage-based cost after a 30-day trial.

## Part F: Launch the Hardened Server

**Q12. Why is there no SSH and no key pair, and how do you debug the server without them?**
An open SSH port is a permanent target for brute force and exploits. A key pair is a long-lived secret that must be stored, shared and revoked. Removing both eliminates an entire login path. My G4 probe confirmed that port 22 timed out, and the flow logs show the packets from `52.124.37.145` to port 22 rejected. Nothing on the server needs interactive access, because it is rebuilt from the public repository at boot and keeps no state that matters (the data is in S3).

To debug, I used three channels. The first is the serial console output (`aws ec2 get-console-output`), where `user-data.sh` writes its whole boot log; that is how I obtained the TLS certificate fingerprint. The second is the container logs, shipped to CloudWatch Logs group `/lab01/app` by the `awslogs` driver (one stream per container). The third is the application's own `/healthz` endpoints and the Dashboard. If interactive access were ever needed, AWS Systems Manager Session Manager would provide audited shell access over outbound HTTPS, with no inbound port and no key.

**Q13. If the web container were compromised, what does egress filtering stop and what does it not stop?**
Egress is limited to TCP 443 and 80. It stops reverse shells and command-and-control on other ports, outbound SSH, SMTP spam and other non-web protocols. The flow logs showed this working even for benign traffic: the instance's own NTP requests to public servers on UDP 123 were rejected (time is still synchronized through the link-local Amazon Time Sync service).

It does not stop exfiltration or command-and-control over HTTPS to any internet host, because 443 is open to `0.0.0.0/0`. It does not stop DNS tunneling through the VPC resolver, or access to the instance metadata service, which security groups do not filter. That matters because a compromised container can obtain the instance role and assume any service role (Q9). Nor does it stop lateral movement inside the Compose network: the web container holds the internal token and can call the onboarding and offboarding services directly. A domain allow-list (an egress proxy or AWS Network Firewall) and per-service identities would be needed for stronger containment.

**Q14 (explore). Certificates and trust on first use.**
The server printed `SHA256 Fingerprint=16:13:29:C8:…:11:F1:78:8F` to its console. Edge showed the same value (`161329c8…1911f1788f`) for the self-signed certificate (`CN=13.184.60.240`, valid 9–12 November 2026). Comparing the two through an independent, authenticated channel (the AWS API) defends against a man-in-the-middle attack: someone between my browser and the server presenting their own self-signed certificate, which would produce the same browser warning. Most users skip the check because the warning looks identical either way, the fingerprint is long and must be found in two places, and clicking "continue" trains people to ignore warnings. That is why trust on first use is fragile.

With AWS Certificate Manager behind an Application Load Balancer, a publicly trusted certificate for a real domain name is issued and renewed automatically, and the browser validates it against its trust store, so no manual comparison is needed. The cost is a load balancer (not free) and a domain. A public certificate authority (for example Let's Encrypt) provides the same browser trust directly on the instance, but then the private key lives on the server and renewal must be automated.

HSTS (the app sends `Strict-Transport-Security: max-age=86400`) tells the browser to use HTTPS only for that host and to refuse click-through on certificate errors for the max-age period, which removes downgrade and click-through attacks after the first visit. Certificate Transparency requires CAs to publish every issued certificate in public append-only logs, so a domain owner can detect a mis-issued or rogue certificate for their domain. Browsers reject publicly trusted certificates that are not logged.

## Part H, G4: Network Proofs

**Q15. Which of the six checks proved encryption in transit, which proved a smaller attack surface, and which proved protection against password guessing?**
- **Encryption in transit:** check 1 (HTTPS to `/login` returned 200), check 2 (plain HTTP to port 8443 got no response, curl exit code 52, because the port speaks only TLS) and check 3, where `Strict-Transport-Security` forces HTTPS in the browser. The other headers in check 3 (`X-Frame-Options: DENY`, `Content-Security-Policy` with `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`) harden the browser side against clickjacking, content sniffing and caching of one-time passwords.
- **Smaller attack surface:** check 4 (ports 22 and 8080 closed; the security group dropped the packets, later confirmed as REJECT records in the flow logs) and check 6 (inbound only TCP 8443 from my `/32`, outbound only 80 and 443, S3 traffic through a Gateway endpoint in state `available`).
- **Protection against password guessing:** check 5, the login lockout. With six wrong passwords I first received six 200 responses. A second run of twelve attempts returned four 200s and then 429 for every remaining attempt. The difference is explained by the design: the failure counter is kept in memory *per Gunicorn worker* (two workers), so requests alternated between workers and each worker needed five failures before locking. An attacker therefore gets about five attempts per worker per five-minute window, and the counter resets if the container restarts. A shared store (Redis or a database), a WAF rate rule, or an identity provider with lockout would fix this.

## Part H, G1 to G3: Identity Experiments

**Q16. Why does the same user and action get denied without MFA and allowed with it? Quote the condition key.**
For `user/nimbus/jennifer` and `ce:GetCostAndUsage`, the simulator returned `explicitDeny` with `aws:MultiFactorAuthPresent=false` and `allowed` with `aws:MultiFactorAuthPresent=true`. I also supplied `aws:RequestedRegion=us-east-1`, because the Allow in `BusinessTeam-ReadOnly` only applies in `us-east-1` and `us-east-2`; without it, both runs would be implicit denies.

The deciding statement is `DenyEverythingExceptMFASetupWhenNoMFA` in `Nimbus-RequireMFA`. It denies every action not in its `NotAction` list under the condition `"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}`. When MFA is absent the condition is true, and the explicit Deny overrides the Allow from the group policy. When MFA is present the condition is false, the Deny does not apply, and the BusinessTeam Allow takes effect.

I then confirmed this for real. I signed in as `james` with the one-time password and was forced to change it; every console widget showed "Access denied". I then enrolled a virtual MFA device (it had to be named `james`, because the policy only allows `mfa/${aws:username}`). CloudTrail recorded `CreateVirtualMFADevice` at 03:15:12 and `EnableMFADevice` at 03:15:38 UTC, and the Dashboard moved james from MFA PENDING to OK. The expected `lab01-signin-without-mfa` email did not arrive, for the regional reason explained in Q11.

**Q17. Who created mallory and how did you find out? Why does the audit trail in S3 not show it?**
`lab-user` created `mallory` at 2026-11-10T03:42:54Z. I found this in CloudTrail: `08-investigate.sh mallory`, after I added `--region us-east-1`, listed `CreateUser` by `lab-user` in the ResourceName lookup. The original script searched the `us-east-2` event history, where IAM events are not stored, and returned nothing.

The Dashboard flagged mallory as UNTRACKED because the user exists in IAM but has no registry record in S3. The registry audit trail showed "no audit entries for mallory", and the container logs had nothing either. The S3 audit trail only records actions that go *through the application*: the onboarding and offboarding services write an audit object for each action they perform. Mallory was created directly with the AWS CLI, bypassing the application entirely. This is why independent sources matter: the application's own records describe intent, CloudTrail describes what actually happened in AWS, and comparing the two (drift detection) is what reveals out-of-band changes.

**Q18 (explore). Replacing IAM users with single sign-on.**
With AWS IAM Identity Center federated to an external identity provider (for example Entra ID or Okta), people no longer get IAM users, passwords or access keys in the account. They sign in to the IdP and receive short-lived role credentials through permission sets.

Much of the lab becomes unnecessary: the onboarding service creating IAM users and login profiles, the one-time passwords, the per-user MFA guard (MFA is enforced at the IdP), the access-key handling in offboarding, and the `/nimbus/` user path. Joiner and leaver events move to the IdP (HR-driven provisioning through SCIM). Disabling the person there removes access everywhere at once, which is a better kill switch for humans.

Several things still matter. MFA must still be enforced, now as IdP policy (ideally phishing-resistant WebAuthn), and the account-level MFA requirement for any remaining IAM users and root stays. A kill switch is still needed for active sessions, because already issued role credentials remain valid until they expire; you revoke sessions in Identity Center or use a deny policy on `aws:TokenIssueTime`. Drift detection still matters, now comparing IdP group assignments with permission-set assignments and looking for any IAM users or keys that appear outside the process (like mallory). Logging, alerting and least-privilege permission sets remain essential.

New risks appear. A compromised IdP, or an IdP administrator account, can grant itself access to every account at once, so the IdP becomes the crown jewel and needs its own MFA, monitoring and break-glass procedures. There is a dependency on IdP availability, which requires emergency break-glass IAM access stored offline. Session hijacking is now the main threat instead of key theft. SCIM synchronization errors can leave access in place after an employee leaves the IdP.

## Part H, G5 and G6: Data Proofs and Incident Drill

**Q19. Why is a token rotation safe with no restart, and what would break if the services accepted only the current token?**
`07-rotate-token.sh` created a new version (`3efd8fad…`, AWSCURRENT) and kept the old one (`c54a0a54…`) as AWSPREVIOUS. The services read the secret with a 60-second cache, and `require_internal_token` accepts both the AWSCURRENT and the AWSPREVIOUS value. If it receives an unknown token, it refreshes its cache once before rejecting. During the rotation window, a caller still holding the old token is accepted (it is now AWSPREVIOUS), and a caller that already has the new token is accepted once the receiver refreshes. No process needs a restart, and nothing in the code or image changes.

In my run, the Dashboard kept working immediately after rotation. CloudWatch Logs contained no `internal_auth_rejected` event, so there was not a single 401. There was also no `internal_token_refreshed` event, which is consistent: no receiver saw the new token before its own cache had refreshed, and the old token was still accepted. If the services accepted only the current token, each one would switch to the new value at a different moment within its 60-second cache window (and each Gunicorn worker separately). A caller with the new token talking to a receiver with the old cache, or the reverse, would get 401 errors. The web pages would fail until every cache converged, which is a self-inflicted outage on every rotation and a strong incentive never to rotate.

**Q20. Which control would have prevented the incident, and which only limited it? Name one more free control you would add.**
The incident started with stolen long-term credentials of `lab-user`, which has AdministratorAccess and no MFA requirement for API calls.

Controls that would have **prevented** it:
- Not having long-term administrator access keys at all, using short-lived credentials from SSO or `aws sts get-session-token` with MFA.
- A policy that denies sensitive IAM writes such as `iam:CreateAccessKey` on `user/nimbus/*` unless `aws:MultiFactorAuthPresent` is true, so that stolen keys alone are useless for persistence.
- An SCP or permissions guard forbidding access-key creation for application-managed users.

None of these was in place for `lab-user`, which is the lab's main weakness.

Controls that only **limited** it:
- The EventBridge alert, which detected it in under a minute.
- The investigation script and CloudTrail, which identified the caller `lab-user`, the source IP `52.124.37.145` and the target `james`.
- The offboarding kill switch: `Nimbus-DenyAll` plus key deactivation, so the backdoor key was useless from 04:14:55 UTC.
- Drift detection on the Dashboard.
- The MFA guard on `james`, which already blocked the new key's use for most actions because the key carried no MFA context.

One more free control I would add is an automated EventBridge response. The same `lab01-risky-iam` rule would invoke a small Lambda function (free tier) that immediately deactivates any access key created for a user under `/nimbus/` by anyone other than the onboarding role, and notifies the team. That shrinks containment from minutes to seconds. IAM Access Analyzer's external-access analyzer, which is free, is another good addition.

My drill timeline (UTC, 10 November 2026):

| NIST phase | Action | Time |
|---|---|---|
| Preparation | Trail (converted to multi-Region), alerts, roles, kill switch, investigate script | n/a |
| Detection | Backdoor key `AKIARGXHISZ22GDKBWX6` created for james; alert email received | T0 04:09:45 (event 04:10:26); alert ≈ 04:10 |
| Analysis | `08-investigate.sh james` plus CloudTrail lookup: `CreateAccessKey` by `lab-user` from `52.124.37.145` | 04:13:09 |
| Containment | Offboarded james (DenyAll, key deactivated, console and group removed) | 04:14:55 |
| Eradication | Deleted the backdoor key; Dashboard shows james CLOSED | 04:15:27 |
| Recovery | Onboarded `james2` (developer, TechTeam) | ≈ 04:16 |
| Post-incident | Read REJECT records in `/lab01/flow` | 04:16:46 |

**Q21 (explore). Mapping the drill to a framework.**
Mapping to the MITRE ATT&CK Cloud matrix:
- **Initial Access – T1078.004 Valid Accounts: Cloud Accounts.** The attacker uses the stolen `lab-user` access keys.
- **Persistence – T1098.001 Account Manipulation: Additional Cloud Credentials.** `CreateAccessKey` on `james` plants a backdoor key on a legitimate account. (G3's `mallory` corresponds to **T1136.003 Create Account: Cloud Account**.)
- **Discovery (T1087.004 Account Discovery: Cloud Account)** would typically precede choosing a target such as james.
- **Defense Evasion – T1562.008 Impair Defenses: Disable or Modify Cloud Logs** is what an attacker with these rights could do next (for example, deleting the trail). This motivates Q23 and Q24.

Mapping three lab controls to published control sets:
- `Nimbus-RequireMFA` maps to the CIS AWS Foundations Benchmark recommendation to ensure MFA is enabled for all IAM users that have a console password, and to NIST SP 800-53 **IA-2(1)** (multi-factor authentication for privileged accounts) and **IA-2(2)**.
- Groups-based least-privilege policies and per-service roles map to the CIS recommendation that IAM users receive permissions only through groups, and to NIST **AC-6** (least privilege) and **AC-2** (account management, including the offboarding kill switch for disabling accounts).
- `lab01-trail` with log file validation maps to the CIS recommendations to ensure CloudTrail log file validation is enabled and that CloudTrail is enabled in all Regions, and to NIST **AU-2/AU-12** (event logging and audit record generation) and **AU-10** (non-repudiation through digest files).

The lab does not meet at least two requirements in those sets as delivered. First, the trail was created single-Region (`--no-is-multi-region-trail`), which fails the CIS "CloudTrail enabled in all Regions" recommendation; I had to fix it for alerting to work. Second, NIST **AU-9** (protection of audit information) is not met: an administrator can delete the trail and the log bucket, which the cleanup script actually does. Strictly speaking, the CIS "permissions only through groups" recommendation is also not fully met, because `Nimbus-RequireMFA` and `Nimbus-DenyAll` are attached directly to users.

## Part I: From 10 to 100 People

**Q22. Complete the table: which limit do you hit first in each row, and what do you change?**
- **Permissions.** The first limit is not the 5,000 users per account but the IAM quotas of **10 managed policies per group** and **10 groups per user**, both fixed (not adjustable) as shown in the Service Quotas console, which bite as personas and per-team policies multiply. I would change to fewer, broader groups with a permissions boundary, attribute-based access control with tags (`persona`, team) instead of a group per persona, and eventually Identity Center permission sets.
- **Registry.** The first limit is the cost and latency of `ListObjectsV2` plus one `GetObject` per employee on every refresh. At 100 people this is fine, but at a few thousand objects each refresh makes thousands of requests, and the S3 free-tier GET budget of 20,000 per month is consumed quickly. I would move the registry to DynamoDB (single-digit-millisecond queries, an index on `status`, a generous always-free tier) or keep an index object updated on each write.
- **Dashboard.** The first limit is the IAM API **request rate**: about five calls per user per refresh, so 100 users means about 500 IAM calls per refresh, and parallel workers trigger throttling. I would use the IAM credential report (one call for every user's password, MFA and key status), cache the results longer, and refresh incrementally from CloudTrail events instead of polling everything.
- **Service identity.** The first limit is security rather than scale: all four containers share one host, so a compromised container can assume any service role (Q9). I would move to ECS task roles on Fargate, or at least set the IMDS hop limit to 1 and give the containers credentials through a sidecar.
- **Sign in.** The first limit is the single shared admin password: no individual accountability, a lockout that is per worker, and nothing to revoke per person. I would replace it with SSO through the company IdP (OIDC in front of the web app) with per-admin identities and MFA, and stop creating IAM users at all.
- **Logging.** The first limit is people's attention rather than volume: more users mean more CloudTrail events and more alerts, and 7–30-day retention in one account is not evidence-grade. I would move to a central log-archive account (organization trail, Object Lock), forward to a SIEM, and tune alerts to stay high-signal.

**Q23 (explore). Controls that even an administrator cannot remove.**
I experienced this directly in a first AWS account I created with AWS's new "projects" sign-up, which is a member account of an AWS-managed organization: an SCP denied `iam:CreateLoginProfile` even though my role had full administrator permissions, because SCPs set the maximum available permissions for every principal in a member account. Three SCPs protecting controls from this lab follow; the break-glass role name is an example.

1. **Protect the trail** (`lab01-trail`):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProtectLab01Trail",
    "Effect": "Deny",
    "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
               "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors"],
    "Resource": "arn:aws:cloudtrail:*:*:trail/lab01-trail",
    "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass" } }
  }]
}
```

2. **Protect the kill switch** (`Nimbus-DenyAll` cannot be edited, deleted or detached from users):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProtectDenyAllPolicy",
    "Effect": "Deny",
    "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicy",
               "iam:DeletePolicyVersion", "iam:DetachUserPolicy"],
    "Resource": ["arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll", "arn:aws:iam::*:user/nimbus/*"],
    "Condition": {
      "ArnEquals": { "iam:PolicyARN": "arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll" },
      "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass" }
    }
  }]
}
```
(`iam:PolicyARN` is present for attach and detach requests. For the policy-modification actions the resource ARN identifies the policy, so in practice I would split this into two statements, one per action group, to avoid a condition key that is missing for some actions.)

3. **Protect Block Public Access** at account and bucket level:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "KeepS3BlockPublicAccess",
    "Effect": "Deny",
    "Action": ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock",
               "s3:DeleteBucketPolicy", "s3:PutBucketPolicy"],
    "Resource": "*",
    "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass" } }
  }]
}
```
(In practice I would allow `PutBucketPolicy` for the pipeline role that applies the reviewed TLS-only policies and deny it for everyone else.)

An SCP does not grant any permission. It only filters, so principals still need IAM Allows. It does not affect service-linked roles. It does not restrict the management account, including its root user. It does not protect against misuse of permissions that remain allowed: an attacker who can still read data can exfiltrate it, and an SCP does not inspect data or network traffic. It also cannot stop the organization's own administrators, who can edit or detach SCPs from the management account.

The management account is treated differently so that the organization can never lock itself out. If SCPs applied there, a mistaken deny could remove the ability to fix the SCP itself. That is exactly why best practice is to run no workloads in the management account, protect it with strong MFA and few users, and delegate security services to a separate security account.

## Part J: Clean Up

**Q24 (explore). Can you trust the logs?**
Before running `99-cleanup.sh`, I validated the trail:
`aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-2:083163125365:trail/lab01-trail --start-time 2026-11-10T01:00:00Z` reported **3/3 digest files valid and 21/21 log files valid** for 01:00:00Z to 03:40:29Z.

With log file validation enabled, CloudTrail delivers an hourly digest file containing the SHA-256 hash of every log file delivered in that hour. Each digest is signed by CloudTrail with a private key and contains the signature of the previous digest, forming a chain. `validate-logs` downloads the digests and the logs, checks the signatures with CloudTrail's public key, recomputes the hashes, and walks the chain. It therefore proves that each log file is unmodified since delivery, that no log file referenced by a digest was deleted, and that no digest in the sequence was removed or forged. It does not prove that events that never reached the trail happened or did not happen, and validation stops where the chain stops.

In this lab, an attacker with administrator rights could still destroy or suppress the evidence. They could call `StopLogging` or `DeleteTrail` (both are recorded, but the record itself lands in a bucket they control), delete or overwrite log objects and digests in `lab01-logs-…` (versioning helps only until they delete the versions too), change the bucket policy, shorten the lifecycle rule, delete the CloudWatch log groups, or simply wait for the 30-day expiry. Validation would *detect* missing or modified files, but the evidence would be gone. The cleanup script does all of this legitimately in seconds.

A separate log-archive account changes the answer. An organization trail delivers logs to a bucket in a dedicated account that workload administrators cannot access, so compromising the workload account no longer gives control over the evidence. S3 Object Lock in compliance mode makes log objects immutable for a retention period, so not even the root user of the archive account can delete or overwrite them before it expires. MFA Delete on the versioned bucket requires the root user's MFA code to permanently delete versions or change versioning, which blocks automated deletion with stolen keys. Combined with an SCP that protects the trail (Q23), an attacker would have to compromise several independent identities and accounts to erase the evidence.

---

## References

- **Q1:** AWS IAM User Guide, "IAM Access Analyzer policy validation." https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
- **Q1:** AWS CloudFormation Guard (cfn-guard). https://github.com/aws-cloudformation/cloudformation-guard
- **Q4:** AWS IAM User Guide, "Permissions boundaries for IAM entities." https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- **Q4, Q23:** AWS Organizations User Guide, "Service control policies (SCPs)." https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
- **Q7:** AWS Key Management Service Developer Guide, "Key policies in AWS KMS." https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- **Q7:** AWS KMS pricing. https://aws.amazon.com/kms/pricing/
- **Q9:** Amazon EC2 User Guide, "Configure the instance metadata options" (IMDSv2, hop limit). https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- **Q9:** Amazon ECS Developer Guide, "Amazon ECS task IAM role." https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
- **Q11:** AWS CloudTrail User Guide, "CloudTrail supported services and integrations" (a logging trail is required for EventBridge to receive CloudTrail events). https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html
- **Q11:** Amazon GuardDuty User Guide, "What is Amazon GuardDuty?" https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
- **Q14:** RFC 6797, HTTP Strict Transport Security (HSTS). https://www.rfc-editor.org/rfc/rfc6797
- **Q14:** RFC 6962, Certificate Transparency. https://www.rfc-editor.org/rfc/rfc6962
- **Q18:** AWS IAM Identity Center User Guide. https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
- **Q21:** MITRE ATT&CK, T1098.001 Account Manipulation: Additional Cloud Credentials. https://attack.mitre.org/techniques/T1098/001/
- **Q21:** Center for Internet Security, CIS Amazon Web Services Foundations Benchmark. https://www.cisecurity.org/benchmark/amazon_web_services
- **Q24:** AWS CloudTrail User Guide, "Validating CloudTrail log file integrity." https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- **Q24:** Amazon S3 User Guide, "Locking objects with Object Lock." https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
