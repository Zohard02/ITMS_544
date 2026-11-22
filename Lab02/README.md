# Lab02: Identity Management as Code (Terraform) on the AWS Free Tier

Terraform builds a two tier network (public and private subnets in two availability zones), a NAT instance, and one
EC2 instance for each of four microservices. Administrators sign in with Amazon Cognito (password plus authenticator
app code) and every service verifies the resulting JWT. Nothing secret is stored in this folder.

    terraform/bootstrap   run once: creates the S3 bucket that holds the Terraform state (local state)
    terraform/            the lab: network, firewalls, IAM, buckets, secrets, certificates, Cognito, instances
    app/                  the Flask microservices (zipped and shipped to the instances by Terraform)
    scripts/              seed the roster, rotate the token, investigate a user, delete app created users
    tests/                unit tests (moto) and static tests of the Terraform files

Run `./run_tests.sh all` before every `terraform apply`. Start in the lab manual.
