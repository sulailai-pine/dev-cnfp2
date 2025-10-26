# dev-cnfp2

## IAM Security Fix: Disruption of Log Groups/Streams

This repository contains the fix for the IAM security finding "Disruption of Log groups/streams". The security issue occurs when IAM policies grant excessive permissions that could allow deletion or modification of CloudWatch Logs resources.

### Files Included

- **`iam-policy-secure-logs.json`** - Secure IAM policy in JSON format that can be directly applied to AWS
- **`IAM_SECURITY_FIX.md`** - Comprehensive documentation explaining the security issue and fix
- **`secure_cloudwatch_logs_example.py`** - Python example demonstrating secure CloudWatch Logs usage with boto3
- **`terraform-example.tf`** - Terraform configuration for implementing the secure policy
- **`cloudformation-template.yaml`** - CloudFormation template for implementing the secure policy

### Quick Start

1. **Review the security fix documentation**: Read `IAM_SECURITY_FIX.md` for detailed information
2. **Choose your deployment method**:
   - AWS Console/CLI: Use `iam-policy-secure-logs.json`
   - Terraform: Use `terraform-example.tf`
   - CloudFormation: Use `cloudformation-template.yaml`
3. **Apply the policy** to your IAM roles and users
4. **Verify** that logging works but deletion operations are denied

### What This Fix Does

✅ **Allows**: Creating log groups, streams, and writing log events
❌ **Denies**: Deleting log groups, streams, retention policies, and other disruptive operations

### Security Best Practices

- Use explicit Deny statements to prevent unauthorized log deletion
- Follow the principle of least privilege
- Regularly audit IAM policies
- Enable CloudTrail for monitoring

For more information, see `IAM_SECURITY_FIX.md`.
