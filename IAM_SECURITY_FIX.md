# IAM Security Fix: Disruption of Log Groups/Streams

## Problem
The IAM security finding "Disruption of Log groups/streams" indicates that IAM policies grant excessive permissions that could allow deletion or modification of CloudWatch Logs resources. This poses a security risk as it could:
- Allow unauthorized deletion of audit logs
- Disrupt application logging
- Enable attackers to cover their tracks by deleting logs
- Violate compliance requirements for log retention

## Dangerous Permissions
The following CloudWatch Logs permissions should be restricted or denied:
- `logs:DeleteLogGroup` - Allows deletion of entire log groups
- `logs:DeleteLogStream` - Allows deletion of log streams
- `logs:DeleteRetentionPolicy` - Allows modification of log retention settings
- `logs:DeleteDestination` - Allows deletion of log destinations
- `logs:DeleteMetricFilter` - Allows deletion of metric filters
- `logs:DeleteSubscriptionFilter` - Allows deletion of subscription filters
- `logs:DeleteResourcePolicy` - Allows deletion of resource policies

## Solution
The `iam-policy-secure-logs.json` file provides a secure IAM policy that:

1. **Allows necessary operations** - Grants permissions for creating log groups, streams, and writing log events
2. **Explicitly denies dangerous operations** - Uses an explicit Deny statement to prevent deletion of logs
3. **Follows least privilege principle** - Only grants the minimum permissions needed for logging

## Allowed Permissions
- `logs:CreateLogGroup` - Create new log groups
- `logs:CreateLogStream` - Create new log streams
- `logs:PutLogEvents` - Write log events
- `logs:DescribeLogGroups` - List and describe log groups
- `logs:DescribeLogStreams` - List and describe log streams
- `logs:GetLogEvents` - Read log events
- `logs:FilterLogEvents` - Search log events

## Implementation

### AWS Console
1. Go to IAM → Policies
2. Create a new policy
3. Use the JSON editor
4. Paste the contents of `iam-policy-secure-logs.json`
5. Review and create the policy
6. Attach the policy to relevant roles or users

### AWS CLI
```bash
aws iam create-policy \
  --policy-name SecureCloudWatchLogsPolicy \
  --policy-document file://iam-policy-secure-logs.json
```

### Terraform
```hcl
resource "aws_iam_policy" "secure_cloudwatch_logs" {
  name        = "SecureCloudWatchLogsPolicy"
  description = "Secure CloudWatch Logs policy preventing disruption of log groups/streams"
  
  policy = file("${path.module}/iam-policy-secure-logs.json")
}

resource "aws_iam_role_policy_attachment" "attach_secure_logs" {
  role       = aws_iam_role.your_role.name
  policy_arn = aws_iam_policy.secure_cloudwatch_logs.arn
}
```

### CloudFormation
```yaml
Resources:
  SecureCloudWatchLogsPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: SecureCloudWatchLogsPolicy
      Description: Secure CloudWatch Logs policy preventing disruption of log groups/streams
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: SecureCloudWatchLogsAccess
            Effect: Allow
            Action:
              - logs:CreateLogGroup
              - logs:CreateLogStream
              - logs:PutLogEvents
              - logs:DescribeLogGroups
              - logs:DescribeLogStreams
              - logs:GetLogEvents
              - logs:FilterLogEvents
            Resource: '*'
          - Sid: DenyDisruptiveLogOperations
            Effect: Deny
            Action:
              - logs:DeleteLogGroup
              - logs:DeleteLogStream
              - logs:DeleteRetentionPolicy
              - logs:DeleteDestination
              - logs:DeleteMetricFilter
              - logs:DeleteSubscriptionFilter
              - logs:DeleteResourcePolicy
            Resource: '*'
```

## Best Practices
1. **Use explicit Deny** - The Deny statement takes precedence over Allow, ensuring these operations cannot be performed even if granted elsewhere
2. **Apply to specific resources** - Consider restricting to specific log groups if possible using ARN patterns
3. **Audit regularly** - Review IAM policies regularly to ensure they follow least privilege
4. **Enable CloudTrail** - Monitor CloudWatch Logs API calls for any unauthorized access attempts
5. **Use resource tags** - Tag log groups for better policy management and access control

## Verification
After applying the policy, verify that:
1. Applications can still write logs (PutLogEvents)
2. Log groups and streams can be created
3. Attempts to delete log groups or streams are denied
4. CloudTrail shows no unauthorized log deletion attempts

## References
- [AWS CloudWatch Logs Permissions Reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Security Best Practices for CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/security-best-practices.html)
