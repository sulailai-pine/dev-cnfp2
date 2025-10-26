# Terraform configuration for IAM Security Fix: Disruption of Log Groups/Streams
#
# This configuration demonstrates how to implement the secure CloudWatch Logs IAM policy
# that prevents disruption of log groups and streams.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Secure CloudWatch Logs IAM Policy
# This policy allows necessary logging operations while explicitly denying
# dangerous operations that could disrupt logging.

resource "aws_iam_policy" "secure_cloudwatch_logs" {
  name        = "SecureCloudWatchLogsPolicy"
  description = "Secure CloudWatch Logs policy preventing disruption of log groups/streams"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecureCloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDisruptiveLogOperations"
        Effect = "Deny"
        Action = [
          "logs:DeleteLogGroup",
          "logs:DeleteLogStream",
          "logs:DeleteRetentionPolicy",
          "logs:DeleteDestination",
          "logs:DeleteMetricFilter",
          "logs:DeleteSubscriptionFilter",
          "logs:DeleteResourcePolicy"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Purpose         = "Security"
    SecurityFinding = "DisruptionOfLogGroupsStreams"
    Compliance      = "IAM-BestPractices"
  }
}

# Example: IAM Role for Lambda with Secure Logs Policy
resource "aws_iam_role" "lambda_execution_secure" {
  name = "lambda-execution-secure-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "Lambda execution with secure logging"
  }
}

# Attach the secure CloudWatch Logs policy to the Lambda role
resource "aws_iam_role_policy_attachment" "lambda_secure_logs" {
  role       = aws_iam_role.lambda_execution_secure.name
  policy_arn = aws_iam_policy.secure_cloudwatch_logs.arn
}

# Example: IAM Role for ECS Task with Secure Logs Policy
resource "aws_iam_role" "ecs_task_execution_secure" {
  name = "ecs-task-execution-secure-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "ECS task execution with secure logging"
  }
}

# Attach the secure CloudWatch Logs policy to the ECS task role
resource "aws_iam_role_policy_attachment" "ecs_secure_logs" {
  role       = aws_iam_role.ecs_task_execution_secure.name
  policy_arn = aws_iam_policy.secure_cloudwatch_logs.arn
}

# Example: IAM Role for EC2 Instance with Secure Logs Policy
resource "aws_iam_role" "ec2_instance_secure" {
  name = "ec2-instance-secure-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "EC2 instance with secure logging"
  }
}

# Attach the secure CloudWatch Logs policy to the EC2 role
resource "aws_iam_role_policy_attachment" "ec2_secure_logs" {
  role       = aws_iam_role.ec2_instance_secure.name
  policy_arn = aws_iam_policy.secure_cloudwatch_logs.arn
}

# Instance profile for EC2
resource "aws_iam_instance_profile" "ec2_secure" {
  name = "ec2-instance-secure-logs"
  role = aws_iam_role.ec2_instance_secure.name
}

# Outputs
output "secure_logs_policy_arn" {
  description = "ARN of the secure CloudWatch Logs IAM policy"
  value       = aws_iam_policy.secure_cloudwatch_logs.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role with secure logs policy"
  value       = aws_iam_role.lambda_execution_secure.arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task execution role with secure logs policy"
  value       = aws_iam_role.ecs_task_execution_secure.arn
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile with secure logs policy"
  value       = aws_iam_instance_profile.ec2_secure.name
}
