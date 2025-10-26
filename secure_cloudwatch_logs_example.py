"""
Example Python code demonstrating secure CloudWatch Logs usage with the IAM policy fix.

This module shows how to interact with CloudWatch Logs using boto3 with the
secure IAM policy that prevents disruption of log groups/streams.
"""

import json
import boto3
from botocore.exceptions import ClientError


class SecureCloudWatchLogsClient:
    """
    A wrapper around boto3 CloudWatch Logs client that demonstrates
    secure logging practices aligned with the IAM security fix.
    """

    def __init__(self, region_name='us-east-1'):
        """Initialize the CloudWatch Logs client."""
        self.client = boto3.client('logs', region_name=region_name)

    def create_log_group(self, log_group_name):
        """
        Create a log group if it doesn't exist.
        
        This operation is allowed by the secure IAM policy.
        
        Args:
            log_group_name (str): Name of the log group to create
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.client.create_log_group(logGroupName=log_group_name)
            print(f"Successfully created log group: {log_group_name}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                print(f"Log group already exists: {log_group_name}")
                return True
            else:
                print(f"Error creating log group: {e}")
                return False

    def create_log_stream(self, log_group_name, log_stream_name):
        """
        Create a log stream within a log group.
        
        This operation is allowed by the secure IAM policy.
        
        Args:
            log_group_name (str): Name of the log group
            log_stream_name (str): Name of the log stream to create
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            print(f"Successfully created log stream: {log_stream_name}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                print(f"Log stream already exists: {log_stream_name}")
                return True
            else:
                print(f"Error creating log stream: {e}")
                return False

    def put_log_events(self, log_group_name, log_stream_name, messages):
        """
        Write log events to a log stream.
        
        This operation is allowed by the secure IAM policy.
        
        Args:
            log_group_name (str): Name of the log group
            log_stream_name (str): Name of the log stream
            messages (list): List of log messages to write
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import time
            
            log_events = [
                {
                    'timestamp': int(time.time() * 1000),
                    'message': msg
                }
                for msg in messages
            ]
            
            self.client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=log_events
            )
            print(f"Successfully wrote {len(messages)} log events")
            return True
        except ClientError as e:
            print(f"Error writing log events: {e}")
            return False

    def describe_log_groups(self, prefix=None):
        """
        List log groups.
        
        This operation is allowed by the secure IAM policy.
        
        Args:
            prefix (str, optional): Filter log groups by prefix
            
        Returns:
            list: List of log group names
        """
        try:
            kwargs = {}
            if prefix:
                kwargs['logGroupNamePrefix'] = prefix
                
            response = self.client.describe_log_groups(**kwargs)
            log_groups = [lg['logGroupName'] for lg in response.get('logGroups', [])]
            print(f"Found {len(log_groups)} log groups")
            return log_groups
        except ClientError as e:
            print(f"Error describing log groups: {e}")
            return []

    def get_log_events(self, log_group_name, log_stream_name, limit=10):
        """
        Retrieve log events from a log stream.
        
        This operation is allowed by the secure IAM policy.
        
        Args:
            log_group_name (str): Name of the log group
            log_stream_name (str): Name of the log stream
            limit (int): Maximum number of events to retrieve
            
        Returns:
            list: List of log events
        """
        try:
            response = self.client.get_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                limit=limit
            )
            events = response.get('events', [])
            print(f"Retrieved {len(events)} log events")
            return events
        except ClientError as e:
            print(f"Error getting log events: {e}")
            return []

    # The following operations are DENIED by the secure IAM policy
    # and will raise AccessDenied exceptions

    def delete_log_group(self, log_group_name):
        """
        Attempt to delete a log group.
        
        This operation is DENIED by the secure IAM policy and will fail.
        
        Args:
            log_group_name (str): Name of the log group to delete
            
        Returns:
            bool: False (operation is denied)
        """
        try:
            self.client.delete_log_group(logGroupName=log_group_name)
            print(f"Deleted log group: {log_group_name}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"ACCESS DENIED: Cannot delete log group (prevented by security policy)")
            else:
                print(f"Error deleting log group: {e}")
            return False

    def delete_log_stream(self, log_group_name, log_stream_name):
        """
        Attempt to delete a log stream.
        
        This operation is DENIED by the secure IAM policy and will fail.
        
        Args:
            log_group_name (str): Name of the log group
            log_stream_name (str): Name of the log stream to delete
            
        Returns:
            bool: False (operation is denied)
        """
        try:
            self.client.delete_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            print(f"Deleted log stream: {log_stream_name}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                print(f"ACCESS DENIED: Cannot delete log stream (prevented by security policy)")
            else:
                print(f"Error deleting log stream: {e}")
            return False


def load_iam_policy():
    """
    Load and return the secure IAM policy from the JSON file.
    
    Returns:
        dict: The IAM policy document
    """
    try:
        with open('iam-policy-secure-logs.json', 'r') as f:
            policy = json.load(f)
        return policy
    except FileNotFoundError:
        print("Error: iam-policy-secure-logs.json not found")
        return None


def demonstrate_secure_usage():
    """
    Demonstrate secure CloudWatch Logs operations.
    
    This function shows how to use CloudWatch Logs with the secure IAM policy.
    """
    print("=" * 60)
    print("Demonstrating Secure CloudWatch Logs Usage")
    print("=" * 60)
    
    # Initialize the client
    logs_client = SecureCloudWatchLogsClient()
    
    # Test allowed operations
    print("\n--- Testing ALLOWED Operations ---")
    
    log_group = "/aws/lambda/secure-function"
    log_stream = "2025/10/26/[$LATEST]abcdef123456"
    
    # Create log group
    logs_client.create_log_group(log_group)
    
    # Create log stream
    logs_client.create_log_stream(log_group, log_stream)
    
    # Write log events
    messages = [
        "Application started successfully",
        "Processing request ID: 12345",
        "Request completed in 150ms"
    ]
    logs_client.put_log_events(log_group, log_stream, messages)
    
    # List log groups
    logs_client.describe_log_groups(prefix="/aws/lambda/")
    
    # Read log events
    logs_client.get_log_events(log_group, log_stream, limit=5)
    
    # Test denied operations
    print("\n--- Testing DENIED Operations (Should Fail) ---")
    
    # Attempt to delete log stream (will be denied)
    logs_client.delete_log_stream(log_group, log_stream)
    
    # Attempt to delete log group (will be denied)
    logs_client.delete_log_group(log_group)
    
    print("\n" + "=" * 60)
    print("Demo complete. Log resources are protected from deletion.")
    print("=" * 60)


if __name__ == "__main__":
    # Display the IAM policy
    print("Loading secure IAM policy...")
    policy = load_iam_policy()
    if policy:
        print("\nSecure IAM Policy:")
        print(json.dumps(policy, indent=2))
        print("\n")
    
    # Uncomment the following line to run the demonstration
    # Note: This requires valid AWS credentials and appropriate setup
    # demonstrate_secure_usage()
    
    print("\nTo use this in your application:")
    print("1. Apply the IAM policy from iam-policy-secure-logs.json")
    print("2. Attach the policy to your IAM role or user")
    print("3. Use the SecureCloudWatchLogsClient in your code")
    print("4. Verify that deletion operations are denied")
