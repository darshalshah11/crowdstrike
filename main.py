"""
AWS Cognito Security Scanner

This script scans Cognito User Pools for common security misconfigurations:
- MFA not enforced
- Weak password policy
- Insecure authentication flows
- User enumeration enabled
"""

import boto3
import botocore.exceptions
import time

# -----------------------------
# CONFIGURATION
# -----------------------------

# Retry settings for throttling
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds


# -----------------------------
# HELPER: SAFE AWS API CALL
# From AWS and Python Documentation
# -----------------------------
def safe_aws_call(func, **kwargs):
    """
    Wrapper to safely call AWS APIs with retry + error handling
    """
    for attempt in range(MAX_RETRIES):
        try:
            return func(**kwargs)

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code in ['ThrottlingException', 'TooManyRequestsException']:
                print(f"[WARN] Rate limited. Retrying ({attempt+1}/{MAX_RETRIES})...")
                time.sleep(RETRY_DELAY)
            elif error_code == 'AccessDeniedException':
                print("[ERROR] Access denied. Check IAM permissions.")
                return None
            else:
                print(f"[ERROR] AWS ClientError: {e}")
                return None

        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return None

    return None


# -----------------------------
# CHECK 1: MFA
# -----------------------------
def check_mfa(client, user_pool_id):
    findings = []

    response = safe_aws_call(
        client.describe_user_pool,
        UserPoolId=user_pool_id
    )

    if not response:
        return findings

    mfa = response['UserPool'].get('MfaConfiguration')

    if mfa != 'ON':
        findings.append({
            "severity": "HIGH",
            "title": "MFA Not Enforced",
            "description": "Multi-Factor Authentication is not required.",
            "remediation": "Set MFA to REQUIRED in Cognito settings."
        })

    return findings


# -----------------------------
# CHECK 2: PASSWORD POLICY
# -----------------------------
def check_password_policy(client, user_pool_id):
    findings = []

    response = safe_aws_call(
        client.describe_user_pool,
        UserPoolId=user_pool_id
    )

    if not response:
        return findings

    policy = response['UserPool']['Policies']['PasswordPolicy']

    if policy.get('MinimumLength', 0) < 8:
        findings.append({
            "severity": "MEDIUM",
            "title": "Weak Password Length",
            "description": "Minimum password length is less than 8 characters.",
            "remediation": "Set minimum length to at least 12."
        })

    if not policy.get('RequireSymbols'):
        findings.append({
            "severity": "MEDIUM",
            "title": "No Symbol Requirement",
            "description": "Passwords do not require special characters.",
            "remediation": "Enable symbol requirement."
        })

    if not policy.get('RequireNumbers'):
        findings.append({
            "severity": "MEDIUM",
            "title": "No Number Requirement",
            "description": "Passwords do not require numeric characters.",
            "remediation": "Enable number requirement."
        })

    return findings


# -----------------------------
# CHECK 3: AUTH FLOWS
# -----------------------------
def check_auth_flows(client, user_pool_id):
    findings = []

    response = safe_aws_call(
        client.list_user_pool_clients,
        UserPoolId=user_pool_id
    )

    if not response:
        return findings

    for app_client in response.get('UserPoolClients', []):
        detail = safe_aws_call(
            client.describe_user_pool_client,
            UserPoolId=user_pool_id,
            ClientId=app_client['ClientId']
        )

        if not detail:
            continue

        flows = detail['UserPoolClient'].get('ExplicitAuthFlows', [])

        if 'ALLOW_ADMIN_NO_SRP_AUTH' in flows:
            findings.append({
                "severity": "MEDIUM",
                "title": "Insecure Auth Flow Enabled",
                "description": "ADMIN_NO_SRP_AUTH allows direct password authentication.",
                "remediation": "Disable this flow and use SRP-based authentication."
            })

    return findings


# -----------------------------
# CHECK 4: USER ENUMERATION
# -----------------------------
def check_user_enumeration(client, user_pool_id):
    findings = []

    response = safe_aws_call(
        client.describe_user_pool,
        UserPoolId=user_pool_id
    )

    if not response:
        return findings

    setting = response['UserPool'].get('PreventUserExistenceErrors')

    if setting != 'ENABLED':
        findings.append({
            "severity": "LOW",
            "title": "User Enumeration Possible",
            "description": "System reveals whether a user exists.",
            "remediation": "Enable PreventUserExistenceErrors."
        })

    return findings


# -----------------------------
# OUTPUT FORMATTER
# -----------------------------
def print_findings(user_pool_id, findings):
    """
    Print findings in structured, readable format
    """
    print("\n" + "="*60)
    print(f"User Pool: {user_pool_id}")
    print("="*60)

    if not findings:
        print("No issues found")
        return

    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] Severity: {f['severity']}")
        print(f"Title: {f['title']}")
        print(f"Description: {f['description']}")
        print(f"Remediation: {f['remediation']}")


# -----------------------------
# MAIN EXECUTION
# -----------------------------
def main():
    """
    Entry point of the scanner
    """

    print("Starting AWS Cognito Security Scan...\n")

    # Create Cognito client
    client = boto3.client('cognito-idp')

    # Get user pools
    response = safe_aws_call(client.list_user_pools, MaxResults=10)

    if not response:
        print("ERROR, Could not retrieve user pools.")
        return

    user_pools = response.get('UserPools', [])

    if not user_pools:
        print("No Cognito User Pools found.")
        return

    # Iterate through each user pool
    for pool in user_pools:
        pool_id = pool['Id']

        findings = []

        # Run all checks
        findings.extend(check_mfa(client, pool_id))
        findings.extend(check_password_policy(client, pool_id))
        findings.extend(check_auth_flows(client, pool_id))
        findings.extend(check_user_enumeration(client, pool_id))

        # Print results
        print_findings(pool_id, findings)


# -----------------------------
# SCRIPT ENTRY
# -----------------------------
if __name__ == "__main__":
    main()
