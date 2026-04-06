# PART 1 — Setup (AWS + Boto3)

### 1. Create AWS Account
- Go to AWS Free Tier
- Enable MFA on root account

### 2. Create IAM User
- Create a new user, "cognito-user"
- Attach a custom policy with these:
    - `cognito-idp:List*`
    - `cognito-idp:Describe*`
- Create access and secret keys for the user under IAM

### 3. AWS CLI
- `pip install awscli`
- `aws configure`
    - Access Key
    - Secret Key
    - Region

### 4. Boto3
- `pip install boto3`

### 5. Get the code
- Get the code file
- git clone the repo to use main.py

### 6. (OPTIONAL) Test connection to cognito

```python
import boto3

client = boto3.client('cognito-idp')

response = client.list_user_pools(MaxResults=10)

print(response)
```

- run the file

### 7. Sample output with multiple issues

```
Starting AWS Cognito Security Scan...

============================================================
User Pool: us-east-1_xBfAeANKQ
============================================================

[1] Severity: HIGH
Title: MFA Not Enforced
Description: Multi-Factor Authentication is not required.
Remediation: Set MFA to REQUIRED in Cognito settings.

[2] Severity: MEDIUM
Title: Weak Password Length
Description: Minimum password length is less than 8 characters.
Remediation: Set minimum length to at least 12.

[3] Severity: MEDIUM
Title: No Symbol Requirement
Description: Passwords do not require special characters.
Remediation: Enable symbol requirement.

[4] Severity: MEDIUM
Title: Insecure Auth Flow Enabled
Description: ADMIN_NO_SRP_AUTH allows direct password authentication.
Remediation: Disable this flow and use SRP-based authentication.

[5] Severity: LOW
Title: User Enumeration Possible
Description: System reveals whether a user exists.
Remediation: Enable PreventUserExistenceErrors.
```

Another sample output with no issues:

```
Starting AWS Cognito Security Scan...

============================================================
User Pool: us-west-2_xBfAeANKQ
============================================================
No issues found
```
