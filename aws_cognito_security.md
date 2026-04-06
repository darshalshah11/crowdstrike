# AWS Cognito Security Overview

## Core Features and Overview

AWS Cognito is a **Managed Identity Provider (IdP)** that handles **Authentication (AuthN)** and **Authorization (AuthZ)** for applications in AWS.

It is designed to scale to millions of users and offload the complexity of secure credential storage and identity federation from the developer. It supports various sign-in options like Apple, Facebook, or Google, and enterprise directories including SAML 2.0.

- **User Pools** — handle user sign-in
- **Identity Pools** — grant temporary access to AWS services

---

## Potential Targets and Areas of Interest for Attackers

### 1. Front-End of the Application
Attackers can scrape an application's public code. If developers hardcode the `UserPoolID` or `IdentityPoolID` in JavaScript, attackers can bypass the website and directly interact with internal AWS service APIs using their own scripts.

### 2. JWT Token
Once a user logs in via AWS Cognito, the service assigns a JWT token that defines who the user is and what they are allowed to do.

Attackers can inspect the token, identify the assigned role, and attempt to modify it. If the backend does not properly validate the JWT signature, an attacker could forge or alter roles/permissions to gain unauthorized access.

### 3. App User to AWS User (Token Exchange)
Attackers can target the moment an app exchanges a Cognito token for temporary AWS credentials. They can inspect the IAM policy attached to those credentials.

An attacker may log in normally and use the browser console to capture any AWS secret keys sent by the identity pool — then use those keys in their own terminal to exploit access.

---

## Top 5 Security Misconfigurations

### 1. Over-Privileged IAM Roles for Authenticated Users

**Description:**
Identity Pools assign an IAM role to logged-in users. A common mistake is attaching a policy with overly broad permissions (e.g., full S3 access) instead of scoping them appropriately.

**Attack Scenario:**
An attacker creates a legitimate account, captures their own temporary AWS keys from the browser, and uses the AWS CLI to access sensitive data from other users' S3 buckets.

**Remediation:**
Use IAM Policy Variables such as `${cognito-identity.amazonaws.com:sub}` to ensure users can only access resources tied to their specific Identity ID.

---

### 2. Disabled or Optional Multi-Factor Authentication (MFA)

**Description:**
MFA is often left as "Optional" by default, leaving the pool vulnerable to credential stuffing attacks.

**Attack Scenario:**
An attacker uses leaked passwords from an unrelated breach to log into a user's account. Because MFA is not required, they gain immediate access to the user's data and AWS credentials.

**Remediation:**
Set MFA to **Required** and prioritize TOTP (authenticator apps) over SMS-based verification.

---

### 3. User Enumeration Enabled

**Description:**
Cognito may return different error messages depending on whether a user exists. If `PreventUserExistenceErrors` is not enabled, attackers can identify valid usernames.

**Attack Scenario:**
An attacker sends login or password reset requests with different usernames and analyzes the error responses to determine which accounts exist — then targets them with brute-force or phishing attacks.

**Remediation:**
Enable `PreventUserExistenceErrors` in Cognito settings to ensure uniform error responses regardless of whether a user exists.

---

### 4. Overly Permissive Auth Flows

**Description:**
Cognito App Clients support multiple authentication flows. Enabling insecure flows such as `ALLOW_ADMIN_NO_SRP_AUTH` or `ALLOW_USER_PASSWORD_AUTH` can bypass more secure mechanisms like SRP (Secure Remote Password protocol).

**Attack Scenario:**
An attacker exploits a weaker authentication flow that transmits credentials directly instead of using SRP, increasing the risk of credential interception or misuse.

**Remediation:**
Disable insecure authentication flows and only allow secure ones such as `ALLOW_USER_SRP_AUTH` and `ALLOW_REFRESH_TOKEN_AUTH`. Follow AWS best practices for secure authentication mechanisms.

---

### 5. Weak Password Policy

**Description:**
Cognito User Pools allow customization of password policies. Enforcing weak requirements — such as a short minimum length or no complexity rules — reduces resistance to brute-force and credential stuffing attacks.

**Attack Scenario:**
An attacker performs credential stuffing using leaked passwords from other breaches. Because the application allows weak passwords, users are more likely to reuse simple credentials, increasing the chance of a successful account compromise.

**Remediation:**
Enforce a strong password policy requiring:
- Minimum **12+ characters**
- Uppercase and lowercase letters
- Numbers
- Special characters

Regularly review and update password policies to align with AWS security best practices.
