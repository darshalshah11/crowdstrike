Core Features and Overview

AWS Cognito is a Managed Identity Provider (IdP) that handles Authentication (AuthN) and Authorization (AuthZ) for applications in AWS. 

It is designed to scale to millions of users and offload the complexity of secure credential storage and identity federation from the developer. It supports various different sign-in options like Apple, Facebook, or Google, and enterprise directories including SAML 2.0. 

It uses User Pools for sign in, and then identity pools to grant temporary access to aws services. 

Potential Targets and Areas of Interest for Attackers

- The front end of the application.

Attackers can scrape the applications public code. If developers hardcode the UserPoolID, or IdentityPoolID in the javascript, the attackers can bypass the website, and directly start interacting with internal AWS service APIs with their own script. 

- JWT token
Once a user logs in using aws cognito service, the service will assign the user JWT token. This token is what tells the application who you are, and what you are allowed to do.

Attackers can look into the token details, and look for their given role, and can change the role. If the backend does not properly validate the JWT signature, an attacker could forge or modify the roles or permissions and gain unauthorized access.

- App user to AWS user

Attackers can target the moment the app exchanges the cognito token for temporary aws credentionals/token. They can look at the permissions (IAM Policy) attached to those credentials. 

The attacker would login normally but can use the browser console to catch any potential aws secret keys that the identity pool sends. Then the attacker can use those to plug them into his own terminal and exploit it. 


Top 4 security Misconfigurations:

1.Over-Privileged IAM Roles for Authenticated Users

Description: Identity Pools assign an IAM role to logged-in users. A common mistake is attaching a policy with broad permissions (full s3 bucket) rather than restricting access

Attack Scenario: An attacker can create a legitimate account, steal their own temporary AWS keys from the browser, and use the AWS CLI to download sensitive data from other users' S3 buckets.

Remediation: Use IAM Policy Variables (e.g., ${cognito-identity.amazonaws.com:sub}) to ensure users can only access resources matching their specific Identity ID.

2. Disabled or Optional Multi-Factor Authentication (MFA)
Description: MFA is often left as "Optional" by default, making the pool vulnerable to credential stuffing.

Attack Scenario: An attacker uses leaked passwords from an unrelated breach to log into a user's account. Because MFA isn't required, they gain immediate access to the user's data and AWS credentials.

Remediation: Set MFA to "Required" and prioritize TOTP (Authenticator apps) over SMS.

3. User Enumeration Enabled

Description:
Cognito may return different error messages depending on whether a user exists. If PreventUserExistenceErrors is not enabled, attackers can determine valid usernames.

Attack Scenario:
An attacker sends login or password reset requests with different usernames. By analyzing error responses, they can identify which accounts exist and then target those accounts with brute-force or phishing attacks.

Remediation:
Enable PreventUserExistenceErrors in Cognito settings to ensure uniform error responses regardless of whether a user exists.

4. Overly Permissive Auth Flows

Description:
Cognito App Clients support multiple authentication flows. Enabling insecure flows such as ALLOW_ADMIN_NO_SRP_AUTH or ALLOW_USER_PASSWORD_AUTH can bypass more secure mechanisms like SRP (Secure Remote Password protocol).

Attack Scenario:
An attacker exploits a weaker authentication flow that allows direct transmission of credentials instead of using SRP. This increases the risk of credential interception or misuse, especially in improperly secured environments.

Remediation:
Disable insecure authentication flows and only allow secure ones such as ALLOW_USER_SRP_AUTH and ALLOW_REFRESH_TOKEN_AUTH. Follow AWS best practices for secure authentication mechanisms.
5. Weak Password Policy
Description:
Cognito User Pools allow customization of password policies. A common misconfiguration is enforcing weak password requirements, such as short minimum length or lack of complexity,, which reduces resistance to brute-force and credential stuffing attacks.
Attack Scenario:
An attacker performs credential stuffing using leaked passwords from other breaches. Because the application allows weak passwords, users are more likely to reuse simple credentials, increasing the likelihood of successful account compromise.
Remediation:
Enforce a strong password policy requiring a minimum length (e.g., 12+ characters) and a combination of uppercase letters, lowercase letters, numbers, and special characters. Regularly review and update password policies to align with AWS security best practices.

