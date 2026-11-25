# OAuth Token Compromise SOP

**Classification:** TLP:CLEAR  
**Applies To:** Entra ID / Microsoft 365  
**Owner:** Security Operations  
**Version:** 1.0  
**Last Reviewed:** 2026-01-15

## Purpose

Standard Operating Procedure (SOP) for containment, scoping, and recovery following an OAuth token compromise in Entra ID / Microsoft 365 environments, including APT29-style device code phishing and malicious OAuth application grants.

## Scope

This SOP covers:
- Compromised user access tokens, refresh tokens, and session cookies
- Malicious OAuth application registrations and consent grants
- Device code phishing campaigns targeting Entra ID identities
- Persistent access via compromised service principals and app registrations

## Roles & Responsibilities

| Role | Responsibility |
| :--- | :--- |
| **Incident Commander** | Overall coordination, decision authority, stakeholder communication |
| **Security Analyst** | Triage, evidence collection, token revocation, hunting |
| **Identity Admin** | Entra ID configuration changes, app consent policy, conditional access |
| **Communications** | User notifications, executive briefings, legal/regulatory coordination |

## Phase 1 — Detection & Triage

### 1.1 Identify Compromise Indicators

Review the following signals to confirm OAuth token compromise:

- Sign-in logs showing successful authentication from unusual locations or residential ISPs
- OAuth device code authentication events (`deviceCode` grant type)
- New OAuth application registrations or consent grants initiated by users
- Application permissions granted to unfamiliar or high-risk apps (e.g., Mail.Read, User.Read.All, Directory.Read.All)
- Sign-ins from non-corporate devices or unmanaged endpoints
- Impossible travel or concurrent sessions from geographically disparate locations

### 1.2 Initial Containment (0–30 minutes)

| Action | Owner | Tool |
| :--- | :--- | :--- |
| Disable affected user account(s) | Identity Admin | Entra ID portal / PowerShell |
| Revoke all refresh tokens for affected users | Identity Admin | `Revoke-AzureADUserAllRefreshToken` |
| Block sign-in for affected users | Identity Admin | Entra ID > Users > Block sign-in |
| Quarantine suspicious OAuth applications | Security Analyst | Entra ID > App registrations |
| Preserve sign-in and audit logs | Security Analyst | Microsoft Sentinel / Defender |

### 1.3 Evidence Collection

Collect the following artifacts for scoping:

- Entra ID SigninLogs for affected UserPrincipalName (last 30 days)
- Entra ID AuditLogs for OAuth consent and app registration events
- Device code authentication events
- Application permission grants and admin consent records
- Email trace logs for phishing lures containing device code URLs
- Endpoint telemetry from affected devices (Defender for Endpoint)

## Phase 2 — Scoping

### 2.1 Determine Blast Radius

Answer the following questions:

1. Which user accounts were compromised?
2. Which OAuth applications were granted consent?
3. What permissions/scopes were granted (Mail.Read, Files.ReadAll, User.Read.All, etc.)?
4. Which mailboxes, SharePoint sites, or Teams channels were accessed?
5. Were any service principals or managed identities affected?
6. Was MFA bypassed via device code flow?
7. What is the time window of compromise (first to last observed malicious activity)?

### 2.2 Data Access Review

Query the following to determine data exfiltration scope:

```kql
// Mail accessed by compromised account
OfficeActivity
| where Operation in ("Accessed", "Send", "SendAs", "CopyItemsToOtherFolder")
| where UserId == "<compromised_user>"
| where TimeGenerated between (start_time) .. (end_time)

// SharePoint/OneDrive file access
OfficeActivity
| where Workload == "SharePoint" or Workload == "OneDrive"
| where UserId == "<compromised_user>"
| where TimeGenerated between (start_time) .. (end_time)
```

### 2.3 Persistence Check

Review for attacker-established persistence:

- Forwarding rules on compromised mailboxes
- Delegated permissions granted to malicious apps
- Device code phishing URLs sent to other users from compromised account
- New MFA registration methods added (Authenticator app, phone, email)
- Backup authentication methods added
- Conditional Access policy modifications

## Phase 3 — Containment & Eradication

### 3.1 Token Revocation

| Token Type | Action | Command |
| :--- | :--- | :--- |
| Access tokens | Short-lived; expire naturally | Wait for expiry (typically 1 hour) |
| Refresh tokens | Revoke all sessions | `Revoke-AzureADUserAllRefreshToken -ObjectId <user>` |
| Session cookies | Sign out all sessions | Entra ID > Users > Revoke sessions |
| App consent | Remove grants | Entra ID > App registrations > Remove permissions |

### 3.2 Malicious Application Removal

1. Navigate to Entra ID > App registrations
2. Identify apps registered during compromise window
3. Remove admin consent grants
4. Delete malicious app registrations
5. Audit remaining apps for excessive permissions

### 3.3 Credential Reset

- Force password reset for all affected users
- Require re-registration of MFA methods
- Remove any suspicious MFA registration methods added during compromise
- Enforce phishing-resistant MFA (FIDO2/WebAuthn) for affected users

### 3.4 Conditional Access & Policy Updates

- Apply Conditional Access policy requiring compliant devices
- Restrict OAuth device code flows where not required
- Limit user consent to applications (User consent settings)
- Enable tenant restrictions to block access to unauthorized cloud apps

## Phase 4 — Recovery

### 4.1 Restore Access

After verification of eradication:

1. Re-enable affected user accounts
2. Re-issue devices if compromise involved endpoint access
3. Restore email forwarding rules to original state
4. Re-grant required application permissions through approved workflow

### 4.2 Monitoring

Enhanced monitoring for 90 days post-incident:

- Daily review of SigninLogs for affected users
- Alert on new OAuth app registrations
- Alert on device code authentication events
- Alert on consent grants to high-privilege scopes
- Weekly review of Conditional Access sign-in logs

## Phase 5 — Lessons Learned

Document within 14 days of incident closure:

1. Initial infection vector and entry point
2. Time to detect, contain, and eradicate
3. Effectiveness of existing controls
4. Control gaps identified
5. Recommended remediation actions and owners
6. User awareness training updates

## Appendix A — Key PowerShell Commands

```powershell
# Revoke all refresh tokens for a user
Revoke-AzureADUserAllRefreshToken -ObjectId <user_object_id>

# Sign out user from all sessions
Revoke-AzureADSignInSessions -ObjectId <user_object_id>

# Get OAuth2PermissionGrants for a user
Get-AzureADOAuth2PermissionGrant -Filter "UserId eq '<user_object_id>'"

# Get service principals with suspicious names
Get-AzureADServicePrincipal -Filter "contains(DisplayName, '<suspicious_keyword>')"

# Remove OAuth2PermissionGrant
Remove-AzureADOAuth2PermissionGrant -ObjectId <grant_object_id>
```

## Appendix B — Entra ID Audit Log Operations to Review

- Consent to application
- Add OAuth2PermissionGrant
- Add delegated permission grant
- Update application
- Add service principal
- Update user authentication method
- Update user
- Set company information

## Revision History

| Version | Date | Author | Changes |
| :--- | :--- | :--- | :--- |
| 1.0 | 2026-01-15 | GreySentinel CTI Team | Initial release |
