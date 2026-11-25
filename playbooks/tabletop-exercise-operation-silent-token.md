# Tabletop Exercise: Operation Silent Token

**Classification:** TLP:CLEAR  
**Exercise Type:** Incident Response Tabletop  
**Duration:** 90 minutes  
**Facilitator:** Security Operations  
**Participants:** SOC Analysts, Identity Admins, Incident Commander, Communications, Legal  
**Scenario:** APT29-style OAuth device code phishing leading to Entra ID / Microsoft 365 compromise  
**Version:** 1.0  
**Date:** 2026-01-15

## Exercise Overview

**Operation Silent Token** simulates a sophisticated cloud identity compromise where an adversary leverages OAuth device code phishing to obtain persistent access to an organization's Entra ID tenant and Microsoft 365 environment. The exercise tests detection, containment, scoping, and recovery capabilities.

## Scenario Narrative

### T+0: Initial Access

On a Tuesday morning, multiple employees in the Finance and Engineering departments receive Microsoft Teams messages from what appears to be the internal IT Help Desk. The message states:

> "We are performing a mandatory security upgrade on all Microsoft 365 accounts. Please complete device registration at https://microsoft.com/devicelogin using code ABC-12345 to avoid service interruption."

Three users enter the device code on a legitimate Microsoft domain, authenticating their sessions to an attacker-controlled application. The attacker obtains access tokens and refresh tokens for these accounts.

### T+2 Hours: Lateral Movement

The attacker uses the compromised accounts to:
- Send additional device code phishing messages from compromised accounts to other employees
- Search mailboxes for sensitive keywords ("invoice", "payment", "confidential", "merger")
- Grant OAuth consent to a malicious application registered in the tenant with Mail.Read, Files.ReadAll, and User.Read.All permissions
- Add a new MFA registration method (Authenticator app) to one compromised account

### T+6 Hours: Data Access

The attacker:
- Exfiltrates email threads containing financial transaction details
- Accesses SharePoint sites containing quarterly earnings documents
- Creates inbox rules to forward external emails to an attacker-controlled address
- Changes the compromised user's self-service password reset (SSPR) phone number

### T+12 Hours: Detection

The SOC receives an alert from Microsoft Defender for Identity indicating:
- Successful sign-ins from residential IP addresses not previously associated with the organization
- Device code authentication events for users outside normal business hours
- New OAuth application consent grants initiated by affected users

## Exercise Objectives

1. **Detection:** Identify indicators of OAuth device code phishing and malicious app consent
2. **Containment:** Revoke tokens, disable accounts, and block malicious applications
3. **Scoping:** Determine blast radius including data accessed and persistence established
4. **Eradication:** Remove attacker persistence and reset credentials
5. **Recovery:** Restore user access and implement preventive controls
6. **Communication:** Notify affected users, leadership, and potentially regulators

## Exercise Timeline & Injects

| Time | Inject | Description | Expected Response |
| :--- | :--- | :--- | :--- |
| **T+0** | **Inject 1** | IT Help Desk receives 3 calls from employees who entered device codes after Teams messages | SOC triage, identify device code auth in SigninLogs |
| **T+15 min** | **Inject 2** | Additional users report receiving similar Teams messages from compromised accounts | Identify lateral movement via compromised mailboxes |
| **T+30 min** | **Inject 3** | New OAuth application registered in tenant with Mail.ReadAll and Files.ReadAll permissions | Remove app consent, revoke tokens |
| **T+45 min** | **Inject 4** | Attacker added Authenticator app as MFA method to compromised account | Remove MFA method, force password reset |
| **T+60 min** | **Inject 5** | Email forwarding rule created on compromised mailbox to external address | Remove forwarding rule, review mailbox audit logs |
| **T+75 min** | **Inject 6** | Legal asks if data exfiltration is confirmed and which regulators must be notified | Determine data access scope, initiate breach assessment |
| **T+90 min** | **Debrief** | Exercise conclusion and lessons learned | Document gaps, update SOPs |

## Discussion Questions

### Detection Phase
1. Which telemetry sources would first indicate this compromise?
2. How would you distinguish legitimate device code usage from phishing?
3. What is your mean time to detect (MTTD) for OAuth device code authentication anomalies?

### Containment Phase
1. What is the order of operations for revoking access? Which comes first: disabling accounts or revoking tokens?
2. How do you handle users who need continued access during investigation?
3. What is your process for removing malicious OAuth applications from the tenant?

### Scoping Phase
1. Which logs would you review to determine data access scope?
2. How do you identify persistence mechanisms (MFA methods, forwarding rules, delegated permissions)?
3. What is your process for determining if data exfiltration occurred?

### Eradication & Recovery Phase
1. How do you verify all attacker access has been removed?
2. What is your credential reset and MFA re-registration process?
3. How do you restore legitimate application permissions after cleanup?

### Communication Phase
1. When do you notify affected users?
2. At what point do you involve executive leadership?
3. What regulatory notification obligations might apply?

## Evaluation Criteria

| Criteria | Metric | Target |
| :--- | :--- | :--- |
| Detection | Time to identify device code compromise | < 30 minutes |
| Containment | Time to revoke all tokens and disable accounts | < 45 minutes |
| Scoping | Percentage of affected accounts identified | 100% |
| Persistence | All attacker MFA methods and forwarding rules removed | 100% |
| Communication | Affected users notified | < 2 hours |

## Facilitator Notes

- Encourage participants to think through decisions out loud
- Introduce injects based on participant responses; adjust timing as needed
- If participants move too quickly, introduce complications (e.g., attacker already established persistence)
- If participants are stuck, provide hints about relevant telemetry sources
- Document all decisions and action items for the after-action report

## After-Action Items

| Item | Owner | Due Date | Status |
| :--- | :--- | :--- | :--- |
| Update OAuth token revocation SOP | Security Operations | 2 weeks | Open |
| Restrict OAuth device code flows in Conditional Access | Identity Team | 1 week | Open |
| Implement device code authentication alerting | SOC | 2 weeks | Open |
| Conduct user awareness training on device code phishing | Security Awareness | 1 month | Open |
| Review and reduce OAuth application permissions | Identity Team | 2 weeks | Open |

## References

- [MITRE ATT&CK T1528 - Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1098.003 - Account Manipulation: OAuth Application](https://attack.mitre.org/techniques/T1098/003/)
- GreySentinel OAuth Token Compromise SOP (`playbooks/oauth-token-compromise-sop.md`)
- GreySentinel APT29 Intelligence Brief (`briefs⁄apt29-intelligence-brief.md`)
