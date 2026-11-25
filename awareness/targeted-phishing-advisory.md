# Targeted Phishing Advisory

**Classification:** TLP:CLEAR  
**Audience:** Executives and Engineering Staff  
**Issued By:** GreySentinel Security Team  
**Date:** 2026-01-15  
**Version:** 1.0

## Executive Summary

This advisory warns of an increase in targeted phishing campaigns exploiting trusted collaboration platforms (Microsoft Teams, Slack, LinkedIn) and supply chain vectors to deliver credential phishing lures, malicious coding tests, and trojanized software. Adversaries including APT29, Volt Typhoon, and Lazarus Group are actively using these techniques to gain initial access to executive and engineering environments.

## Key Threats

### 1. OAuth Device Code Phishing (APT29)

**Threat:** Users receive messages (Teams, email, or chat) from compromised accounts or impostor IT support, instructing them to enter a device code at `microsoft.com/devicelogin`. This authenticates the attacker's session to the user's Microsoft 365 account without requiring a password.

**Impact:** Full access to mailbox, OneDrive, SharePoint, Teams, and other Entra ID-connected applications. Attackers can establish persistent access via OAuth app consents and additional MFA methods.

**Indicators:**
- Unexpected messages requesting device code entry
- Device code prompts from unfamiliar or external senders
- Requests to "complete security upgrade" or "verify identity" via device code
- Sign-ins from residential IP addresses or unusual locations

### 2. Fake Recruiter Lures & Trojanized Coding Tests (Lazarus Group)

**Threat:** Engineers receive LinkedIn or messaging platform messages from fake recruiters offering technical interviews or coding challenges. Candidates are directed to download a repository or complete a test that contains malicious code, trojanized npm/PyPI packages, or cross-platform implants.

**Impact:** Compromise of developer workstations, theft of source code and signing keys, and potential supply chain contamination of organizational software.

**Indicators:**
- Unsolicited recruiting outreach from unverified profiles
- Requests to download code from external repositories (GitHub, GitLab, Bitbucket)
- Coding tests requiring execution of untrusted scripts or binaries
- Packages with unusual names, low download counts, or recently created accounts

### 3. Edge Device & Living-off-the-Land Attacks (Volt Typhoon)

**Threat:** Adversaries exploit unpatched internet-facing edge devices (VPNs, firewalls, routers) and use native administrative tools (`wmic`, `PowerShell`, `netsh`, `ntdsutil`) for credential access and lateral movement.

**Impact:** Pre-positioning in critical infrastructure networks, credential theft, and potential disruption of communications, energy, water, or transportation services.

**Indicators:**
- Unusual administrative tool usage on edge devices
- Anomalous `ntdsutil`, `vssadmin`, or `wmic` execution
- Connections from compromised SOHO routers
- Unpatched VPNs, firewalls, or internet-facing appliances

## Recommended Actions

### For Executives

| Action | Priority | Timeline |
| :--- | :--- | :--- |
| Enable phishing-resistant MFA (FIDO2/WebAuthn) on all accounts | Critical | Immediate |
| Restrict OAuth device code flows and user app consent | Critical | 1 week |
| Review and approve all OAuth application consents | High | 2 weeks |
| Participate in targeted phishing awareness briefing | High | 1 month |
| Establish verified out-of-band communication channel for IT requests | High | 1 week |

### For Engineering Staff

| Action | Priority | Timeline |
| :--- | :--- | :--- |
| Run untrusted code, tests, and packages in isolated VMs or containers | Critical | Immediate |
| Enforce endpoint allowlisting and MDM controls on macOS/Windows | High | 2 weeks |
| Verify recruiter identity through official channels before engaging | High | Immediate |
| Audit npm/PyPI dependencies for malicious or abandoned packages | High | 1 month |
| Report suspicious recruiting messages to security team | Medium | Ongoing |

### For All Staff

| Action | Priority | Timeline |
| :--- | :--- | :--- |
| Never enter device codes requested via unsolicited messages | Critical | Immediate |
| Verify IT support requests through official channels (not the message itself) | Critical | Immediate |
| Report suspicious messages to security@yourorg.com | High | Ongoing |
| Keep operating systems and browsers patched | High | Ongoing |
| Use hardware-backed approvals for financial and signing operations | High | 1 month |

## Verification Checklist

- [ ] MFA is phishing-resistant (FIDO2 security key or passkey)
- [ ] No unfamiliar OAuth applications have been granted consent
- [ ] No unknown MFA methods are registered on your account
- [ ] No email forwarding rules were created without your knowledge
- [ ] All devices are running patched OS and browser versions
- [ ] You have not executed untrusted code from external sources

## Reporting

Report suspicious messages, emails, or recruiting outreach immediately to:

- **Email:** security@yourorg.com
- **Slack/Teams:** #security-alerts
- **Phone:** +1-XXX-XXX-XXXX (Security Operations)

Include: sender, message content, any links or codes, and whether you interacted with the message.

## Additional Resources

- GreySentinel APT29 Intelligence Brief: `briefs⁄apt29-intelligence-brief.md`
- GreySentinel Lazarus Group Intelligence Brief: `briefs⁄lazarus-group-intelligence-brief.md`
- GreySentinel Volt Typhoon Intelligence Brief: `briefs⁄volt-typhoon-intelligence-brief.md`
- OAuth Token Compromise SOP: `playbooks/oauth-token-compromise-sop.md`
- MITRE ATT&CK T1528: https://attack.mitre.org/techniques/T1528/
- MITRE ATT&CK T1566.003: https://attack.mitre.org/techniques/T1566/003/
- MITRE ATT&CK T1195.001: https://attack.mitre.org/techniques/T1195/001/

## Revision History

| Version | Date | Author | Changes |
| :--- | :--- | :--- | :--- |
| 1.0 | 2026-01-15 | GreySentinel Security Team | Initial release |
