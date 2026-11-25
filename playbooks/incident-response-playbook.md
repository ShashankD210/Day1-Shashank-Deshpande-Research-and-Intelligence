# Incident Response Playbook

**Classification:** TLP:CLEAR  
**Version:** 1.0  
**Last Reviewed:** 2026-01-20  
**Owner:** Security Operations  
**Applies To:** All security incidents involving CTI-relevant threat actors

## Purpose

This playbook provides a standardized incident response framework for handling security incidents, with specific procedures for APT29, Volt Typhoon, and Lazarus Group intrusions.

## Phase 1 — Preparation

### 1.1 Asset Inventory

Maintain an up-to-date inventory of:
- All cloud identities and service principals
- Endpoints and servers
- Network infrastructure (edge devices, VPNs, firewalls)
- Critical applications and data repositories

### 1.2 Detection Tooling

Ensure the following are deployed and configured:
- Microsoft Sentinel / Defender for Cloud
- EDR on all endpoints
- Network traffic analysis
- Identity protection and Conditional Access
- SIEM with KQL/SPL hunting capability

### 1.3 Playbooks & SOPs

- OAuth Token Compromise SOP (`playbooks/oauth-token-compromise-sop.md`)
- APT29 Defense Checklist (`playbooks/apt29-defense-checklist.json`)
- Tabletop Exercise: Operation Silent Token (`playbooks/tabletop-exercise-operation-silent-token.md`)

## Phase 2 — Identification

### 2.1 Detection Sources

| Source | What It Detects | Relevant Actors |
| :--- | :--- | :--- |
| SigninLogs | Device code auth, unusual locations | APT29 |
| AuditLogs | OAuth consent grants | APT29 |
| DeviceProcessEvents | LotL tool execution | Volt Typhoon |
| DeviceNetworkEvents | SOHO router relay | Volt Typhoon |
| DeviceFileEvents | LaunchAgent/plist creation | Lazarus |
| YARA matches | Memory loaders, droppers | All |

### 2.2 Triage Checklist

- [ ] Confirm the alert is not a false positive
- [ ] Identify affected accounts and assets
- [ ] Determine initial access vector
- [ ] Establish timeline of compromise
- [ ] Classify severity (Critical/High/Medium/Low)
- [ ] Notify Incident Commander

## Phase 3 — Containment

### 3.1 Immediate Actions (0–60 minutes)

| Action | Owner | Tool |
| :--- | :--- | :--- |
| Disable compromised accounts | Identity Admin | Entra ID |
| Revoke all refresh tokens | Identity Admin | PowerShell / Graph API |
| Block malicious IP/domain at firewall | Network Admin | Firewall / WAF |
| Isolate affected endpoints | Endpoint Admin | EDR |
| Remove malicious OAuth apps | Identity Admin | Entra ID > App registrations |

### 3.2 Strategic Containment

- Preserve evidence before making changes
- Implement network segmentation for affected zones
- Rotate credentials for privileged accounts
- Enable enhanced logging on affected systems

## Phase 4 — Eradication

### 4.1 Remove Attacker Presence

- Delete malicious OAuth applications and consent grants
- Remove unauthorized MFA methods
- Remove email forwarding rules
- Remove persistence mechanisms (LaunchAgents, scheduled tasks, services)
- Remove malicious files and processes

### 4.2 Vulnerability Remediation

- Patch exploited vulnerabilities
- Update edge devices and VPNs
- Reimage compromised endpoints
- Rotate all potentially compromised credentials

## Phase 5 — Recovery

### 5.1 Restore Operations

- Re-enable accounts after verification
- Restore data from clean backups
- Re-grant application permissions through approved workflow
- Monitor for reinfection for 90 days

### 5.2 Validation

- Confirm all attacker access removed
- Verify no new persistence mechanisms
- Test restored systems
- Obtain sign-off from Incident Commander

## Phase 6 — Lessons Learned

### 6.1 Post-Incident Review

Conduct within 14 days of incident closure:

1. Timeline reconstruction
2. Root cause analysis
3. Control effectiveness review
4. Gap identification
5. Remediation action items with owners and due dates

### 6.2 Metrics to Track

- Mean Time to Detect (MTTD)
- Mean Time to Contain (MTTC)
- Mean Time to Recover (MTTR)
- Number of affected accounts/assets
- Data exfiltration confirmed (Yes/No)

## Threat Actor Specific Guidance

### APT29

Focus on identity and cloud:
- OAuth device code phishing → Revoke tokens, restrict device code flows
- Malicious OAuth apps → Remove app registrations, audit consents
- Cloud API abuse → Monitor Graph API and Entra ID logs

### Volt Typhoon

Focus on edge and infrastructure:
- Edge device exploitation → Patch VPNs/firewalls, isolate management
- LotL credential dumping → Alert on ntdsutil/vssadmin/wmic
- SOHO router relay → Block known SOHO IPs, monitor network

### Lazarus Group

Focus on endpoints and supply chain:
- Malicious packages → Audit npm/PyPI dependencies, sandbox untrusted code
- Cross-platform implants → EDR on macOS/Windows/Linux
- Social engineering → User awareness training, verify recruiter identity

## Revision History

| Version | Date | Author | Changes |
| :--- | :--- | :--- | :--- |
| 1.0 | 2026-01-20 | GreySentinel CTI Team | Initial release |
