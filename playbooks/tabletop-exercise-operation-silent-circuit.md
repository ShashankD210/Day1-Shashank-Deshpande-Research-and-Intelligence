# Tabletop Exercise: Operation Silent Circuit

**Classification:** TLP:CLEAR  
**Exercise Type:** Incident Response Tabletop  
**Duration:** 90 minutes  
**Facilitator:** Security Operations  
**Participants:** SOC Analysts, ICS/OT Engineers, Network Admins, Incident Commander, Communications, Legal  
**Scenario:** Volt Typhoon pre-positioning in critical infrastructure via edge device exploitation  
**Version:** 1.0  
**Date:** 2026-01-20

## Exercise Overview

**Operation Silent Circuit** simulates a Volt Typhoon intrusion targeting critical infrastructure. The adversary exploits unpatched internet-facing edge devices, uses Living-off-the-Land techniques for credential access, and establishes covert persistence through compromised SOHO routers. The exercise tests detection, containment, and recovery capabilities in OT/IT converged environments.

## Scenario Narrative

### T+0: Initial Access

On a Thursday evening, the organization's internet-facing VPN concentrator begins exhibiting unusual behavior. Authentication logs show successful logins from residential IP addresses using valid credentials for dormant service accounts. The VPN appliance is running firmware version 9.2.1, which has a known unauthenticated remote code execution vulnerability (CVE-2026-XXXX) that was disclosed two weeks ago but remains unpatched due to a change freeze.

### T+4 Hours: Lateral Movement

The attacker moves from the VPN concentrator into the corporate network:
- Uses `wmic.exe` and `powershell.exe` to enumerate domain controllers
- Dumps `ntds.dit` via `ntdsutil.exe` on a domain controller
- Extracts LSASS credentials from a jump host used by ICS engineers
- Establishes C2 through a compromised SOHO router in a regional office

### T+12 Hours: OT Network Probing

The attacker pivots from the IT network to the operational technology (OT) network:
- Scans Modbus TCP and Ethernet/IP devices on the plant floor
- Enumerates PLCs and HMIs in the water treatment facility
- Modifies historian database access permissions
- Creates a new scheduled task on an engineering workstation: `C:\Windows\System32\schtasks.exe /create /tn "SystemUpdate" /tr "powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\update.ps1" /sc daily /st 02:00`

### T+24 Hours: Detection

The SOC receives multiple alerts:
- Anomalous `ntdsutil.exe` execution on a domain controller at 02:00 AM
- Successful VPN logins from residential IP addresses not in the allowed country list
- Unusual Modbus TCP traffic from the IT subnet to OT devices
- New scheduled task on an engineering workstation

## Exercise Objectives

1. **Detection:** Identify indicators of Volt Typhoon activity in IT and OT environments
2. **Containment:** Isolate affected edge devices, block C2 channels, and segment IT from OT
3. **Scoping:** Determine if the adversary has accessed OT/ICS assets
4. **Eradication:** Remove persistence, patch edge devices, and rotate credentials
5. **Recovery:** Restore normal operations and verify OT integrity
6. **Communication:** Notify critical infrastructure regulators and stakeholders

## Exercise Timeline & Injects

| Time | Inject | Description | Expected Response |
| :--- | :--- | :--- | :--- |
| **T+0** | **Inject 1** | VPN appliance shows unusual authentication spikes from residential IPs | SOC investigates VPN logs, identifies valid credential use from unusual locations |
| **T+15 min** | **Inject 2** | NOC reports slow performance on water treatment plant HMI systems | Investigate IT-to-OT network traffic, check for unauthorized Modbus/TCP sessions |
| **T+30 min** | **Inject 3** | Domain controller event log shows ntdsutil.exe execution at 02:00 AM | Initiate credential dumping investigation, revoke affected service account credentials |
| **T+45 min** | **Inject 4** | New scheduled task found on engineering workstation connecting to external IP | Isolate workstation, remove scheduled task, block C2 IP at firewall |
| **T+60 min** | **Inject 5** | OT engineer reports unauthorized PLC configuration changes | Halt OT changes, isolate OT network, involve ICS/OT engineers, preserve PLC logs |
| **T+75 min** | **Inject 6** | CISA contacts organization about suspected Volt Typhoon activity in sector | Engage legal/comms, prepare regulatory notification, coordinate with CISA |
| **T+90 min** | **Debrief** | Exercise conclusion and lessons learned | Document gaps, update SOPs, identify OT/IT segmentation improvements |

## Discussion Questions

### Detection Phase
1. Which telemetry sources would first indicate VPN exploitation?
2. How would you detect LotL tool usage (`ntdsutil`, `wmic`, `vssadmin`) in real time?
3. What OT-specific indicators should trigger immediate escalation?
4. How do you distinguish legitimate engineering activity from adversary activity on OT networks?

### Containment Phase
1. What is the order of operations when both IT and OT are potentially compromised?
2. How do you isolate edge devices without disrupting critical operations?
3. What is your process for blocking C2 through SOHO routers?
4. How do you segment IT from OT rapidly during an active intrusion?

### Scoping Phase
1. Which logs would you review to determine OT/ICS access?
2. How do you identify persistence across both IT and OT assets?
3. What is your process for verifying PLC integrity?
4. How do you determine if historian data was accessed or modified?

### Eradication & Recovery Phase
1. How do you verify all attacker access has been removed from OT systems?
2. What is your process for patching edge devices during an active incident?
3. How do you restore OT operations safely?
4. What is your credential rotation strategy for service accounts and engineering accounts?

### Communication Phase
1. When do you notify CISA and other critical infrastructure regulators?
2. At what point do you involve executive leadership and board members?
3. What regulatory notification obligations apply to critical infrastructure incidents?
4. How do you communicate with OT/ICS vendors during an incident?

## Evaluation Criteria

| Criteria | Metric | Target |
| :--- | :--- | :--- |
| Detection | Time to identify VPN exploitation | < 30 minutes |
| Containment | Time to isolate affected edge devices | < 45 minutes |
| OT Isolation | Time to segment IT from OT | < 60 minutes |
| Scoping | Percentage of affected accounts identified | 100% |
| Persistence | All attacker scheduled tasks and router relay removed | 100% |
| Communication | Regulatory notification initiated | < 4 hours |

## Facilitator Notes

- Encourage participants to consider both IT and OT impacts
- Introduce injects based on participant responses; adjust timing as needed
- If participants focus only on IT, introduce OT-specific complications
- If participants are stuck, provide hints about relevant OT telemetry sources
- Document all decisions and action items for the after-action report

## After-Action Items

| Item | Owner | Due Date | Status |
| :--- | :--- | :--- | :--- |
| Patch all internet-facing edge devices | Infrastructure Team | 1 week | Open |
| Implement IT/OT network segmentation | Network Team | 2 weeks | Open |
| Deploy LotL alerting for ntdsutil/vssadmin/wmic | SOC | 2 weeks | Open |
| Establish OT incident response contact list | OT Engineering | 1 week | Open |
| Conduct OT-specific user awareness training | Security Awareness | 1 month | Open |
| Update IR playbook with OT/ICS procedures | Security Operations | 2 weeks | Open |

## References

- [MITRE ATT&CK T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1003.003 - OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)
- [MITRE ATT&CK T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- GreySentinel Volt Typhoon Intelligence Brief (`briefs/volt-typhoon-intelligence-brief.md`)
- GreySentinel Incident Response Playbook (`playbooks/incident-response-playbook.md`)
- CISA Alert on Volt Typhoon: https://www.cisa.gov/news-events/cybersecurity-advisories
