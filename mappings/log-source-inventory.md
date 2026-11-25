| Detection Rule | Log Source | Log Type | Required Fields | Relevant Actors |
| :--- | :--- | :--- | :--- | :--- |
| apt29_oauth_device_code.yml | Entra ID SigninLogs | Authentication | AuthenticationDetails, ResultType, UserPrincipalName, AppDisplayName, IPAddress, Location | APT29 |
| apt29_oauth_consent.yml | Entra ID AuditLogs | Web Application | OperationName, ResultType, InitiatedBy, TargetResources | APT29 |
| volt_typhoon_lotl_cred_dump.yml | Windows Event Log | Process Creation | Image, CommandLine, AccountName, DeviceName | Volt Typhoon |
| volt_typhoon_soho_relay.yml | Network Firewall/Proxy | Network Connection | DestinationPort, DestinationIp, SourceIp, DeviceName | Volt Typhoon |
| lazarus_macos_launchagent.yml | macOS Endpoint | File Event | TargetFilename, ActionType, AccountName, DeviceName | Lazarus Group |
| lazarus_macos_macho.yml | macOS Endpoint | Process Creation | Image, AccountName, DeviceName, FolderPath | Lazarus Group |
| lazarus_cross_platform_implant.yml | Windows Endpoint | Process Creation | ParentImage, Image, CommandLine, DeviceName | Lazarus Group |
| lazarus_supply_chain_package.yml | Windows Endpoint | Process Creation | Image, CommandLine, AccountName, DeviceName | Lazarus Group |

## Data Source Requirements

### Identity (Entra ID / Azure AD)
- SigninLogs — Authentication events, device code flows, MFA events
- AuditLogs — OAuth consent grants, app registrations, admin actions
- Required license: Azure AD Premium P1/P2 or Microsoft Defender for Identity

### Endpoint (Windows/macOS/Linux)
- Process creation events (Event ID 4688 on Windows)
- File creation/modification events
- Network connection events
- Required: EDR agent (Defender for Endpoint, CrowdStrike, SentinelOne, etc.)

### Network
- Firewall logs (allow/deny, source/destination IP/port)
- Proxy logs (URL, user agent, destination)
- DNS logs (query, response, client)
- Required: Network traffic visibility at perimeter and internal segments

### Cloud (Microsoft 365)
- Office 365 Management Activity API
- Mail, SharePoint, OneDrive, Teams activity
- Required: Microsoft 365 E3/E5 or equivalent

### OT/ICS
- Historian database access logs
- PLC/HMI configuration change logs
- Modbus TCP / Ethernet/IP traffic monitoring
- Required: OT network monitoring (Dragos, Nozomi, Claroty, or equivalent)

## Log Source Coverage Gaps

| Log Source | Status | Required For |
| :--- | :--- | :--- |
| Entra ID SigninLogs | Available | APT29 detection |
| Windows Process Creation | Available | Volt Typhoon, Lazarus detection |
| macOS File/Process Events | Partial | Lazarus LaunchAgent/Mach-O detection |
| Network Firewall Logs | Available | Volt Typhoon SOHO relay detection |
| Office 365 Audit | Partial | APT29 data exfiltration hunting |
| OT/ICS Protocol Logs | Not Available | Volt Typhoon OT intrusion detection |
| DNS Logs | Not Available | C2 domain detection across all actors |

## Recommended Log Source Additions

1. Deploy OT network monitoring for Modbus TCP/Ethernet/IP visibility
2. Enable DNS query logging at recursive resolvers
3. Implement cloud access security broker (CASB) for SaaS visibility
4. Deploy EDR on all OT engineering workstations (in monitoring mode)
