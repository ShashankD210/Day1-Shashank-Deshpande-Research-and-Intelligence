# Threat Hunting Queries

Behavioral hunting queries for KQL (Microsoft Sentinel / Defender) and Splunk SPL covering APT29, Volt Typhoon, and Lazarus Group TTPs.

## APT29 — OAuth Device Code Phishing & Cloud Identity Abuse

### KQL — Suspicious OAuth Device Code Grants

```kql
SigninLogs
| where AuthenticationDetails contains "deviceCode" or AuthenticationDetails contains "device_code"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId, ClientAppUsed, IPAddress, Location, AuthenticationDetails
| order by TimeGenerated desc
```

### KQL — Malicious OAuth App Consent Grants

```kql
AuditLogs
| where OperationName contains "Consent to application" or OperationName contains "Add OAuth2PermissionGrant"
| where ResultType == "Success"
| project TimeGenerated, InitiatedBy, TargetResources, AdditionalDetails
| order by TimeGenerated desc
```

### Splunk SPL — OAuth Device Code Authentication

```
index=azure_ad sourcetype="azure:ad:reporting:signins"
| search AuthenticationDetails="*deviceCode*" OR AuthenticationDetails="*device_code*"
| table _time, userPrincipalName, appDisplayName, appId, clientAppUsed, ipAddress, location, authenticationDetails
| sort - _time
```

---

## APT29 — Residential Proxy & Anomalous Login Patterns

### KQL — Sign-ins from Residential ISP ASNs

```kql
SigninLogs
| where ResultType == 0
| where IPAddress matches regex @"(residential|ISP|broadband)" // Replace with known residential ASN list
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed
| order by TimeGenerated desc
```

### Splunk SPL — Anomalous Geo-Location Logins

```
index=azure_ad sourcetype="azure:ad:reporting:signins"
| where ResultType="0"
| eval travel_speed=if(isnotnull(prev_lat) AND isnotnull(prev_lon), haversine(lat, lon, prev_lat, prev_lon) / (_time - prev_time), null)
| where travel_speed > 500
| table _time, userPrincipalName, ipAddress, city, country, appDisplayName, travel_speed
| sort - _time
```

---

## Volt Typhoon — Living-off-the-Land & Edge Device Activity

### KQL — Suspicious ntdsutil / vssadmin / wmic Execution

```kql
DeviceProcessEvents
| where FileName in~ ("ntdsutil.exe", "vssadmin.exe", "wmic.exe", "netsh.exe", "nltest.exe")
| where ProcessCommandLine has_any ("ntdsutil", "vssadmin", "wmic", "netsh", "nltest")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Splunk SPL — LotL Administrative Tool Abuse

```
index=endpoint sourcetype="endpoint:process"
| search FileName IN ("ntdsutil.exe", "vssadmin.exe", "wmic.exe", "netsh.exe", "nltest.exe")
| table _time, device_name, account_name, file_name, process_command_line, initiating_process_file_name
| sort - _time
```

### KQL — SOHO Router Relay Connections

```kql
DeviceNetworkEvents
| where RemoteIP in~ (known_soho_router_ips) // Replace with your SOHO router IP inventory
| where RemotePort in~ (443, 8443, 8080, 22)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalIP, LocalPort, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Lazarus Group — Cross-Platform Persistence & Supply Chain

### KQL — macOS LaunchAgent / LaunchDaemon Creation

```kql
DeviceFileEvents
| where FolderPath contains_any (@"/Library/LaunchAgents", "/Library/LaunchDaemons", "~/Library/LaunchAgents")
| where ActionType == "FileCreated" or ActionType == "FileModified"
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, SHA256
| order by TimeGenerated desc
```

### KQL — Suspicious Mach-O Execution

```kql
DeviceProcessEvents
| where FileExtension == "mach-o" or FolderPath endswith ".app" or FolderPath endswith ".dylib"
| where AccountName != "SYSTEM"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by TimeGenerated desc
```

### Splunk SPL — Malicious Package Installation (npm / PyPI)

```
index=endpoint sourcetype="endpoint:process"
| search (process_command_line="*npm install*" OR process_command_line="*pip install*")
| where NOT process_command_line IN ("*npm install * --registry*", "*pip install --index-url*")
| table _time, device_name, account_name, file_name, process_command_line, parent_process_name
| sort - _time
```

---

## Lazarus Group — Cryptocurrency & Wallet Activity

### KQL — Wallet/Key File Access

```kql
DeviceFileEvents
| where FileName in_any_of (wallet_file_names) // Replace with known wallet file names
| where ActionType == "FileRead" or ActionType == "FileCopied"
| project TimeGenerated, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Splunk SPL — Crypto Wallet Access

```
index=endpoint sourcetype="endpoint:file"
| search file_name IN ("*wallet*", "*keystore*", "*seed*", "*mnemonic*", "*.json", "*.dat")
| table _time, device_name, account_name, file_name, folder_path, action_type, initiating_process_name
| sort - _time
```

---

## Volt Typhoon — Credential Dumping via ntdsutil

### KQL — ntdsutil IFM / Shadow Copy Activity

```kql
DeviceProcessEvents
| where FileName == "ntdsutil.exe"
| where ProcessCommandLine has_any ("ifm", "create full", "dump", "shadow copy", "vssadmin")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, ParentProcessFileName
| order by TimeGenerated desc
```

---

## General Hunting — Lateral Movement

### KQL — Unusual Remote Desktop / PsExec Activity

```kql
DeviceNetworkEvents
| where RemotePort in~ (445, 3389, 135, 139)
| where InitiatingProcessFileName in~ ("psexec.exe", "wmic.exe", "powershell.exe", "cmd.exe")
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Splunk SPL — Lateral Movement via SMB/RDP

```
index=endpoint sourcetype="endpoint:network"
| search remote_port IN ("445", "3389", "135", "139")
| search initiating_process_file_name IN ("psexec.exe", "wmic.exe", "powershell.exe", "cmd.exe")
| table _time, device_name, remote_ip, remote_port, initiating_process_file_name, initiating_process_command_line
| sort - _time
```
