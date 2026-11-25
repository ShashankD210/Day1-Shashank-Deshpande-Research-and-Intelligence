# Cyber Threat Intelligence Brief: Volt Typhoon

**Classification:** TLP:CLEAR  
**Threat Actor:** Volt Typhoon (Bronze Silhouette, Vanguard Panda, Insidious Taurus)  
**Attribution:** People's Republic of China (PRC) State-Sponsored — *High Confidence*  

## Executive Summary & Motivations

Volt Typhoon conducts long-term access and pre-positioning inside critical infrastructure networks rather than traditional intelligence theft alone. Its strategic objective is maintaining covert persistence that could disrupt communications, energy, water, or transportation logistics during a geopolitical crisis.

## Primary Targets

* Critical infrastructure across communications, energy, water, and transportation.
* Defense logistics, maritime/port infrastructure, and Indo-Pacific strategic targets.

## Primary TTPs (Living off the Land)

* **Initial Access:** Exploiting unpatched internet-facing edge devices such as VPNs, firewalls, and routers (`T1190`).
* **Execution & Credential Access:** Hands-on-keyboard commands using native tools (`wmic`, `PowerShell`, `netsh`, `nltest`), dumping `ntds.dit` via `ntdsutil.exe` or shadow copies (`T1003.003`), and extracting LSASS credentials.
* **Defense Evasion & C2:** Minimizing custom malware and routing C2 through compromised SOHO routers and network appliances (`T1090`).

## Key Mitigations

1. Patch internet-facing edge devices rapidly and restrict management interfaces to hardened jump hosts.
2. Baseline and alert on administrative abuse of `ntdsutil.exe`, `vssadmin.exe`, and `wmic.exe`.
3. Protect Tier-0 Active Directory assets and forward logs to tamper-evident centralized storage.
