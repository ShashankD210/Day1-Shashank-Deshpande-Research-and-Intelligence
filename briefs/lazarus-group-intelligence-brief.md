# Cyber Threat Intelligence Brief: Lazarus Group

**Classification:** TLP:CLEAR  
**Threat Actor:** Lazarus Group (HIDDEN COBRA, Labyrinth Chollima, TraderTraitor, Diamond Sleet)  
**Attribution:** Democratic People's Republic of Korea (DPRK) — Reconnaissance General Bureau (RGB) — *High Confidence*  

## Executive Summary & Motivations

Lazarus Group operates with a dual mandate: generating illicit financial revenue (primarily via cryptocurrency theft and laundering) to evade sanctions and fund state priorities, alongside defense and diplomatic espionage.

## Primary Targets

* Cryptocurrency exchanges, DeFi protocols, bridges, and Web3/software developers.
* Defense, aerospace, and research organizations.
* Open-source package ecosystems (`npm`, `PyPI`) and enterprise software supply chains.

## Primary TTPs

* **Initial Access:** Social engineering on LinkedIn/messaging platforms using fake recruiter lures or trojanized coding tests (`T1566.003`), plus malicious packages and trojanized apps (`T1195.001`).
* **Execution & Persistence:** Cross-platform implants across macOS, Windows, and Linux, persisting via macOS LaunchAgents/LaunchDaemons (`T1543.001`) and scheduled tasks (`T1053`).
* **Defense Evasion & Impact:** Code signing abuse/BYOVD (`T1553.002`, `T1068`), wallet/key theft, and cross-chain laundering (`T1657`).

## Key Mitigations

1. Run untrusted coding tests, repositories, and third-party packages inside isolated VMs or containers.
2. Enforce application allowlisting and MDM controls on macOS and Windows endpoints.
3. Require hardware-backed multi-signature or MPC approvals for high-value financial and signing operations.
