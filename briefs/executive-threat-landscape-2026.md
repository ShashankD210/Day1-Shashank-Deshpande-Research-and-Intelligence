# Executive Threat Landscape Report

## Cross-Adversary Comparison

| Dimension | APT29 (Russia / SVR) | Volt Typhoon (China / PLA) | Lazarus Group (DPRK / RGB) |
| :--- | :--- | :--- | :--- |
| **Core Objective** | Strategic & diplomatic espionage | Critical infrastructure pre-positioning | Financial theft & defense espionage |
| **Primary Entry Vector** | OAuth phishing, exploits, watering holes | Unpatched edge appliances | Recruiter lures, trojanized dev/crypto apps |
| **Malware Footprint** | Low–Medium (in-memory, cloud APIs) | Near-Zero (Living off the Land) | High (cross-platform implants) |
| **Concealment** | Residential proxies, lookalike/hijacked sites | Compromised SOHO routers | Proxies, bridges, mixers |
| **Top Priority Control** | FIDO2 MFA, OAuth governance, OS patching | Edge patching, Tier-0 AD & LotL alerts | Dev sandboxing, endpoint/signing controls |

## 90-Day Priority Roadmap

* **Days 1–30 (Identity):** Enforce phishing-resistant MFA and restrict OAuth device code flows and user consent.
* **Days 15–45 (Perimeter):** Patch internet-facing VPNs, firewalls, and appliances and isolate management planes.
* **Days 30–60 (Endpoints & Engineering):** Sandbox untrusted code/recruiter files and enforce endpoint/mobile patching.
* **Days 60–90 (Detection):** Deploy behavioral hunting for `deviceCode`, residential proxy logins, and `ntdsutil`/LotL activity.
