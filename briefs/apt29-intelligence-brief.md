# Cyber Threat Intelligence Brief: APT29

**Classification:** TLP:CLEAR  
**Threat Actor:** APT29  
**Aliases:** Cozy Bear, Midnight Blizzard, The Dukes, Nobelium, Storm-2945  
**Attribution:** Russian Foreign Intelligence Service (SVR) — *High Confidence*  
**Active Since:** At least 2008  

## Executive Summary & Motivations

APT29 is a state-sponsored cyber espionage group operating under Russia's Foreign Intelligence Service (SVR). The group prioritizes long-term strategic intelligence collection supporting Russian foreign policy, defense, and counterintelligence priorities—targeting diplomatic communications, defense and policy research, intellectual property, and cloud ecosystems.

## Diamond Model of Intrusion Analysis

| Vertex | Operational Profile |
| :--- | :--- |
| **Adversary** | Russian Foreign Intelligence Service (SVR); patient operators with strong operational security |
| **Victim** | NATO/EU governments, embassies, think tanks, MSPs, defense/tech organizations, and traveling staff |
| **Infrastructure** | Compromised residential ISP proxies, hijacked web analytics scripts, lookalike/watering-hole domains, hotel captive portals, and legitimate cloud APIs |
| **Capability** | Memory-resident loaders, OAuth device code phishing, mobile n-day exploit chains (iOS/Android), and browser/session token theft |

## Primary Tactics, Techniques, and Procedures (TTPs)

* **Initial Access:** OAuth device code phishing (`T1528`), spear-phishing (`T1566`), supply-chain compromises (`T1195`) including hijacked web scripts, and mobile watering holes exploiting unpatched iOS/Android vulnerabilities (`T1189`, `T1203`).
* **Persistence & Defense Evasion:** Malicious OAuth application registration (`T1098.003`), routing traffic through residential proxies (`T1090.002`), DLL side-loading, log/artifact cleanup (`T1070`), and in-memory execution without disk persistence.
* **Command & Control and Collection:** Abusing legitimate cloud APIs (`T1102`) and harvesting email/cloud data (`T1114`) or session cookies (`T1539`).

## Key Mitigations

1. Enforce phishing-resistant MFA (FIDO2/WebAuthn) and restrict OAuth device code flows and user app consent.
2. Keep OS and browser versions patched on mobile and desktop endpoints, and apply strict network/identity segmentation.
3. Monitor identity logs for residential proxy ASNs and unusual OAuth grants.
