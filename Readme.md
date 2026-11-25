# Cyber Threat Intelligence (CTI) & SecOps Portfolio

A structured collection of Cyber Threat Intelligence (CTI) briefs, behavioral hunting queries, Sigma/YARA detection rules, incident response playbooks, tabletop exercises, security awareness advisories, IOC feeds, and contribution/governance documentation covering **APT29**, **Volt Typhoon**, and **Lazarus Group**.

## Repository Contents

| Folder | Artifact | Description |
| :--- | :--- | :--- |
| `briefs/` | `apt29-intelligence-brief.md` | APT29 profile, Diamond Model, OAuth/cloud TTPs, and 2026 mobile watering-hole tradecraft |
| `briefs/` | `volt-typhoon-intelligence-brief.md` | Volt Typhoon profile, edge exploitation, and Living-off-the-Land TTPs |
| `briefs/` | `lazarus-group-intelligence-brief.md` | Lazarus Group profile, dual financial/espionage mandate, and cross-platform malware |
| `briefs/` | `executive-threat-landscape-2026.md` | Cross-adversary comparison matrix and 90-day leadership roadmap |
| `mappings/` | `adversary-tactic-mapping.csv` | Adversary-to-tactic mapping with primary controls for APT29, Volt Typhoon, and Lazarus Group |
| `mappings/` | `mitre-attack-coverage.json` | MITRE ATT&CK technique coverage matrix across detections, hunting, and playbooks |
| `mappings/` | `log-source-inventory.md` | Required log sources per detection rule with coverage gaps |
| `detections/hunting/` | `threat-hunting-queries.md` | KQL and Splunk SPL behavioral hunting queries |
| `detections/sigma/` | `lazarus_macos_launchagent.yml` | Sigma rule for macOS LaunchAgent/LaunchDaemon persistence |
| `detections/sigma/` | `lazarus_macos_macho.yml` | Sigma rule for suspicious Mach-O binary execution |
| `detections/sigma/` | `apt29_oauth_device_code.yml` | Sigma rule for APT29 OAuth device code phishing |
| `detections/sigma/` | `apt29_oauth_consent.yml` | Sigma rule for APT29 malicious OAuth application consent |
| `detections/sigma/` | `volt_typhoon_lotl_cred_dump.yml` | Sigma rule for Volt Typhoon LotL credential dumping |
| `detections/sigma/` | `volt_typhoon_soho_relay.yml` | Sigma rule for Volt Typhoon SOHO router C2 relay |
| `detections/sigma/` | `lazarus_cross_platform_implant.yml` | Sigma rule for Lazarus cross-platform implant execution |
| `detections/sigma/` | `lazarus_supply_chain_package.yml` | Sigma rule for Lazarus malicious npm/PyPI package |
| `detections/yara/` | `apt29_lazarus_loaders.yar` | Structural YARA rules for memory loaders and cross-platform droppers |
| `detections/yara/` | `extended_threat_rules.yar` | Extended YARA rules for LotL, implant, package, and cloud abuse patterns |
| `scripts/` | `validate_detections.py` | Python script validating JSON, YAML, YARA, and Markdown artifacts |
| `playbooks/` | `oauth-token-compromise-sop.md` | Step-by-step containment, scoping, and recovery SOP for Entra ID / M365 |
| `playbooks/` | `apt29-defense-checklist.json` | Hardening and threat-hunting checklist items for APT29 |
| `playbooks/` | `tabletop-exercise-operation-silent-token.md` | 90-minute APT29 incident response tabletop scenario and injects |
| `playbooks/` | `tabletop-exercise-operation-silent-circuit.md` | 90-minute Volt Typhoon OT/ICS tabletop scenario and injects |
| `playbooks/` | `incident-response-playbook.md` | General incident response playbook with threat actor-specific guidance |
| `awareness/` | `targeted-phishing-advisory.md` | Executive and engineering security awareness advisory |
| `iocs/` | `apt29_iocs.json` | APT29 indicators of compromise (domains, IPs, URLs, MITRE mappings) |
| `iocs/` | `volt_typhoon_iocs.json` | Volt Typhoon indicators of compromise |
| `iocs/` | `lazarus_iocs.json` | Lazarus Group indicators of compromise |
| `iocs/` | `stix-bundle.json` | STIX 2.1 bundle of IOCs for all three threat actors |
| `.github/workflows/` | `validate-cti.yml` | CI workflow validating YAML, JSON, YARA, and Markdown artifacts |
| `.github/` | `CONTRIBUTING.md` | Contribution guidelines, naming conventions, and submission process |
| `.github/` | `SECURITY.md` | Security policy and responsible disclosure instructions |

## Disclaimer

All intelligence briefs, detection signatures, and playbooks in this repository are provided for defensive security, threat hunting, incident response training, and educational purposes (`TLP:CLEAR`).
