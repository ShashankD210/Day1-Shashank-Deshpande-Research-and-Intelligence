# Cyber Threat Intelligence (CTI) & SecOps Portfolio

A structured collection of Cyber Threat Intelligence (CTI) briefs, behavioral hunting queries, Sigma/YARA detection rules, incident response playbooks, tabletop exercises, and security awareness advisories covering **APT29**, **Volt Typhoon**, and **Lazarus Group**.

## Repository Contents

| Folder | Artifact | Description |
| :--- | :--- | :--- |
| `briefs/` | `apt29-intelligence-brief.md` | APT29 profile, Diamond Model, OAuth/cloud TTPs, and 2026 mobile watering-hole tradecraft |
| `briefs/` | `volt-typhoon-intelligence-brief.md` | Volt Typhoon profile, edge exploitation, and Living-off-the-Land TTPs |
| `briefs/` | `lazarus-group-intelligence-brief.md` | Lazarus Group profile, dual financial/espionage mandate, and cross-platform malware |
| `briefs/` | `executive-threat-landscape-2026.md` | Cross-adversary comparison matrix and 90-day leadership roadmap |
| `mappings/` | `adversary-tactic-mapping.csv` | Adversary-to-tactic mapping with primary controls for APT29, Volt Typhoon, and Lazarus Group |
| `detections/hunting/` | `threat-hunting-queries.md` | KQL and Splunk SPL behavioral hunting queries |
| `detections/sigma/` | `lazarus_macos_launchagent.yml` | Sigma rule for macOS LaunchAgent/LaunchDaemon persistence |
| `detections/sigma/` | `lazarus_macos_macho.yml` | Sigma rule for suspicious Mach-O binary execution |
| `detections/yara/` | `apt29_lazarus_loaders.yar` | Structural YARA rules for memory loaders and cross-platform droppers |
| `playbooks/` | `oauth-token-compromise-sop.md` | Step-by-step containment, scoping, and recovery SOP for Entra ID / M365 |
| `playbooks/` | `apt29-defense-checklist.json` | Hardening and threat-hunting checklist items for APT29 |
| `playbooks/` | `tabletop-exercise-operation-silent-token.md` | 90-minute incident response tabletop scenario and injects |
| `awareness/` | `targeted-phishing-advisory.md` | Executive and engineering security awareness advisory |
| `.github/workflows/` | `validate-cti.yml` | CI workflow validating YAML, JSON, YARA, and Markdown artifacts |

## Disclaimer

All intelligence briefs, detection signatures, and playbooks in this repository are provided for defensive security, threat hunting, incident response training, and educational purposes (`TLP:CLEAR`).
