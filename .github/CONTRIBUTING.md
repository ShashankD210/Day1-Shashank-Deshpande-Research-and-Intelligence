# Contributing Guidelines

## How to Contribute

We welcome contributions to the GreySentinel CTI & SecOps Portfolio. Please follow these guidelines when submitting changes.

### Submission Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Validate your changes (see Validation section)
5. Commit your changes (`git commit -m "Description of changes"`)
6. Push to your fork (`git push origin feature/your-feature`)
7. Open a Pull Request

### Content Guidelines

- All intelligence briefs must be marked `TLP:CLEAR`
- Detection rules must include MITRE ATT&CK technique mappings
- Playbooks must include roles, responsibilities, and revision history
- IOC files must follow the established JSON schema
- All Markdown files must include a classification header

### Naming Conventions

| Artifact Type | Naming Pattern | Example |
| :--- | :--- | :--- |
| Intelligence Brief | `<actor>-intelligence-brief.md` | `apt29-intelligence-brief.md` |
| Sigma Rule | `<actor>_<technique>.yml` | `apt29_oauth_device_code.yml` |
| YARA Rule | `<actor>_<category>.yar` | `apt29_memory_loader.yar` |
| Playbook | `<purpose>-<name>.md` | `oauth-token-compromise-sop.md` |
| IOC File | `<actor>_iocs.json` | `apt29_iocs.json` |

### Validation

Before submitting a Pull Request:

1. Validate all YAML files parse correctly
2. Validate all JSON files parse correctly
3. Compile all YARA rules successfully
4. Verify all Markdown files exist and are non-empty
5. Update `Readme.md` if adding new artifacts

### Code of Conduct

- Be respectful and professional
- Do not share classified or sensitive information
- All content must be suitable for public release (TLP:CLEAR)

## Questions

Open an issue for questions or discussions about contributions.
