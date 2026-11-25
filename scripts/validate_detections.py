#!/usr/bin/env python3
"""
Detection Rule Validation Script

Validates Sigma YAML rules, YARA rules, JSON files, and Markdown artifacts
in the GreySentinel CTI Portfolio repository.

Usage:
    python3 validate_detections.py [--path <repository-root>]

Exit codes:
    0 - All validations passed
    1 - One or more validations failed
"""

import argparse
import glob
import json
import os
import sys
import yaml

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


def validate_json(path):
    """Validate a JSON file parses correctly."""
    try:
        with open(path, encoding="utf-8") as f:
            json.load(f)
        return True, None
    except (json.JSONDecodeError, ValueError) as e:
        return False, str(e)


def validate_yaml(path):
    """Validate a YAML file parses correctly."""
    try:
        with open(path, encoding="utf-8") as f:
            yaml.safe_load(f)
        return True, None
    except yaml.YAMLError as e:
        return False, str(e)


def validate_yara(path):
    """Validate a YARA rule file compiles correctly."""
    if not YARA_AVAILABLE:
        return True, "yara-python not installed, skipping compilation check"
    try:
        yara.compile(filepath=path)
        return True, None
    except yara.SyntaxError as e:
        return False, str(e)


def validate_markdown(path):
    """Validate a Markdown file exists and is non-empty."""
    if not os.path.isfile(path):
        return False, "File not found"
    if os.path.getsize(path) == 0:
        return False, "File is empty"
    return True, None


def main():
    parser = argparse.ArgumentParser(description="Validate CTI detection artifacts")
    parser.add_argument(
        "--path",
        default=".",
        help="Repository root path (default: current directory)",
    )
    args = parser.parse_args()

    root = args.path
    errors = []
    checks = 0

    # Validate JSON files
    json_files = glob.glob(os.path.join(root, "**", "*.json"), recursive=True)
    for path in json_files:
        checks += 1
        ok, err = validate_json(path)
        if not ok:
            errors.append(f"JSON {path}: {err}")
        else:
            print(f"[OK] JSON: {path}")

    # Validate Sigma YAML files
    sigma_files = glob.glob(os.path.join(root, "detections", "sigma", "*.yml"))
    for path in sigma_files:
        checks += 1
        ok, err = validate_yaml(path)
        if not ok:
            errors.append(f"YAML {path}: {err}")
        else:
            print(f"[OK] YAML: {path}")

    # Validate YARA files
    yara_files = glob.glob(os.path.join(root, "detections", "yara", "*.yar"))
    for path in yara_files:
        checks += 1
        ok, err = validate_yara(path)
        if not ok:
            errors.append(f"YARA {path}: {err}")
        else:
            print(f"[OK] YARA: {path}")

    # Validate Markdown files
    md_patterns = [
        "Readme.md",
        "briefs/*.md",
        "detections/hunting/*.md",
        "playbooks/*.md",
        "awareness/*.md",
        ".github/*.md",
    ]
    md_files = []
    for pattern in md_patterns:
        md_files.extend(glob.glob(os.path.join(root, pattern)))
    for path in md_files:
        checks += 1
        ok, err = validate_markdown(path)
        if not ok:
            errors.append(f"Markdown {path}: {err}")
        else:
            print(f"[OK] Markdown: {path}")

    # Validate CSV files
    csv_files = glob.glob(os.path.join(root, "mappings", "*.csv"))
    for path in csv_files:
        checks += 1
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            errors.append(f"CSV {path}: missing or empty")
        else:
            print(f"[OK] CSV: {path}")

    # Summary
    print(f"\n{'=' * 60}")
    print(f"Total checks: {checks}")
    print(f"Passed: {checks - len(errors)}")
    print(f"Failed: {len(errors)}")

    if errors:
        print(f"\n{'=' * 60}")
        print("FAILURES:")
        for err in errors:
            print(f"  [FAIL] {err}")
        sys.exit(1)

    print("\nAll validations passed.")


if __name__ == "__main__":
    main()
