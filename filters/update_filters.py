#!/usr/bin/env python3
"""
Wadoblock Custom Filter Updater

Compares AdGuard Japanese filter against a saved baseline to detect
newly added domain block rules, then appends them to custom_rules.txt.
"""

import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

FILTERS_DIR = Path(__file__).parent
CUSTOM_RULES = FILTERS_DIR / "custom_rules.txt"
BASELINE = FILTERS_DIR / ".adguard_baseline_domains.txt"
ADGUARD_FILE = Path("/tmp/adguard_jp.txt")

JST = timezone(timedelta(hours=9))


def extract_domains(filepath: Path) -> set[str]:
    """Extract domain names from ||domain^ rules in an AdGuard filter file."""
    domains = set()
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("||") and "^" in line and not line.startswith("!"):
                m = re.match(r"\|\|([a-zA-Z0-9.*-]+)\^", line)
                if m:
                    domains.add(m.group(1))
    return domains


def extract_full_rules(filepath: Path) -> dict[str, str]:
    """Extract domain -> full rule mapping from AdGuard filter."""
    rules = {}
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("||") and "^" in line and not line.startswith("!"):
                m = re.match(r"\|\|([a-zA-Z0-9.*-]+)\^", line)
                if m:
                    domain = m.group(1)
                    if domain not in rules:
                        rules[domain] = line
    return rules


def load_baseline() -> set[str]:
    """Load baseline domains from file."""
    if not BASELINE.exists():
        return set()
    return set(BASELINE.read_text().strip().splitlines())


def save_baseline(domains: set[str]):
    """Save sorted domain list as new baseline."""
    BASELINE.write_text("\n".join(sorted(domains)) + "\n")


def update_custom_rules(new_rules: list[str]):
    """Insert new rules into custom_rules.txt before the Adult/Piracy section."""
    content = CUSTOM_RULES.read_text()

    # Find insertion point: just before "! --- Tracking ---" line
    # This puts new rules at the end of the "Other ad networks" section
    marker = "! --- Tracking ---"
    if marker not in content:
        # Fallback: append before Adult/Piracy section
        marker = "! =====================================================================\n! Adult/Piracy"

    rules_block = "\n".join(new_rules) + "\n"
    content = content.replace(marker, rules_block + "\n" + marker)

    # Update last modified date
    today = datetime.now(JST).strftime("%Y-%m-%d")
    content = re.sub(r"^! Last modified:.*$", f"! Last modified: {today}", content, flags=re.MULTILINE)

    CUSTOM_RULES.write_text(content)


def main():
    if not ADGUARD_FILE.exists():
        print("ERROR: AdGuard filter not found at /tmp/adguard_jp.txt")
        sys.exit(1)

    # Load current state
    baseline_domains = load_baseline()
    adguard_domains = extract_domains(ADGUARD_FILE)
    adguard_rules = extract_full_rules(ADGUARD_FILE)

    print(f"Baseline domains: {len(baseline_domains)}")
    print(f"AdGuard domains:  {len(adguard_domains)}")

    # Find newly added domains (in AdGuard but not in baseline)
    new_domains = adguard_domains - baseline_domains
    # Also find domains in custom_rules.txt to avoid duplicates
    custom_domains = set()
    with open(CUSTOM_RULES) as f:
        for line in f:
            line = line.strip()
            if line.startswith("||") and "^" in line:
                m = re.match(r"\|\|([a-zA-Z0-9.*-]+)\^", line)
                if m:
                    custom_domains.add(m.group(1))

    # Only add rules not already in custom_rules.txt
    truly_new = new_domains - custom_domains

    if truly_new:
        new_rules = []
        for domain in sorted(truly_new):
            if domain in adguard_rules:
                new_rules.append(adguard_rules[domain])
        print(f"New rules to add: {len(new_rules)}")
        for r in new_rules:
            print(f"  + {r}")
        update_custom_rules(new_rules)
    else:
        print("No new domain block rules found.")
        # Still update the date
        content = CUSTOM_RULES.read_text()
        today = datetime.now(JST).strftime("%Y-%m-%d")
        content = re.sub(r"^! Last modified:.*$", f"! Last modified: {today}", content, flags=re.MULTILINE)
        CUSTOM_RULES.write_text(content)

    # Always update baseline to current AdGuard state
    save_baseline(adguard_domains)
    print(f"Baseline updated: {len(adguard_domains)} domains")


if __name__ == "__main__":
    main()
