import requests
import json
import re

BASE_URL = "https://rulezet.org/api/rule/public/searchPage?rule_type=suricata&page=1&per_page=100"

def get_sid(rule_content):
    """Extract SID from Suricata rule content."""
    match = re.search(r"sid\s*:\s*(\d+)", rule_content)
    return match.group(1) if match else None


def fetch_all_rules():
    next_page = BASE_URL
    seen_sids = set()       # prevent duplicates by SID
    seen_uuids = set()      # fallback dedupe by UUID
    all_rules = []

    while next_page:
        print(f"[+] Fetching: {next_page}")
        resp = requests.get(next_page)
        data = resp.json()

        for rule in data.get("results", []):
            uuid = rule.get("uuid")
            content = rule.get("content", "")

            sid = get_sid(content)

            # Deduplication logic
            if sid and sid in seen_sids:
                continue
            if uuid in seen_uuids:
                continue

            # Track new rule
            if sid:
                seen_sids.add(sid)
            seen_uuids.add(uuid)
            all_rules.append(content)

        # Move to next page if available
        next_page = data.get("pagination", {}).get("next_page")

    return all_rules


def save_rules_to_file(rules, filename="suricata_rules.rule"):
    """Save all rules to one .rule file."""
    with open(filename, "w") as f:
        for rule in rules:
            f.write(rule.strip() + "\n")
    print(f"[✓] Saved {len(rules)} unique rules to {filename}")


if __name__ == "__main__":
    rules = fetch_all_rules()
    save_rules_to_file(rules)
