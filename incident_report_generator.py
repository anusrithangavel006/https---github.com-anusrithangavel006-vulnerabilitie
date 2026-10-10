import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Convert a JSON list of findings into a Markdown incident report.")
    parser.add_argument("input_json", help="JSON file containing findings")
    parser.add_argument("--out", default="incident_report.md", help="Output Markdown file")
    args = parser.parse_args()
    data = json.loads(Path(args.input_json).read_text(encoding="utf-8"))
    findings = data if isinstance(data, list) else data.get("findings", [])
    lines = [
        "# Security Findings Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"Total findings: {len(findings)}",
        "",
        "| # | Severity | Asset / CVE | Finding |",
        "|---:|---|---|---|"
    ]
    for index, item in enumerate(findings, 1):
        severity = str(item.get("severity", "UNKNOWN")).replace("|", "\\|")
        asset = str(item.get("resource", item.get("cve_id", "Not specified"))).replace("|", "\\|")
        description = str(item.get("finding", item.get("description", "No description"))).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {index} | {severity} | {asset} | {description} |")
    lines += ["", "> Review findings and validate them before remediation. This report is not proof of compromise."]
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Report saved to: {Path(args.out).resolve()}")
    print(f"Findings included: {len(findings)}")

if __name__ == "__main__":
    main()
