import argparse
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def main():
    parser = argparse.ArgumentParser(description="Retrieve NVD CVE metadata and produce a source-grounded summary.")
    parser.add_argument("cve_id", help="Example: CVE-2021-44228")
    args = parser.parse_args()
    cve_id = args.cve_id.upper().strip()
    if not cve_id.startswith("CVE-") or len(cve_id) > 32:
        raise SystemExit("Enter a valid-looking CVE identifier, e.g. CVE-2021-44228.")
    try:
        response = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=20)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise SystemExit(f"NVD request failed: {exc}")
    entries = payload.get("vulnerabilities", [])
    if not entries:
        print(f"No NVD record found for {cve_id}.")
        return
    cve = entries[0]["cve"]
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No English description supplied.")
    metrics = cve.get("metrics", {})
    score = None
    severity = "Not supplied"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0].get("cvssData", {})
            score = metric.get("baseScore")
            severity = metric.get("baseSeverity", severity)
            break
    print("VulnCentral Vulnerability Explanation")
    print("=" * 40)
    print("CVE:", cve_id)
    print("Status:", cve.get("vulnStatus", "Not supplied"))
    print("Published:", cve.get("published", "Not supplied"))
    print("Severity:", severity)
    print("CVSS base score:", score if score is not None else "Not supplied")
    print("\nDescription:\n", description)
    print("\nRecommended next steps:")
    print("1. Confirm whether your exact product and version are affected.")
    print("2. Read the official NVD record and vendor advisory.")
    print("3. Apply vendor-supported fixes or mitigations where applicable.")
    print("4. Verify remediation and document evidence.")
    print("\nSource:", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    print("\nNote: This is a source-grounded summary, not an AI-generated response or a host scan.")

if __name__ == "__main__":
    main()
