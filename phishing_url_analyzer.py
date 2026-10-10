import argparse
import ipaddress
from urllib.parse import urlparse, unquote

SUSPICIOUS_WORDS = {"login", "verify", "secure", "account", "update", "password", "wallet", "confirm"}

def analyze(raw_url):
    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    findings = []
    score = 0

    if parsed.scheme != "https":
        score += 1
        findings.append("URL does not use HTTPS.")
    if "@" in parsed.netloc:
        score += 2
        findings.append("User-info marker (@) appears in the authority section.")
    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        findings.append("Punycode domain label detected; inspect for lookalike characters.")
    try:
        ipaddress.ip_address(host)
        score += 2
        findings.append("URL uses an IP address instead of a conventional domain.")
    except ValueError:
        pass
    if len(host) > 45:
        score += 1
        findings.append("Unusually long hostname.")
    if host.count(".") >= 4:
        score += 1
        findings.append("Hostname has many subdomain levels.")
    decoded = unquote((parsed.path + " " + parsed.query).lower())
    words = sorted(word for word in SUSPICIOUS_WORDS if word in decoded or word in host)
    if words:
        score += min(2, len(words))
        findings.append("Sensitive-themed words found: " + ", ".join(words))
    if parsed.scheme not in ("http", "https") or not host:
        score += 3
        findings.append("URL format is unusual or incomplete.")
    if not findings:
        findings.append("No simple heuristic indicators found.")

    label = "LOW" if score <= 1 else "MEDIUM" if score <= 3 else "HIGH"
    return score, label, findings

def main():
    parser = argparse.ArgumentParser(description="Static URL risk heuristics; never visits the URL.")
    parser.add_argument("url", help="URL to analyze")
    args = parser.parse_args()
    score, label, findings = analyze(args.url)
    print("URL:", args.url)
    print(f"Heuristic score: {score} | Indicator level: {label}")
    for finding in findings:
        print("-", finding)
    print("Caution: this is not a verdict. Do not open suspicious links to test them.")

if __name__ == "__main__":
    main()
