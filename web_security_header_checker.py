import sys
from urllib.parse import urlparse
import requests

RECOMMENDED = {
    "strict-transport-security": "Encourages HTTPS-only access in supported browsers.",
    "content-security-policy": "Helps limit content sources and reduce some injection risks.",
    "x-content-type-options": "Set to nosniff to reduce MIME-type sniffing.",
    "x-frame-options": "Helps control framing; CSP frame-ancestors is a modern alternative.",
    "referrer-policy": "Controls referrer information sent to other sites.",
    "permissions-policy": "Restricts browser features such as camera and microphone."
}

def main():
    if len(sys.argv) != 2:
        print("Usage: python web_security_header_checker.py https://your-authorized-site.example")
        raise SystemExit(2)
    url = sys.argv[1].strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit("Please provide a valid http:// or https:// URL.")
    try:
        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "VulnCentral-Header-Checker/1.0"})
    except requests.RequestException as exc:
        raise SystemExit(f"Request failed: {exc}")
    print(f"Requested: {url}")
    print(f"Final URL: {response.url}")
    print(f"HTTP status: {response.status_code}")
    print(f"HTTPS used: {'YES' if urlparse(response.url).scheme == 'https' else 'NO'}")
    print("\nSecurity headers:")
    for header, meaning in RECOMMENDED.items():
        value = response.headers.get(header)
        print(f"- {header}: {value if value else 'MISSING'}")
        if not value:
            print(f"  Note: {meaning}")
    print("\nThis is a basic header check, not a full web application security assessment.")

if __name__ == "__main__":
    main()
