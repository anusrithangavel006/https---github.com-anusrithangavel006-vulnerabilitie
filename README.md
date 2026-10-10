# Cybersecurity Programs Pack (Python)

Eight educational programs with separate scripts, setup instructions, and safe defaults.

## Programs
1. `web_security_header_checker.py` — checks HTTPS and response security headers.
2. `malware_hash_checker.py` — calculates SHA-256 and optionally queries VirusTotal using an API key.
3. `phishing_url_analyzer.py` — static URL heuristics; it does not open the URL.
4. `encryption_tool.py` — encrypts/decrypts text using Fernet authenticated encryption.
5. `cloud_misconfiguration_checker.py` — read-only AWS checks for public S3 settings and broad security-group ingress.
6. `incident_report_generator.py` — converts JSON findings to a Markdown report.
7. `ai_vulnerability_explainer.py` — retrieves CVE data from NVD and creates a grounded summary (rule-based; no AI model is called).
8. `database_audit.py` — read-only PostgreSQL audit for role attributes and table privileges.

## Setup
Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
```

Some programs need extra setup:
- Header checker: network access to a website you are authorized to check.
- Malware hash checker: VirusTotal API key only for optional online lookup; do not upload files.
- Encryption tool: creates/uses a local key file. Keep that key private; losing it means encrypted text cannot be decrypted.
- Cloud checker: AWS CLI credentials or environment credentials with read-only permissions; checks only the account you are authorized to audit.
- CVE explainer: internet access to query NVD's public API.
- Database audit: `DATABASE_URL` environment variable and a read-only PostgreSQL account.

## Examples
```bash
python web_security_header_checker.py https://example.com
python malware_hash_checker.py ./sample_file.txt
python phishing_url_analyzer.py "http://example-login.test.example/path"
python encryption_tool.py generate-key
python encryption_tool.py encrypt "hello world"
python encryption_tool.py decrypt "PASTE_FERNET_TOKEN_HERE"
python cloud_misconfiguration_checker.py
python incident_report_generator.py sample_findings.json --out report.md
python ai_vulnerability_explainer.py CVE-2021-44228
python database_audit.py
```

## Important notes
- Use these tools only on websites, files, cloud accounts, and databases you own or are explicitly authorized to assess.
- The URL analyzer is heuristic and may produce false positives/negatives.
- The malware hash checker calculates a hash locally. Online reputation lookup is optional and sends only the hash to VirusTotal.
- The AWS checker is read-only and does not change cloud configuration.
- The CVE explainer summarizes NVD metadata; it does not perform host scanning or generate AI responses.
- Do not treat tool output as proof that a system is secure.
