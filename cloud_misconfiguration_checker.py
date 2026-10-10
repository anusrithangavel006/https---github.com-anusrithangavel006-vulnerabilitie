import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError

def main():
    s3 = boto3.client("s3")
    ec2 = boto3.client("ec2")
    findings = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                status = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(status.get(key, False) for key in (
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets"
                ))
                if not blocked:
                    findings.append({"severity": "HIGH", "resource": f"s3://{name}",
                                     "finding": "Not all S3 Block Public Access controls are enabled."})
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
                    findings.append({"severity": "REVIEW", "resource": f"s3://{name}",
                                     "finding": "Could not confirm all public-access-block settings."})
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for group in groups:
            for permission in group.get("IpPermissions", []):
                ports = f"{permission.get('FromPort', 'all')}-{permission.get('ToPort', 'all')}"
                for item in permission.get("IpRanges", []):
                    if item.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "severity": "REVIEW",
                            "resource": f"{group.get('GroupId')} ({group.get('GroupName')})",
                            "finding": f"Ingress allows IPv4 from 0.0.0.0/0 on ports {ports}; verify business need."
                        })
                for item in permission.get("Ipv6Ranges", []):
                    if item.get("CidrIpv6") == "::/0":
                        findings.append({
                            "severity": "REVIEW",
                            "resource": f"{group.get('GroupId')} ({group.get('GroupName')})",
                            "finding": f"Ingress allows IPv6 from ::/0 on ports {ports}; verify business need."
                        })
        print(json.dumps({"findings_count": len(findings), "findings": findings}, indent=2))
        if not findings:
            print("No issues detected by these limited checks. This does not prove the account is secure.")
    except (BotoCoreError, ClientError) as exc:
        raise SystemExit(f"AWS read failed. Check region and read-only IAM permissions: {exc}")

if __name__ == "__main__":
    main()
