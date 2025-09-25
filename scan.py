import json
import os
import datetime
from modules import whois_lookup, dns_enum, subdomain_enum, port_scan, tech_detect, vuln_scan

def default_serializer(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    return str(obj)

def run_scan(domain):
    print(f"🔍 Scanning domain: {domain}")

    result = {
        "domain": domain,
        "whois": whois_lookup.get_whois(domain),
        "dns": dns_enum.get_dns_records(domain),
        "subdomains": subdomain_enum.get_subdomains(domain),
        "open_ports": port_scan.scan_ports(domain),
        "technologies": tech_detect.detect_technologies(domain),
        "vulnerabilities": vuln_scan.scan_vulnerabilities(domain)
    }

    # Save result
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/{domain}_report.json", "w") as f:
        json.dump(result, f, indent=2, default=default_serializer)

    print(f"✅ Report saved to reports/{domain}_report.json")

if __name__ == "__main__":
    target = input("Enter domain (e.g., example.com): ")
    run_scan(target)
