from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from modules import dns_enum, port_scan, reputation, subdomain_enum, tech_detect, vuln_scan, whois_lookup


def sanitize_domain(domain: str) -> str:
    value = domain.strip().lower().replace("https://", "").replace("http://", "")
    value = value.rstrip("/")
    if "/" in value:
        value = value.split("/", 1)[0]
    return value


def safe_filename(domain: str) -> str:
    cleaned = sanitize_domain(domain)
    return "".join(ch if ch.isalnum() or ch in {"-", "."} else "_" for ch in cleaned)


def build_summary(result: dict) -> dict:
    ports_result = result.get("ports", {})
    port_count = len(ports_result.get("ports", []))
    subdomains = result.get("subdomains", [])
    vulns = result.get("vulnerabilities", {}).get("findings", [])
    risk_score = result.get("reputation", {}).get("score", 100)

    summary = {
        "domain": result["domain"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "port_count": port_count,
        "subdomain_count": len(subdomains),
        "vulnerability_count": len(vulns),
        "risk_score": risk_score,
        "risk_level": result.get("reputation", {}).get("level", "unknown"),
        "highlights": [
            f"Open ports: {port_count}",
            f"Discovered subdomains: {len(subdomains)}",
            f"Vulnerability findings: {len(vulns)}",
        ],
    }
    return summary


def run_scan(domain: str, output_dir: str | None = None):
    clean_domain = sanitize_domain(domain)
    report_dir = Path(output_dir) if output_dir else Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    dns_result = dns_enum.get_dns_records(clean_domain)
    ports_result = port_scan.scan_ports(clean_domain)
    subdomains = subdomain_enum.get_subdomains(clean_domain)
    tech_result = tech_detect.detect_technologies(clean_domain)
    vuln_result = vuln_scan.scan_vulnerabilities(clean_domain, output_dir=str(report_dir))
    whois_result = whois_lookup.get_whois(clean_domain)

    reputation_result = reputation.get_domain_reputation(
        clean_domain,
        dns=dns_result,
        ports=ports_result,
        tech=tech_result,
        vulnerabilities=vuln_result,
    )

    report = {
        "domain": clean_domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "whois": whois_result,
        "dns": dns_result,
        "subdomains": subdomains,
        "ports": ports_result,
        "technologies": tech_result,
        "vulnerabilities": vuln_result,
        "reputation": reputation_result,
    }
    report["summary"] = build_summary(report)

    file_name = f"{safe_filename(clean_domain)}_report.json"
    output_path = report_dir / file_name
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    return {
        "report_path": str(output_path),
        "summary": report["summary"],
        "report": report,
    }


def main():
    parser = argparse.ArgumentParser(description="Scan a domain and export a JSON report.")
    parser.add_argument("domain", nargs="?", help="Domain to scan, for example example.com")
    parser.add_argument("--domain", dest="domain_flag", help="Domain to scan, for example example.com")
    parser.add_argument("--output-dir", default="reports", help="Directory to write reports to")
    args = parser.parse_args()

    target = args.domain_flag or args.domain
    if not target:
        target = input("Enter domain (e.g., example.com): ").strip()

    result = run_scan(target, output_dir=args.output_dir)
    print(json.dumps(result["summary"], indent=2))
    print(f"\nReport saved to: {result['report_path']}")


if __name__ == "__main__":
    main()
