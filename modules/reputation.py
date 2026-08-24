from __future__ import annotations


def get_domain_reputation(domain, dns=None, ports=None, tech=None, vulnerabilities=None):
    """Return a conservative heuristic reputation score."""
    score = 100
    reasons = []

    if dns and dns.get("records", {}).get("A") == []:
        score -= 20
        reasons.append("No A record detected for the root domain.")

    if ports and isinstance(ports, dict):
        for item in ports.get("ports", []):
            port_number = item.get("port")
            if port_number in {21, 22, 23, 110, 445, 3389, 8080, 8443}:
                score -= 10
                reasons.append(f"Open high-risk port {port_number} observed.")

    if tech and tech.get("technologies"):
        score -= 5
        reasons.append("Technology fingerprinting succeeded for the domain.")

    if vulnerabilities and vulnerabilities.get("findings"):
        findings = vulnerabilities.get("findings", [])
        score -= min(30, len(findings) * 5)
        reasons.append(f"{len(findings)} vulnerability finding(s) were reported.")

    if score < 0:
        score = 0

    if score >= 80:
        level = "good"
    elif score >= 50:
        level = "moderate"
    else:
        level = "poor"

    return {
        "domain": domain,
        "source": "heuristic",
        "score": score,
        "level": level,
        "reasons": reasons or ["No major risk indicators were found in the collected scan data."],
    }
