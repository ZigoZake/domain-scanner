from __future__ import annotations

import dns.resolver


DEFAULT_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def get_dns_records(domain):
    records = {"domain": domain, "records": {}}
    try:
        for record_type in DEFAULT_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records["records"][record_type] = [answer.to_text() for answer in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
                records["records"][record_type] = []
    except Exception as exc:
        records["error"] = str(exc)
    return records