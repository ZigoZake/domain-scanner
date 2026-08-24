from __future__ import annotations

import dns.resolver

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "login",
    "admin",
    "api",
    "ftp",
    "test",
    "dev",
    "staging",
    "beta",
    "portal",
    "shop",
    "blog",
    "app",
    "cdn",
    "assets",
    "ns1",
    "ns2",
    "smtp",
    "imap",
    "vpn",
    "remote",
    "db",
    "mysql",
    "redis",
    "docs",
    "support",
    "status",
    "m",
    "www2",
]


def get_subdomains(domain, wordlist=None):
    candidates = wordlist or COMMON_SUBDOMAINS
    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for candidate in candidates:
        host = f"{candidate}.{domain}"
        try:
            answers = resolver.resolve(host, "A")
            if answers:
                found.append({
                    "subdomain": host,
                    "records": [answer.to_text() for answer in answers],
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            continue

    return found